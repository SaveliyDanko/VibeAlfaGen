// Package engine implements the PII boundary without HTTP or provider dependencies.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/alfagen/pii-service/internal/pii"
	"github.com/alfagen/pii-service/internal/pii/masking"
	"github.com/alfagen/pii-service/internal/pii/policy"
	"github.com/alfagen/pii-service/internal/pii/store"
)

type Processor struct {
	store    store.Store
	registry *pii.Registry
	metrics  contracts.PIIObserver
}

func New(st store.Store, registry *pii.Registry, metrics contracts.PIIObserver) *Processor {
	return &Processor{store: st, registry: registry, metrics: metrics}
}

var _ contracts.PIIProcessor = (*Processor)(nil)

// validate checks scope against the policy contract. The valid type universe
// comes from the actual registered detectors (built-in and config-driven
// custom types alike), not a static list, so it always matches what this
// Processor can actually detect and mask.
func (p *Processor) validate(scope contracts.Scope) error {
	if scope.TenantID == "" || scope.ContextID == "" {
		return contracts.ErrInvalidRequest
	}
	return policy.ValidateContract(scope.Policy, p.registry.SupportedTypeNames())
}

func key(scope contracts.Scope, namespace string) string {
	// Structured encoding avoids delimiter collisions in user/configured identifiers.
	encoded, _ := json.Marshal([]string{scope.TenantID, namespace, scope.ContextID})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func (p *Processor) read(ctx context.Context, id string) (*store.Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	start := time.Now()
	defer func() { p.stage("store_read", start) }()
	rec, ok, err := p.store.Get(ctx, id)
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if err != nil {
		p.storeError("read")
		return nil, false, contracts.ErrStoreUnavailable
	}
	if ok && rec == nil {
		return nil, false, contracts.ErrStoreUnavailable
	}
	if ok && !rec.ExpiresAt.IsZero() && !time.Now().Before(rec.ExpiresAt) {
		return nil, false, nil
	}
	return rec, ok, nil
}
func (p *Processor) save(ctx context.Context, id string, rec *store.Record) (*store.Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	start := time.Now()
	defer func() { p.stage("store_write", start) }()
	saved, created, err := p.store.CreateIfAbsent(ctx, id, rec)
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if err != nil {
		p.storeError("write")
		return nil, false, contracts.ErrStoreUnavailable
	}
	if saved == nil {
		p.storeError("write")
		return nil, false, contracts.ErrStoreUnavailable
	}
	if !saved.ExpiresAt.IsZero() && !time.Now().Before(saved.ExpiresAt) {
		return nil, false, contracts.ErrStoreUnavailable
	}
	return saved, created, nil
}
func (p *Processor) detect(ctx context.Context, text string, pol contracts.Policy) ([]pii.Finding, error) {
	start := time.Now()
	defer func() { p.stage("detect", start) }()
	all, err := p.registry.CollectCandidates(ctx, text, pol.DetectTypes)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, contracts.ErrDetectionUnavailable
	}
	all, stats := pii.ResolveContext(text, all)
	if observer, ok := p.metrics.(contracts.PIIContextObserver); ok {
		for _, typ := range []pii.PIIType{pii.TypeFullName, pii.TypeAddress} {
			observer.ObserveContextDecision(string(typ), "promoted", stats.Promoted[typ])
			observer.ObserveContextDecision(string(typ), "suppressed", stats.Suppressed[typ])
		}
	}
	all = pii.FilterConfidence(all, pol.DetectionProfile)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	present := map[pii.PIIType]bool{}
	for _, f := range all {
		present[f.Type] = true
	}
	filter := policy.New("request")
	if pol.MaskTypes != nil {
		filter.Types = map[pii.PIIType]bool{}
		for _, typ := range pol.MaskTypes {
			filter.Types[pii.PIIType(typ)] = true
		}
	}
	for _, r := range pol.Rules {
		rule := policy.Rule{Type: pii.PIIType(r.Type)}
		for _, typ := range r.Requires {
			rule.Requires = append(rule.Requires, pii.PIIType(typ))
		}
		filter.Rules = append(filter.Rules, rule)
	}
	// Filter before resolving overlaps: disabled categories cannot hide enabled ones.
	return pii.ResolveOverlaps(filter.Apply(all, present)), nil
}
func (p *Processor) mask(ctx context.Context, text string, pol contracts.Policy, forceTokens bool) (string, map[string]string, []pii.Finding, string, error) {
	findings, err := p.detect(ctx, text, pol)
	if err != nil {
		return "", nil, nil, "", err
	}
	start := time.Now()
	defer func() { p.stage("mask", start) }()
	nonce := ""
	if forceTokens || pol.Mode == "tokens" || pol.DetectionProfile == pii.ProfileStrict {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", nil, nil, "", contracts.ErrDetectionUnavailable
		}
		nonce = hex.EncodeToString(b)
	}
	var out strings.Builder
	out.Grow(len(text))
	cursor := 0
	mapping := map[string]string{}
	// Reserve token-like strings already supplied by the caller. Generation
	// never aliases one, even if a nonce collision is forced in a unit test.
	tokens := newTokenTable(text, nonce)
	for _, f := range findings {
		if err := ctx.Err(); err != nil {
			return "", nil, nil, "", err
		}
		out.WriteString(text[cursor:f.Start])
		value := text[f.Start:f.End]
		replacement := masking.Mask(f.Type, value)
		if nonce != "" {
			replacement = tokens.token(f.Type, value)
			mapping[replacement] = value
		}
		out.WriteString(replacement)
		cursor = f.End
	}
	out.WriteString(text[cursor:])
	masked := out.String()
	if len(findings) > 0 {
		if err := p.verify(ctx, masked, pol, findings); err != nil {
			return "", nil, nil, "", err
		}
	}
	return masked, mapping, findings, nonce, nil
}
func (p *Processor) record(text, masked string, mapping map[string]string, nonce string, pol contracts.Policy) *store.Record {
	now := time.Now()
	// Findings are used for request metrics, not state transitions. Do not retain
	// duplicate PII values in every context. Old envelope-v2 records still decode.
	return &store.Record{Original: text, Masked: masked, TransformMap: mapping, TokenNonce: nonce, CreatedAt: now, ExpiresAt: now.Add(pol.TTL), PolicyVersion: pol.Version}
}
func (p *Processor) Process(ctx context.Context, scope contracts.Scope, text string) (string, error) {
	opStart := time.Now()
	if err := p.validate(scope); err != nil {
		p.logOp(ctx, "process", scope, failureOutcome(err, "invalid_request"), nil, len(text), time.Since(opStart))
		return "", err
	}
	id := key(scope, "process")
	rec, ok, err := p.read(ctx, id)
	if err != nil {
		p.logOp(ctx, "process", scope, failureOutcome(err, "store_unavailable"), nil, len(text), time.Since(opStart))
		return "", err
	}
	if ok {
		result, err := processExisting(rec, text, scope.Policy.AllowDemask)
		p.logOp(ctx, "process", scope, outcomeOf(err, rec.Original != text && rec.Masked == text), nil, len(text), time.Since(opStart))
		return result, err
	}
	masked, mapping, findings, nonce, err := p.mask(ctx, text, scope.Policy, false)
	if err != nil {
		p.logOp(ctx, "process", scope, failureOutcome(err, "detection_failed"), nil, len(text), time.Since(opStart))
		return "", err
	}
	types := typesOf(findings)
	rec, created, err := p.save(ctx, id, p.record(text, masked, mapping, nonce, scope.Policy))
	if err != nil {
		p.logOp(ctx, "process", scope, failureOutcome(err, "store_unavailable"), types, len(text), time.Since(opStart))
		return "", err
	}
	if created {
		p.observe(text, findings)
	}
	result, err := processExisting(rec, text, scope.Policy.AllowDemask)
	outcome := outcomeOf(err, rec.Original != text && rec.Masked == text)
	if created && err == nil {
		outcome = "masked_new"
	}
	p.logOp(ctx, "process", scope, outcome, types, len(text), time.Since(opStart))
	return result, err
}

// outcomeOf turns a processExisting error (or its success case) into a
// logged outcome label without repeating the same error switch everywhere.
func outcomeOf(err error, wasMasked bool) string {
	switch {
	case errors.Is(err, contracts.ErrDemaskDenied):
		return "demask_denied"
	case errors.Is(err, contracts.ErrConflict):
		return "conflict"
	case wasMasked:
		return "demasked"
	default:
		return "masked_existing"
	}
}
func processExisting(rec *store.Record, text string, allow bool) (string, error) {
	if rec.Original == text {
		return rec.Masked, nil
	}
	if rec.Masked == text {
		if !allow {
			return "", contracts.ErrDemaskDenied
		}
		return rec.Original, nil
	}
	return "", contracts.ErrConflict
}
func (p *Processor) Mask(ctx context.Context, scope contracts.Scope, text string) (contracts.Masked, error) {
	opStart := time.Now()
	var result contracts.Masked
	if err := p.validate(scope); err != nil {
		p.logOp(ctx, "mask", scope, failureOutcome(err, "invalid_request"), nil, len(text), time.Since(opStart))
		return result, err
	}
	id := key(scope, "generate")
	rec, ok, err := p.read(ctx, id)
	if err != nil {
		p.logOp(ctx, "mask", scope, failureOutcome(err, "store_unavailable"), nil, len(text), time.Since(opStart))
		return result, err
	}
	var types []string
	outcome := "masked_existing"
	if !ok {
		masked, mapping, findings, nonce, err := p.mask(ctx, text, scope.Policy, true)
		if err != nil {
			p.logOp(ctx, "mask", scope, failureOutcome(err, "detection_failed"), nil, len(text), time.Since(opStart))
			return result, err
		}
		types = typesOf(findings)
		var created bool
		rec, created, err = p.save(ctx, id, p.record(text, masked, mapping, nonce, scope.Policy))
		if err != nil {
			p.logOp(ctx, "mask", scope, failureOutcome(err, "store_unavailable"), types, len(text), time.Since(opStart))
			return result, err
		}
		if created {
			outcome = "masked_new"
			p.observe(text, findings)
		}
	}
	if rec.Original != text {
		p.logOp(ctx, "mask", scope, "conflict", types, len(text), time.Since(opStart))
		return result, contracts.ErrConflict
	}
	p.logOp(ctx, "mask", scope, outcome, types, len(text), time.Since(opStart))
	return contracts.Masked{Text: rec.Masked, ContextID: scope.ContextID, PolicyVersion: rec.PolicyVersion}, nil
}

// The type segment allows digits (not just A-Z/_) because config-driven
// custom_pii_types names may contain them (e.g. "employee_badge_v2" ->
// "EMPLOYEE_BADGE_V2" after tokens.token's strings.ToUpper); config validation
// restricts custom type names to a charset this pattern can always parse back.
var markerPattern = regexp.MustCompile(`<([A-Z0-9_]+)_([a-f0-9]{32})_([0-9]+)>`)

// Demask sanitizes provider-added PII and restores only exact, saved markers if
// permission is enabled. Unknown/damaged markers are never resolved by guesswork.
func (p *Processor) Demask(ctx context.Context, scope contracts.Scope, text string) (string, error) {
	opStart := time.Now()
	if err := p.validate(scope); err != nil {
		p.logOp(ctx, "demask", scope, failureOutcome(err, "invalid_request"), nil, len(text), time.Since(opStart))
		return "", err
	}
	rec, ok, err := p.read(ctx, key(scope, "generate"))
	if err != nil {
		p.logOp(ctx, "demask", scope, failureOutcome(err, "store_unavailable"), nil, len(text), time.Since(opStart))
		return "", err
	}
	if !ok {
		p.logOp(ctx, "demask", scope, "context_gone", nil, len(text), time.Since(opStart))
		return "", contracts.ErrContextGone
	}
	// Exact saved echoes are unambiguous even if a marker touches literal
	// letters or another marker. No provider-added text exists in this case.
	if scope.Policy.AllowDemask && text == rec.Masked {
		p.logOp(ctx, "demask", scope, "demasked", nil, len(text), time.Since(opStart))
		return rec.Original, nil
	}
	start := time.Now()
	defer func() { p.stage("demask", start) }()
	spans := markerPattern.FindAllStringIndex(text, -1)
	scan := hideMarkerSpans(text, spans)
	findings, err := p.detect(ctx, scan, scope.Policy)
	if err != nil {
		p.logOp(ctx, "demask", scope, failureOutcome(err, "detection_failed"), nil, len(text), time.Since(opStart))
		return "", err
	}
	// Findings here are PII the provider added to its response; sanitizing and
	// logging their types is the main security signal for this operation.
	types := typesOf(findings)
	// Never allow a detector to overwrite an opaque marker. Reject an ambiguous
	// span crossing one; returning an error is safer than corrupting restoration.
	if findingsCrossMarkers(findings, spans) {
		p.logOp(ctx, "demask", scope, "marker_conflict", types, len(text), time.Since(opStart))
		return "", contracts.ErrDetectionUnavailable
	}
	var safe strings.Builder
	cursor := 0
	for _, f := range findings {
		safe.WriteString(text[cursor:f.Start])
		safe.WriteString("[REDACTED]")
		cursor = f.End
	}
	safe.WriteString(text[cursor:])
	result := safe.String()
	if err := ctx.Err(); err != nil {
		p.logOp(ctx, "demask", scope, failureOutcome(err, "cancelled"), types, len(text), time.Since(opStart))
		return "", err
	}
	if !scope.Policy.AllowDemask {
		p.logOp(ctx, "demask", scope, "sanitized_only", types, len(text), time.Since(opStart))
		return result, nil
	}
	// One-pass replacement: restored fragments are not scanned for other markers.
	result = restoreTokens(result, rec.TransformMap)
	p.logOp(ctx, "demask", scope, "demasked", types, len(text), time.Since(opStart))
	return result, nil
}
func (p *Processor) stage(stage string, start time.Time) {
	if p.metrics != nil {
		p.metrics.ObserveStage(stage, time.Since(start))
	}
}
func (p *Processor) storeError(operation string) {
	if p.metrics != nil {
		p.metrics.ObserveStoreError(operation)
	}
}
func (p *Processor) observe(text string, findings []pii.Finding) {
	if p.metrics == nil {
		return
	}
	p.metrics.ObserveFindings(typesOf(findings))
	p.metrics.ObserveProcessed(len(text), (len(text)+3)/4)
}

func typesOf(findings []pii.Finding) []string {
	if len(findings) == 0 {
		return nil
	}
	types := make([]string, 0, len(findings))
	for _, f := range findings {
		types = append(types, string(f.Type))
	}
	return types
}

// failureOutcome distinguishes request cancellation from dependency failures.
func failureOutcome(err error, fallback string) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, contracts.ErrInvalidPolicy) {
		return "invalid_policy"
	}
	return fallback
}

// logOp records one completed PII operation. Only technical fields reach the
// log: no payload text, PII values, or the caller-controlled ID in the clear.
func (p *Processor) logOp(ctx context.Context, operation string, scope contracts.Scope, outcome string, types []string, textLen int, dur time.Duration) {
	if p.metrics == nil {
		return
	}
	p.metrics.ObserveOperation(contracts.OperationEvent{
		Operation: operation,
		System:    scope.TenantID,
		RequestID: contracts.RequestIDFromContext(ctx),
		Outcome:   outcome,
		Types:     uniqueTypes(types),
		Bytes:     textLen,
		Duration:  dur,
	})
}

// Check is used by readiness without importing the concrete store into Proxy.
func (p *Processor) Check(ctx context.Context) error {
	if p.store == nil || p.registry == nil {
		return errors.New("PII is not configured")
	}
	if checker, ok := p.store.(contracts.HealthChecker); ok {
		return checker.Check(ctx)
	}
	return nil
}

// Deduplicate only event fields; finding counters still count every occurrence.
func uniqueTypes(types []string) []string {
	seen := make(map[string]bool, len(types))
	var result []string
	for _, typ := range types {
		if !seen[typ] {
			seen[typ] = true
			result = append(result, typ)
		}
	}
	return result
}

func findingsCrossMarkers(findings []pii.Finding, spans [][]int) bool {
	markerIndex := 0
	for _, finding := range findings {
		for markerIndex < len(spans) && spans[markerIndex][1] <= finding.Start {
			markerIndex++
		}
		if markerIndex < len(spans) && finding.Start < spans[markerIndex][1] && spans[markerIndex][0] < finding.End {
			return true
		}
	}
	return false
}
