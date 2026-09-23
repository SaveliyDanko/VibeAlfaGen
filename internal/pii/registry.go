package pii

import (
	"context"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

// Registry holds all registered detectors and resolves overlapping findings
// deterministically. Detectors are registered once at startup; the registry is
// safe for concurrent reads after construction.
type Registry struct {
	detectors []Detector
	supported [][]PIIType
	// supportedSet and supportedNames cache the union of supported across
	// every detector, computed once at construction (r.supported is never
	// mutated afterward). SupportedTypeSet/SupportedTypeNames are called on
	// every request (policy validation), so this avoids re-walking every
	// detector's type list and re-allocating a map per call. Callers must
	// treat the returned maps as read-only.
	supportedSet   map[PIIType]bool
	supportedNames map[string]bool
}

// NewRegistry creates a registry from the given detectors. Detectors are kept
// in registration order; this order is used as a tie-breaker in overlap
// resolution.
func NewRegistry(detectors ...Detector) *Registry {
	r := &Registry{detectors: append([]Detector(nil), detectors...), supported: make([][]PIIType, len(detectors))}
	for i, detector := range detectors {
		r.supported[i] = append([]PIIType(nil), SupportedTypes(detector)...)
	}
	r.supportedSet = make(map[PIIType]bool)
	r.supportedNames = make(map[string]bool)
	for _, types := range r.supported {
		for _, t := range types {
			r.supportedSet[t] = true
			r.supportedNames[string(t)] = true
		}
	}
	return r
}

// Detectors returns the registered detectors.
func (r *Registry) Detectors() []Detector {
	return append([]Detector(nil), r.detectors...)
}

// SupportedTypeSet returns every PII type covered by at least one registered
// detector. Config validation and "detect everything" requests use this as
// the universe of valid types instead of the static built-in AllTypes list,
// so a config-driven custom type behaves exactly like a built-in one. The
// returned map is shared and must not be mutated.
func (r *Registry) SupportedTypeSet() map[PIIType]bool {
	return r.supportedSet
}

// SupportedTypeNames is SupportedTypeSet with string keys, for callers (like
// policy.ValidateContract) that compare against contracts.Policy's
// string-typed fields. The returned map is shared and must not be mutated.
func (r *Registry) SupportedTypeNames() map[string]bool {
	return r.supportedNames
}

// Collect returns validated, unresolved findings. Policy filtering must happen
// before overlap resolution so an excluded type cannot suppress an allowed one.
func (r *Registry) Collect(ctx context.Context, input string, types []string) (out []Finding, err error) {
	return r.collect(ctx, input, types, false)
}

// CollectCandidates includes ambiguous candidates for subsequent resolution.
func (r *Registry) CollectCandidates(ctx context.Context, input string, types []string) ([]Finding, error) {
	return r.collect(ctx, input, types, true)
}

func (r *Registry) collect(ctx context.Context, input string, types []string, candidates bool) (out []Finding, err error) {
	defer func() {
		if recover() != nil {
			out = nil
			err = fmt.Errorf("detector failed")
		}
	}()
	if !utf8.ValidString(input) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	view := normalizeText(input)
	wanted := r.requestedTypes(types)
	covered := map[PIIType]bool{}
	for index, d := range r.detectors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !coverRequested(r.supported[index], wanted, covered) {
			continue
		}
		findings := detectorFindings(d, view.text, candidates)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out, err = appendOriginalFindings(out, input, view, wanted, findings)
		if err != nil {
			return nil, err
		}
	}
	for typ := range wanted {
		if !covered[typ] {
			return nil, fmt.Errorf("required detector unavailable")
		}
	}
	return out, nil
}

// Detect runs every detector and returns the merged, overlap-resolved findings
// sorted by Start ascending. Findings are resolved deterministically.
func (r *Registry) Detect(input string) []Finding {
	// Compatibility helper for registry consumers and eval. Use only registered
	// types here; Collect still enforces mandatory detector availability.
	var types []string
	for _, supported := range r.supported {
		for _, typ := range supported {
			types = append(types, string(typ))
		}
	}
	all, err := r.CollectCandidates(context.Background(), input, types)
	if err != nil {
		return nil
	}
	resolved, _ := ResolveContext(input, all)
	return ResolveOverlaps(FilterConfidence(resolved, ProfileBalanced))
}

// ResolveOverlaps takes a set of findings and returns a non-overlapping subset
// chosen deterministically. Overlapping findings are resolved by priority:
//  1. higher Confidence wins;
//  2. on equal confidence, the longer span wins;
//  3. on equal span, the earlier Start wins;
//  4. on identical spans, the detector registered first wins (stable order).
//
// The result is sorted by Start ascending.
func ResolveOverlaps(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}
	// Sort by Start, then by the resolution priority so that when we sweep
	// left-to-right the "best" finding at each position is encountered first.
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		return better(a, b)
	})

	var out []Finding
	for _, f := range findings {
		if len(out) == 0 {
			out = append(out, f)
			continue
		}
		last := &out[len(out)-1]
		if f.Start >= last.End {
			// No overlap with the last accepted finding.
			out = append(out, f)
			continue
		}
		// Overlap: keep the better one. Since findings are sorted by Start and
		// better() is a total order, the earlier one is already the better one
		// when it overlaps; but a later finding could still be better if it
		// starts at the same position (handled by sort) — otherwise keep last.
		// Keep the complete union covered by either PII finding. Dropping the
		// outer span in favour of a narrow candidate could reveal its suffix.
		start, end := last.Start, last.End
		if f.End > end {
			end = f.End
		}
		if better(f, *last) {
			out[len(out)-1] = f
		}
		out[len(out)-1].Start = start
		out[len(out)-1].End = end
	}
	return out
}

// better reports whether a should be preferred over b when they overlap.
func better(a, b Finding) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	aLen := a.End - a.Start
	bLen := b.End - b.Start
	if aLen != bLen {
		return aLen > bLen
	}
	if a.Start != b.Start {
		return a.Start < b.Start
	}
	// Identical span: prefer the detector registered earlier. We rely on the
	// stable sort preserving registration order, so returning false keeps the
	// earlier one.
	return false
}

func (r *Registry) requestedTypes(types []string) map[PIIType]bool {
	wanted := map[PIIType]bool{}
	if types == nil {
		for typ := range r.SupportedTypeSet() {
			wanted[typ] = true
		}
	} else {
		for _, typ := range types {
			wanted[PIIType(typ)] = true
		}
	}
	return wanted
}

func coverRequested(supported []PIIType, wanted, covered map[PIIType]bool) bool {
	run := false
	for _, typ := range supported {
		if wanted[typ] {
			run = true
			covered[typ] = true
		}
	}
	return run
}

func appendOriginalFindings(out []Finding, input string, view normalizedText, wanted map[PIIType]bool, findings []Finding) ([]Finding, error) {
	for _, f := range findings {
		if !wanted[f.Type] {
			continue
		}
		if err := validateFinding(view.text, f); err != nil {
			return nil, err
		}
		f.Start, f.End = view.originalOffset(f.Start), view.originalOffset(f.End)
		f.Value = input[f.Start:f.End]
		out = append(out, f)
	}
	return out, nil
}

func validateFinding(text string, f Finding) error {
	if f.Start < 0 || f.End <= f.Start || f.End > len(text) {
		return fmt.Errorf("invalid detector span")
	}
	if !utf8.RuneStart(text[f.Start]) || (f.End < len(text) && !utf8.RuneStart(text[f.End])) {
		return fmt.Errorf("invalid detector span")
	}
	if math.IsNaN(float64(f.Confidence)) || f.Confidence < 0 || f.Confidence > 1 {
		return fmt.Errorf("invalid detector confidence")
	}
	return nil
}

func detectorFindings(d Detector, text string, candidates bool) []Finding {
	if cd, ok := d.(CandidateDetector); ok && candidates {
		return cd.Candidates(text)
	}
	return d.Detect(text)
}
