// Package policy decides which findings to apply for a given consumer system.
package policy

import (
	"fmt"
	"sort"
	"time"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/alfagen/pii-service/internal/pii"
)

// MaskMode selects the masking strategy.
type MaskMode string

const (
	// MaskModeFormat is the default format-preserving mask.
	MaskModeFormat MaskMode = "format"
	// MaskModeToken replaces values with typed tokens.
	MaskModeToken MaskMode = "token"
)

// Rule is a conditional rule that can enable or disable a PII type based on
// the presence of other findings.
type Rule struct {
	// Type is the PII type this rule governs.
	Type pii.PIIType
	// Requires lists PII types that must be present for Type to be masked.
	Requires []pii.PIIType
}

// Policy describes how a consumer system should be handled.
type Policy struct {
	DetectionProfile string
	// SystemID is the consumer system identifier.
	SystemID string
	// Enabled indicates whether masking is active for this system.
	Enabled bool
	// Types is the set of PII types to mask. Empty means all supported types.
	Types map[pii.PIIType]bool
	// MaskMode selects the masking strategy.
	MaskMode MaskMode
	// AllowDemask permits the demasking operation.
	AllowDemask bool
	// Rules are conditional rules applied on top of Types.
	Rules       []Rule
	DetectTypes []string
	Version     string
	TTL         time.Duration
}

// New creates a Policy with defaults.
func New(systemID string) *Policy {
	return &Policy{
		SystemID:         systemID,
		DetectionProfile: pii.ProfileBalanced,
		Enabled:          true,
		Types:            nil, // nil means all types.
		MaskMode:         MaskModeFormat,
		AllowDemask:      true,
		Version:          "v1",
		TTL:              time.Hour,
	}
}

// Contract creates a detached request policy. Legacy format/token names are
// accepted at the file boundary; the module contract uses benchmark/tokens.
func (p *Policy) Contract() contracts.Policy {
	out := contracts.Policy{DetectionProfile: p.DetectionProfile, Version: p.Version, Mode: "benchmark", AllowDemask: p.AllowDemask, TTL: p.TTL}
	if p.MaskMode == MaskModeToken {
		out.Mode = "tokens"
	}
	if p.DetectTypes != nil {
		out.DetectTypes = append([]string{}, p.DetectTypes...)
	}
	if p.Types != nil {
		// Whether a type is built-in or config-driven custom is irrelevant at
		// this layer: p.Types is already the full set of enabled types, so a
		// single sorted pass (for deterministic output) covers both without
		// distinguishing their origin.
		out.MaskTypes = make([]string, 0, len(p.Types))
		for typ, on := range p.Types {
			if on {
				out.MaskTypes = append(out.MaskTypes, string(typ))
			}
		}
		sort.Strings(out.MaskTypes)
	}
	for _, r := range p.Rules {
		rule := contracts.PolicyRule{Type: string(r.Type)}
		for _, typ := range r.Requires {
			rule.Requires = append(rule.Requires, string(typ))
		}
		out.Rules = append(out.Rules, rule)
	}
	return out
}

// Allows reports whether the given PII type should be masked for this policy.
func (p *Policy) Allows(typ pii.PIIType) bool {
	if !p.Enabled {
		return false
	}
	if p.Types != nil {
		if !p.Types[typ] {
			return false
		}
	}
	return true
}

// Apply filters findings according to the policy and conditional rules.
// present is the set of all detected types in the input.
func (p *Policy) Apply(findings []pii.Finding, present map[pii.PIIType]bool) []pii.Finding {
	if !p.Enabled {
		return nil
	}
	out := make([]pii.Finding, 0, len(findings))
	for _, f := range findings {
		if !p.Allows(f.Type) {
			continue
		}
		if !p.ruleAllows(f.Type, present) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// ruleAllows checks conditional rules for the given type.
func (p *Policy) ruleAllows(typ pii.PIIType, present map[pii.PIIType]bool) bool {
	for _, r := range p.Rules {
		if r.Type != typ {
			continue
		}
		for _, req := range r.Requires {
			if !present[req] {
				return false
			}
		}
	}
	return true
}

// Validate checks the policy for configuration errors.
func (p *Policy) Validate() error {
	if !pii.ValidProfile(p.DetectionProfile) {
		return contracts.ErrInvalidPolicy
	}
	if p.SystemID == "" {
		return fmt.Errorf("policy: system_id is required")
	}
	if p.MaskMode != MaskModeFormat && p.MaskMode != MaskModeToken {
		return fmt.Errorf("policy: unknown mask_mode %q", p.MaskMode)
	}
	for _, r := range p.Rules {
		if r.Type == "" {
			return fmt.Errorf("policy: rule with empty type")
		}
	}
	return nil
}
