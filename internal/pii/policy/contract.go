package policy

import (
	"slices"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/alfagen/pii-service/internal/pii"
)

// BuiltinTypes returns the built-in PII type set. Callers that also register
// config-driven custom types extend this set before validating a contract, so
// ValidateContract never special-cases where a type came from.
func BuiltinTypes() map[string]bool {
	valid := make(map[string]bool, len(pii.AllTypes))
	for _, typ := range pii.AllTypes {
		valid[string(typ)] = true
	}
	return valid
}

// ValidateContract is shared by configuration validation and request
// processing. validTypes is the full universe of PII type names this policy
// may reference: built-in types plus any registered custom types.
func ValidateContract(pol contracts.Policy, validTypes map[string]bool) error {
	if !pii.ValidProfile(pol.DetectionProfile) || pol.Version == "" || pol.TTL <= 0 || (pol.Mode != "tokens" && pol.Mode != "benchmark") {
		return contracts.ErrInvalidPolicy
	}
	if !knownTypes(pol.DetectTypes, validTypes) || !knownTypes(pol.MaskTypes, validTypes) {
		return contracts.ErrInvalidPolicy
	}
	if err := validateMaskTypes(pol); err != nil {
		return err
	}
	for _, rule := range pol.Rules {
		if !validTypes[rule.Type] || !detectionEnabled(pol, rule.Type) {
			return contracts.ErrInvalidPolicy
		}
		if !knownTypes(rule.Requires, validTypes) || !allDetected(pol, rule.Requires) {
			return contracts.ErrInvalidPolicy
		}
	}
	return nil
}

func knownTypes(types []string, validTypes map[string]bool) bool {
	for _, typ := range types {
		if !validTypes[typ] {
			return false
		}
	}
	return true
}

func detectionEnabled(pol contracts.Policy, typ string) bool {
	return pol.DetectTypes == nil || slices.Contains(pol.DetectTypes, typ)
}

func allDetected(pol contracts.Policy, types []string) bool {
	for _, typ := range types {
		if !detectionEnabled(pol, typ) {
			return false
		}
	}
	return true
}

func validateMaskTypes(pol contracts.Policy) error {
	if pol.DetectTypes != nil && pol.MaskTypes == nil {
		for _, typ := range pii.AllTypes {
			if !detectionEnabled(pol, string(typ)) {
				return contracts.ErrInvalidPolicy
			}
		}
	}
	if !allDetected(pol, pol.MaskTypes) {
		return contracts.ErrInvalidPolicy
	}
	return nil
}
