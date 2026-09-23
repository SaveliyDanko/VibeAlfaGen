package engine

import (
	"context"
	"time"

	"github.com/alfagen/pii-service/internal/contracts"
	"github.com/alfagen/pii-service/internal/pii"
)

var criticalTypes = []string{"phone", "email", "card_number", "cvv", "card_pin", "inn", "passport_number", "driver_license"}

// verify reruns the exact recognizers against the actual result. Typed opaque
// markers are excluded: random nonce digits are not new PIN/CVV candidates.
// Failure rejects the whole response before CreateIfAbsent. Policies selecting
// no masking intentionally do not promise sanitization of excluded categories.
func (p *Processor) verify(ctx context.Context, masked string, pol contracts.Policy, applied []pii.Finding) error {
	start := time.Now()
	defer func() { p.stage("verify", start) }()
	types := verificationTypes(pol, applied)
	if len(types) == 0 {
		return ctx.Err()
	}
	findings, err := p.registry.Collect(ctx, hideMarkers(masked), types)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || len(pii.FilterConfidence(findings, pol.DetectionProfile)) > 0 {
		return contracts.ErrDetectionUnavailable
	}
	return nil
}
func selectedType(types []string, typ string) bool {
	if types == nil {
		return true
	}
	for _, t := range types {
		if t == typ {
			return true
		}
	}
	return false
}

func verificationTypes(pol contracts.Policy, applied []pii.Finding) []string {
	var types []string
	accepted := map[string]bool{}
	for _, f := range applied {
		accepted[string(f.Type)] = true
	}
	for _, typ := range criticalTypes {
		conditional := false
		for _, rule := range pol.Rules {
			if rule.Type == typ && len(rule.Requires) > 0 {
				conditional = true
			}
		}
		// A conditionally excluded category is intentionally outside the
		// policy's sanitation promise. Its remaining value is not a failure.
		if conditional && !accepted[typ] {
			continue
		}
		if selectedType(pol.DetectTypes, typ) && selectedType(pol.MaskTypes, typ) {
			types = append(types, typ)
		}
	}
	return types
}
