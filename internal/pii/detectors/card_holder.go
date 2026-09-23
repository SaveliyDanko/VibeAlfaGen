package detectors

import (
	"github.com/alfagen/pii-service/internal/pii"
)

// CardHolderDetector finds the card holder name after markers like
// "держатель карты" or "имя держателя".
type CardHolderDetector struct {
	markers []*pattern
}

// NewCardHolderDetector builds a CardHolderDetector.
func NewCardHolderDetector() *CardHolderDetector {
	return &CardHolderDetector{
		markers: []*pattern{
			compilePattern(`(?i)держател\p{L}*\s+карт\p{L}*`),
			compilePattern(`(?i)имя\s+держателя`),
			compilePattern(`(?i)имя\s+на\s+карт\p{L}*`),
			compilePattern(`(?i)\bcardholder\b`),
			compilePattern(`(?i)\bcard\s+holder\b`),
		},
	}
}

// Type implements pii.Detector.
func (d *CardHolderDetector) Type() pii.PIIType { return pii.TypeCardHolder }

// Detect implements pii.Detector.
func (d *CardHolderDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.markers {
		for _, loc := range m.FindAllStringIndex(input, -1) {
			start, end, ok := collectLabeledWords(input, loc[1], 3, nil)
			if !ok {
				continue
			}
			out = append(out, pii.Finding{
				Type:       pii.TypeCardHolder,
				Start:      start,
				End:        end,
				Confidence: pii.ConfidenceHigh,
				Detector:   "card_holder",
				Value:      input[start:end],
			})
		}
	}
	return out
}
