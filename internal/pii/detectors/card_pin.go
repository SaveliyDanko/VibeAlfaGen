package detectors

import (
	"github.com/alfagen/pii-service/internal/pii"
)

var pinMarkers = []*pattern{
	compilePattern(`(?i)\bpin\b`),
	compilePattern(`(?i)(?:^|[^\p{L}\p{N}])пин`),
	compilePattern(`(?i)пин-код`),
	compilePattern(`(?i)пин\s+код`),
	compilePattern(`(?i)пароль\s+от\s+карт\p{L}*`),
}

// CardPINDetector finds card PIN codes only with explicit context words, so
// that arbitrary 4-digit numbers are not masked. The context word must be the
// nearest preceding marker within the current field; a closer date or CVV
// marker excludes the PIN marker.
type CardPINDetector struct {
	re *pattern
}

// NewCardPINDetector builds a CardPINDetector.
func NewCardPINDetector() *CardPINDetector {
	return &CardPINDetector{re: compilePattern(`\b(\d{4})\b`)}
}

// Type implements pii.Detector.
func (d *CardPINDetector) Type() pii.PIIType { return pii.TypeCardPIN }

// Detect implements pii.Detector.
func (d *CardPINDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.re.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		if !pinLocalContext(input, start) {
			continue
		}
		out = append(out, pii.Finding{
			Type:       pii.TypeCardPIN,
			Start:      start,
			End:        end,
			Confidence: pii.ConfidenceHigh,
			Detector:   "card_pin",
			Value:      input[start:end],
		})
	}
	return out
}

// pinLocalContext reports whether the nearest preceding marker in the current
// field is a PIN marker (and not a date or CVV marker).
func pinLocalContext(input string, start int) bool {
	groups := []markerGroup{
		{typ: 0, markers: pinMarkers},
		{typ: 1, markers: dateDOBMarkers},
		{typ: 1, markers: dateIssueMarkers},
		{typ: 1, markers: dateGenericMarkers},
		{typ: 2, markers: cvvMarkers},
	}
	return nearestPrecedingMarker(input, start, groups) == 0
}
