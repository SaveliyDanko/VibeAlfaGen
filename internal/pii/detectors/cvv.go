package detectors

import (
	"github.com/alfagen/pii-service/internal/pii"
)

var cvvMarkers = []*pattern{
	compilePattern(`(?i)\bcvv\b`),
	compilePattern(`(?i)\bcvc\b`),
	compilePattern(`(?i)код\s+безопасности`),
	compilePattern(`(?i)защитный\s+код`),
	compilePattern(`(?i)код\s+проверки`),
	compilePattern(`(?i)проверочный\s+код`),
}

// CVVDetector finds CVV/CVC codes only with explicit context words, so that
// arbitrary 3-4 digit numbers are not masked. The context word must be the
// nearest preceding marker within the current field; a closer date or PIN
// marker excludes the CVV marker.
type CVVDetector struct {
	re *pattern
}

// NewCVVDetector builds a CVVDetector.
func NewCVVDetector() *CVVDetector {
	return &CVVDetector{re: compilePattern(`\b(\d{3,4})\b`)}
}

// Type implements pii.Detector.
func (d *CVVDetector) Type() pii.PIIType { return pii.TypeCVV }

// Detect implements pii.Detector.
func (d *CVVDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.re.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		if !cvvLocalContext(input, start) {
			continue
		}
		out = append(out, pii.Finding{
			Type:       pii.TypeCVV,
			Start:      start,
			End:        end,
			Confidence: pii.ConfidenceHigh,
			Detector:   "cvv",
			Value:      input[start:end],
		})
	}
	return out
}

// cvvLocalContext reports whether the nearest preceding marker in the current
// field is a CVV marker (and not a date or PIN marker).
func cvvLocalContext(input string, start int) bool {
	groups := []markerGroup{
		{typ: 0, markers: cvvMarkers},
		{typ: 1, markers: dateDOBMarkers},
		{typ: 1, markers: dateIssueMarkers},
		{typ: 1, markers: dateGenericMarkers},
		{typ: 2, markers: pinMarkers},
	}
	return nearestPrecedingMarker(input, start, groups) == 0
}
