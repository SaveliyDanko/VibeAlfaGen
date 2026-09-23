package detectors

import (
	"github.com/alfagen/pii-service/internal/pii"
)

// DriverLicenseDetector finds Russian driver's license series and numbers.
// Format: 2-3 Cyrillic letters + 6 digits, or 4 digits + 6 digits, with
// context markers like "водительское удостоверение" or "права".
type DriverLicenseDetector struct {
	markers []*pattern
	re      *pattern
}

// NewDriverLicenseDetector builds a DriverLicenseDetector.
func NewDriverLicenseDetector() *DriverLicenseDetector {
	return &DriverLicenseDetector{
		markers: []*pattern{
			compilePattern(`(?i)водительск\p{L}*\s+удостоверени\p{L}*`),
			compilePattern(`(?i)водительск\p{L}*\s+права`),
			compilePattern(`(?i)права`),
			compilePattern(`(?i)в\.у\.`),
			compilePattern(`(?i)удостоверение\s+водителя`),
			compilePattern(`(?i)водительск\p{L}*`),
		},
		// Russian driver license: 2 digits + 2 Cyrillic letters + 6 digits
		// (e.g. "77АВ 123456"), or 4 digits + 6 digits (e.g. "7712 345678").
		re: compilePattern(`(?i)(\d{2}[А-ЯЁ]{2}\s?\d{6}|\d{4}\s?\d{6})`),
	}
}

// Type implements pii.Detector.
func (d *DriverLicenseDetector) Type() pii.PIIType { return pii.TypeDriverLicense }

// Detect implements pii.Detector.
func (d *DriverLicenseDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.re.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		if !hasContextRegex(input, start, end, d.markers) {
			continue
		}
		out = append(out, pii.Finding{
			Type:       pii.TypeDriverLicense,
			Start:      start,
			End:        end,
			Confidence: pii.ConfidenceHigh,
			Detector:   "driver_license",
			Value:      input[start:end],
		})
	}
	return out
}
