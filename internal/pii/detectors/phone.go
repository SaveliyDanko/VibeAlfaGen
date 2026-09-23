package detectors

import (
	"github.com/alfagen/pii-service/internal/pii"
)

// PhoneDetector finds Russian phone numbers with +7/8, parentheses, spaces and
// hyphens.
type PhoneDetector struct {
	re              *pattern
	phoneMarkers    []*pattern
	nonPhoneContext *pattern
}

// NewPhoneDetector builds a PhoneDetector.
func NewPhoneDetector() *PhoneDetector {
	return &PhoneDetector{
		// +7/8 followed by either a three-digit mobile/area code and 7 digits,
		// or a four-digit regional code and 6 digits.
		re: compilePattern(`(?:\+7|8)[\s\-]?(?:\(?\d{4}\)?[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}|\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})`),
		phoneMarkers: []*pattern{
			compilePattern(`(?i)телефон`), compilePattern(`(?i)мобильн\p{L}*`), compilePattern(`(?i)контактн\p{L}*`),
		},
		nonPhoneContext: compilePattern(`(?i)(?:^|[^\p{L}\p{N}])(?:номер(?:\s+(?:заказа|договора|сч[её]та|накладной))?|сч[её]т|заказ|накладная|код|артикул|договор|регистрационный\s+номер)\s*[:#№\-—]?\s*$`),
	}
}

// Type implements pii.Detector.
func (d *PhoneDetector) Type() pii.PIIType { return pii.TypePhone }

// Detect implements pii.Detector.
func (d *PhoneDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.re.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		if !hasContextRegex(input, start, end, d.phoneMarkers) && precedingLabel(input, start, d.nonPhoneContext) {
			continue
		}
		out = append(out, pii.Finding{
			Type:       pii.TypePhone,
			Start:      start,
			End:        end,
			Confidence: pii.ConfidenceHigh,
			Detector:   "phone",
			Value:      input[start:end],
		})
	}
	return out
}
