package detectors

import (
	"github.com/alfagen/pii-service/internal/pii"
)

// INNDetector finds Russian INN numbers (10 or 12 digits) with checksum
// validation. Context markers like "ИНН" boost confidence.
type INNDetector struct {
	re      *pattern
	markers []*pattern
}

// NewINNDetector builds an INNDetector.
func NewINNDetector() *INNDetector {
	return &INNDetector{
		re: compilePattern(`\b(\d{10}|\d{12})\b`),
		markers: []*pattern{
			compilePattern(`(?i)инн`),
			compilePattern(`(?i)идентификационн\p{L}*\s+номер\s+налогоплательщика`),
		},
	}
}

// Type implements pii.Detector.
func (d *INNDetector) Type() pii.PIIType { return pii.TypeINN }

// Detect implements pii.Detector.
func (d *INNDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.re.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		digits := input[start:end]
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		hasCtx := hasContextRegex(input, start, end, d.markers)
		valid := innChecksum(digits)
		if !hasCtx {
			continue
		}
		conf := pii.ConfidenceMedium
		if valid {
			conf = pii.ConfidenceHigh
		}
		if hasCtx {
			conf = pii.ConfidenceHigh
		}
		out = append(out, pii.Finding{
			Type:       pii.TypeINN,
			Start:      start,
			End:        end,
			Confidence: conf,
			Detector:   "inn",
			Value:      digits,
		})
	}
	return out
}

// innChecksum validates a 10- or 12-digit INN.
func innChecksum(inn string) bool {
	switch len(inn) {
	case 10:
		weights := []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
		sum := 0
		for i := 0; i < 9; i++ {
			sum += int(inn[i]-'0') * weights[i]
		}
		return sum%11%10 == int(inn[9]-'0')
	case 12:
		w1 := []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
		w2 := []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
		sum1 := 0
		for i := 0; i < 10; i++ {
			sum1 += int(inn[i]-'0') * w1[i]
		}
		n11 := sum1 % 11 % 10
		if n11 != int(inn[10]-'0') {
			return false
		}
		sum2 := 0
		for i := 0; i < 11; i++ {
			sum2 += int(inn[i]-'0') * w2[i]
		}
		n12 := sum2 % 11 % 10
		return n12 == int(inn[11]-'0')
	}
	return false
}
