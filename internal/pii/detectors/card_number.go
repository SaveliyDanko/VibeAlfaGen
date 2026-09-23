package detectors

import (
	"github.com/alfagen/pii-service/internal/pii"
)

// CardNumberDetector finds payment card numbers (13-19 digits) with Luhn
// validation. Explicit context like "карта"/"номер карты" boosts confidence.
type CardNumberDetector struct {
	re             *pattern
	markers        []*pattern
	nonCardContext *pattern
}

// NewCardNumberDetector builds a CardNumberDetector.
func NewCardNumberDetector() *CardNumberDetector {
	return &CardNumberDetector{
		// 13-19 digits, either contiguous or grouped by a single space or
		// hyphen. Separator consistency is validated in Detect so that mixed
		// separators and double spaces are rejected. The 4-6-5 grouping covers
		// Amex-style cards; the 4-4-4-4 grouping covers the common 16-digit
		// layout with an optional trailing 1-3 digits.
		re: compilePattern(`\b(?:\d{13,19}|\d{4}[\s-]\d{6}[\s-]\d{5}|\d{4}(?:[\s-]\d{4}){2,3}(?:[\s-]\d{1,3})?)\b`),
		markers: []*pattern{
			compilePattern(`(?i)номер\s+карт\p{L}*`),
			compilePattern(`(?i)карт\p{L}*`),
			compilePattern(`(?i)банковск\p{L}*\s+карт\p{L}*`),
			compilePattern(`(?i)платёжн\p{L}*\s+карт\p{L}*`),
			compilePattern(`(?i)платежн\p{L}*\s+карт\p{L}*`),
		},
		nonCardContext: compilePattern(`(?i)(?:^|[^\p{L}\p{N}])(?:номер|сч[её]т|код|артикул|заказ|договор|накладная|телефон|регистрационный\s+номер)\s*[:#№\-]?\s*$`),
	}
}

// Type implements pii.Detector.
func (d *CardNumberDetector) Type() pii.PIIType { return pii.TypeCardNumber }

// Detect implements pii.Detector.
func (d *CardNumberDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.re.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		candidate := input[start:end]
		digits := normalizeDigits(candidate)
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if !consistentSeparators(candidate) {
			continue
		}
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		hasCtx := hasContextRegex(input, start, end, d.markers)
		if !hasCtx && precedingLabel(input, start, d.nonCardContext) {
			continue
		}
		valid := luhn(digits)
		if !valid && !hasCtx {
			continue
		}
		// The previous guard requires either valid checksum or explicit context.
		conf := pii.ConfidenceHigh
		out = append(out, pii.Finding{
			Type:       pii.TypeCardNumber,
			Start:      start,
			End:        end,
			Confidence: conf,
			Detector:   "card_number",
			Value:      candidate,
		})
	}
	return out
}

// consistentSeparators reports whether every separator between digit groups in
// s is the same single character (a space or a hyphen). A contiguous digit
// string with no separators is accepted.
func consistentSeparators(s string) bool {
	var sep byte
	seen := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '-' {
			if !seen {
				sep = s[i]
				seen = true
			} else if s[i] != sep {
				return false
			}
		}
	}
	return true
}

// luhn validates a card number using the Luhn algorithm.
func luhn(s string) bool {
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
