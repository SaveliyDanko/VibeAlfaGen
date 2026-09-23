package detectors

import (
	"strings"

	"github.com/alfagen/pii-service/internal/pii"
)

// PassportDetector finds Russian passport series and numbers, the issuing
// authority, and the division code. It supports variants like
// "серия 4509 номер 123456", "паспорт 4509 123456", and merged/split forms
// when context is present.
type PassportDetector struct {
	// passportMarkers indicate a passport number.
	passportMarkers []*pattern
	// issuerMarkers indicate the issuing authority.
	issuerMarkers []*pattern
	// divisionMarkers indicate the division code.
	divisionMarkers []*pattern
	// seriesNumberRe matches "серия XXXX номер YYYYYY" or "паспорт XXXX YYYYYY".
	seriesNumberRe *pattern
	// mergedRe matches a merged 10-digit passport number with context.
	mergedRe *pattern
	// divisionRe matches "код подразделения XXX-XXX".
	divisionRe *pattern
}

// NewPassportDetector builds a PassportDetector.
func NewPassportDetector() *PassportDetector {
	return &PassportDetector{
		passportMarkers: []*pattern{
			compilePattern(`(?i)паспорт`),
			compilePattern(`(?i)серия`),
			compilePattern(`(?i)номер\s+паспорта`),
			compilePattern(`(?i)паспортные\s+данные`),
			compilePattern(`(?i)удостоверение\s+личности`),
		},
		issuerMarkers: []*pattern{
			compilePattern(`(?i)(?:^|[^\p{L}\p{N}])выдан(?:о|а)?(?:$|[^\p{L}\p{N}])`),
			compilePattern(`(?i)(?:^|[^\p{L}\p{N}])орган\p{L}*\s+выдавш\p{L}*(?:$|[^\p{L}\p{N}])`),
			compilePattern(`(?i)(?:^|[^\p{L}\p{N}])кем\s+выдан(?:$|[^\p{L}\p{N}])`),
		},
		divisionMarkers: []*pattern{
			compilePattern(`(?i)код\s+подразделения`),
			compilePattern(`(?i)подразделение`),
		},
		seriesNumberRe: compilePattern(`(?i)(?:серия\s*)?(\d{2})[\s-]?(\d{2})\s*,?\s*(?:(?:номер|№)\s*)?(\d{6})`),
		mergedRe:       compilePattern(`\b(\d{10})\b`),
		divisionRe:     compilePattern(`\b(\d{3})[\s\-](\d{3})\b`),
	}
}

// Type implements pii.Detector.
func (d *PassportDetector) Type() pii.PIIType { return pii.TypePassportNumber }

func (d *PassportDetector) Types() []pii.PIIType {
	return []pii.PIIType{pii.TypePassportNumber, pii.TypePassportIssuer, pii.TypePassportDivision}
}

// Detect implements pii.Detector.
func (d *PassportDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding

	out = append(out, d.detectSeriesNumber(input)...)
	out = append(out, d.detectMergedNumber(input, out)...)
	out = append(out, d.detectDivision(input)...)

	// Issuing authority: a capitalized phrase following "выдан"/"кем выдан".
	out = append(out, d.detectIssuer(input)...)

	return out
}

// detectIssuer finds the issuing authority phrase after "выдан".
func (d *PassportDetector) detectIssuer(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.issuerMarkers {
		for _, loc := range m.FindAllStringIndex(input, -1) {
			start, end, ok := collectLabelValue(input, loc[1], 8, nil, true)
			if !ok {
				continue
			}
			if !isPassportAuthority(input[start:end]) {
				continue
			}
			out = append(out, pii.Finding{
				Type:       pii.TypePassportIssuer,
				Start:      start,
				End:        end,
				Confidence: pii.ConfidenceHigh,
				Detector:   "passport_issuer",
				Value:      input[start:end],
			})
		}
	}
	return out
}

func isPassportAuthority(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"овд", "увд", "уфмс", "мвд", "отдел полиции", "отделом полиции"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func (d *PassportDetector) detectSeriesNumber(input string) []pii.Finding {
	var out []pii.Finding
	// Series + number form.
	for _, m := range d.seriesNumberRe.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[2], m[7]
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		if !hasContextRegex(input, start, end, d.passportMarkers) {
			continue
		}
		out = append(out, pii.Finding{
			Type:       pii.TypePassportNumber,
			Start:      start,
			End:        end,
			Confidence: pii.ConfidenceHigh,
			Detector:   "passport",
			Value:      input[start:end],
		})
	}

	return out
}

func (d *PassportDetector) detectMergedNumber(input string, previous []pii.Finding) []pii.Finding {
	var out []pii.Finding
	covered := make(map[int]int, len(previous))
	for _, f := range previous {
		if f.End > covered[f.Start] {
			covered[f.Start] = f.End
		}
	}
	// Merged 10-digit form with context.
	for _, m := range d.mergedRe.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		if !hasContextRegex(input, start, end, d.passportMarkers) {
			continue
		}
		// Avoid double-reporting if already covered by series+number.
		if covered[start] >= end {
			continue
		}
		out = append(out, pii.Finding{
			Type:       pii.TypePassportNumber,
			Start:      start,
			End:        end,
			Confidence: pii.ConfidenceMedium,
			Detector:   "passport",
			Value:      input[start:end],
		})
	}

	return out
}

func (d *PassportDetector) detectDivision(input string) []pii.Finding {
	var out []pii.Finding
	// Division code.
	for _, m := range d.divisionRe.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		if partOfLongerDigitSequence(input, start, end) {
			continue
		}
		if !hasContextRegex(input, start, end, d.divisionMarkers) {
			continue
		}
		out = append(out, pii.Finding{
			Type:       pii.TypePassportDivision,
			Start:      start,
			End:        end,
			Confidence: pii.ConfidenceHigh,
			Detector:   "passport_division",
			Value:      input[start:end],
		})
	}

	return out
}
