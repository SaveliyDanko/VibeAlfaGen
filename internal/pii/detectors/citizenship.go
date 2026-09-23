package detectors

import (
	"strings"

	"github.com/alfagen/pii-service/internal/pii"
)

// CitizenshipDetector finds citizenship after markers like "гражданство".
type CitizenshipDetector struct {
	markers []*pattern
}

// NewCitizenshipDetector builds a CitizenshipDetector.
func NewCitizenshipDetector() *CitizenshipDetector {
	return &CitizenshipDetector{
		markers: []*pattern{
			compilePattern(`(?i)гражданство`),
		},
	}
}

// Type implements pii.Detector.
func (d *CitizenshipDetector) Type() pii.PIIType { return pii.TypeCitizenship }

// Detect implements pii.Detector.
func (d *CitizenshipDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.markers {
		for _, loc := range m.FindAllStringIndex(input, -1) {
			start, end, ok := collectLabeledWords(input, loc[1], 3, nil)
			if !ok {
				continue
			}
			value := strings.ToLower(input[start:end])
			if strings.Contains(value, "не указано") || strings.Contains(value, "не подтверждено") || strings.Contains(value, "отсутствует") || strings.Contains(value, "неизвестно") {
				continue
			}
			out = append(out, pii.Finding{
				Type:       pii.TypeCitizenship,
				Start:      start,
				End:        end,
				Confidence: pii.ConfidenceHigh,
				Detector:   "citizenship",
				Value:      input[start:end],
			})
		}
	}
	return out
}
