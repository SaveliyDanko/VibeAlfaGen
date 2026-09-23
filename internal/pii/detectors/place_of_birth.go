package detectors

import (
	"strings"

	"github.com/alfagen/pii-service/internal/pii"
)

// PlaceOfBirthDetector finds the place of birth after markers like
// "место рождения".
type PlaceOfBirthDetector struct {
	markers []*pattern
}

// NewPlaceOfBirthDetector builds a PlaceOfBirthDetector.
func NewPlaceOfBirthDetector() *PlaceOfBirthDetector {
	return &PlaceOfBirthDetector{
		markers: []*pattern{
			compilePattern(`(?i)место\s+рождения`),
			compilePattern(`(?i)место\s+рожд\.`),
			compilePattern(`(?i)родил\p{L}*\s+в`),
			compilePattern(`(?i)уроженец`),
			compilePattern(`(?i)уроженка`),
		},
	}
}

// Type implements pii.Detector.
func (d *PlaceOfBirthDetector) Type() pii.PIIType { return pii.TypePlaceOfBirth }

// Detect implements pii.Detector.
func (d *PlaceOfBirthDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.markers {
		for _, loc := range m.FindAllStringIndex(input, -1) {
			start, end, ok := collectLabeledWords(input, loc[1], 4, map[string]bool{
				"г": true, "гор": true, "город": true, "городе": true, "города": true, "с": true, "село": true,
			})
			if !ok {
				continue
			}
			switch strings.ToLower(strings.Join(strings.Fields(input[start:end]), " ")) {
			case "неизвестно", "не указано", "не установлено", "отсутствует":
				continue
			}
			out = append(out, pii.Finding{
				Type:       pii.TypePlaceOfBirth,
				Start:      start,
				End:        end,
				Confidence: pii.ConfidenceHigh,
				Detector:   "place_of_birth",
				Value:      input[start:end],
			})
		}
	}
	return out
}
