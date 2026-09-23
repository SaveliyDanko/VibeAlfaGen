package detectors

import (
	"fmt"
	"regexp"

	"github.com/alfagen/pii-service/internal/pii"
)

// PatternDetector matches a personal-data category described entirely by a
// configured regular expression. It exists so operators can add a new PII
// type via config alone, without a dedicated Go detector file.
type PatternDetector struct {
	typ        pii.PIIType
	confidence pii.Confidence
	re         *pattern
}

// NewPatternDetector validates expr eagerly (regexp.Compile) so a broken
// configured pattern fails at startup with a clear error instead of panicking
// on the first matching request.
func NewPatternDetector(typ pii.PIIType, expr string, confidence pii.Confidence) (*PatternDetector, error) {
	if typ == "" {
		return nil, fmt.Errorf("pii: custom pattern detector requires a type")
	}
	if expr == "" {
		return nil, fmt.Errorf("pii: custom pattern detector requires a pattern")
	}
	if _, err := regexp.Compile(expr); err != nil {
		return nil, fmt.Errorf("pii: invalid pattern for type %q: %w", typ, err)
	}
	return &PatternDetector{typ: typ, confidence: confidence, re: compilePattern(expr)}, nil
}

// Type implements pii.Detector.
func (d *PatternDetector) Type() pii.PIIType { return d.typ }

// Detect implements pii.Detector.
func (d *PatternDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.re.FindAllStringIndex(input, -1) {
		start, end := m[0], m[1]
		// Valid regexps may also produce empty matches (e.g. optional groups
		// or word boundaries). They contain no PII and are not valid spans.
		if start == end {
			continue
		}
		out = append(out, pii.Finding{
			Type:       d.typ,
			Start:      start,
			End:        end,
			Confidence: d.confidence,
			Detector:   "custom:" + string(d.typ),
			Value:      input[start:end],
		})
	}
	return out
}
