package detectors

import (
	"strings"

	"github.com/alfagen/pii-service/internal/pii"
)

// EmailDetector finds email addresses.
type EmailDetector struct {
	re *pattern
}

// NewEmailDetector builds an EmailDetector.
func NewEmailDetector() *EmailDetector {
	return &EmailDetector{
		re: compilePattern(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`),
	}
}

// Type implements pii.Detector.
func (d *EmailDetector) Type() pii.PIIType { return pii.TypeEmail }

// Detect implements pii.Detector.
func (d *EmailDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range d.re.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		candidate := input[start:end]
		if !validEmail(candidate) {
			continue
		}
		out = append(out, pii.Finding{
			Type:       pii.TypeEmail,
			Start:      start,
			End:        end,
			Confidence: pii.ConfidenceHigh,
			Detector:   "email",
			Value:      candidate,
		})
	}
	return out
}

// validEmail rejects malformed addresses that the permissive regex would
// otherwise accept: consecutive dots, leading/trailing dots, and labels with a
// leading or trailing hyphen.
func validEmail(s string) bool {
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return false
	}
	local := s[:at]
	domain := s[at+1:]
	if !validEmailPart(local) || !validEmailPart(domain) {
		return false
	}
	return strings.Contains(domain, ".")
}

func validEmailPart(s string) bool {
	if s == "" || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}
