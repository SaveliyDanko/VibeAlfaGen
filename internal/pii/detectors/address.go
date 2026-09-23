package detectors

import (
	"github.com/alfagen/pii-service/internal/pii"
	"strings"
)

// AddressDetector finds addresses and their components: country, postal code,
// city, street, house, apartment. It only masks addresses with a client
// context marker, so bank/office/branch addresses without client context are
// not masked.
type AddressDetector struct {
	clientMarkers []*pattern
	// addressMarkers indicate an address.
	addressMarkers []*pattern
	// componentMarkers map a component label to its PII type.
	componentMarkers map[pii.PIIType][]*pattern
	// postalRe matches a 6-digit Russian postal code.
	postalRe *pattern
	// streetRe matches "ул. Name" / "улица Name".
	streetRe *pattern
	// houseRe matches "д. 12" / "дом 12".
	houseRe *pattern
	// apartmentRe matches "кв. 5" / "квартира 5".
	apartmentRe *pattern
}

// NewAddressDetector builds an AddressDetector.
func NewAddressDetector() *AddressDetector {
	return &AddressDetector{
		clientMarkers: []*pattern{
			compilePattern(`(?i)клиент`),
			compilePattern(`(?i)прожива\p{L}*`),
			compilePattern(`(?i)зарегистрирован\p{L}*`),
			compilePattern(`(?i)прописан\p{L}*`),
			compilePattern(`(?i)адрес\s+проживания`),
			compilePattern(`(?i)адрес\s+регистрации`),
			compilePattern(`(?i)место\s+жительства`),
			compilePattern(`(?i)получател\p{L}*`),
			compilePattern(`(?i)держател\p{L}*`),
		},
		addressMarkers: []*pattern{
			compilePattern(`(?i)адрес`),
			compilePattern(`(?i)прожива\p{L}*`),
			compilePattern(`(?i)зарегистрирован\p{L}*`),
			compilePattern(`(?i)прописан\p{L}*`),
			compilePattern(`(?i)место\s+жительства`),
		},
		componentMarkers: map[pii.PIIType][]*pattern{
			pii.TypeAddress: {
				compilePattern(`(?i)страна`),
				compilePattern(`(?i)город`),
				compilePattern(`(?i)гор\.`),
				compilePattern(`(?i)(?:^|[^\p{L}\p{N}])г\.`),
				compilePattern(`(?i)(?:^|[^\p{L}\p{N}])г\s`),
				compilePattern(`(?i)населённ\p{L}*\s+пункт`),
				compilePattern(`(?i)населенн\p{L}*\s+пункт`),
				compilePattern(`(?i)регион`),
				compilePattern(`(?i)область`),
				compilePattern(`(?i)край`),
				compilePattern(`(?i)республика`),
			},
		},
		postalRe:    compilePattern(`\b(\d{6})\b`),
		streetRe:    compilePattern(`(?i)(?:ул\.|улица|проспект|пр-т|проезд|переулок|пер\.|бульвар|б-р|набережная|наб\.|шоссе|аллея)\s+([А-ЯЁ][А-ЯЁа-яё\-]+(?:\s+[А-ЯЁ][А-ЯЁа-яё\-]+)*)`),
		houseRe:     compilePattern(`(?i)(?:д\.|дом|строение|стр\.)\s*(\d+[А-ЯЁа-яё]?)`),
		apartmentRe: compilePattern(`(?i)(?:кв\.|квартира|офис|помещение)\s*(\d+)`),
	}
}

// Type implements pii.Detector.
func (d *AddressDetector) Type() pii.PIIType { return pii.TypeAddress }

// Detect implements pii.Detector.
func (d *AddressDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, f := range d.Candidates(input) {
		if f.Confidence >= pii.ConfidenceMedium {
			out = append(out, f)
		}
	}
	return out
}

func (d *AddressDetector) confidence(input string, start, end int) pii.Confidence {
	lo, hi := contextBounds(input, start, end)
	// A client marker only counts within the same sentence: a fixed byte
	// window alone lets an unrelated marker (e.g. "клиент" describing a
	// different address in the next sentence) leak across a ". " boundary
	// and falsely promote this candidate.
	for j := start - 1; j >= lo; j-- {
		if strings.IndexByte("\n\r;!?", input[j]) >= 0 || pii.SentenceBoundary(input, j) {
			lo = j + 1
			break
		}
	}
	for j := end; j < hi; j++ {
		if strings.IndexByte("\n\r;!?", input[j]) >= 0 || pii.SentenceBoundary(input, j) {
			hi = j
			break
		}
	}
	if hasContextRegex(input[lo:hi], start-lo, end-lo, d.clientMarkers) {
		return pii.ConfidenceHigh
	}
	return pii.AddressCandidateConfidence
}

func (d *AddressDetector) Candidates(input string) []pii.Finding {
	var out []pii.Finding

	// Postal code.
	for _, m := range d.postalRe.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		if d.confidence(input, start, end) < pii.ConfidenceHigh && !precedingLabel(input, start, postalLabel) {
			continue
		}
		out = append(out, d.finding(input, start, end, pii.TypeAddress, d.confidence(input, start, end)))
	}

	// Street.
	for _, m := range d.streetRe.FindAllStringSubmatchIndex(input, -1) {
		matchStart, matchEnd := m[0], m[1]
		start, end, ok := collectLabeledWords(input, m[2], 4, nil)
		if !ok {
			continue
		}
		out = append(out, d.finding(input, start, end, pii.TypeAddress, d.confidence(input, matchStart, matchEnd)))
	}

	// House.
	for _, m := range d.houseRe.FindAllStringSubmatchIndex(input, -1) {
		matchStart, matchEnd := m[0], m[1]
		start, end := m[2], m[3]
		out = append(out, d.finding(input, start, end, pii.TypeAddress, d.confidence(input, matchStart, matchEnd)))
	}

	// Apartment.
	for _, m := range d.apartmentRe.FindAllStringSubmatchIndex(input, -1) {
		matchStart, matchEnd := m[0], m[1]
		start, end := m[2], m[3]
		out = append(out, d.finding(input, start, end, pii.TypeAddress, d.confidence(input, matchStart, matchEnd)))
	}

	// Country / city / region components with explicit labels.
	out = append(out, d.detectLabeledComponents(input)...)
	for _, loc := range plainAddressLabel.FindAllStringIndex(input, -1) {
		start, end, ok := collectLabeledWords(input, loc[1], 4, nil)
		if !ok || addressComponentPrefix(input[start:end]) {
			continue
		}
		out = append(out, d.finding(input, start, end, pii.TypeAddress, pii.AddressCandidateConfidence))
	}
	out = dedupBySpan(out)

	return out
}

// detectLabeledComponents finds values following component labels like
// "страна", "город", "область".
func (d *AddressDetector) detectLabeledComponents(input string) []pii.Finding {
	var out []pii.Finding
	skipPrefixes := map[string]bool{"г": true, "гор": true, "город": true}
	for typ, markers := range d.componentMarkers {
		for _, m := range markers {
			for _, loc := range m.FindAllStringIndex(input, -1) {
				start, end, ok := collectLabeledWords(input, loc[1], 4, skipPrefixes)
				if !ok {
					continue
				}
				out = append(out, d.finding(input, start, end, typ, d.confidence(input, loc[0], loc[1])))
			}
		}
	}
	return out
}

func (d *AddressDetector) finding(input string, start, end int, typ pii.PIIType, conf pii.Confidence) pii.Finding {
	return pii.Finding{
		Type:       typ,
		Start:      start,
		End:        end,
		Confidence: conf,
		Detector:   "address",
		Value:      input[start:end],
	}
}

var postalLabel = compilePattern(`(?i)(?:^|[^\p{L}])индекс\s*:?\s*$`)
var plainAddressLabel = compilePattern(`(?i)(?:^|[^\p{L}])адрес\s*:\s*`)

func addressComponentPrefix(value string) bool {
	word := strings.ToLower(strings.Fields(value)[0])
	switch word {
	case "г", "гор", "город", "ул", "улица", "дом", "д", "кв":
		return true
	}
	return false
}
