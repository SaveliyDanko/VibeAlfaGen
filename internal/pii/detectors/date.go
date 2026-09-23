package detectors

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/alfagen/pii-service/internal/pii"
)

var (
	dateDOBMarkers = []*pattern{
		compilePattern(`(?i)дата\s+рождения`),
		compilePattern(`(?i)дата\s+рожд`),
		compilePattern(`(?i)родил\p{L}*\s*[:.]?\s*$`),
		compilePattern(`(?i)родился`),
		compilePattern(`(?i)родилась`),
		compilePattern(`(?i)д\.р\.`),
		compilePattern(`(?i)год\s+рождения`),
	}
	dateIssueMarkers = []*pattern{
		compilePattern(`(?i)(?:^|[^\p{L}\p{N}])дата\s+выдачи(?:\s+паспорта)?(?:$|[^\p{L}\p{N}])`),
		compilePattern(`(?i)(?:^|[^\p{L}\p{N}])выдан(?:о|а)?(?:$|[^\p{L}\p{N}])`),
	}
	dateGenericMarkers = []*pattern{
		compilePattern(`(?i)число`),
		compilePattern(`(?i)день\s+рождения`),
		compilePattern(`(?i)(?:^|[^\p{L}\p{N}])год`),
	}
)

// dayOrdinalWords maps a single-word Russian genitive ordinal day (1-30) to its
// numeric value. Compound days like "двадцать первого" are built from
// dayTensWords plus dayOrdinalWords.
var dayOrdinalWords = map[string]int{
	"первого": 1, "второго": 2, "третьего": 3, "четвёртого": 4, "четвертого": 4,
	"пятого": 5, "шестого": 6, "седьмого": 7, "восьмого": 8, "девятого": 9,
	"десятого": 10, "одиннадцатого": 11, "двенадцатого": 12, "тринадцатого": 13,
	"четырнадцатого": 14, "пятнадцатого": 15, "шестнадцатого": 16, "семнадцатого": 17,
	"восемнадцатого": 18, "девятнадцатого": 19, "двадцатого": 20, "тридцатого": 30,
}

// dayTensWords maps the tens prefix of a compound day to its numeric value.
var dayTensWords = map[string]int{
	"двадцать": 20, "тридцать": 30,
}

// monthWords maps a Russian genitive month name to its numeric value.
var monthWords = map[string]int{
	"января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
	"июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
}

// A fully-worded year has a fixed, short grammar. Cardinal tens require an
// ordinal unit ("восемьдесят пятого"), while exact tens use their ordinal form
// ("девяностого"). Keeping these maps separate prevents arbitrary sums of
// number words from being accepted as years.
var yearOrdinalUnderHundred = map[string]int{
	"первого": 1, "второго": 2, "третьего": 3, "четвёртого": 4, "четвертого": 4,
	"пятого": 5, "шестого": 6, "седьмого": 7, "восьмого": 8, "девятого": 9,
	"десятого": 10, "одиннадцатого": 11, "двенадцатого": 12, "тринадцатого": 13,
	"четырнадцатого": 14, "пятнадцатого": 15, "шестнадцатого": 16, "семнадцатого": 17,
	"восемнадцатого": 18, "девятнадцатого": 19, "двадцатого": 20,
	"тридцатого": 30, "сорокового": 40, "пятидесятого": 50, "шестидесятого": 60,
	"семидесятого": 70, "восьмидесятого": 80, "девяностого": 90,
}

var yearCardinalTens = map[string]int{
	"двадцать": 20, "тридцать": 30, "сорок": 40, "пятьдесят": 50,
	"шестьдесят": 60, "семьдесят": 70, "восемьдесят": 80, "девяносто": 90,
}

// dayMonthRe matches a fully-worded day followed by a Russian month name. The
// day may be a single word or a compound like "двадцать первого". The leading
// boundary uses a Unicode-aware class because Go's \b is ASCII-only and does
// not treat Cyrillic letters as word characters.
var dayMonthRe = compilePattern(`(?i)(?:^|[^\p{L}\p{N}])((?:первого|второго|третьего|четвёртого|четвертого|пятого|шестого|седьмого|восьмого|девятого|десятого|одиннадцатого|двенадцатого|тринадцатого|четырнадцатого|пятнадцатого|шестнадцатого|семнадцатого|восемнадцатого|девятнадцатого|двадцатого|тридцатого|двадцать|тридцать)(?:\s+(?:первого|второго|третьего|четвёртого|четвертого|пятого|шестого|седьмого|восьмого|девятого))?)\s+(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)`)

// DateDetector finds dates of birth and passport issue dates. It supports
// DD.MM.YYYY, MM.DD.YYYY (with sufficient context), YYYY.MM.DD, hyphens,
// slashes and Russian textual months. It only reports a date as personal data
// when a contextual marker (e.g. "дата рождения", "выдан", "родился") is
// present, to avoid masking arbitrary dates. The marker is chosen as the
// nearest preceding one within the current field, so a neighbouring field does
// not leak its type onto this date.
type DateDetector struct {
	// numeric date pattern: DD.MM.YYYY / MM.DD.YYYY with separators . - /
	numericRe *pattern
	// yearFirstRe matches YYYY.MM.DD / YYYY.DD.MM.
	yearFirstRe *pattern
	// textual date pattern with Russian month names.
	textualRe *pattern
	// yearOnlyRe is intentionally tied to the explicit "год рождения" label.
	yearOnlyRe *pattern
}

// NewDateDetector builds a DateDetector.
func NewDateDetector() *DateDetector {
	return &DateDetector{
		numericRe:   compilePattern(`\b(\d{1,2})[./\-](\d{1,2})[./\-](\d{2,4})\b`),
		yearFirstRe: compilePattern(`\b(\d{4})[./\-](\d{1,2})[./\-](\d{1,2})\b`),
		textualRe:   compilePattern(`(?i)(\d{1,2})\s+(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+(\d{4})`),
		yearOnlyRe:  compilePattern(`(?i)(?:^|[^\p{L}\p{N}])год\s+рождения\s*[:\-]?\s*((?:19|20)\d{2})(?:$|[^\d])`),
	}
}

// Type implements pii.Detector.
func (d *DateDetector) Type() pii.PIIType { return pii.TypeDateOfBirth }

func (d *DateDetector) Types() []pii.PIIType {
	return []pii.PIIType{pii.TypeDateOfBirth, pii.TypePassportIssueDate}
}

// Detect implements pii.Detector.
func (d *DateDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding

	for _, m := range d.yearOnlyRe.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[2], m[3]
		out = append(out, pii.Finding{Type: pii.TypeDateOfBirth, Start: start, End: end, Confidence: pii.ConfidenceHigh, Detector: "date", Value: input[start:end]})
	}

	out = append(out, d.detectYearLast(input)...)
	out = append(out, d.detectYearFirst(input)...)
	out = append(out, d.detectTextual(input)...)
	// Fully-worded dates: "пятнадцатого марта тысяча девятьсот восемьдесят
	// пятого года".
	out = append(out, d.detectWordsInWords(input)...)
	return dedupBySpan(out)
}

// detectWordsInWords finds dates written entirely in Russian words, e.g.
// "пятнадцатого марта тысяча девятьсот восемьдесят пятого года". The span
// covers the day, month and year words and stops at "года".
func (d *DateDetector) detectWordsInWords(input string) []pii.Finding {
	var out []pii.Finding
	for _, m := range dayMonthRe.FindAllStringSubmatchIndex(input, -1) {
		start := m[2]
		if dateWordContinues(input, m[5]) {
			continue
		}
		day, ok := parseDayWords(input[m[2]:m[3]])
		if !ok {
			continue
		}
		month, ok := monthWords[strings.ToLower(input[m[4]:m[5]])]
		if !ok {
			continue
		}
		year, end, ok := parseYearWords(input, m[5])
		if !ok {
			continue
		}
		if !validDateParts(day, month, year) {
			continue
		}
		typ, conf := d.classify(input, start, end)
		if typ == "" {
			continue
		}
		out = append(out, pii.Finding{
			Type:       typ,
			Start:      start,
			End:        end,
			Confidence: conf,
			Detector:   "date",
			Value:      input[start:end],
		})
	}
	return out
}

// parseDayWords parses a fully-worded Russian day (genitive ordinal) into its
// numeric value. It supports single words and compounds like "двадцать первого".
func parseDayWords(s string) (int, bool) {
	words := strings.Fields(s)
	if len(words) == 0 {
		return 0, false
	}
	if len(words) == 1 {
		v, ok := dayOrdinalWords[strings.ToLower(words[0])]
		return v, ok
	}
	tens, ok := dayTensWords[strings.ToLower(words[0])]
	if !ok {
		return 0, false
	}
	ones, ok := dayOrdinalWords[strings.ToLower(words[1])]
	if !ok {
		return 0, false
	}
	return tens + ones, true
}

// parseYearWords parses a fully-worded Russian year (1900-2099) starting at the
// byte offset start in input. It consumes at most five words and requires the
// terminal "года", so every candidate has bounded work independent of the
// remaining input length.
const yearThousandWord = "тысяча"

func parseYearWords(input string, start int) (int, int, bool) {
	word, _, end, ok := nextDateWord(input, start)
	if !ok {
		return 0, 0, false
	}
	word = strings.ToLower(word)
	if word == "двухтысячного" {
		return finishYearWords(input, end, 2000)
	}
	if word != yearThousandWord && word != "две" {
		return 0, 0, false
	}

	base := 0
	second, _, secondEnd, ok := nextDateWord(input, end)
	if !ok {
		return 0, 0, false
	}
	second = strings.ToLower(second)
	switch {
	case word == yearThousandWord && second == "девятисотого":
		return finishYearWords(input, secondEnd, 1900)
	case word == yearThousandWord && second == "девятьсот":
		base = 1900
	case word == "две" && second == "тысячи":
		base = 2000
	default:
		return 0, 0, false
	}

	remainder, _, remainderEnd, ok := nextDateWord(input, secondEnd)
	if !ok {
		return 0, 0, false
	}
	remainder = strings.ToLower(remainder)
	if value, exists := yearOrdinalUnderHundred[remainder]; exists {
		return finishYearWords(input, remainderEnd, base+value)
	}
	tens, exists := yearCardinalTens[remainder]
	if !exists {
		return 0, 0, false
	}
	onesWord, _, onesEnd, ok := nextDateWord(input, remainderEnd)
	if !ok {
		return 0, 0, false
	}
	ones, exists := dayOrdinalWords[strings.ToLower(onesWord)]
	if !exists || ones < 1 || ones > 9 {
		return 0, 0, false
	}
	return finishYearWords(input, onesEnd, base+tens+ones)
}

func finishYearWords(input string, start, year int) (int, int, bool) {
	word, _, end, ok := nextDateWord(input, start)
	if !ok || strings.ToLower(word) != "года" || year < 1900 || year > 2099 {
		return 0, 0, false
	}
	if end < len(input) {
		r, _ := utf8.DecodeRuneInString(input[end:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return 0, 0, false
		}
	}
	return year, end, true
}

// nextDateWord consumes optional whitespace and exactly one letter-only word.
// Punctuation or digits before the next word terminate the grammar instead of
// causing a scan through the remaining payload.
func nextDateWord(input string, start int) (string, int, int, bool) {
	i := start
	for i < len(input) {
		r, size := utf8.DecodeRuneInString(input[i:])
		if !unicode.IsSpace(r) {
			break
		}
		i += size
	}
	wordStart := i
	for i < len(input) {
		r, size := utf8.DecodeRuneInString(input[i:])
		if !unicode.IsLetter(r) {
			break
		}
		i += size
	}
	if i == wordStart {
		return "", 0, 0, false
	}
	return input[wordStart:i], wordStart, i, true
}

// classify determines the PII type and confidence for a date span using the
// nearest preceding marker within the current field.
func (d *DateDetector) classify(input string, start, end int) (pii.PIIType, pii.Confidence) {
	groups := []markerGroup{
		{typ: 0, markers: dateDOBMarkers},
		{typ: 1, markers: dateIssueMarkers},
		{typ: 2, markers: dateGenericMarkers},
	}
	group, markerEnd := nearestPrecedingMarkerMatch(input, start, groups)
	switch group {
	case 0:
		return pii.TypeDateOfBirth, pii.ConfidenceHigh
	case 1:
		if containsLetterOrDigit(input[markerEnd:start]) {
			return "", 0
		}
		return pii.TypePassportIssueDate, pii.ConfidenceHigh
	case 2:
		return pii.TypeDateOfBirth, pii.ConfidenceMedium
	}
	return "", 0
}

// validDateParts reports whether dd/mm/yy form a real calendar date. Two-digit
// years are interpreted as 2000+.
func validDateParts(dd, mm, yy int) bool {
	if mm < 1 || mm > 12 || dd < 1 {
		return false
	}
	if yy < 100 {
		yy += 2000
	}
	if yy < 1900 || yy > 2100 {
		return false
	}
	days := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if isLeap(yy) {
		days[1] = 29
	}
	return dd <= days[mm-1]
}

func isLeap(yy int) bool {
	return yy%4 == 0 && (yy%100 != 0 || yy%400 == 0)
}

// dedupBySpan removes findings that share the same byte span, keeping the
// first occurrence.
func dedupBySpan(findings []pii.Finding) []pii.Finding {
	if len(findings) < 2 {
		return findings
	}
	seen := make(map[[2]int]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		key := [2]int{f.Start, f.End}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			continue
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func (d *DateDetector) detectYearLast(input string) []pii.Finding {
	var out []pii.Finding
	// Numeric year-last dates. First try DD.MM.YYYY, then MM.DD.YYYY.
	for _, m := range d.numericRe.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		a := atoi(input[m[2]:m[3]])
		b := atoi(input[m[4]:m[5]])
		yy := atoi(input[m[6]:end])
		dd, mm := a, b
		if !validDateParts(dd, mm, yy) {
			dd, mm = b, a
			if !validDateParts(dd, mm, yy) {
				continue
			}
		}
		typ, conf := d.classify(input, start, end)
		if typ == "" {
			continue
		}
		out = append(out, pii.Finding{
			Type:       typ,
			Start:      start,
			End:        end,
			Confidence: conf,
			Detector:   "date",
			Value:      input[start:end],
		})
	}

	return out
}

func (d *DateDetector) detectYearFirst(input string) []pii.Finding {
	var out []pii.Finding
	// Numeric year-first dates. First try YYYY.MM.DD, then YYYY.DD.MM.
	for _, m := range d.yearFirstRe.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		yy := atoi(input[m[2]:m[3]])
		a := atoi(input[m[4]:m[5]])
		b := atoi(input[m[6]:end])
		mm, dd := a, b
		if !validDateParts(dd, mm, yy) {
			mm, dd = b, a
			if !validDateParts(dd, mm, yy) {
				continue
			}
		}
		typ, conf := d.classify(input, start, end)
		if typ == "" {
			continue
		}
		out = append(out, pii.Finding{
			Type:       typ,
			Start:      start,
			End:        end,
			Confidence: conf,
			Detector:   "date",
			Value:      input[start:end],
		})
	}

	return out
}

func (d *DateDetector) detectTextual(input string) []pii.Finding {
	var out []pii.Finding
	// Textual dates.
	for _, m := range d.textualRe.FindAllStringSubmatchIndex(input, -1) {
		start, end := m[0], m[1]
		dd := atoi(input[m[2]:m[3]])
		yy := atoi(input[m[6]:end])
		mm := monthWords[strings.ToLower(input[m[4]:m[5]])]
		if !validDateParts(dd, mm, yy) {
			continue
		}
		typ, conf := d.classify(input, start, end)
		if typ == "" {
			continue
		}
		out = append(out, pii.Finding{
			Type:       typ,
			Start:      start,
			End:        end,
			Confidence: conf,
			Detector:   "date",
			Value:      input[start:end],
		})
	}

	return out
}

func dateWordContinues(input string, end int) bool {
	if end >= len(input) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(input[end:])
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}
