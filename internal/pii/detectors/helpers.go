// Package detectors contains independent, pure detectors for each PII category.
// Each detector only locates data and returns pii.Finding values; it never
// modifies the input text. All regular expressions are compiled once at package
// init time.
package detectors

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// contextWindow is the number of runes examined before/after a candidate value
// when looking for contextual markers.
const contextWindow = 96

// collectLabeledWords returns a short value following a label. It accepts
// lower-, title- and upper-case Unicode words and stops at sentence/list
// punctuation, unlike the original tokenizer-only implementation which could
// silently skip lower-case values or consume text after a comma.
//
// The parser scans forward from the label and stops after maxWords words, a
// field delimiter, or the first invalid construction. It never tokenizes the
// whole remaining tail, so the total work is linear in the number of words
// actually consumed rather than quadratic in the input length.
func collectLabeledWords(input string, start, maxWords int, skipPrefixes map[string]bool) (int, int, bool) {
	return collectLabelValue(input, start, maxWords, skipPrefixes, false)
}

func collectLabelValue(input string, start, maxWords int, skipPrefixes map[string]bool, issuerNumbers bool) (int, int, bool) {
	input = boundedLabelInput(input, start)
	scan := labelScanner{input: input, pos: labelValueStart(input, start), start: -1, end: -1}
	for scan.count < maxWords && scan.pos < len(input) {
		wordStart := scanLetters(input, scan.pos, false)
		if wordStart >= len(input) || scan.endsAtGap(input[scan.pos:wordStart]) {
			break
		}
		wordEnd := scanLetters(input, wordStart, true)
		if !scan.acceptWord(wordStart, wordEnd, skipPrefixes) {
			break
		}
		if issuerNumbers {
			scan.acceptIssuerNumber()
		}
	}
	return scan.start, scan.end, scan.count > 0
}

// Authority names may contain a numbered district or police department. Only
// attached suffixes and explicit number signs belong to the name; a bare date,
// passport number or division code must remain outside the issuer span.
func (s *labelScanner) acceptIssuerNumber() {
	tail := s.input[s.pos:]
	if strings.HasPrefix(tail, "-") {
		tail = tail[1:]
	} else {
		tail = strings.TrimLeft(tail, " \t")
		if !strings.HasPrefix(tail, "№") {
			return
		}
		tail = strings.TrimLeft(strings.TrimPrefix(tail, "№"), " \t")
	}
	digits := 0
	for digits < len(tail) && isDigit(rune(tail[digits])) {
		digits++
	}
	if digits == 0 || digits > 4 {
		return
	}
	if digits < len(tail) {
		r, _ := utf8.DecodeRuneInString(tail[digits:])
		if isLetter(r) || r == '-' {
			return
		}
	}
	s.end = len(s.input) - len(tail) + digits
	s.pos = s.end
}

func boundedLabelInput(input string, start int) string {
	const maxLabelBytes = 512
	if len(input)-start <= maxLabelBytes {
		return input
	}
	end := start + maxLabelBytes
	for end > start && !utf8.RuneStart(input[end]) {
		end--
	}
	return input[:end]
}

func labelValueStart(input string, start int) int {
	for start < len(input) {
		r, size := utf8.DecodeRuneInString(input[start:])
		// Never consume a field boundary as part of the separator.
		if r == ';' || r == '\n' {
			break
		}
		if !unicode.IsSpace(r) && r != ':' && r != '-' {
			break
		}
		start += size
	}
	return start
}

func scanLetters(input string, pos int, letters bool) int {
	for pos < len(input) {
		r, size := utf8.DecodeRuneInString(input[pos:])
		if isLetter(r) != letters {
			break
		}
		pos += size
	}
	return pos
}

type labelScanner struct {
	input                  string
	pos, start, end, count int
	skippedPrefix          bool
}

func (s *labelScanner) endsAtGap(gap string) bool {
	if strings.ContainsAny(gap, ";\n") {
		return true
	}
	if s.count > 0 {
		return strings.ContainsAny(gap, ",.!?:0123456789<>@")
	}
	return !s.skippedPrefix && strings.ContainsAny(gap, "0123456789,!?")
}

func (s *labelScanner) acceptWord(start, end int, skipPrefixes map[string]bool) bool {
	word := s.input[start:end]
	lower := strings.ToLower(word)
	if s.count > 0 && fieldLabelWord(lower) {
		return false
	}
	if end < len(s.input) && s.input[end] == ':' {
		return false
	}
	if s.count == 0 && skipPrefixes[lower] {
		s.skippedPrefix, s.pos = true, end
		return true
	}
	if !isCyrillicWord(word) && !allLatinLetters(word) {
		return false
	}
	if s.start < 0 {
		s.start = start
	}
	s.end, s.pos = end, end
	s.count++
	return true
}

func allLatinLetters(word string) bool {
	if word == "" {
		return false
	}
	for _, r := range word {
		if !isLatin(r) {
			return false
		}
	}
	return true
}

// hasContextRegex reports whether any of the compiled regexes match within the
// context window around [start,end).
func hasContextRegex(input string, start, end int, markers []*pattern) bool {
	lo, hi := contextBounds(input, start, end)
	window := input[lo:hi]
	for _, m := range markers {
		if m.MatchString(window) {
			return true
		}
	}
	return false
}

func contextBounds(input string, start, end int) (int, int) {
	lo := start
	for n := 0; n < contextWindow && lo > 0; n++ {
		_, size := utf8.DecodeLastRuneInString(input[:lo])
		if size == 0 {
			break
		}
		lo -= size
	}
	hi := end
	for n := 0; n < contextWindow && hi < len(input); n++ {
		_, size := utf8.DecodeRuneInString(input[hi:])
		if size == 0 {
			break
		}
		hi += size
	}
	return lo, hi
}

// markerGroup is a set of regexes that classify a contextual marker into a
// type index. It is used by the local-context detectors (date, CVV, PIN).
type markerGroup struct {
	typ     int
	markers []*pattern
}

// nearestPrecedingMarker returns the type index of the marker group whose
// marker appears nearest before [start,end) within the current field. A field
// is delimited by ';' and a newline. The backward scan is bounded to
// contextWindow runes so that a candidate does not scan the whole remaining
// text. It returns -1 when no marker precedes the candidate.
func nearestPrecedingMarker(input string, start int, groups []markerGroup) int {
	group, _ := nearestPrecedingMarkerMatch(input, start, groups)
	return group
}

// nearestPrecedingMarkerMatch is nearestPrecedingMarker plus the absolute byte
// end of the chosen marker. Callers use the end to reject unrelated words
// between a label and a candidate.
func nearestPrecedingMarkerMatch(input string, start int, groups []markerGroup) (int, int) {
	fieldStart := start
	for n := 0; n < contextWindow && fieldStart > 0; n++ {
		r, size := utf8.DecodeLastRuneInString(input[:fieldStart])
		if r == ';' || r == '\n' {
			break
		}
		fieldStart -= size
	}
	prefix := input[fieldStart:start]
	bestEnd := -1
	bestGroup := -1
	for gi, g := range groups {
		if end := lastMarkerEnd(prefix, g.markers); end > bestEnd {
			bestEnd, bestGroup = end, gi
		}
	}
	if bestGroup < 0 {
		return -1, -1
	}
	return bestGroup, fieldStart + bestEnd
}

func containsLetterOrDigit(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// precedingLabel reports whether re matches the end of the current bounded
// field immediately before a candidate.
func precedingLabel(input string, start int, re *pattern) bool {
	fieldStart := start
	for n := 0; n < contextWindow && fieldStart > 0; n++ {
		r, size := utf8.DecodeLastRuneInString(input[:fieldStart])
		if r == ';' || r == '\n' || r == ',' {
			break
		}
		fieldStart -= size
	}
	return re.MatchString(input[fieldStart:start])
}

// isCyrillic reports whether the rune is a Cyrillic letter.
func isCyrillic(r rune) bool {
	return r >= '\u0400' && r <= '\u04FF'
}

// isLatin reports whether the rune is a basic Latin letter.
func isLatin(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// isLetter reports whether the rune is a letter (Cyrillic or Latin).
func isLetter(r rune) bool {
	return isCyrillic(r) || isLatin(r)
}

// isDigit reports whether the rune is an ASCII digit.
func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

// partOfLongerDigitSequence reports whether [start,end) is adjacent to another
// digit directly or through one grouping separator. Both boundaries matter:
// otherwise a valid-looking suffix such as the card in "1 4111 1111 1111 1111"
// would be accepted as a standalone identifier.
func partOfLongerDigitSequence(input string, start, end int) bool {
	if precededByMoreDigits(input, start) {
		return true
	}
	return followedByMoreDigits(input, end)
}

func precededByMoreDigits(input string, start int) bool {
	i := start
	if i > 0 && (input[i-1] == ' ' || input[i-1] == '-') {
		i--
	}
	return i > 0 && input[i-1] >= '0' && input[i-1] <= '9'
}

func followedByMoreDigits(input string, end int) bool {
	i := end
	if i < len(input) && (input[i] == ' ' || input[i] == '-') {
		i++
	}
	return i < len(input) && input[i] >= '0' && input[i] <= '9'
}

// normalizeDigits strips all non-digit characters from a string.
func normalizeDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// hasLowerLetter reports whether the string contains at least one lowercase
// letter.
func hasLowerLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func fieldLabelWord(word string) bool {
	switch word {
	case "телефон", "email", "почта", "паспорт", "инн", "фио", "город", "адрес", "дата", "индекс", "дом", "квартира", "ул", "д", "кв", "клиент", "получатель":
		return true
	}
	return false
}

func lastMarkerEnd(input string, markers []*pattern) int {
	end := -1
	for _, re := range markers {
		for _, match := range re.FindAllStringSubmatchIndex(input, -1) {
			end = max(end, match[1])
		}
	}
	return end
}
