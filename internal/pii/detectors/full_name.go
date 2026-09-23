package detectors

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/alfagen/pii-service/internal/pii"
)

// FullNameDetector finds Russian full names (Фамилия Имя Отчество) and
// variants with explicit markers like "клиент", "ФИО", "держатель",
// "получатель". It deliberately avoids masking famous names without a
// client-context marker (e.g. "поэт Александр Пушкин").
type FullNameDetector struct {
	// markers that strongly indicate a personal name.
	strongMarkers []*pattern
	// weakMarkers that indicate a name only when combined with a strong one.
	weakMarkers []*pattern
	// trapNames are famous names that must not be masked without context.
	trapNames []string
}

// NewFullNameDetector builds a FullNameDetector.
func NewFullNameDetector() *FullNameDetector {
	return &FullNameDetector{
		strongMarkers: []*pattern{
			compilePattern(`(?i)фио`),
			compilePattern(`(?i)клиент`),
			compilePattern(`(?i)держател\p{L}*`),
			compilePattern(`(?i)получател\p{L}*`),
			compilePattern(`(?i)заказчик`),
			compilePattern(`(?i)пациент`),
			compilePattern(`(?i)сотрудник`),
			compilePattern(`(?i)гражданин`),
			compilePattern(`(?i)заявител\p{L}*`),
			compilePattern(`(?i)владелец`),
			compilePattern(`(?i)пользовател\p{L}*`),
			compilePattern(`(?i)абонент`),
			compilePattern(`(?i)имя`),
			compilePattern(`(?i)фамилия`),
			compilePattern(`(?i)отчество`),
		},
		weakMarkers: []*pattern{
			compilePattern(`(?i)г-н`),
			compilePattern(`(?i)г-жа`),
			compilePattern(`(?i)товарищ`),
			compilePattern(`(?i)уважаем\p{L}*`),
		},
		trapNames: []string{
			"пушкин", "александр сергеевич пушкин", "александр пушкин",
			"толстой", "лев толстой", "лев николаевич толстой",
			"достоевский", "чехов", "гоголь", "лермонтов", "есенин",
			"маяковский", "пастернак", "ахматова", "цветаева",
			"блок", "тютчев", "фет", "некрасов", "тургенев",
			"гончаров", "островский", "салтыков-щедрин", "бунин",
			"куприн", "горький", "шолохов", "солженицын", "бродский",
		},
	}
}

// Type implements pii.Detector.
func (d *FullNameDetector) Type() pii.PIIType { return pii.TypeFullName }

// Detect implements pii.Detector.
// Detect preserves the standalone recognizer API: only strong findings.
func (d *FullNameDetector) Detect(input string) []pii.Finding {
	var out []pii.Finding
	for _, f := range d.Candidates(input) {
		if f.Confidence >= pii.ConfidenceHigh && f.Evidence&pii.EvidenceTrap == 0 {
			out = append(out, f)
		}
	}
	return out
}

// Candidates separates lexical plausibility from contextual acceptance.
func (d *FullNameDetector) Candidates(input string) []pii.Finding {
	words := nameTokens(input)
	var out []pii.Finding
	for i := 0; i < len(words); i++ {
		finding, count := d.nameCandidate(input, words[i:])
		if count == 0 {
			continue
		}
		out = append(out, finding)
		i += count - 1
	}
	return out
}

func (d *FullNameDetector) nameCandidate(input string, words []wordTok) (pii.Finding, int) {
	w := words[0]
	if !nameStart(w.text) {
		return pii.Finding{}, 0
	}
	strong := markerImmediatelyBefore(input, w.start, d.strongMarkers)
	weak := !strong && markerImmediatelyBefore(input, w.start, d.weakMarkers)
	if !nameCapitalized(w.text) && !strong {
		return pii.Finding{}, 0
	}
	count := nameWordCount(input, words, strong)
	conf := nameConfidence(words[:count], strong || weak)
	requiresAnchor := conf == 0 && contextualNamePair(input, words, count)
	if requiresAnchor {
		conf = pii.NameCandidateConfidence
	}
	if conf == 0 {
		return pii.Finding{}, 0
	}
	f := d.finding(input, w.start, words[count-1].end)
	f.Confidence = conf
	if requiresAnchor {
		f.Evidence |= pii.EvidenceRequiresAnchor
	}
	if strong || weak {
		f.Evidence |= pii.EvidenceLabel
	}
	if !strong && d.hasTrapName(words[:count]) {
		f.Evidence |= pii.EvidenceTrap
	}
	return f, count
}

func nameStart(word string) bool {
	return !nameStop(word) && nameLetters(word) && (nameCapitalized(word) || commonGivenName(word) || surnameForm(word))
}

func nameWordCount(input string, words []wordTok, strong bool) int {
	count := 1
	for count < 3 && count < len(words) {
		next := words[count]
		if nameStop(next.text) || !nameLetters(next.text) || (!strong && !nameCapitalized(next.text)) || !nameWordsAdjacent(input, words[count-1], next, strong) {
			break
		}
		count++
	}
	// Without a patronymic a third word is not part of the name.
	if count == 3 && !isPatronymic(words[1].text) && !isPatronymic(words[2].text) {
		count = 2
	}
	return count
}

func nameConfidence(words []wordTok, labelled bool) pii.Confidence {
	if labelled {
		if len(words) >= 2 || commonGivenName(words[0].text) || surnameForm(words[0].text) {
			return pii.ConfidenceHigh
		}
		return 0
	}
	if len(words) == 3 {
		return pii.ConfidenceHigh
	}
	if len(words) == 2 && plausibleNamePair(words[0].text, words[1].text) {
		return pii.NameCandidateConfidence
	}
	return 0
}

func (d *FullNameDetector) hasTrapName(words []wordTok) bool {
	for _, word := range words {
		if slices.Contains(d.trapNames, strings.ToLower(word.text)) {
			return true
		}
	}
	return false
}

// nameTokens keeps hyphenated components as one word; spans still refer to
// the original bytes. No whole-document case conversion is performed.
func nameTokens(input string) []wordTok {
	words := tokenizeWords(input)
	out := words[:0]
	for _, w := range words {
		if len(out) > 0 && input[out[len(out)-1].end:w.start] == "-" {
			last := &out[len(out)-1]
			last.end = w.end
			last.text = input[last.start:last.end]
		} else {
			out = append(out, w)
		}
	}
	return out
}

func nameLetters(w string) bool {
	for {
		part, rest, more := strings.Cut(w, "-")
		if !isCyrillicWord(part) {
			return false
		}
		if !more {
			return true
		}
		w = rest
	}
}
func nameCapitalized(w string) bool {
	for {
		part, rest, more := strings.Cut(w, "-")
		r, _ := utf8.DecodeRuneInString(part)
		if !unicode.IsUpper(r) {
			return false
		}
		if !more {
			return true
		}
		w = rest
	}
}
func plausibleNamePair(a, b string) bool {
	return commonGivenName(a) && surnameForm(b) || surnameForm(a) && commonGivenName(b)
}

func contextualNamePair(input string, words []wordTok, count int) bool {
	if count != 2 || !isCapitalizedWord(words[0].text) || !isCapitalizedWord(words[1].text) {
		return false
	}
	// Do not consume a given name at the end of a weak prefix when a complete
	// name starts there (e.g. a greeting followed by given name and surname).
	if commonGivenName(words[1].text) && len(words) > 2 && nameCapitalized(words[2].text) && !nameStop(words[2].text) && wordsAdjacent(input, words[1], words[2]) {
		return false
	}
	// Exactly one known given name, with an otherwise unconstrained surname.
	// Candidate creation alone never authorizes masking this pair.
	return commonGivenName(words[0].text) != commonGivenName(words[1].text)
}

func nameStop(w string) bool {
	if isMarkerWord(w) {
		return true
	}
	switch strings.ToLower(w) {
	case "город", "адрес", "телефон", "почта", "email", "паспорт", "инн", "карта", "карты", "счёта", "счета",
		"проживает", "по", "адресу", "место", "жительства", "рождения", "дата", "компания", "компании", "офис", "банка",
		"написал", "писатель", "поэт", "автор", "отделение", "филиал", "склад", "находится", "не", "указано", "отсутствует",
		"здравствуйте", "спасибо", "пожалуйста", "привет",
		"какой", "какая", "какие", "какого", "который", "которая", "кто", "что", "это", "страны", "вы":
		return true
	}
	return false
}

func wordsAdjacent(input string, left, right wordTok) bool {
	for _, r := range input[left.end:right.start] {
		if r == '\n' || r == '\r' || (!unicode.IsSpace(r) && r != '-') {
			return false
		}
	}
	return true
}

func markerImmediatelyBefore(input string, start int, markers []*pattern) bool {
	candidate := precedingNameLabel(input, start)
	if candidate == "" {
		return false
	}
	for _, marker := range markers {
		if loc := marker.re.FindStringIndex(candidate); loc != nil && loc[0] == 0 && loc[1] == len(candidate) {
			return true
		}
	}
	return false
}

// isMarkerWord reports whether the word is a contextual marker that should not
// be treated as part of a name.
func isMarkerWord(w string) bool {
	l := strings.ToLower(w)
	switch l {
	case "клиент", "фио", "держатель", "держателя", "получатель", "получателя",
		"заказчик", "пациент", "сотрудник", "гражданин", "заявитель",
		"владелец", "пользователь", "абонент", "имя", "фамилия", "отчество",
		"г-н", "г-жа", "товарищ", "уважаемый", "уважаемая", "уважаемые",
		"господин", "госпожа", "гражданка":
		return true
	}
	return false
}

type wordTok struct {
	text  string
	start int
	end   int
}

// tokenizeWords splits input into letter-only words with byte offsets.
func tokenizeWords(input string) []wordTok {
	var out []wordTok
	i := 0
	n := len(input)
	for i < n {
		// skip non-letters
		for i < n {
			r, sz := decodeRune(input[i:])
			if isLetter(r) {
				break
			}
			i += sz
		}
		if i >= n {
			break
		}
		start := i
		for i < n {
			r, sz := decodeRune(input[i:])
			if !isLetter(r) {
				break
			}
			i += sz
		}
		out = append(out, wordTok{text: input[start:i], start: start, end: i})
	}
	return out
}

func decodeRune(s string) (rune, int) {
	return utf8.DecodeRuneInString(s)
}

// isCapitalizedWord reports whether the word starts with an uppercase letter
// and contains at least one lowercase letter (i.e. is a proper noun form).
func isCapitalizedWord(w string) bool {
	if len(w) == 0 {
		return false
	}
	r, _ := decodeRune(w)
	if !unicode.IsUpper(r) {
		return false
	}
	return hasLowerLetter(w)
}

func isCyrillicWord(w string) bool {
	for _, r := range w {
		if !isCyrillic(r) {
			return false
		}
	}
	return len(w) > 0
}

// isPatronymic reports whether the word looks like a Russian patronymic.
func isPatronymic(w string) bool {
	l := strings.ToLower(w)
	for _, suffix := range []string{"ович", "евич", "ич", "овна", "евна", "чна", "ична", "овича", "евича", "овичу", "евичу", "овичем", "евичем", "овной", "евной", "овны", "евны"} {
		if strings.HasSuffix(l, suffix) && len(l) > len(suffix) {
			return true
		}
	}
	return false
}

func (d *FullNameDetector) finding(input string, start, end int) pii.Finding {
	return pii.Finding{
		Type:       pii.TypeFullName,
		Start:      start,
		End:        end,
		Confidence: pii.ConfidenceHigh,
		Detector:   "full_name",
		Value:      input[start:end],
	}
}

func nameWordsAdjacent(input string, left, right wordTok, labelled bool) bool {
	if !labelled {
		return wordsAdjacent(input, left, right)
	}
	for _, r := range input[left.end:right.start] {
		if r == '\n' || r == '\r' || (!unicode.IsSpace(r) && r != ',') {
			return false
		}
	}
	return true
}

func precedingNameLabel(input string, start int) string {
	lo, _ := contextBounds(input, start, start)
	prefix := input[lo:start]
	end := len(prefix)
	for end > 0 {
		r, size := utf8.DecodeLastRuneInString(prefix[:end])
		if r == '\n' || r == '\r' {
			return ""
		}
		if !unicode.IsSpace(r) && !strings.ContainsRune(":-—«\"'", r) {
			break
		}
		end -= size
	}
	begin := end
	for begin > 0 {
		r, size := utf8.DecodeLastRuneInString(prefix[:begin])
		if !unicode.IsLetter(r) && r != '-' {
			break
		}
		begin -= size
	}
	candidate := prefix[begin:end]
	return candidate
}
