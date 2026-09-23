package pii

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Scores are deterministic decision weights, not calibrated probabilities.
const (
	ProfileConservative                   = "conservative"
	ProfileBalanced                       = "balanced"
	ProfileStrict                         = "strict"
	NameCandidateConfidence    Confidence = 0.60
	AddressCandidateConfidence Confidence = 0.60
	BalancedThreshold          Confidence = 0.80
	StrictThreshold            Confidence = 0.55
	ConservativeThreshold      Confidence = 0.95
	AnchorPromotion            Confidence = 0.22
	MultipleTypesPromotion     Confidence = 0.08
	NegativePenalty            Confidence = 1.0
	ContextWindowBytes                    = 512
	MaxStructuredRecordBytes              = 2048
	MaxStructuredRecordLines              = 8
)

func ValidProfile(profile string) bool {
	return profile == "" || profile == ProfileConservative || profile == ProfileBalanced || profile == ProfileStrict
}
func Threshold(profile string, typ PIIType) Confidence {
	switch profile {
	case ProfileStrict:
		return StrictThreshold
	case ProfileConservative:
		return ConservativeThreshold
	default:
		if typ == TypeFullName || typ == TypeAddress {
			return BalancedThreshold
		}
		// Existing exact/context recognizers already gate medium findings with
		// type-specific grammar. Preserve their recall under the default policy.
		return ConfidenceMedium
	}
}
func FilterConfidence(all []Finding, profile string) []Finding {
	out := make([]Finding, 0, len(all))
	for _, f := range all {
		if f.Confidence >= Threshold(profile, f.Type) {
			out = append(out, f)
		}
	}
	return out
}

// ContextStats carries only bounded categories and aggregate counts.
type ContextStats struct{ Promoted, Suppressed map[PIIType]int }
type textRecord struct{ start, end int }

var (
	personHeader    = regexp.MustCompile(`(?i)^[\s\p{Zs}]*(?:фио|клиент|получатель|пациент|заявитель|владелец)[\s\p{Zs}]*[:：]`)
	fieldHeader     = regexp.MustCompile(`(?i)^[\s\p{Zs}]*(?:имя|фамилия|отчество|город|адрес(?:[\s\p{Zs}]+(?:проживания|регистрации))?|место[\s\p{Zs}]+жительства|телефон|email|почта|паспорт|инн|карта|дата[\s\p{Zs}]+рождения)[\s\p{Zs}]*[:：]`)
	negativeContext = regexp.MustCompile(`(?i)(?:^|[^\p{L}])(?:поэт\p{L}*|писател\p{L}*|автор\p{L}*|роман|офис\p{L}*|отделени\p{L}*|филиал\p{L}*|склад\p{L}*|компани\p{L}*|организаци\p{L}*|магазин\p{L}*|завод\p{L}*|представительств\p{L}*|пункт\s+выдачи)(?:$|[^\p{L}])`)
)

// logicalRecords joins only explicitly structured personal records. Arbitrary
// adjacent lines never share evidence. A new person header starts a new record.
func logicalRecords(text string) []textRecord {
	var out []textRecord
	active, lines := false, 0
	for start := 0; start < len(text); {
		end := len(text)
		if i := strings.IndexAny(text[start:], "\n\r\u2028\u2029"); i >= 0 {
			end = start + i
		}
		line := text[start:end]
		// Header checks are bounded even on an unbroken megabyte line.
		prefix := line
		if len(prefix) > ContextWindowBytes {
			prefix = prefix[:ContextWindowBytes]
		}
		person := personHeader.MatchString(prefix)
		join := active && !person && fieldHeader.MatchString(prefix) && lines < MaxStructuredRecordLines && end-out[len(out)-1].start <= MaxStructuredRecordBytes
		if join {
			out[len(out)-1].end = end
			lines++
		} else {
			out = append(out, textRecord{start, end})
			active, lines = person, 1
		}
		start = end
		if end < len(text) {
			_, width := utf8.DecodeRuneInString(text[end:])
			start += width
		}
		if end < len(text) && text[end] == '\r' && start < len(text) && text[start] == '\n' {
			start++
		}
	}
	return out
}

func anchorType(t PIIType) bool {
	switch t {
	case TypeFullName, TypePhone, TypeEmail, TypePassportNumber, TypeCardNumber, TypeINN:
		return true
	}
	return false
}

// ResolveContext is one directed pass over a frozen set of strong anchors.
// Promoted candidates never become anchors, even when several types co-occur.
func ResolveContext(text string, all []Finding) ([]Finding, ContextStats) {
	stats := ContextStats{map[PIIType]int{}, map[PIIType]int{}}
	out := append([]Finding(nil), all...)
	if len(out) == 0 {
		return out, stats
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	records := logicalRecords(text)
	suppressContext(text, out, records, stats)
	anchors := contextAnchors(text, out, records)
	promoteContext(text, out, records, anchors, stats)
	return out, stats
}

func suppressContext(text string, out []Finding, records []textRecord, stats ContextStats) {
	for i := range out {
		f := &out[i]
		if f.Type != TypeFullName && f.Type != TypeAddress {
			continue
		}
		lo, hi := localWindow(text, *f, records)
		negative := f.Evidence&EvidenceTrap != 0
		if f.Evidence&EvidenceLabel == 0 && negativeOutsideValue(text, *f, lo, hi) {
			negative = true
		}
		if negative {
			f.Confidence -= NegativePenalty
			if f.Confidence < 0 {
				f.Confidence = 0
			}
			stats.Suppressed[f.Type]++
		}
	}
}

func contextAnchors(text string, out []Finding, records []textRecord) []Finding {
	anchors := make([]Finding, 0, len(out))
	for _, f := range out {
		if f.Confidence >= ConfidenceHigh && anchorType(f.Type) {
			lo, hi := localWindow(text, f, records)
			// Office contacts remain sensitive themselves but cannot authorize
			// masking an organisation's name or geographic address.
			if f.Evidence&EvidenceLabel == 0 && negativeOutsideNames(text, lo, hi, out) {
				continue
			}
			anchors = append(anchors, f)
		}
	}
	return anchors
}

func promoteContext(text string, out []Finding, records []textRecord, anchors []Finding, stats ContextStats) {
	for i := range out {
		f := &out[i]
		if f.Confidence <= 0 || f.Confidence >= ConfidenceHigh || (f.Type != TypeFullName && f.Type != TypeAddress) {
			continue
		}
		lo, hi := contextWindow(text, *f, records)
		seen := nearbyAnchorTypes(*f, anchors, lo, hi)
		if len(seen) == 0 {
			if f.Evidence&EvidenceRequiresAnchor != 0 {
				f.Confidence = 0
				stats.Suppressed[f.Type]++
			}
			continue
		}
		f.Confidence += AnchorPromotion
		if len(seen) > 1 {
			f.Confidence += MultipleTypesPromotion
		}
		f.Confidence = min(f.Confidence, ConfidenceHigh)
		stats.Promoted[f.Type]++
	}
}

func contextWindow(text string, f Finding, records []textRecord) (int, int) {
	lo, hi := recordWindow(text, f, records)
	// Sentences bound promotion; dots inside email/abbreviations are not stops.
	for j := f.Start - 1; j >= lo; j-- {
		if SentenceBoundary(text, j) {
			lo = j + 1
			break
		}
	}
	for j := f.End; j < hi; j++ {
		if SentenceBoundary(text, j) {
			hi = j
			break
		}
	}
	return lo, hi
}

// SentenceBoundary reports whether byte index i in text terminates a
// sentence, treating common Russian address abbreviations (г., ул., д., ...)
// as non-terminating. Exported so a detector with its own context window
// (e.g. AddressDetector.confidence) can stay within one sentence instead of
// only stopping at line/record breaks.
func SentenceBoundary(text string, i int) bool {
	switch text[i] {
	case '!', '?', '|', '{', '}':
		return true
	case '.':
		if i+1 < len(text) {
			r, _ := utf8.DecodeRuneInString(text[i+1:])
			if !unicode.IsSpace(r) {
				return false
			}
		}
		start := i
		for n := 0; n < 5 && start > 0; n++ {
			r, sz := utf8.DecodeLastRuneInString(text[:start])
			if !unicode.IsLetter(r) {
				break
			}
			start -= sz
		}
		switch strings.ToLower(text[start:i]) {
		case "г", "гор", "ул", "д", "кв", "стр", "пер", "пр", "наб":
			return false
		}
		return true
	}
	return false
}

// Context describes the value's surroundings. A given name or surname may
// itself resemble a negative keyword; it must not suppress its own finding.
func negativeOutsideValue(text string, f Finding, lo, hi int) bool {
	return negativeContext.MatchString(text[lo:f.Start]) || negativeContext.MatchString(text[f.End:hi])
}

// An adjacent name value is not negative evidence against a contact either.
// Findings are already sorted and suppressed; scan only the bounded window,
// ignoring accepted lexical name spans, never unrelated prose or trap names.
func negativeOutsideNames(text string, lo, hi int, findings []Finding) bool {
	i := sort.Search(len(findings), func(i int) bool { return findings[i].Start >= lo })
	if i > 0 {
		i--
	}
	cursor := lo
	for ; i < len(findings) && findings[i].Start < hi; i++ {
		f := findings[i]
		if f.Type != TypeFullName || f.Confidence < NameCandidateConfidence || f.End <= cursor {
			continue
		}
		if f.Start > cursor && negativeContext.MatchString(text[cursor:f.Start]) {
			return true
		}
		cursor = min(hi, f.End)
	}
	return negativeContext.MatchString(text[cursor:hi])
}

// Suppression is field-local so an office clause cannot erase an explicitly
// labelled customer earlier in the same record.
func localWindow(text string, f Finding, records []textRecord) (int, int) {
	lo, hi := contextWindow(text, f, records)
	if j := strings.LastIndexAny(text[lo:f.Start], ",;\n\r\u2028\u2029"); j >= 0 {
		_, width := utf8.DecodeRuneInString(text[lo+j:])
		lo += j + width
	}
	if j := strings.IndexAny(text[f.End:hi], ",;\n\r\u2028\u2029"); j >= 0 {
		hi = f.End + j
	}
	return lo, hi
}

func nearbyAnchorTypes(f Finding, anchors []Finding, lo, hi int) map[PIIType]bool {
	seen := map[PIIType]bool{}
	j := sort.Search(len(anchors), func(j int) bool { return anchors[j].Start >= lo })
	for ; j < len(anchors) && anchors[j].Start < hi; j++ {
		a := anchors[j]
		if a.End <= hi && a.Type != f.Type && (a.End <= f.Start || a.Start >= f.End) {
			seen[a.Type] = true
		}
	}
	return seen
}

func recordWindow(text string, f Finding, records []textRecord) (int, int) {
	i := sort.Search(len(records), func(i int) bool { return records[i].end >= f.End })
	lo, hi := f.Start, f.End
	if i < len(records) && records[i].start <= f.Start {
		lo, hi = records[i].start, records[i].end
	}
	if f.Start-lo > ContextWindowBytes {
		lo = f.Start - ContextWindowBytes
		for lo < f.Start && !utf8.RuneStart(text[lo]) {
			lo++
		}
	}
	if hi-f.End > ContextWindowBytes {
		hi = f.End + ContextWindowBytes
		for hi > f.End && hi < len(text) && !utf8.RuneStart(text[hi]) {
			hi--
		}
	}
	return lo, hi
}
