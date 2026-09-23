// Package transform implements format-preserving masking strategies. Strategies
// are described centrally by PII type so they can be changed quickly after
// comparison with a reference implementation.
package masking

import (
	"strings"
	"unicode"

	"github.com/alfagen/pii-service/internal/pii"
)

// MaskMode selects the masking strategy.
type MaskMode string

const (
	// MaskModeFormat is the default format-preserving mask.
	MaskModeFormat MaskMode = "format"
	// MaskModeToken replaces values with typed tokens like <PHONE_1>.
	MaskModeToken MaskMode = "token"
)

// Strategy masks a single finding value. It must be deterministic.
type Strategy func(value string) string

// strategies maps each PII type to its masking strategy.
var strategies = map[pii.PIIType]Strategy{
	pii.TypeFullName:          maskFullName,
	pii.TypeDateOfBirth:       maskDate,
	pii.TypePlaceOfBirth:      maskWords,
	pii.TypePassportNumber:    maskPassport,
	pii.TypeCitizenship:       maskWords,
	pii.TypePassportIssuer:    maskAllAlphaNumeric,
	pii.TypePassportDivision:  maskDigitsKeepEdges,
	pii.TypePassportIssueDate: maskDate,
	pii.TypeDriverLicense:     maskDriverLicense,
	pii.TypeAddress:           maskAllAlphaNumeric,
	pii.TypeEmail:             maskEmail,
	pii.TypePhone:             maskPhone,
	pii.TypeINN:               maskDigitsKeepEdges,
	pii.TypeCardNumber:        maskCardNumber,
	pii.TypeCVV:               maskAllDigits,
	pii.TypeCardPIN:           maskAllDigits,
	pii.TypeCardHolder:        maskFullName,
}

// Mask applies the format-preserving strategy for the given type.
func Mask(typ pii.PIIType, value string) string {
	if s, ok := strategies[typ]; ok {
		return s(value)
	}
	// Configured categories can contain numeric identifiers. Without a
	// dedicated strategy, hide both letters and digits instead of exposing
	// the entire numeric value through the word-only fallback.
	return maskAllAlphaNumeric(value)
}

// MaskToken returns a typed token for the given type and index.
func MaskToken(typ pii.PIIType, index int) string {
	return "<" + strings.ToUpper(string(typ)) + "_" + itoa(index+1) + ">"
}

// maskFullName converts "Иванов Иван Иванович" -> "И. И. И.".
func maskFullName(value string) string {
	words := strings.Fields(value)
	if len(words) == 0 {
		return value
	}
	var b strings.Builder
	for i, w := range words {
		if i > 0 {
			b.WriteString(" ")
		}
		rs := []rune(w)
		if len(rs) == 0 {
			continue
		}
		b.WriteRune(rs[0])
		b.WriteString(".")
	}
	return b.String()
}

// maskDate keeps the year and masks day/month digits when other digits are
// present to mask. A value that consists solely of a 4-digit year (e.g. a
// standalone "год рождения") has nothing else to obscure, so the year itself
// is partially masked instead; a fully-worded date has no digits at all and
// falls back to word masking. Either case must not return the value
// unchanged.
func maskDate(value string) string {
	runes := []rune(value)
	digitTotal, yearStart, yearEnd := dateDigitRuns(runes)
	if digitTotal == 0 {
		// No digits at all: a fully-worded date ("пятнадцатого марта ...").
		return maskWords(value)
	}
	// Keep the year run visible only when there are other digits (day/month)
	// being masked around it; a value that IS the year run must still lose
	// some of its digits.
	keepYear := yearStart >= 0 && digitTotal > yearEnd-yearStart
	var out []rune
	for i := 0; i < len(runes); i++ {
		if keepYear && i >= yearStart && i < yearEnd {
			out = append(out, runes[i])
			continue
		}
		if !keepYear && yearStart >= 0 && i >= yearStart+2 && i < yearEnd {
			// Standalone year: keep only the last two digits visible.
			out = append(out, runes[i])
			continue
		}
		if isDigitRune(runes[i]) {
			out = append(out, '*')
		} else {
			out = append(out, runes[i])
		}
	}
	return string(out)
}

// maskPassport converts "4509 123456" -> "45** ****56".
func maskPassport(value string) string {
	digits := 0
	for _, r := range value {
		if isDigitRune(r) {
			digits++
		}
	}
	// Keep first 2 and last 2 digits of the whole number.
	runes := []rune(value)
	var out []rune
	digitIdx := 0
	for i := 0; i < len(runes); i++ {
		if isDigitRune(runes[i]) {
			if digitIdx < 2 || digitIdx >= digits-2 {
				out = append(out, runes[i])
			} else {
				out = append(out, '*')
			}
			digitIdx++
		} else {
			out = append(out, runes[i])
		}
	}
	return string(out)
}

// maskDriverLicense keeps first 2 and last 2 digits.
func maskDriverLicense(value string) string {
	return maskPassport(value)
}

// maskCardNumber keeps first 4 and last 4 digits.
func maskCardNumber(value string) string {
	digits := 0
	for _, r := range value {
		if isDigitRune(r) {
			digits++
		}
	}
	runes := []rune(value)
	var out []rune
	digitIdx := 0
	for i := 0; i < len(runes); i++ {
		if isDigitRune(runes[i]) {
			if digitIdx < 4 || digitIdx >= digits-4 {
				out = append(out, runes[i])
			} else {
				out = append(out, '*')
			}
			digitIdx++
		} else {
			out = append(out, runes[i])
		}
	}
	return string(out)
}

// maskDigitsKeepEdges keeps first 2 and last 2 digits.
func maskDigitsKeepEdges(value string) string {
	return maskPassport(value)
}

// maskAllDigits replaces every digit with *.
func maskAllDigits(value string) string {
	runes := []rune(value)
	for i := range runes {
		if isDigitRune(runes[i]) {
			runes[i] = '*'
		}
	}
	return string(runes)
}

func maskAllAlphaNumeric(value string) string {
	runes := []rune(value)
	for i := range runes {
		if isDigitRune(runes[i]) || isLetterRune(runes[i]) {
			runes[i] = '*'
		}
	}
	return string(runes)
}

// maskPhone keeps +7/8 prefix and last 2 digits.
func maskPhone(value string) string {
	runes := []rune(value)
	var out []rune
	digitIdx := 0
	totalDigits := 0
	for _, r := range runes {
		if isDigitRune(r) {
			totalDigits++
		}
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if isDigitRune(r) {
			if digitIdx < 1 || digitIdx >= totalDigits-2 {
				out = append(out, r)
			} else {
				out = append(out, '*')
			}
			digitIdx++
		} else {
			out = append(out, r)
		}
	}
	return string(out)
}

// maskEmail keeps first char of local part and domain TLD.
func maskEmail(value string) string {
	at := strings.IndexByte(value, '@')
	if at < 0 {
		return maskWords(value)
	}
	local := value[:at]
	domain := value[at+1:]
	dot := strings.LastIndexByte(domain, '.')
	var maskedLocal string
	if len(local) > 0 {
		maskedLocal = string(local[0]) + strings.Repeat("*", len(local)-1)
	} else {
		maskedLocal = "*"
	}
	var maskedDomain string
	if dot > 0 {
		maskedDomain = strings.Repeat("*", dot) + domain[dot:]
	} else {
		maskedDomain = strings.Repeat("*", len(domain))
	}
	return maskedLocal + "@" + maskedDomain
}

// maskWords replaces letters with * while preserving digits and separators.
func maskWords(value string) string {
	runes := []rune(value)
	for i := range runes {
		if isLetterRune(runes[i]) {
			runes[i] = '*'
		}
	}
	return string(runes)
}

func isDigitRune(r rune) bool { return unicode.IsDigit(r) }

func isLetterRune(r rune) bool { return unicode.IsLetter(r) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func dateDigitRuns(runes []rune) (int, int, int) {
	digitTotal := 0
	// Find the (last) 4-digit run, treated as the year.
	yearStart, yearEnd := -1, -1
	for i := 0; i < len(runes); {
		if isDigitRune(runes[i]) {
			j := i
			for j < len(runes) && isDigitRune(runes[j]) {
				j++
			}
			digitTotal += j - i
			if j-i == 4 {
				yearStart, yearEnd = i, j
			}
			i = j
		} else {
			i++
		}
	}
	return digitTotal, yearStart, yearEnd
}
