package pii

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// normalizedText is a detection-only view. Original bytes are never changed.
// The common case has no allocation; only changed text needs a boundary map.
type normalizedText struct {
	text    string
	offsets []int
}

func normalizeText(input string) normalizedText {
	changed := false
	for _, r := range input {
		if normalizeRune(r) != r {
			changed = true
			break
		}
	}
	if !changed {
		return normalizedText{text: input}
	}
	var b strings.Builder
	b.Grow(len(input))
	offsets := make([]int, 0, len(input)+1)
	for pos, r := range input {
		n := normalizeRune(r)
		width := utf8.RuneLen(n)
		for i := 0; i < width; i++ {
			offsets = append(offsets, pos)
		}
		b.WriteRune(n)
	}
	offsets = append(offsets, len(input))
	return normalizedText{b.String(), offsets}
}

func normalizeRune(r rune) rune {
	switch {
	case r == '\r' || r == '\u2028' || r == '\u2029':
		return '\n'
	case unicode.IsSpace(r) && r != '\n':
		return ' '
	case r == '\u2010' || r == '\u2011' || r == '\u2212' || r == '\uff0d':
		return '-'
	case r >= '\uff10' && r <= '\uff19':
		return '0' + r - '\uff10'
	case r == '\uff0b':
		return '+'
	case r == '\uff1a':
		return ':'
	default:
		return r
	}
}

func (n normalizedText) originalOffset(i int) int {
	if n.offsets == nil {
		return i
	}
	return n.offsets[i]
}
