package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/alfagen/pii-service/internal/pii"
)

type tokenValue struct {
	typ   pii.PIIType
	value string
}
type tokenTable struct {
	nonce    string
	next     int
	reserved map[string]bool
	values   map[tokenValue]string
}

func newTokenTable(input, nonce string) *tokenTable {
	t := &tokenTable{nonce: nonce, reserved: map[string]bool{}, values: map[tokenValue]string{}}
	if nonce != "" {
		for _, marker := range markerPattern.FindAllString(input, -1) {
			t.reserved[marker] = true
		}
	}
	return t
}
func (t *tokenTable) token(typ pii.PIIType, value string) string {
	k := tokenValue{typ, value}
	if token, ok := t.values[k]; ok {
		return token
	}
	for {
		// The context nonce is a secret key, never part of a visible token.
		// Knowing one marker cannot authenticate another type/value/index.
		mac := hmac.New(sha256.New, []byte(t.nonce))
		mac.Write([]byte(typ))
		mac.Write([]byte{0})
		mac.Write([]byte(value))
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(t.next))
		mac.Write(counter[:])
		tag := mac.Sum(nil)
		token := fmt.Sprintf("<%s_%s_%d>", strings.ToUpper(string(typ)), hex.EncodeToString(tag[:16]), t.next)
		t.next++
		if t.reserved[token] {
			continue
		}
		t.reserved[token] = true
		t.values[k] = token
		return token
	}
}

// A saved mapping is the only authority; there is no hash decoding or fuzzy
// lookup. Replacement scans the provider text once, never the restored bytes.
func restoreTokens(text string, mapping map[string]string) string {
	var out strings.Builder
	cursor := 0
	for _, span := range markerPattern.FindAllStringIndex(text, -1) {
		value, ok := mapping[text[span[0]:span[1]]]
		if !ok || !tokenBoundary(text, span[0]-1) || !tokenBoundary(text, span[1]) {
			continue
		}
		out.WriteString(text[cursor:span[0]])
		out.WriteString(value)
		cursor = span[1]
	}
	if cursor == 0 {
		return text
	}
	out.WriteString(text[cursor:])
	return out.String()
}
func tokenBoundary(text string, i int) bool {
	if i < 0 || i >= len(text) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(text[i:])
	if !utf8.RuneStart(text[i]) {
		r, _ = utf8.DecodeLastRuneInString(text[:i+1])
	}
	return r != '<' && r != '>' && r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsMark(r)
}

func hideMarkers(text string) string {
	spans := markerPattern.FindAllStringIndex(text, -1)
	return hideMarkerSpans(text, spans)
}

func hideMarkerSpans(text string, spans [][]int) string {
	if len(spans) == 0 {
		return text
	}
	scan := []byte(text)
	for _, span := range spans {
		for i := span[0]; i < span[1]; i++ {
			scan[i] = ' '
		}
	}
	return string(scan)
}
