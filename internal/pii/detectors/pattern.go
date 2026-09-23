package detectors

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// pattern adds a conservative literal prefilter to the original regexp. A
// rejected input cannot match; positive inputs still use the unchanged regexp,
// including its Unicode case folding, captures, boundaries and byte offsets.
type pattern struct {
	re      *regexp.Regexp
	needles []literal
}

type literal struct {
	text  string
	fold  bool
	first string
	runes int
}

func compilePattern(expr string) *pattern {
	re := regexp.MustCompile(expr)
	ast, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		panic(err)
	}
	return &pattern{re: re, needles: requiredLiterals(ast)}
}

// Each alternative must contain at least one returned literal. An empty list
// means unknown, never "no match". Concatenations may choose any required child.
func requiredLiterals(re *syntax.Regexp) []literal {
	switch re.Op {
	case syntax.OpLiteral:
		return regexpLiteral(re)
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return requiredLiterals(re.Sub[0])
		}
	case syntax.OpConcat:
		return concatLiterals(re.Sub)
	case syntax.OpAlternate:
		return alternateLiterals(re.Sub)
	}
	return nil
}

func regexpLiteral(re *syntax.Regexp) []literal {
	if len(re.Rune) == 0 {
		return nil
	}
	v := literal{text: string(re.Rune), fold: re.Flags&syntax.FoldCase != 0, runes: len(re.Rune), first: string(re.Rune[0])}
	if v.fold {
		for r := unicode.SimpleFold(re.Rune[0]); r != re.Rune[0]; r = unicode.SimpleFold(r) {
			v.first += string(r)
		}
	}
	return []literal{v}
}

func concatLiterals(parts []*syntax.Regexp) []literal {
	var best []literal
	bestScore := 0
	for _, sub := range parts {
		candidates := requiredLiterals(sub)
		if score := shortestLiteral(candidates); score > bestScore {
			best, bestScore = candidates, score
		}
	}
	return best
}

func shortestLiteral(candidates []literal) int {
	if len(candidates) == 0 {
		return 0
	}
	score := len(candidates[0].text)
	for _, candidate := range candidates {
		score = min(score, len(candidate.text))
	}
	return score
}

func alternateLiterals(parts []*syntax.Regexp) []literal {
	var all []literal
	for _, sub := range parts {
		candidates := requiredLiterals(sub)
		if len(candidates) == 0 {
			return nil
		}
		all = append(all, candidates...)
		if len(all) > 16 {
			return nil
		}
	}
	return all
}

func (p *pattern) possible(input string) bool {
	if len(p.needles) == 0 {
		return true
	}
	for _, needle := range p.needles {
		if needle.matches(input) {
			return true
		}
	}
	return false
}

func (n literal) matches(input string) bool {
	if !n.fold {
		return strings.Contains(input, n.text)
	}
	for rest := input; len(rest) > 0; {
		i := strings.IndexAny(rest, n.first)
		if i < 0 {
			return false
		}
		rest = rest[i:]
		end := 0
		for count := 0; count < n.runes && end < len(rest); count++ {
			_, size := utf8.DecodeRuneInString(rest[end:])
			end += size
		}
		if strings.EqualFold(rest[:end], n.text) {
			return true
		}
		_, size := utf8.DecodeRuneInString(rest)
		rest = rest[size:]
	}
	return false
}

func (p *pattern) MatchString(s string) bool { return p.possible(s) && p.re.MatchString(s) }
func (p *pattern) FindAllStringIndex(s string, n int) [][]int {
	if !p.possible(s) {
		return nil
	}
	return p.re.FindAllStringIndex(s, n)
}
func (p *pattern) FindAllStringSubmatchIndex(s string, n int) [][]int {
	if !p.possible(s) {
		return nil
	}
	return p.re.FindAllStringSubmatchIndex(s, n)
}
