package detectors

import "strings"

// Small linguistic vocabulary, not a list of people. It only proposes weak
// pairs; it never makes an unlabelled two-word sequence high-confidence.
var givenNames = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Fields(`август адам адриан александр алексей альберт анатолий андрей антон аркадий арсений артём артем артур борис вадим валентин валерий василий виктор виталий владимир владислав вячеслав геннадий георгий герман глеб григорий даниил данила денис дмитрий евгений егор иван игорь илья кирилл константин лев леонид максим марк матвей михаил никита николай олег павел пётр петр платон роман ростислав руслан савелий семён семен сергей сидор станислав степан тимофей тимур фёдор федор филипп эдуард юрий ярослав агата александра алина алиса алла анастасия ангелина анна антонина валентина валерия варвара вера вероника виктория галина дарья диана евгения екатерина елена елизавета жанна зинаида зоя инна ирина карина кира ксения лариса лидия любовь людмила маргарита марина мария надежда наталья нина оксана ольга полина светлана софия софья тамара татьяна ульяна юлия яна`) {
		m[n] = true
	}
	return m
}()

func commonGivenName(w string) bool {
	w = strings.ToLower(w)
	for {
		p, rest, more := strings.Cut(w, "-")
		found := givenNameForm(p)
		if !found {
			return false
		}
		if !more {
			return true
		}
		w = rest
	}
}

func surnameForm(w string) bool {
	w = strings.ToLower(w)
	for {
		part, rest, more := strings.Cut(w, "-")
		found := false
		for _, suffix := range []string{"ов", "ев", "ёв", "ин", "ын", "ова", "ева", "ёва", "ина", "ына", "ой", "ский", "цкий", "ская", "цкая", "енко", "ко", "ук", "юк", "их", "ых", "ого", "ому", "овой", "евой", "иной", "овым", "евым", "иным", "ову", "еву", "ину", "скую"} {
			if strings.HasSuffix(part, suffix) && len(part) > len(suffix)+2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		if !more {
			return true
		}
		w = rest
	}
}

func givenNameForm(p string) bool {
	found := givenNames[p]
	// Conservative oblique forms; no stemming of arbitrary unknown names.
	for _, ending := range []string{"ом", "ем", "ей", "у", "ю", "а", "я", "е", "ы", "и", "ой"} {
		if !strings.HasSuffix(p, ending) {
			continue
		}
		stem := strings.TrimSuffix(p, ending)
		for _, base := range []string{stem, stem + "а", stem + "я", stem + "й", stem + "ь"} {
			if givenNames[base] {
				found = true
				break
			}
		}
	}
	return found
}
