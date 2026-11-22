// Package termtext makes untrusted text safe to show on a terminal.
//
// Everything a client prints from the daemon (petnames, handles, groups,
// IMs, away messages, error text) may come from another person. The daemon
// rejects control characters in what it accepts, but clients clean what
// they print anyway: a hostile string must not move the cursor, rewrite the
// screen, set the window title or reorder the text around it.
package termtext

import (
	"strings"
	"unicode"

	"golang.org/x/text/width"
)

// Replacement stands in for every unsafe rune and invalid UTF-8 sequence.
const Replacement = '\ufffd'

// Unsafe reports runes that can move the cursor, rewrite the screen or
// reorder text: C0 and C1 controls, DEL, line and paragraph separators, and
// the bidirectional marks, overrides, embeddings and isolates.
func Unsafe(r rune) bool {
	switch {
	case unicode.IsControl(r):
		return true
	case r == '\u2028', r == '\u2029': // line and paragraph separators
		return true
	case r == '\u061c', r == '\u200e', r == '\u200f': // ALM, LRM, RLM
		return true
	case r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069': // embeddings, overrides, isolates
		return true
	}
	return false
}

// Clean makes s safe to print on one line: newlines and tabs become spaces
// and other unsafe runes (and invalid UTF-8) become U+FFFD.
func Clean(s string) string {
	s = strings.ToValidUTF8(s, string(Replacement))
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case Unsafe(r):
			return Replacement
		}
		return r
	}, s)
}

// CleanText makes multi-line text (an IM) safe to print: it keeps tabs and
// line breaks, indenting continuation lines by indent.
func CleanText(s, indent string) string {
	s = strings.ToValidUTF8(s, string(Replacement))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteByte('\n')
			b.WriteString(indent)
		case r == '\t':
			b.WriteRune(r)
		case Unsafe(r):
			b.WriteRune(Replacement)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Lines splits multi-line text into lines, each cleaned with Clean.
func Lines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	parts := strings.Split(s, "\n")
	for i, p := range parts {
		parts[i] = Clean(p)
	}
	return parts
}

// Width is how many terminal columns s takes, roughly: wide East Asian
// runes take two and combining marks none.
func Width(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r):
		case width.LookupRune(r).Kind() == width.EastAsianWide, width.LookupRune(r).Kind() == width.EastAsianFullwidth:
			n += 2
		default:
			n++
		}
	}
	return n
}
