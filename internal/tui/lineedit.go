package tui

import (
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/aghman/openaim/internal/termtext"
)

// lineEdit is a one-line text field: the IM input and the dialogs' fields.
//
// It is deliberately small instead of bubbles/textinput: that widget binds
// Ctrl+A and Ctrl+N (which the TUI uses for away and new IM), reads the
// system clipboard by running a helper program on Ctrl+V, and blinks its
// own cursor with a stream of timer messages. Here the terminal's cursor
// is placed on the field instead, and pastes arrive as tea.PasteMsg.
type lineEdit struct {
	runes []rune
	pos   int // cursor, 0..len(runes)
	limit int // most runes accepted; 0 is no limit
}

func (e *lineEdit) Value() string { return string(e.runes) }

func (e *lineEdit) SetValue(s string) {
	e.runes = sanitizeInput([]rune(s))
	if e.limit > 0 && len(e.runes) > e.limit {
		e.runes = e.runes[:e.limit]
	}
	e.pos = len(e.runes)
}

func (e *lineEdit) Reset() { e.runes, e.pos = nil, 0 }

// sanitizeInput turns line breaks and tabs into spaces and drops runes that
// would disturb the terminal (or break the daemon's text rules) when echoed.
func sanitizeInput(rs []rune) []rune {
	out := make([]rune, 0, len(rs))
	for _, r := range rs {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			out = append(out, ' ')
		case termtext.Unsafe(r):
		default:
			out = append(out, r)
		}
	}
	return out
}

// Insert adds text at the cursor (typed or pasted).
func (e *lineEdit) Insert(text string) {
	rs := sanitizeInput([]rune(text))
	if e.limit > 0 {
		rs = rs[:min(len(rs), max(0, e.limit-len(e.runes)))]
	}
	if len(rs) == 0 {
		return
	}
	tail := append(rs, e.runes[e.pos:]...)
	e.runes = append(e.runes[:e.pos], tail...)
	e.pos += len(rs)
}

// Update applies an editing key and reports whether it was one.
func (e *lineEdit) Update(k tea.KeyPressMsg) bool {
	if k.Text != "" && k.Mod&^tea.ModShift == 0 {
		e.Insert(k.Text)
		return true
	}
	switch k.Keystroke() {
	case "backspace", "ctrl+h":
		if e.pos > 0 {
			e.runes = append(e.runes[:e.pos-1], e.runes[e.pos:]...)
			e.pos--
		}
	case "alt+backspace", "ctrl+w":
		l := e.wordLeft()
		e.runes = append(e.runes[:l], e.runes[e.pos:]...)
		e.pos = l
	case "delete", "ctrl+d":
		if e.pos < len(e.runes) {
			e.runes = append(e.runes[:e.pos], e.runes[e.pos+1:]...)
		}
	case "alt+d", "alt+delete":
		e.runes = append(e.runes[:e.pos], e.runes[e.wordRight():]...)
	case "left", "ctrl+b":
		if e.pos > 0 {
			e.pos--
		}
	case "right", "ctrl+f":
		if e.pos < len(e.runes) {
			e.pos++
		}
	case "alt+left", "ctrl+left", "alt+b":
		e.pos = e.wordLeft()
	case "alt+right", "ctrl+right", "alt+f":
		e.pos = e.wordRight()
	case "home", "ctrl+a":
		e.pos = 0
	case "end", "ctrl+e":
		e.pos = len(e.runes)
	case "ctrl+u":
		e.runes = append([]rune(nil), e.runes[e.pos:]...)
		e.pos = 0
	case "ctrl+k":
		e.runes = e.runes[:e.pos]
	default:
		return false
	}
	return true
}

func (e *lineEdit) wordLeft() int {
	i := e.pos
	for i > 0 && unicode.IsSpace(e.runes[i-1]) {
		i--
	}
	for i > 0 && !unicode.IsSpace(e.runes[i-1]) {
		i--
	}
	return i
}

func (e *lineEdit) wordRight() int {
	i := e.pos
	for i < len(e.runes) && unicode.IsSpace(e.runes[i]) {
		i++
	}
	for i < len(e.runes) && !unicode.IsSpace(e.runes[i]) {
		i++
	}
	return i
}

// View renders the field in width columns, scrolled so the cursor shows,
// and returns the cursor's column within it.
func (e *lineEdit) View(width int) (string, int) {
	if width < 1 {
		return "", 0
	}
	// Scroll: the widest window ending at the cursor that fits (with a
	// cell for the cursor itself), then as much after it as fits.
	start, w := e.pos, 1
	for start > 0 {
		rw := max(ansi.StringWidth(string(e.runes[start-1])), 1)
		if w+rw > width {
			break
		}
		w += rw
		start--
	}
	var b strings.Builder
	used, col := 0, -1
	for i := start; i < len(e.runes); i++ {
		if i == e.pos {
			col = used
		}
		ch := string(e.runes[i])
		cw := max(ansi.StringWidth(ch), 1)
		if used+cw > width {
			break
		}
		used += cw
		b.WriteString(ch)
	}
	if col < 0 {
		col = used
	}
	return b.String(), min(col, width-1)
}
