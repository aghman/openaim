package tui

import (
	"slices"

	"github.com/charmbracelet/x/ansi"
)

// style is a set of SGR attributes for one span of text. Bubble Tea's
// renderer downsamples it to what the terminal can show (and NO_COLOR asks
// for), so the model always emits the full style.
type style ansi.Style

// with is s plus more attributes; s itself is never changed.
func (s style) with(attrs ...ansi.Attr) style {
	return style(append(slices.Clip(ansi.Style(s)), ansi.NewStyle(attrs...)...))
}

// theme holds the TUI's styles. Every state a style shows is also shown in
// text (a marker, a badge or a word), so the screen still makes sense with
// no styling at all (TERM=dumb).
type theme struct {
	border, title, focusTitle style
	group                     style
	selected                  style
	online, away, offline     style
	unverified                style // design §5.3: italic, with a ⚠ badge
	warn, errStyle, dim, bold style
	me, them                  style
	key                       style
}

// newTheme builds the styles. With color false (NO_COLOR) it keeps text
// attributes (bold, italic, reverse, faint) but sets no colors.
func newTheme(color bool) theme {
	var none style
	fg := func(s style, c ansi.Attr) style {
		if color {
			return s.with(c)
		}
		return s
	}
	bold := none.with(ansi.AttrBold)
	return theme{
		border:     fg(none, ansi.AttrBrightBlackForegroundColor),
		title:      bold,
		focusTitle: fg(bold, ansi.AttrBrightBlueForegroundColor),
		group:      bold,
		selected:   none.with(ansi.AttrReverse),
		online:     fg(none, ansi.AttrBrightGreenForegroundColor),
		away:       fg(none, ansi.AttrBrightYellowForegroundColor),
		offline:    fg(none.with(ansi.AttrFaint), ansi.AttrBrightBlackForegroundColor),
		unverified: fg(none.with(ansi.AttrItalic), ansi.AttrBrightYellowForegroundColor),
		warn:       fg(bold, ansi.AttrBrightYellowForegroundColor),
		errStyle:   fg(bold, ansi.AttrBrightRedForegroundColor),
		dim:        none.with(ansi.AttrFaint),
		bold:       bold,
		me:         fg(bold, ansi.AttrBrightBlueForegroundColor),
		them:       fg(bold, ansi.AttrBrightRedForegroundColor),
		key:        bold,
	}
}

// render styles text, which must already be safe (cleaned) and hold no
// styling of its own.
func (t theme) render(s style, text string) string {
	if text == "" || len(s) == 0 {
		return text
	}
	return ansi.Style(s).Styled(text)
}
