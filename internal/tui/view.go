package tui

import (
	"errors"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/aghman/openaim/internal/termtext"
)

// Layout (design §11.2):
//
//	┌ Buddy List ──────┐┌ SkaterDude99 · ~k3f9 · online ──────────────┐
//	│ ▾ Buddies (1/3)  ││ [13:02] SkaterDude99: you going friday?     │
//	│>  SkaterDude99   ││ [13:03] me: yeah if my radio reaches  [queued]
//	│ ▸ Offline (2)    │├─────────────────────────────────────────────┤
//	│                  ││ > _                    159 bytes left (1/4) │
//	└──────────────────┘└─────────────────────────────────────────────┘
//	 [Tab] switch  [Ctrl+N] new IM  [Ctrl+A] away  [?] help

const (
	minWidth  = 40
	minHeight = 10
)

// cell is a position on the screen (or within a box's body).
type cell struct{ row, col int }

// View draws the screen on the alternate screen, with the terminal's
// cursor in the field being typed into.
func (m *Model) View() tea.View {
	content, cur := m.screen()
	v := tea.NewView(content)
	v.AltScreen = true
	v.WindowTitle = "OpenAIM"
	if cur != nil {
		v.Cursor = tea.NewCursor(cur.col, cur.row)
		v.Cursor.Blink = false
	}
	return v
}

// screen is the screen's text and where its cursor goes (nil: hidden).
func (m *Model) screen() (string, *cell) {
	if m.width == 0 || m.height == 0 {
		return "", nil
	}
	if m.width < minWidth || m.height < minHeight {
		return "The terminal is too small for openaim tui (needs 40×10).", nil
	}
	if m.conn != connUp {
		return m.downView(), nil
	}
	mainH := m.height - 1
	listW := m.listWidth()
	imW := m.width - listW
	var cur *cell

	listTitle := "Buddy List"
	if m.focus == focusList && m.dlg == nil {
		listTitle = m.th.render(m.th.focusTitle, listTitle)
	} else {
		listTitle = m.th.render(m.th.title, listTitle)
	}
	left := m.box(listTitle, listW, mainH, m.listLines(listW-2, mainH-2), -1)

	var right []string
	switch {
	case m.dlg != nil:
		title := m.th.render(m.th.focusTitle, m.dialogTitle())
		lines, c := m.dialogLines(imW - 2)
		right = m.box(title, imW, mainH, lines, -1)
		if c != nil && c.row < mainH-2 && c.col < imW-2 {
			cur = &cell{row: 1 + c.row, col: listW + 1 + c.col}
		}
	case m.open != "" && m.buddies[m.open] != nil:
		histH := m.historyHeight()
		body, hidden := m.convLines(imW-2, histH)
		// Newest at the bottom: pad above.
		lines := make([]string, histH-len(body), histH+2)
		lines = append(lines, body...)
		input, col := m.inputLine(imW - 2)
		lines = append(lines, "", input)
		if col >= 0 {
			cur = &cell{row: 1 + histH + 1, col: listW + 1 + col}
		}
		title := m.convTitle(m.buddies[m.open])
		if m.focus == focusIM {
			title = "» " + title
		}
		right = m.box(title, imW, mainH, lines, histH)
		if hidden > 0 {
			right[histH+1] = m.th.render(m.th.border, "├"+center(" ↓ "+strconv.Itoa(hidden)+" more (PgDn) ", imW-2, "─")+"┤")
		}
	default:
		histH := m.historyHeight()
		lines := make([]string, histH, histH+2)
		hint := []string{
			"Pick a buddy and press Enter to open an IM,",
			"or press Ctrl+N and type a name.",
		}
		if len(m.buddies) == 0 {
			hint = []string{"Your buddy list is empty.", "Press Ctrl+B to add a buddy by identity key."}
		}
		for i, h := range hint {
			if j := histH/2 - 1 + i; j >= 0 && j < histH {
				lines[j] = center(m.th.render(m.th.dim, h), imW-2, " ")
			}
		}
		input, _ := m.inputLine(imW - 2)
		lines = append(lines, "", input)
		right = m.box(m.th.render(m.th.title, "IM"), imW, mainH, lines, histH)
	}

	var b strings.Builder
	for i := range mainH {
		b.WriteString(left[i])
		b.WriteString(right[i])
		b.WriteByte('\n')
	}
	b.WriteString(m.statusBar())
	return b.String(), cur
}

func (m *Model) listWidth() int {
	return min(max(m.width/3, 22), 34)
}

// historyHeight is how many rows the conversation gets: the IM box less
// its borders, the separator and the input line.
func (m *Model) historyHeight() int { return max(m.height-1-2-2, 1) }

// box draws a bordered box of exactly width × height cells. title is
// already safe. If sep >= 0, the body line at that index becomes a
// horizontal divider.
func (m *Model) box(title string, width, height int, body []string, sep int) []string {
	bs := func(s string) string { return m.th.render(m.th.border, s) }
	inner := width - 2
	out := make([]string, 0, height)
	t := truncate(title, max(inner-3, 1))
	fill := inner - 2 - ansi.StringWidth(t)
	out = append(out, bs("┌ ")+t+bs(" "+strings.Repeat("─", max(fill, 0))+"┐"))
	for i := range height - 2 {
		if i == sep {
			out = append(out, bs("├"+strings.Repeat("─", inner)+"┤"))
			continue
		}
		line := ""
		if i < len(body) {
			line = body[i]
		}
		out = append(out, bs("│")+pad(truncate(line, inner), inner)+bs("│"))
	}
	out = append(out, bs("└"+strings.Repeat("─", inner)+"┘"))
	return out
}

func (m *Model) statusBar() string {
	t := m.th
	var left string
	if m.notice != "" {
		st := t.bold
		if m.noticeErr {
			st = t.errStyle
		}
		left = " " + t.render(st, termtext.Clean(m.notice))
	} else {
		hint := func(k, what string) string { return t.render(t.key, "["+k+"]") + " " + what }
		help := hint("?", "help")
		if m.focus == focusIM || m.dlg != nil {
			help = hint("F1", "help")
		}
		awayHint := hint("Ctrl+A", "away")
		if m.away() {
			awayHint = hint("Ctrl+A", "back")
		}
		left = " " + strings.Join([]string{hint("Tab", "switch"), hint("Ctrl+N", "new IM"), awayHint, hint("Ctrl+B", "add buddy"), help}, "  ")
	}
	me := termtext.Clean(m.status.GetKeyId())
	right := t.render(t.online, "online")
	if m.away() {
		right = t.render(t.away, "away")
	}
	right = me + " " + right + " "
	space := m.width - ansi.StringWidth(right)
	return pad(truncate(left, max(space-1, 1)), space) + right
}

// downView is the whole screen while the daemon can't be reached.
func (m *Model) downView() string {
	t := m.th
	var lines []string
	add := func(s ...string) { lines = append(lines, s...) }
	add(t.render(t.title, "OpenAIM"), "")
	switch {
	case m.conn == connConnecting && m.everUp:
		add("Reconnecting to openaimd…")
	case m.conn == connConnecting:
		add("Connecting to openaimd…")
	case IsNotRunning(m.downErr) && m.opt.Embedded:
		add(t.render(t.errStyle, "The embedded openaimd stopped."), "",
			"Quit and start openaim tui again.")
	case IsNotRunning(m.downErr):
		if m.everUp {
			add(t.render(t.errStyle, "Lost the connection to openaimd."))
		} else {
			add(t.render(t.errStyle, "openaimd is not running."))
		}
		var nr *NotRunningError
		if errors.As(m.downErr, &nr) {
			add(t.render(t.dim, "("+termtext.Clean(nr.Reason)+")"))
		}
		add("", "Start it with `openaimd run` in another terminal,",
			"or quit and run `openaim tui --embedded` to run one inside the TUI.")
	default:
		if m.everUp {
			add(t.render(t.errStyle, "Lost the connection to openaimd:"))
		} else {
			add(t.render(t.errStyle, "Can't talk to openaimd:"))
		}
		add(termtext.Clean(errText(m.downErr)))
	}
	add("")
	switch {
	case m.conn == connConnecting:
	case m.trying:
		add(t.render(t.dim, "Trying again…   [q] quit"))
	default:
		add(t.render(t.dim, "Retrying in "+m.retryIn.Round(100_000_000).String()+".   [r] retry now   [q] quit"))
	}

	top := max((m.height-len(lines))/2, 0)
	var b strings.Builder
	for i := range m.height {
		line := ""
		if j := i - top; j >= 0 && j < len(lines) {
			line = center(truncate(lines[j], m.width), m.width, " ")
		}
		b.WriteString(pad(line, m.width))
		if i < m.height-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// truncate cuts s (which may hold our own styling) to width columns.
func truncate(s string, width int) string {
	if ansi.StringWidth(s) <= width {
		return s
	}
	return ansi.Truncate(s, width, "…")
}

// pad fills s with spaces to width columns.
func pad(s string, width int) string {
	if w := ansi.StringWidth(s); w < width {
		return s + strings.Repeat(" ", width-w)
	}
	return s
}

// center places s in the middle of width columns, filling with fill.
func center(s string, width int, fill string) string {
	w := ansi.StringWidth(s)
	if w >= width {
		return s
	}
	l := (width - w) / 2
	return strings.Repeat(fill, l) + s + strings.Repeat(fill, width-w-l)
}
