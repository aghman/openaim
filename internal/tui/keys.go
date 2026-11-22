package tui

import (
	tea "charm.land/bubbletea/v2"

	pb "github.com/aghman/openaim/internal/apipb"
)

// key handles one key press.
func (m *Model) key(k tea.KeyPressMsg) tea.Cmd {
	s := k.String()
	if s == "ctrl+c" {
		return tea.Quit
	}
	m.notice = "" // a notice lasts until the next key
	if m.conn != connUp {
		switch s {
		case "q", "esc":
			return tea.Quit
		case "r":
			if m.conn == connDown && !m.trying {
				m.attempt = 0
				return m.connect()
			}
		}
		return nil
	}
	if m.dlg != nil {
		return m.dialogKey(k)
	}

	switch s {
	case "tab", "shift+tab":
		if m.focus == focusIM {
			m.toList()
			return nil
		}
		if m.open != "" {
			m.focus = focusIM
			return nil
		}
		if b := m.selectedBuddy(); b != nil {
			return m.openConv(b.GetIdentityKey())
		}
		m.setNotice("Pick a buddy and press Enter to open an IM.")
		return nil
	case "ctrl+n":
		m.openDialog(dlgNewIM)
		return nil
	case "ctrl+a":
		if m.away() {
			return m.setPresence(pb.PresenceState_PRESENCE_STATE_ONLINE, "")
		}
		m.openDialog(dlgAway)
		return nil
	case "ctrl+b":
		m.openDialog(dlgAdd)
		return nil
	case "f1":
		m.openDialog(dlgHelp)
		return nil
	case "pgup", "pgdown":
		if c := m.convs[m.open]; c != nil {
			step := max(m.historyHeight()/2, 1)
			if s == "pgup" {
				c.scroll += step
			} else {
				c.scroll = max(c.scroll-step, 0)
			}
		}
		return nil
	}

	if m.focus == focusIM {
		return m.imKey(k)
	}
	return m.listKey(k)
}

// toList moves the focus to the buddy list, onto the open buddy.
func (m *Model) toList() {
	m.focus = focusList
	if m.open != "" {
		m.cursor = buddyRow(m.open)
	}
	m.fixCursor()
}

func (m *Model) imKey(k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "enter":
		return m.send()
	case "esc":
		m.toList()
		return nil
	case "up":
		if c := m.convs[m.open]; c != nil {
			c.scroll++
		}
		return nil
	case "down":
		if c := m.convs[m.open]; c != nil {
			c.scroll = max(c.scroll-1, 0)
		}
		return nil
	}
	m.input.Update(k)
	return nil
}

func (m *Model) listKey(k tea.KeyPressMsg) tea.Cmd {
	r, ok := m.selectedRow()
	switch k.String() {
	case "q":
		return tea.Quit
	case "?":
		m.openDialog(dlgHelp)
	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "home", "g":
		m.moveCursor(-1 << 20)
	case "end", "G":
		m.moveCursor(1 << 20)
	case "enter", "space":
		switch {
		case !ok:
		case r.buddy != nil && k.String() == "enter":
			return m.openConv(r.buddy.GetIdentityKey())
		case r.buddy == nil:
			m.collapsed[r.group.key] = !m.collapsed[r.group.key]
		}
	case "left", "h":
		if ok {
			m.collapsed[r.group.key] = true
			m.cursor = groupRow(r.group.key)
		}
	case "right", "l":
		if ok && r.buddy == nil {
			m.collapsed[r.group.key] = false
		}
	case "a":
		m.openDialog(dlgAdd)
	case "v":
		if ok && r.buddy != nil {
			return m.openVerify(r.buddy)
		}
	case "x", "delete":
		if ok && r.buddy != nil {
			m.dlg = &dialog{kind: dlgRemove, target: r.buddy.GetIdentityKey()}
		}
	case "esc":
		if m.open != "" {
			m.focus = focusIM
		}
	}
	return nil
}

// paste inserts pasted text into the field that has the cursor, if any.
func (m *Model) paste(text string) {
	switch {
	case m.conn != connUp:
	case m.dlg != nil:
		if len(m.dlg.fields) > 0 && !m.dlg.busy {
			m.dlg.fields[m.dlg.focus].edit.Insert(text)
			m.dlg.err = ""
		}
	case m.focus == focusIM && m.open != "":
		m.input.Insert(text)
	}
}
