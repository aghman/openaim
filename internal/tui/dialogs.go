package tui

import (
	"context"
	"strings"

	tea "charm.land/bubbletea/v2"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/termtext"
)

// Dialogs take over the IM window while open: away message, add buddy,
// new IM, verify (safety number), remove, and help.

type dialogKind int

const (
	dlgHelp dialogKind = iota + 1
	dlgAway
	dlgAdd
	dlgNewIM
	dlgVerify
	dlgRemove
)

type field struct {
	label       string
	placeholder string
	edit        lineEdit
}

type dialog struct {
	kind   dialogKind
	fields []*field
	focus  int    // field with the cursor
	pick   int    // new IM: selected match
	target string // identity key of the buddy it is about
	sn     *pb.SafetyNumber
	err    string // raw; cleaned when drawn
	busy   bool
}

const defaultAway = "I am away from my computer right now."

func (m *Model) openDialog(kind dialogKind) {
	d := &dialog{kind: kind}
	switch kind {
	case dlgAway:
		msg := m.lastAway
		if msg == "" {
			msg = m.presence.GetAwayMessage()
		}
		if msg == "" {
			msg = defaultAway
		}
		f := &field{label: "Away message"}
		f.edit.limit = 1024
		f.edit.SetValue(msg)
		d.fields = []*field{f}
	case dlgAdd:
		d.fields = []*field{
			{label: "Identity key", placeholder: "base32 key from their invite"},
			{label: "Petname", placeholder: "optional"},
			{label: "Group", placeholder: defaultGroup},
		}
		for _, f := range d.fields {
			f.edit.limit = 256
		}
	case dlgNewIM:
		f := &field{label: "To", placeholder: "petname, handle or key ID"}
		f.edit.limit = 256
		d.fields = []*field{f}
	}
	m.dlg = d
}

// dialogKey handles a key while a dialog is open.
func (m *Model) dialogKey(k tea.KeyPressMsg) tea.Cmd {
	d := m.dlg
	if k.String() == "esc" {
		m.dlg = nil
		return nil
	}
	switch d.kind {
	case dlgHelp:
		m.dlg = nil
		return nil
	case dlgVerify:
		return m.verifyKey(k)
	case dlgRemove:
		if s := strings.ToLower(k.String()); s == "y" {
			m.dlg = nil
			return m.removeCmd(d.target)
		}
		if k.String() == "enter" || strings.ToLower(k.String()) == "n" {
			m.dlg = nil
		}
		return nil
	}
	if d.busy {
		return nil
	}
	switch k.String() {
	case "enter":
		return m.submitDialog()
	case "tab", "down":
		if d.kind == dlgNewIM {
			d.pick = min(d.pick+1, max(len(m.matches(d.fields[0].edit.Value()))-1, 0))
		} else {
			d.focus = (d.focus + 1) % len(d.fields)
		}
		return nil
	case "shift+tab", "up":
		if d.kind == dlgNewIM {
			d.pick = max(d.pick-1, 0)
		} else {
			d.focus = (d.focus + len(d.fields) - 1) % len(d.fields)
		}
		return nil
	}
	if d.fields[d.focus].edit.Update(k) {
		d.err = ""
		if d.kind == dlgNewIM {
			d.pick = 0
		}
	}
	return nil
}

func (m *Model) submitDialog() tea.Cmd {
	d := m.dlg
	cl, gen := m.client, m.gen
	switch d.kind {
	case dlgAway:
		msg := strings.TrimSpace(d.fields[0].edit.Value())
		if msg == "" {
			msg = defaultAway
		}
		m.lastAway = msg
		m.dlg = nil
		return m.setPresence(pb.PresenceState_PRESENCE_STATE_AWAY, msg)
	case dlgAdd:
		key := strings.TrimSpace(d.fields[0].edit.Value())
		if key == "" {
			d.err = "enter the buddy's identity key"
			d.focus = 0
			return nil
		}
		req := &pb.AddBuddyRequest{
			IdentityKey: strings.ToLower(key),
			Petname:     strings.TrimSpace(d.fields[1].edit.Value()),
			Group:       strings.TrimSpace(d.fields[2].edit.Value()),
		}
		d.busy = true
		return func() tea.Msg {
			ctx, cancel := withTimeout(context.Background())
			defer cancel()
			b, err := cl.AddBuddy(ctx, req)
			return addedMsg{gen, b, err}
		}
	case dlgNewIM:
		ms := m.matches(d.fields[0].edit.Value())
		if len(ms) == 0 {
			d.err = "no buddy by that name; Ctrl+B adds one"
			return nil
		}
		b := ms[min(d.pick, len(ms)-1)]
		m.dlg = nil
		return m.openConv(b.GetIdentityKey())
	}
	return nil
}

// matches are the buddies a new-IM query names, best first: exact matches
// on key ID, petname or handle, then prefixes, then substrings. An empty
// query lists everyone.
func (m *Model) matches(q string) []*pb.Buddy {
	q = strings.ToLower(strings.TrimSpace(q))
	all := sortedBuddies(m.buddies)
	if q == "" {
		return all
	}
	var exact, prefix, sub []*pb.Buddy
	for _, b := range all {
		names := []string{strings.ToLower(b.GetPetname()), strings.ToLower(b.GetHandle()), strings.ToLower(b.GetKeyId()), strings.ToLower(b.GetIdentityKey())}
		best := 0
		for _, n := range names {
			switch {
			case n == "":
			case n == q:
				best = max(best, 3)
			case strings.HasPrefix(n, q):
				best = max(best, 2)
			case strings.Contains(n, q):
				best = max(best, 1)
			}
		}
		switch best {
		case 3:
			exact = append(exact, b)
		case 2:
			prefix = append(prefix, b)
		case 1:
			sub = append(sub, b)
		}
	}
	return append(append(exact, prefix...), sub...)
}

// openVerify shows the safety number with a buddy.
func (m *Model) openVerify(b *pb.Buddy) tea.Cmd {
	key := b.GetIdentityKey()
	m.dlg = &dialog{kind: dlgVerify, target: key, busy: true}
	cl, gen := m.client, m.gen
	return func() tea.Msg {
		ctx, cancel := withTimeout(context.Background())
		defer cancel()
		sn, err := cl.GetSafetyNumber(ctx, key)
		return safetyMsg{gen, key, sn, err}
	}
}

func (m *Model) verifyKey(k tea.KeyPressMsg) tea.Cmd {
	d := m.dlg
	b := m.buddies[d.target]
	if b == nil {
		m.dlg = nil
		return nil
	}
	s := strings.ToLower(k.String())
	switch {
	case s == "n" || s == "q":
		m.dlg = nil
		return nil
	case d.busy || d.sn == nil:
		return nil
	case s == "y" && !b.GetVerified(), s == "u" && b.GetVerified():
		d.busy = true
		cl, gen, key, verified := m.client, m.gen, d.target, s == "y"
		return func() tea.Msg {
			ctx, cancel := withTimeout(context.Background())
			defer cancel()
			nb, err := cl.SetBuddyVerified(ctx, key, verified)
			return verifiedMsg{gen, nb, err}
		}
	}
	return nil
}

func (m *Model) removeCmd(key string) tea.Cmd {
	b := m.buddies[key]
	if b == nil {
		return nil
	}
	name := termtext.Clean(displayName(b))
	cl, gen := m.client, m.gen
	return func() tea.Msg {
		ctx, cancel := withTimeout(context.Background())
		defer cancel()
		err := cl.RemoveBuddy(ctx, key)
		return removedMsg{gen, key, name, err}
	}
}

// safetyGroups lays a safety number out as two rows of four groups of five
// digits. Anything else comes back cleaned, as it was.
func safetyGroups(sn string) []string {
	var digits strings.Builder
	for _, r := range sn {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r == ' ' || r == '-':
		default:
			return []string{termtext.Clean(sn)}
		}
	}
	d := digits.String()
	if len(d) != 40 {
		return []string{termtext.Clean(sn)}
	}
	var groups []string
	for i := 0; i < 40; i += 5 {
		groups = append(groups, d[i:i+5])
	}
	return []string{strings.Join(groups[:4], "  "), strings.Join(groups[4:], "  ")}
}

// dialogTitle and dialogLines render the open dialog for the right pane.
func (m *Model) dialogTitle() string {
	switch m.dlg.kind {
	case dlgHelp:
		return "Help"
	case dlgAway:
		return "Set away message"
	case dlgAdd:
		return "Add a buddy"
	case dlgNewIM:
		return "New IM"
	case dlgVerify:
		return "Verify safety number"
	case dlgRemove:
		return "Remove buddy"
	}
	return ""
}

// dialogLines also returns where the terminal cursor goes (in the focused
// field), or nil.
func (m *Model) dialogLines(width int) ([]string, *cell) {
	t := m.th
	d := m.dlg
	var lines []string
	var cur *cell
	add := func(s ...string) { lines = append(lines, s...) }
	fields := func() {
		for i, f := range d.fields {
			label := f.label + ": "
			fw := max(width-1-len(label)-1, 4)
			val, col := f.edit.View(fw)
			if f.edit.Value() == "" && f.placeholder != "" {
				val = t.render(t.dim, f.placeholder)
			}
			mark := " "
			if i == d.focus {
				mark = ">"
				if !d.busy {
					cur = &cell{row: len(lines), col: 1 + len(label) + col}
				}
			}
			add(mark + t.render(t.bold, label) + val)
		}
	}
	switch d.kind {
	case dlgHelp:
		add(helpLines...)
		add("", t.render(t.dim, "Press any key to close."))
	case dlgAway:
		add("Buddies who IM you get this reply while you're away.",
			t.render(t.dim, "%n is their name, %d the date, %t the time."), "")
		fields()
		add("", t.render(t.dim, "[Enter] go away   [Esc] cancel"))
	case dlgAdd:
		add("Add someone by the identity key in their invite.", "")
		fields()
		add("", t.render(t.dim, "[Tab] next field   [Enter] add   [Esc] cancel"))
	case dlgNewIM:
		fields()
		add("")
		ms := m.matches(d.fields[0].edit.Value())
		for i, b := range ms {
			if i >= 8 {
				add(t.render(t.dim, "  …"))
				break
			}
			mark := "  "
			label := buddyLabel(b)
			if i == d.pick {
				mark = "> "
				label = t.render(t.selected, label)
			}
			add(mark + label)
		}
		add("", t.render(t.dim, "[↑/↓] choose   [Enter] open   [Esc] cancel"))
	case dlgVerify:
		b := m.buddies[d.target]
		add("Safety number with " + termtext.Clean(displayName(b)) + " (" + termtext.Clean(b.GetKeyId()) + "):")
		add("")
		switch {
		case d.sn != nil:
			for _, l := range safetyGroups(d.sn.GetSafetyNumber()) {
				add("    " + t.render(t.bold, l))
			}
		case d.busy:
			add(t.render(t.dim, "    Loading…"))
		}
		add("", "Compare it with the number "+termtext.Clean(displayName(b))+" sees, in person",
			"or over a call you trust. If every digit matches, mark them verified.", "")
		if b.GetVerified() {
			add(t.render(t.online, "Currently: verified."))
			add("", t.render(t.dim, "[u] mark unverified   [Esc] close"))
		} else {
			add(t.render(t.unverified, "Currently: ⚠ unverified."))
			add("", t.render(t.dim, "[y] they match, mark verified   [n/Esc] not now"))
		}
	case dlgRemove:
		b := m.buddies[d.target]
		add("Remove "+buddyLabel(b)+" from your buddy list?", "",
			"This deletes your history with them and any IMs still queued.", "",
			t.render(t.dim, "[y] remove   [n/Esc] keep"))
	}
	if d.busy && d.kind != dlgVerify {
		add("", t.render(t.dim, "Working…"))
	}
	if d.err != "" {
		add("", t.render(t.errStyle, termtext.Clean(d.err)))
	}
	return lines, cur
}

var helpLines = []string{
	"Anywhere",
	"  Tab        buddy list / IM window   Ctrl+N  new IM, by name",
	"  Ctrl+A     go away, or come back    Ctrl+B  add a buddy by key",
	"  PgUp/PgDn  scroll the conversation  F1      this help",
	"  Ctrl+C     quit",
	"Buddy list",
	"  ↑/↓ k/j    move                     Enter   open an IM",
	"  Space ←/→  collapse or expand       v       verify (safety no.)",
	"  x          remove the buddy         ?  q    help, quit",
	"IM window",
	"  Enter      send                     Esc     back to the list",
	"  ↑/↓        scroll one line",
	"",
	"The counter shows the bytes left for the IM over mesh: 159 B in",
	"the first fragment, 166 B in each later one, up to 4 (657 B).",
	"⚠ marks a contact whose safety number you haven't checked; its",
	"key ID always shows beside the name.",
}
