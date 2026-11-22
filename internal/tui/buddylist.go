package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/x/ansi"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/termtext"
)

// The buddy list (design §11.2): the user's groups, each showing who in it
// is online, then an "Offline" group holding everyone signed off, the way
// AIM did. Groups collapse and expand.

const (
	defaultGroup = "Buddies"
	// offlineGroup keys the synthetic Offline group; the NUL keeps it apart
	// from a user group that happens to be called "Offline".
	offlineGroup = "\x00offline"
)

type group struct {
	key     string // the group name, or offlineGroup
	name    string // raw; cleaned when drawn
	buddies []*pb.Buddy
	online  int // buddies of the group who are on (not offline)
	total   int
}

// row is one line of the buddy list: a group header or a buddy.
type row struct {
	key   string // groupRow(...) or buddyRow(...)
	group *group
	buddy *pb.Buddy
}

func groupRow(key string) string { return "g:" + key }
func buddyRow(key string) string { return "b:" + key }

func isOffline(b *pb.Buddy) bool {
	switch b.GetPresence().GetState() {
	case pb.PresenceState_PRESENCE_STATE_ONLINE, pb.PresenceState_PRESENCE_STATE_AWAY:
		return b.GetState() == pb.BuddyState_BUDDY_STATE_BLOCKED
	}
	return true
}

func groupOf(b *pb.Buddy) string {
	if b.GetGroup() == "" {
		return defaultGroup
	}
	return b.GetGroup()
}

// groups lays the buddies out: "Buddies" first, the other groups by name,
// then Offline. A group with nobody online still shows, with its count.
func (m *Model) groups() []*group {
	byKey := map[string]*group{}
	var order []*group
	get := func(key, name string) *group {
		g, ok := byKey[key]
		if !ok {
			g = &group{key: key, name: name}
			byKey[key] = g
			order = append(order, g)
		}
		return g
	}
	off := &group{key: offlineGroup, name: "Offline"}
	for _, b := range sortedBuddies(m.buddies) {
		g := get(groupOf(b), groupOf(b))
		g.total++
		if isOffline(b) {
			off.buddies = append(off.buddies, b)
			off.total++
			continue
		}
		g.online++
		g.buddies = append(g.buddies, b)
	}
	if _, ok := byKey[defaultGroup]; !ok {
		get(defaultGroup, defaultGroup)
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i].key, order[j].key
		if (a == defaultGroup) != (b == defaultGroup) {
			return a == defaultGroup
		}
		return strings.ToLower(a) < strings.ToLower(b)
	})
	return append(order, off)
}

// rows is the visible buddy list, top to bottom.
func (m *Model) rows() []row {
	var rs []row
	for _, g := range m.groups() {
		rs = append(rs, row{key: groupRow(g.key), group: g})
		if m.collapsed[g.key] {
			continue
		}
		for _, b := range g.buddies {
			rs = append(rs, row{key: buddyRow(b.GetIdentityKey()), group: g, buddy: b})
		}
	}
	return rs
}

// fixCursor keeps the selection on a row that exists: the same row if it
// is still there, else the buddy's group, else the top.
func (m *Model) fixCursor() {
	rs := m.rows()
	for _, r := range rs {
		if r.key == m.cursor {
			return
		}
	}
	if k, ok := strings.CutPrefix(m.cursor, "b:"); ok {
		if b, ok := m.buddies[k]; ok {
			g := groupOf(b)
			if isOffline(b) {
				g = offlineGroup
			}
			m.cursor = groupRow(g)
			return
		}
	}
	// The first buddy if there is one, else the first group.
	for _, r := range rs {
		if r.buddy != nil {
			m.cursor = r.key
			return
		}
	}
	if len(rs) > 0 {
		m.cursor = rs[0].key
	}
}

func (m *Model) cursorIndex(rs []row) int {
	for i, r := range rs {
		if r.key == m.cursor {
			return i
		}
	}
	return 0
}

func (m *Model) selectedRow() (row, bool) {
	rs := m.rows()
	if len(rs) == 0 {
		return row{}, false
	}
	return rs[m.cursorIndex(rs)], true
}

func (m *Model) selectedBuddy() *pb.Buddy {
	r, ok := m.selectedRow()
	if !ok {
		return nil
	}
	return r.buddy
}

func (m *Model) moveCursor(delta int) {
	rs := m.rows()
	if len(rs) == 0 {
		return
	}
	i := min(max(m.cursorIndex(rs)+delta, 0), len(rs)-1)
	m.cursor = rs[i].key
}

// displayName is what the list calls a buddy (raw; clean before drawing):
// the petname, else the handle, else the key ID.
func displayName(b *pb.Buddy) string {
	switch {
	case b.GetPetname() != "":
		return b.GetPetname()
	case b.GetHandle() != "":
		return b.GetHandle()
	}
	return b.GetKeyId()
}

// buddyLabel is a buddy's name for the screen, cleaned. Unverified contacts
// always show their key ID beside the name, behind a ⚠ badge (§5.3).
func buddyLabel(b *pb.Buddy) string {
	name := termtext.Clean(displayName(b))
	if b.GetVerified() {
		return name
	}
	id := termtext.Clean(b.GetKeyId())
	if name == id {
		return "⚠ " + id
	}
	return "⚠ " + id + " " + name
}

// buddyNotes are the words after a name in the list: away, pending,
// blocked.
func buddyNotes(b *pb.Buddy) string {
	var notes []string
	switch b.GetState() {
	case pb.BuddyState_BUDDY_STATE_PENDING_OUT:
		notes = append(notes, "pending")
	case pb.BuddyState_BUDDY_STATE_PENDING_IN:
		notes = append(notes, "wants to add you")
	case pb.BuddyState_BUDDY_STATE_BLOCKED:
		notes = append(notes, "blocked")
	}
	if b.GetPresence().GetState() == pb.PresenceState_PRESENCE_STATE_AWAY {
		notes = append(notes, "away")
	}
	if len(notes) == 0 {
		return ""
	}
	return "(" + strings.Join(notes, ", ") + ")"
}

// listLines renders the buddy list body in width columns and height rows,
// scrolled to keep the selection in view.
func (m *Model) listLines(width, height int) []string {
	rs := m.rows()
	cur := m.cursorIndex(rs)
	top := 0
	if cur >= height {
		top = cur - height + 1
	}
	var lines []string
	for i := top; i < len(rs) && len(lines) < height; i++ {
		lines = append(lines, m.rowLine(rs[i], i == cur, width))
	}
	if len(m.buddies) == 0 && len(lines) < height-2 {
		lines = append(lines, "", m.th.render(m.th.dim, " No buddies yet."), m.th.render(m.th.dim, " Ctrl+B adds one."))
	}
	return lines
}

func (m *Model) rowLine(r row, selected bool, width int) string {
	t := m.th
	mark := " "
	if selected {
		mark = ">"
	}
	var text string
	if r.buddy == nil {
		arrow := "▾"
		if m.collapsed[r.group.key] {
			arrow = "▸"
		}
		var count string
		if r.group.key == offlineGroup {
			count = fmt.Sprintf("(%d)", r.group.total)
		} else {
			count = fmt.Sprintf("(%d/%d)", r.group.online, r.group.total)
		}
		text = t.render(t.group, arrow+" "+termtext.Clean(r.group.name)) + " " + t.render(t.dim, count)
		if selected && m.focus == focusList && m.dlg == nil {
			text = t.render(t.selected, arrow+" "+termtext.Clean(r.group.name)+" "+count)
		}
		return truncate(mark+text, width)
	}
	b := r.buddy
	label := buddyLabel(b)
	st := t.online
	switch {
	case !b.GetVerified():
		st = t.unverified
	case b.GetPresence().GetState() == pb.PresenceState_PRESENCE_STATE_AWAY:
		st = t.away
	case isOffline(b):
		st = t.offline
	}
	if selected && m.focus == focusList && m.dlg == nil {
		st = st.with(ansi.AttrReverse)
	}
	if b.GetIdentityKey() == m.open {
		st = st.with(ansi.AttrBold)
	}
	text = "  " + t.render(st, label)
	if n := buddyNotes(b); n != "" {
		text += " " + t.render(t.dim, n)
	}
	if n := m.unread[b.GetIdentityKey()]; n > 0 {
		text += " " + t.render(t.warn, fmt.Sprintf("[%d new]", n))
	}
	return truncate(mark+text, width)
}
