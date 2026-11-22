package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/termtext"
)

// The route-capacity counter (design §8.3, §8.4). Every IM is sealed in the
// mesh layout so it can take any route (M1 has no IP-only content yet):
// fragment 0 carries 159 bytes of text, each later fragment 166, and an IM
// has at most 4 fragments, 657 bytes before compression.
const (
	firstFragBytes = 159
	laterFragBytes = 166
	maxFrags       = 4
	maxIMBytes     = firstFragBytes + (maxFrags-1)*laterFragBytes // 657
)

// capacity says how many fragments n bytes of text take and how many bytes
// are left in the last one. left is negative when n doesn't fit at all.
func capacity(n int) (frags, left int) {
	if n <= firstFragBytes {
		return 1, firstFragBytes - n
	}
	frags = 1 + (n-firstFragBytes+laterFragBytes-1)/laterFragBytes
	if frags > maxFrags {
		return maxFrags, maxIMBytes - n
	}
	return frags, firstFragBytes + (frags-1)*laterFragBytes - n
}

// counterText is "159 bytes left (1/4)", or "12 bytes over (max 657)".
func counterText(n int) string {
	frags, left := capacity(n)
	if left < 0 {
		return fmt.Sprintf("%d %s over (max %d)", -left, plural(-left, "byte"), maxIMBytes)
	}
	return fmt.Sprintf("%d %s left (%d/%d)", left, plural(left, "byte"), frags, maxFrags)
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// fmtWhen is a message time: "15:04" today, else "Jan 02 15:04".
func fmtWhen(t, now time.Time) string {
	t, now = t.Local(), now.Local()
	if t.Year() == now.Year() && t.YearDay() == now.YearDay() {
		return t.Format("15:04")
	}
	return t.Format("Jan 02 15:04")
}

func deliveryMark(d pb.DeliveryState) string {
	switch d {
	case pb.DeliveryState_DELIVERY_STATE_QUEUED:
		return "[queued]"
	case pb.DeliveryState_DELIVERY_STATE_ACKED:
		return "[delivered]"
	case pb.DeliveryState_DELIVERY_STATE_FAILED:
		return "[failed]"
	}
	return ""
}

// messageLines renders one IM, wrapped to width:
//
//	[13:02] SkaterDude99: you going to the lan party friday?
//	[13:03] me: yeah if my radio reaches lol  [queued]
//
// Continuation lines are indented under the text.
func (m *Model) messageLines(msg *pb.Message, width int) []string {
	t := m.th
	out := msg.GetDirection() == pb.Direction_DIRECTION_OUTGOING
	who, whoStyle := "me", t.me
	if !out {
		who, whoStyle = m.nameFor(msg.GetBuddyKey()), t.them
	}
	when := "--:--"
	if ts := msg.GetSentAt(); ts != nil {
		when = fmtWhen(ts.AsTime(), m.opt.Now())
	}
	stamp := "[" + when + "] "
	head := t.render(t.dim, stamp) + t.render(whoStyle, who+":") + " "
	indent := ansi.StringWidth(stamp) + ansi.StringWidth(who) + 2
	if width-indent < 12 {
		indent = 2
	}
	textWidth := max(width-indent, 1)
	firstWidth := max(width-ansi.StringWidth(stamp+who+": "), 1)

	var lines []string
	for i, para := range termtext.Lines(msg.GetText()) {
		w := textWidth
		if i == 0 {
			w = firstWidth
		}
		wrapped := strings.Split(ansi.Wrap(para, w, " -"), "\n")
		if i == 0 && len(wrapped) > 1 && firstWidth != textWidth {
			// Re-wrap the rest of the first paragraph at the indented width.
			rest := strings.TrimLeft(strings.Join(wrapped[1:], " "), " ")
			wrapped = append(wrapped[:1], strings.Split(ansi.Wrap(rest, textWidth, " -"), "\n")...)
		}
		lines = append(lines, wrapped...)
	}
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " ")
		if i == 0 {
			lines[i] = head + lines[i]
		} else {
			lines[i] = strings.Repeat(" ", indent) + lines[i]
		}
	}
	if mark := deliveryMark(msg.GetDelivery()); out && mark != "" {
		st := t.dim
		if msg.GetDelivery() == pb.DeliveryState_DELIVERY_STATE_FAILED {
			st = t.errStyle
		}
		last := len(lines) - 1
		if ansi.StringWidth(lines[last])+2+len(mark) <= width {
			lines[last] += "  " + t.render(st, mark)
		} else {
			lines = append(lines, strings.Repeat(" ", max(width-len(mark), 0))+t.render(st, mark))
		}
	}
	return lines
}

// nameFor is a buddy's display name by identity key, cleaned.
func (m *Model) nameFor(key string) string {
	if b, ok := m.buddies[key]; ok {
		return termtext.Clean(displayName(b))
	}
	if len(key) > 8 {
		key = key[:8] + "…"
	}
	return termtext.Clean(key)
}

// convLines renders the open conversation's history into height rows of
// width columns, newest at the bottom, honoring the scroll offset. It
// returns how many lines are hidden below.
func (m *Model) convLines(width, height int) ([]string, int) {
	c := m.convs[m.open]
	if c == nil || (!c.loaded && len(c.msgs) == 0) {
		if c != nil && c.loading {
			return []string{m.th.render(m.th.dim, "Loading history…")}, 0
		}
		return nil, 0
	}
	if len(c.msgs) == 0 {
		b := m.buddies[m.open]
		return []string{m.th.render(m.th.dim, "No messages yet with "+termtext.Clean(displayName(b))+". Say hi!")}, 0
	}
	var all []string
	for _, msg := range c.msgs {
		all = append(all, m.messageLines(msg, width)...)
	}
	maxScroll := max(len(all)-height, 0)
	c.scroll = min(c.scroll, maxScroll)
	end := len(all) - c.scroll
	start := max(end-height, 0)
	return all[start:end], c.scroll
}

// convTitle is the IM window's title: name, key ID, presence, and a
// warning for unverified contacts.
func (m *Model) convTitle(b *pb.Buddy) string {
	t := m.th
	parts := []string{t.render(t.title, termtext.Clean(displayName(b)))}
	if displayName(b) != b.GetKeyId() {
		parts = append(parts, t.render(t.dim, termtext.Clean(b.GetKeyId())))
	}
	parts = append(parts, presenceWord(b.GetPresence()))
	if n := buddyNotes(b); n != "" && b.GetState() != pb.BuddyState_BUDDY_STATE_ACCEPTED {
		parts = append(parts, strings.Trim(n, "()"))
	}
	if !b.GetVerified() {
		parts = append(parts, t.render(t.unverified, "⚠ unverified"))
	}
	return strings.Join(parts, " · ")
}

func presenceWord(p *pb.Presence) string {
	switch p.GetState() {
	case pb.PresenceState_PRESENCE_STATE_ONLINE:
		return "online"
	case pb.PresenceState_PRESENCE_STATE_AWAY:
		if p.GetAwayMessage() != "" {
			return "away: " + termtext.Clean(p.GetAwayMessage())
		}
		return "away"
	}
	return "offline"
}

// inputLine is the IM input with the counter on the right. It also returns
// the cursor's column, or -1 when the input doesn't have the focus.
func (m *Model) inputLine(width int) (string, int) {
	t := m.th
	if m.open == "" {
		return t.render(t.dim, "> "), -1
	}
	n := len(m.input.Value())
	counter := counterText(n)
	_, left := capacity(n)
	switch {
	case left < 0:
		counter = t.render(t.errStyle, counter)
	case left <= 20 && n > 0:
		counter = t.render(t.warn, counter)
	default:
		counter = t.render(t.dim, counter)
	}
	fieldW := width - 2 - ansi.StringWidth(counter) - 2
	if fieldW < 8 {
		fieldW, counter = max(width-2, 1), "" // too narrow for both: the field wins
	}
	field, col := m.input.View(fieldW)
	if m.focus != focusIM || m.dlg != nil {
		col = -1
	} else {
		col += 2
	}
	if counter == "" {
		return "> " + field, col
	}
	return "> " + pad(field, fieldW) + "  " + counter, col
}
