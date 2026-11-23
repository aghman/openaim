package tui

import (
	"errors"

	tea "charm.land/bubbletea/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/termtext"
)

const (
	online  = pb.PresenceState_PRESENCE_STATE_ONLINE
	away    = pb.PresenceState_PRESENCE_STATE_AWAY
	offline = pb.PresenceState_PRESENCE_STATE_OFFLINE
)

func fourBuddies() *fake {
	f := newFake()
	bob := buddy("kbob0000", "Bob", "Family", away, true)
	bob.Presence.AwayMessage = "at class"
	f.buddies = []*pb.Buddy{
		buddy("kalice00", "Alice", "Buddies", online, true),
		bob,
		buddy("kcarol00", "Carol", "Co-Workers", offline, true),
		buddy("kdave000", "Dave", "Buddies", offline, true),
	}
	return f
}

func ev(kind any) *pb.Event {
	e := &pb.Event{}
	switch k := kind.(type) {
	case *pb.Event_BuddyAdded:
		e.Kind = k
	case *pb.Event_BuddyChanged:
		e.Kind = k
	case *pb.Event_BuddyRemoved:
		e.Kind = k
	case *pb.Event_MessageQueued:
		e.Kind = k
	case *pb.Event_MessageReceived:
		e.Kind = k
	case *pb.Event_PresenceChanged:
		e.Kind = k
	case *pb.Event_BuddyPresence:
		e.Kind = k
	case *pb.Event_MessageUpdated:
		e.Kind = k
	}
	return e
}

func incoming(id, key, text string) *pb.Message {
	return &pb.Message{MsgId: id, BuddyKey: key, Direction: pb.Direction_DIRECTION_INCOMING, Text: text, SentAt: timestamppb.New(testNow)}
}

// lineIndex is the index of the first line containing s, or -1.
func lineIndex(text, s string) int {
	return slices.IndexFunc(strings.Split(text, "\n"), func(l string) bool { return strings.Contains(l, s) })
}

func TestBuddyListGrouping(t *testing.T) {
	t.Parallel()
	h := startUp(t, fourBuddies())
	list := h.listText()
	order := []string{"▾ Buddies (1/2)", "Alice", "▾ Co-Workers (0/1)", "▾ Family (1/1)", "Bob (away)", "▾ Offline (2)", "Carol", "Dave"}
	last := -1
	for _, s := range order {
		i := lineIndex(list, s)
		if i <= last {
			t.Fatalf("%q at line %d, want after line %d:\n%s", s, i, last, list)
		}
		last = i
	}
	if !strings.Contains(list, "Buddy List") {
		t.Fatalf("no title:\n%s", list)
	}
	// The cursor starts on the first buddy.
	if l := h.line("Alice"); !strings.Contains(l, ">  Alice") {
		t.Fatalf("cursor not on Alice: %q", l)
	}

	// Collapse Offline: its buddies go, the header stays.
	h.keys("down", "down", "down", "down") // Co-Workers, Family, Bob, Offline
	if l := h.line("Offline"); !strings.Contains(l, ">▾ Offline") {
		t.Fatalf("cursor not on Offline: %q\n%s", l, h.view())
	}
	h.keys(" ")
	if l := h.line("Offline"); !strings.Contains(l, "▸ Offline (2)") || strings.Contains(h.view(), "Carol") {
		t.Fatalf("Offline didn't collapse:\n%s", h.view())
	}
	h.keys("right")
	if !strings.Contains(h.view(), "Carol") {
		t.Fatalf("Offline didn't expand:\n%s", h.view())
	}
	// ← on a buddy collapses its group and moves to the header.
	h.keys("down", "left")
	if l := h.line("Offline"); !strings.Contains(l, ">▸ Offline") {
		t.Fatalf("left didn't collapse: %q", l)
	}

	// Status bar key hints (design §11.2).
	for _, want := range []string{"[Tab] switch", "[Ctrl+N] new IM", "[Ctrl+A] away", "[?] help", "~me00 online"} {
		if !strings.Contains(h.line("[Tab]"), want) {
			t.Fatalf("status bar lacks %q: %q", want, h.line("[Tab]"))
		}
	}
}

func TestEmptyList(t *testing.T) {
	t.Parallel()
	h := startUp(t, newFake())
	h.waitView("▾ Buddies (0/0)", "▾ Offline (0)", "Ctrl+B adds one", "Your buddy list is empty.")
}

func TestSendIM(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	f.history["kalice00"] = []*pb.Message{incoming("00000000000000aa", "kalice00", "you going to the lan party friday?")}
	h := startUp(t, f)
	h.keys("enter") // Alice
	h.waitView("[13:02] Alice: you going to the lan party friday?", "Alice · ~kali · online", "159 bytes left (1/4)")
	if h.m.focus != focusIM {
		t.Fatal("focus didn't move to the IM window")
	}
	h.keys("yeah if my radio reaches lol")
	h.waitView("> yeah if my radio reaches lol ", "131 bytes left (1/4)")
	// The terminal's cursor sits after the text, on the input line.
	if c := h.m.View().Cursor; c == nil || c.Y != 24-3 || c.X != h.m.listWidth()+3+len("yeah if my radio reaches lol") {
		t.Fatalf("cursor at %+v", c)
	}
	h.keys("left", "left")
	if c := h.m.View().Cursor; c == nil || c.X != h.m.listWidth()+3+len("yeah if my radio reaches l") {
		t.Fatalf("cursor at %+v after ←←", c)
	}
	h.keys("ctrl+e")
	h.keys("enter")
	h.waitView("[13:02] me: yeah if my radio reaches lol  [queued]", "159 bytes left (1/4)")
	sent, _, _ := f.calls()
	if len(sent) != 1 || sent[0] != (sendCall{"kalice00", "yeah if my radio reaches lol"}) {
		t.Fatalf("SendIM calls: %v", sent)
	}
	// The daemon's message_queued event for the same IM doesn't duplicate it.
	m := h.m.convs["kalice00"].msgs[1]
	f.push(ev(&pb.Event_MessageQueued{MessageQueued: m}))
	f.push(ev(&pb.Event_BuddyAdded{BuddyAdded: buddy("kzed0000", "Zed", "Buddies", online, true)})) // a marker
	h.waitView("Zed")
	if n := strings.Count(h.view(), "radio reaches"); n != 1 {
		t.Fatalf("message shown %d times:\n%s", n, h.view())
	}
	// Blank input sends nothing.
	h.keys(" ", "enter")
	if sent, _, _ := f.calls(); len(sent) != 1 {
		t.Fatalf("blank IM sent: %v", sent)
	}

	// Tab goes back to the list, Tab again to the IM.
	h.keys("backspace", "tab")
	if h.m.focus != focusList {
		t.Fatal("tab didn't switch to the list")
	}
	h.keys("tab")
	if h.m.focus != focusIM {
		t.Fatal("tab didn't switch back")
	}
}

func TestSendError(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	f.sendErr = status.Error(codes.InvalidArgument, "daemon: IM of 700 bytes is too long")
	h := startUp(t, f)
	h.keys("enter", "hello")
	h.keys("enter")
	h.waitView("not sent: IM of 700 bytes is too long", "> hello")
}

func TestCounter(t *testing.T) {
	t.Parallel()
	cases := map[int]string{
		0:   "159 bytes left (1/4)",
		1:   "158 bytes left (1/4)",
		158: "1 byte left (1/4)",
		159: "0 bytes left (1/4)",
		160: "165 bytes left (2/4)",
		325: "0 bytes left (2/4)",
		326: "165 bytes left (3/4)",
		491: "0 bytes left (3/4)",
		492: "165 bytes left (4/4)",
		657: "0 bytes left (4/4)",
		658: "1 byte over (max 657)",
		700: "43 bytes over (max 657)",
	}
	for n, want := range cases {
		if got := counterText(n); got != want {
			t.Errorf("counterText(%d) = %q, want %q", n, got, want)
		}
	}

	// On screen: the counter counts UTF-8 bytes, not characters.
	f := fourBuddies()
	h := startUp(t, f)
	h.keys("enter", strings.Repeat("a", 157), "é") // 159 bytes
	h.waitView("0 bytes left (1/4)")
	h.keys("b")
	h.waitView("165 bytes left (2/4)")
	h.keys(strings.Repeat("c", 325-160), "d")
	h.waitView("165 bytes left (3/4)")
	h.keys(strings.Repeat("e", 657-326))
	h.waitView("0 bytes left (4/4)")
	h.keys("f")
	h.waitView("1 byte over (max 657)")
	h.keys("enter")
	h.waitView("shorten the message to send it")
	if sent, _, _ := f.calls(); len(sent) != 0 {
		t.Fatalf("over-long IM sent: %d", len(sent))
	}
	// Back under the limit, it goes.
	h.keys("backspace", "enter")
	h.waitFor("send", func() bool { s, _, _ := f.calls(); return len(s) == 1 })
	if s, _, _ := f.calls(); len(s[0].text) != 657 {
		t.Fatalf("sent %d bytes", len(s[0].text))
	}
}

func TestIncomingMessage(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	h := startUp(t, f)
	h.keys("enter") // Alice
	h.waitView("No messages yet with Alice")
	f.push(ev(&pb.Event_MessageReceived{MessageReceived: incoming("01", "kalice00", "hey there\nsecond line")}))
	h.waitView("[13:02] Alice: hey there")
	if l := h.line("second line"); !strings.Contains(l, "│"+strings.Repeat(" ", len("[13:02] Alice: "))+"second line") {
		t.Fatalf("continuation not indented: %q", l)
	}
	if strings.Contains(h.view(), "[1 new]") {
		t.Fatal("the open conversation counts as unread")
	}
	// A message for someone else marks them unread in the list.
	f.push(ev(&pb.Event_MessageReceived{MessageReceived: incoming("02", "kbob0000", "brb")}))
	h.waitView("Bob (away) [1 new]")
	h.keys("tab")
	h.selectBuddy("kbob0000")
	h.keys("enter")
	h.waitView("[13:02] Bob: brb", "Bob · ~kbob · away: at class")
	if strings.Contains(h.view(), "[1 new]") {
		t.Fatal("unread mark stayed after opening")
	}
}

func TestPresenceChange(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	h := startUp(t, f)
	if i, j := lineIndex(h.listText(), "Dave"), lineIndex(h.listText(), "Offline"); i < j {
		t.Fatalf("Dave not under Offline:\n%s", h.listText())
	}
	dave := buddy("kdave000", "Dave", "Buddies", online, true)
	f.push(ev(&pb.Event_BuddyChanged{BuddyChanged: dave}))
	h.waitView("▾ Buddies (2/2)", "▾ Offline (1)")
	list := h.listText()
	if i, j := lineIndex(list, "Dave"), lineIndex(list, "Offline"); i > j || i < lineIndex(list, "Buddies (2/2)") {
		t.Fatalf("Dave didn't move to Buddies:\n%s", list)
	}
	// Our own presence shows in the status bar.
	f.push(ev(&pb.Event_PresenceChanged{PresenceChanged: &pb.Presence{State: away, AwayMessage: "brb"}}))
	h.waitView("~me00 away", "[Ctrl+A] back")

	// Added and removed buddies.
	f.push(ev(&pb.Event_BuddyAdded{BuddyAdded: buddy("kerin000", "Erin", "Family", online, true)}))
	h.waitView("▾ Family (2/2)", "Erin")
	f.push(ev(&pb.Event_BuddyRemoved{BuddyRemoved: buddy("kerin000", "Erin", "Family", online, true)}))
	h.waitView("▾ Family (1/1)")
	if strings.Contains(h.view(), "Erin") {
		t.Fatal("removed buddy still listed")
	}
}

var italicThenBadge = regexp.MustCompile(`\x1b\[(?:[0-9]+;)*3(?:;[0-9]+)*m⚠ ~keve Eve`)

func TestUnverifiedStyling(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	f.buddies = append(f.buddies, buddy("keve0000", "Eve", "Buddies", online, false))
	opt := testOptions(f.connect)
	h := start(t, opt)
	h.waitView("⚠ ~keve Eve")
	if !italicThenBadge.MatchString(h.raw()) {
		t.Fatalf("unverified buddy not italic:\n%q", h.raw())
	}
	// A verified buddy has no badge.
	if strings.Contains(h.line("Alice"), "⚠") {
		t.Fatalf("verified buddy has a badge: %q", h.line("Alice"))
	}
	// The IM window says so too.
	h.selectBuddy("keve0000")
	h.keys("enter")
	h.waitView("Eve · ~keve · online · ⚠ unverified")

	// Verify: the safety number in 8 groups of 5, then y marks verified.
	h.keys("tab", "v")
	h.waitView("Verify safety number", "12345  67890  12345  67890", "Currently: ⚠ unverified.")
	h.keys("y")
	h.waitFor("verified", func() bool { return h.m.dlg == nil })
	if f.verified[0] != "keve0000=true" {
		t.Fatalf("SetBuddyVerified calls: %v", f.verified)
	}
	h.waitView("Eve is verified.")
	if strings.Contains(h.view(), "⚠") {
		t.Fatalf("badge stayed after verifying:\n%s", h.view())
	}
}

func TestNoColor(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	f.buddies = append(f.buddies, buddy("keve0000", "Eve", "Buddies", online, false))
	opt := testOptions(f.connect)
	opt.Color = false
	h := start(t, opt)
	h.waitView("⚠ ~keve Eve")
	v := h.raw()
	if regexp.MustCompile(`\x1b\[(?:[0-9]+;)*(?:3[0-79]|9[0-7]|38;5)(?:;[0-9]+)*m`).MatchString(v) {
		t.Fatalf("NO_COLOR screen has colors:\n%q", v)
	}
	if !italicThenBadge.MatchString(v) {
		t.Fatalf("NO_COLOR dropped italics:\n%q", v)
	}
}

func TestHostileText(t *testing.T) {
	t.Parallel()
	f := newFake()
	evil := &pb.Buddy{IdentityKey: "kmal0000", KeyId: "~kmal\x1b[38;5;1m", Petname: "\x1b[2J\x1b]0;pwned\x07Mallory\u202egnp.exe",
		Group: "Evil\r\n\x1b[31mGroup", State: pb.BuddyState_BUDDY_STATE_ACCEPTED, Verified: false,
		Presence: &pb.Presence{State: away, AwayMessage: "\x9b2J\u2066away"}}
	f.buddies = []*pb.Buddy{evil}
	f.history["kmal0000"] = []*pb.Message{incoming("01", "kmal0000", "\x1b[H\u2028hi\ttab\x00\x7f\xff")}
	f.status.KeyId = "~me\x1b[5m"
	f.sn = "\x1b[2Jnot digits"
	// No colors, so the only escape sequences the TUI itself writes are
	// SGR text attributes (bold 1, faint 2, italic 3, reverse 7, reset).
	opt := testOptions(f.connect)
	opt.Color = false
	h := start(t, opt)
	h.waitFor("connected", func() bool { return h.m.conn == connUp })
	h.keys("enter")
	h.waitView("hi tab")
	ours := regexp.MustCompile(`\x1b\[(?:[0-37](?:;[0-37])*)?m`)
	safe := func(what, v string) {
		t.Helper()
		for _, r := range ours.ReplaceAllString(v, "") {
			if r != '\n' && termtext.Unsafe(r) {
				t.Fatalf("%s: unsafe rune %U on screen:\n%q", what, r, v)
			}
		}
	}
	safe("conversation", h.raw())
	if !strings.Contains(h.view(), "Mallory\uFFFDgnp.exe") || !strings.Contains(h.view(), "Evil\uFFFD \uFFFD[31mGroup") {
		t.Fatalf("names not shown cleaned:\n%s", h.view())
	}
	h.keys("tab", "v")
	h.waitView("Safety number with")
	safe("verify dialog", h.raw())
	h.keys("esc", "x")
	h.waitView("Remove ⚠")
	safe("remove dialog", h.raw())
	h.keys("esc", "ctrl+n", "mal")
	safe("new IM dialog", h.raw())
	h.keys("esc")
	f.push(ev(&pb.Event_MessageReceived{MessageReceived: incoming("02", "kmal0000", "\x1b]52;c;cGF5bG9hZA==\x07")}))
	h.waitView("\uFFFD]52;c;cGF5bG9hZA==\uFFFD")
	safe("event", h.raw())
	f.kill(status.Error(codes.Internal, "daemon: boom \x1b[2J"))
	h.waitView("Lost the connection")
	safe("down screen", h.raw())
}

func TestDaemonDown(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	nr := &NotRunningError{Socket: "/tmp/oa/openaimd.sock", Reason: "no socket at /tmp/oa/openaimd.sock"}
	for range 1000 {
		f.dialErrs = append(f.dialErrs, nr)
	}
	opt := testOptions(f.connect)
	opt.BackoffMin, opt.BackoffMax = time.Hour, time.Hour // no automatic retry
	h := start(t, opt)
	h.waitView("openaimd is not running.", "(no socket at /tmp/oa/openaimd.sock)", "`openaimd run`", "openaim tui --embedded",
		"Retrying in 1h0m0s.", "[r] retry now")
	if strings.Contains(h.view(), "Buddy List") {
		t.Fatal("buddy list shown with no daemon")
	}
	// r retries at once.
	_, _, dials := f.calls()
	h.keys("r")
	h.waitFor("a second dial", func() bool { _, _, d := f.calls(); return d == dials+1 && !h.m.trying })
	// The daemon comes up; the next retry connects.
	f.mu.Lock()
	f.dialErrs = nil
	f.mu.Unlock()
	h.keys("r")
	h.waitView("Buddy List", "Alice")

	// q quits from the down screen.
	f2 := newFake()
	f2.dialErrs = []error{nr}
	h2 := start(t, testOptions(f2.connect))
	h2.waitView("openaimd is not running.")
	h2.keys("q")
	h2.waitFor("quit", func() bool { return h2.quit })
}

func TestEmbeddedDown(t *testing.T) {
	t.Parallel()
	f := newFake()
	f.dialErrs = []error{&NotRunningError{Reason: "no socket"}}
	opt := testOptions(f.connect)
	opt.Embedded, opt.BackoffMin, opt.BackoffMax = true, time.Hour, time.Hour
	h := start(t, opt)
	h.waitView("The embedded openaimd stopped.")
}

func TestReconnect(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	f.history["kalice00"] = []*pb.Message{incoming("01", "kalice00", "before")}
	h := startUp(t, f)
	h.keys("enter")
	h.waitView("Alice: before")

	// The daemon goes away and takes a few tries to come back; meanwhile
	// a buddy is added and a message arrives.
	f.mu.Lock()
	f.dialErrs = []error{&NotRunningError{Reason: "no socket"}, status.Error(codes.Unavailable, "connection refused")}
	f.buddies = append(f.buddies, buddy("kerin000", "Erin", "Buddies", online, true))
	f.history["kalice00"] = append(f.history["kalice00"], incoming("02", "kalice00", "while you were out"))
	f.mu.Unlock()
	_, _, dials := f.calls()
	f.kill(status.Error(codes.Unavailable, "daemon shutting down"))
	h.waitFor("disconnect", func() bool { return h.m.conn != connUp })
	h.waitView("Buddy List", "Erin", "Alice: while you were out")
	if _, _, d := f.calls(); d != dials+3 {
		t.Fatalf("%d dials to reconnect, want 3", d-dials)
	}
	if h.m.open != "kalice00" {
		t.Fatal("the open conversation was lost")
	}
	if h.m.attempt != 0 {
		t.Fatalf("attempt = %d after reconnecting", h.m.attempt)
	}

	// Falling behind resubscribes at once.
	_, _, dials = f.calls()
	f.kill(status.Error(codes.ResourceExhausted, "fell behind"))
	h.waitFor("resubscribe", func() bool { _, _, d := f.calls(); return d == dials+1 && h.m.conn == connUp })
}

func TestBackoff(t *testing.T) {
	t.Parallel()
	m := New(Options{BackoffMin: 100 * time.Millisecond, BackoffMax: time.Second})
	var got []time.Duration
	for i := range 6 {
		got = append(got, m.backoff(i))
	}
	want := []time.Duration{100e6, 200e6, 400e6, 800e6, 1e9, 1e9}
	if !slices.Equal(got, want) {
		t.Fatalf("backoff = %v, want %v", got, want)
	}
}

func TestAway(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	h := startUp(t, f)
	h.keys("ctrl+a")
	h.waitView("Set away message", "Away message: "+defaultAway, "%n is their name")
	h.keys("ctrl+u", "at class. %n, IM me later", "enter")
	h.waitView("You are away.", "~me00 away")
	_, pres, _ := f.calls()
	if len(pres) != 1 || pres[0].GetState() != away || pres[0].GetAwayMessage() != "at class. %n, IM me later" {
		t.Fatalf("SetPresence calls: %v", pres)
	}
	h.keys("ctrl+a")
	h.waitView("You are back.", "~me00 online")
	h.keys("ctrl+a")
	h.waitView("Away message: at class. %n, IM me later") // remembered
	h.keys("esc")
	if h.m.dlg != nil {
		t.Fatal("esc didn't close the dialog")
	}
	if _, pres, _ := f.calls(); len(pres) != 2 || pres[1].GetState() != online {
		t.Fatalf("SetPresence calls: %v", pres)
	}
}

func TestAddBuddy(t *testing.T) {
	t.Parallel()
	f := newFake()
	h := startUp(t, f)
	h.keys("ctrl+b")
	h.waitView("Add a buddy", "Identity key:")
	h.keys("enter")
	h.waitView("enter the buddy's identity key")
	h.keys("xbad", "enter")
	h.waitView("bad identity key")
	h.keys("ctrl+u", "kfrank00", "tab", "Frank", "tab", "Family", "enter")
	h.waitView("Added Frank (~kfra)", "▾ Family (0/1)", "Frank (pending)")
	if r := f.added[len(f.added)-1]; r.GetIdentityKey() != "kfrank00" || r.GetPetname() != "Frank" || r.GetGroup() != "Family" {
		t.Fatalf("AddBuddy: %v", r)
	}
	if !strings.Contains(h.line("Frank"), "> ") {
		t.Fatalf("new buddy not selected: %q", h.line("Frank"))
	}
}

func TestNewIMAndRemove(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	h := startUp(t, f)
	h.keys("ctrl+n")
	h.waitView("New IM", "> Alice")
	if n := strings.Count(h.view(), "Dave"); n != 2 { // the list and the dialog
		t.Fatalf("Dave shown %d times:\n%s", n, h.view())
	}
	h.keys("ca")
	if v := h.view(); !strings.Contains(v, "> Carol") || strings.Count(v, "Dave") != 1 {
		t.Fatalf("filter didn't apply:\n%s", v)
	}
	h.keys("enter")
	h.waitView("Carol · ~kcar · offline")

	h.keys("tab", "x")
	h.waitView("Remove Carol from your buddy list?")
	h.keys("n")
	if h.m.dlg != nil || len(f.removed) != 0 {
		t.Fatal("n didn't keep the buddy")
	}
	h.keys("x", "y")
	h.waitView("Removed Carol.")
	if f.removed[0] != "kcarol00" || h.m.open != "" {
		t.Fatalf("removed %v, open %q", f.removed, h.m.open)
	}

	h.keys("ctrl+n", "zzz", "enter")
	h.waitView("no buddy by that name")
}

func TestHelpAndQuit(t *testing.T) {
	t.Parallel()
	h := startUp(t, fourBuddies())
	h.keys("?")
	h.waitView("Help", "Ctrl+N  new IM", "⚠ marks a contact")
	h.keys("?")
	if h.m.dlg != nil {
		t.Fatal("help didn't close")
	}
	h.keys("enter", "f1")
	h.waitView("Help")
	h.keys("esc", "ctrl+c")
	h.waitFor("quit", func() bool { return h.quit })
}

func TestSmallTerminal(t *testing.T) {
	t.Parallel()
	h := startUp(t, fourBuddies())
	h.update(teaSize(30, 8))
	if !strings.Contains(h.view(), "too small") {
		t.Fatalf("small screen: %q", h.view())
	}
	// Every line fits the width at a normal size.
	h.update(teaSize(60, 15))
	for _, l := range strings.Split(h.view(), "\n") {
		if w := termtext.Width(l); w > 60 {
			t.Fatalf("line of width %d: %q", w, l)
		}
	}
	if n := strings.Count(h.view(), "\n") + 1; n != 15 {
		t.Fatalf("%d lines, want 15", n)
	}
}

func TestErrText(t *testing.T) {
	t.Parallel()
	cases := map[error]string{
		status.Error(codes.NotFound, "daemon: no such buddy"):   "no such buddy",
		status.Error(codes.Unavailable, "x"):                    "openaimd is not answering",
		&NotRunningError{Reason: "no socket at /s"}:             "openaimd is not running (no socket at /s)",
		errors.New("plain"):                                     "plain",
		status.Error(codes.DeadlineExceeded, "context timeout"): "openaimd did not answer in time",
	}
	for err, want := range cases {
		if got := errText(err); got != want {
			t.Errorf("errText(%v) = %q, want %q", err, got, want)
		}
	}
	if !IsNotRunning(status.Error(codes.Unavailable, "")) || IsNotRunning(errors.New("x")) {
		t.Fatal("IsNotRunning")
	}
}

func teaSize(w, h int) tea.WindowSizeMsg { return tea.WindowSizeMsg{Width: w, Height: h} }

// selectBuddy moves the list cursor to a buddy.
func (h *harness) selectBuddy(key string) {
	h.t.Helper()
	h.keys("home")
	for range 50 {
		if h.m.selectedBuddy().GetIdentityKey() == key {
			return
		}
		h.keys("down")
	}
	h.t.Fatalf("can't select %s:\n%s", key, h.view())
}

// TestNetworkEvents: buddy_presence moves a buddy in the list, and
// message_updated changes an IM's delivery mark.
func TestNetworkEvents(t *testing.T) {
	t.Parallel()
	f := fourBuddies()
	h := startUp(t, f)
	dave := buddy("kdave000", "Dave", "Buddies", online, true)
	f.push(ev(&pb.Event_BuddyPresence{BuddyPresence: &pb.BuddyPresence{Buddy: dave, From: offline, To: online, DoorOpen: true}}))
	h.waitView("▾ Buddies (2/2)", "▾ Offline (1)")

	h.keys("enter") // Alice
	h.keys("hi", "enter")
	h.waitView("[13:02] me: hi  [queued]")
	id := h.m.convs["kalice00"].msgs[0].GetMsgId()
	f.push(ev(&pb.Event_MessageUpdated{MessageUpdated: &pb.MessageUpdate{MsgId: id, BuddyKey: "kalice00",
		Delivery: pb.DeliveryState_DELIVERY_STATE_SENT, FragCount: 1}}))
	h.waitView("[13:02] me: hi  [sent]")
	f.push(ev(&pb.Event_MessageUpdated{MessageUpdated: &pb.MessageUpdate{MsgId: id, BuddyKey: "kalice00",
		Delivery: pb.DeliveryState_DELIVERY_STATE_ACKED, FragCount: 1, AckedMask: 1}}))
	h.waitView("[13:02] me: hi  [delivered]")
	// Updates for messages we don't have are ignored.
	f.push(ev(&pb.Event_MessageUpdated{MessageUpdated: &pb.MessageUpdate{MsgId: "00000000000000ff", BuddyKey: "kbob0000"}}))
	f.push(ev(&pb.Event_BuddyAdded{BuddyAdded: buddy("kzed0000", "Zed", "Buddies", online, true)})) // a marker
	h.waitView("Zed")
}
