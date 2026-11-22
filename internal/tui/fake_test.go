package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/aghman/openaim/internal/apipb"
)

// fake is an in-memory daemon behind the Client interface.
type fake struct {
	mu       sync.Mutex
	status   *pb.Status
	buddies  []*pb.Buddy
	history  map[string][]*pb.Message
	sn       string
	dialErrs []error // returned by the next dials, in order
	dials    int
	stream   *fakeStream // the current subscription
	nextID   int

	sent     []sendCall
	presence []*pb.SetPresenceRequest
	added    []*pb.AddBuddyRequest
	verified []string
	removed  []string
	sendErr  error
}

type sendCall struct{ buddy, text string }

type item struct {
	ev  *pb.Event
	err error
}

type fakeStream struct {
	ctx context.Context
	ch  chan item
}

func (s *fakeStream) Recv() (*pb.Event, error) {
	select {
	case it := <-s.ch:
		return it.ev, it.err
	case <-s.ctx.Done():
		return nil, status.Error(codes.Canceled, "canceled")
	}
}

func newFake() *fake {
	return &fake{
		status:  &pb.Status{KeyId: "~me00", IdentityKey: "mekey", Presence: &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_ONLINE}},
		history: map[string][]*pb.Message{},
		sn:      "12345678901234567890123456789012345678901234567890"[:40],
	}
}

func (f *fake) connect(context.Context) (Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dials++
	if len(f.dialErrs) > 0 {
		err := f.dialErrs[0]
		f.dialErrs = f.dialErrs[1:]
		return nil, err
	}
	return f, nil
}

func (f *fake) Close() error { return nil }

func (f *fake) GetStatus(context.Context) (*pb.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, nil
}

func (f *fake) ListBuddies(context.Context) ([]*pb.Buddy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.Buddy(nil), f.buddies...), nil
}

func (f *fake) AddBuddy(_ context.Context, req *pb.AddBuddyRequest) (*pb.Buddy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, req)
	if !strings.HasPrefix(req.GetIdentityKey(), "k") {
		return nil, status.Error(codes.InvalidArgument, "daemon: bad identity key")
	}
	b := &pb.Buddy{IdentityKey: req.GetIdentityKey(), KeyId: "~" + req.GetIdentityKey()[:4], Petname: req.GetPetname(), Group: req.GetGroup(),
		State: pb.BuddyState_BUDDY_STATE_PENDING_OUT}
	if b.Group == "" {
		b.Group = "Buddies"
	}
	f.buddies = append(f.buddies, b)
	return b, nil
}

func (f *fake) RemoveBuddy(_ context.Context, buddy string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, buddy)
	return nil
}

func (f *fake) SetBuddyVerified(_ context.Context, buddy string, v bool) (*pb.Buddy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verified = append(f.verified, fmt.Sprintf("%s=%v", buddy, v))
	for _, b := range f.buddies {
		if b.GetIdentityKey() == buddy {
			nb := clone(b)
			nb.Verified = v
			return nb, nil
		}
	}
	return nil, status.Error(codes.NotFound, "no such buddy")
}

func (f *fake) GetSafetyNumber(_ context.Context, buddy string) (*pb.SafetyNumber, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &pb.SafetyNumber{SafetyNumber: f.sn}, nil
}

func (f *fake) SendIM(_ context.Context, buddy, text string) (*pb.SendIMResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	f.sent = append(f.sent, sendCall{buddy, text})
	f.nextID++
	m := &pb.Message{MsgId: fmt.Sprintf("%016x", f.nextID), BuddyKey: buddy, Direction: pb.Direction_DIRECTION_OUTGOING, Text: text,
		SentAt: timestamppb.New(testNow), Delivery: pb.DeliveryState_DELIVERY_STATE_QUEUED}
	return &pb.SendIMResponse{MsgId: m.MsgId, Message: m}, nil
}

func (f *fake) History(_ context.Context, buddy string, _ uint32) ([]*pb.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.Message(nil), f.history[buddy]...), nil
}

func (f *fake) SetPresence(_ context.Context, st pb.PresenceState, away string) (*pb.Presence, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.presence = append(f.presence, &pb.SetPresenceRequest{State: st, AwayMessage: away})
	return &pb.Presence{State: st, AwayMessage: away}, nil
}

func (f *fake) Subscribe(ctx context.Context) (EventStream, error) {
	s := &fakeStream{ctx: ctx, ch: make(chan item, 64)}
	s.ch <- item{ev: &pb.Event{Kind: &pb.Event_Ready{Ready: &pb.Ready{}}}}
	f.mu.Lock()
	f.stream = s
	f.mu.Unlock()
	return s, nil
}

// push sends an event on the current subscription.
func (f *fake) push(ev *pb.Event) {
	f.mu.Lock()
	s := f.stream
	f.mu.Unlock()
	s.ch <- item{ev: ev}
}

// kill ends the current subscription with err.
func (f *fake) kill(err error) {
	f.mu.Lock()
	s := f.stream
	f.mu.Unlock()
	s.ch <- item{err: err}
}

func (f *fake) calls() (sent []sendCall, pres []*pb.SetPresenceRequest, dials int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sendCall(nil), f.sent...), append([]*pb.SetPresenceRequest(nil), f.presence...), f.dials
}

func clone(b *pb.Buddy) *pb.Buddy { return proto.Clone(b).(*pb.Buddy) }

var testNow = time.Date(2026, 11, 22, 13, 2, 0, 0, time.Local)

func buddy(key, pet, grp string, ps pb.PresenceState, verified bool) *pb.Buddy {
	return &pb.Buddy{IdentityKey: key, KeyId: "~" + key[:4], Petname: pet, Group: grp, State: pb.BuddyState_BUDDY_STATE_ACCEPTED,
		Verified: verified, Presence: &pb.Presence{State: ps}}
}

// harness runs the model the way tea.Program does, but on the test's
// goroutine: Update and View happen here; commands run in goroutines and
// their messages come back through msgs.
type harness struct {
	t    *testing.T
	m    *Model
	msgs chan tea.Msg
	quit bool
}

func testOptions(c Connector) Options {
	return Options{
		Connect: c, Socket: "/tmp/oa/openaimd.sock", Color: true,
		Now: func() time.Time { return testNow }, BackoffMin: time.Millisecond, BackoffMax: 4 * time.Millisecond,
	}
}

func start(t *testing.T, opt Options) *harness {
	t.Helper()
	h := &harness{t: t, m: New(opt), msgs: make(chan tea.Msg, 1024)}
	t.Cleanup(h.m.Close)
	h.update(tea.WindowSizeMsg{Width: 100, Height: 24})
	h.run(h.m.Init())
	return h
}

// startUp starts the model against f and waits until it is connected.
func startUp(t *testing.T, f *fake) *harness {
	t.Helper()
	h := start(t, testOptions(f.connect))
	h.waitFor("connected", func() bool { return h.m.conn == connUp })
	return h
}

func (h *harness) run(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	go func() { h.msgs <- cmd() }()
}

func (h *harness) update(msg tea.Msg) {
	switch msg := msg.(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			h.run(c)
		}
	case tea.QuitMsg:
		h.quit = true
	default:
		_, cmd := h.m.Update(msg)
		h.run(cmd)
	}
}

var keyCodes = map[string]tea.Key{
	"enter": {Code: tea.KeyEnter}, "tab": {Code: tea.KeyTab}, "shift+tab": {Code: tea.KeyTab, Mod: tea.ModShift},
	"esc": {Code: tea.KeyEscape}, "up": {Code: tea.KeyUp}, "down": {Code: tea.KeyDown}, "left": {Code: tea.KeyLeft},
	"right": {Code: tea.KeyRight}, "pgup": {Code: tea.KeyPgUp}, "pgdown": {Code: tea.KeyPgDown},
	"backspace": {Code: tea.KeyBackspace}, "home": {Code: tea.KeyHome}, "f1": {Code: tea.KeyF1},
	"space": {Code: tea.KeySpace, Text: " "},
}

// keys presses each named key ("enter", "ctrl+n", "space"), or types it
// as text, one key per rune, if it isn't a name.
func (h *harness) keys(ks ...string) {
	h.t.Helper()
	for _, k := range ks {
		if key, ok := keyCodes[k]; ok {
			h.update(tea.KeyPressMsg(key))
			continue
		}
		if c, ok := strings.CutPrefix(k, "ctrl+"); ok && len(c) == 1 {
			h.update(tea.KeyPressMsg{Code: rune(c[0]), Mod: tea.ModCtrl})
			continue
		}
		for _, r := range k {
			h.update(tea.KeyPressMsg{Code: r, Text: string(r)})
		}
	}
}

// waitFor processes command results until cond holds.
func (h *harness) waitFor(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.After(5 * time.Second)
	for !cond() {
		select {
		case msg := <-h.msgs:
			h.update(msg)
		case <-deadline:
			h.t.Fatalf("timed out waiting for %s; screen:\n%s", what, h.view())
		}
	}
}

// waitView waits until the screen shows every one of want.
func (h *harness) waitView(want ...string) {
	h.t.Helper()
	h.waitFor(fmt.Sprintf("%q on screen", want), func() bool {
		v := h.view()
		for _, w := range want {
			if !strings.Contains(v, w) {
				return false
			}
		}
		return true
	})
}

// view is the screen as text, styling removed.
func (h *harness) view() string { return ansi.Strip(h.raw()) }

// raw is the screen as the terminal gets it, styling included.
func (h *harness) raw() string { return h.m.View().Content }

// line is the first screen line containing s, or "".
func (h *harness) line(s string) string {
	for _, l := range strings.Split(h.view(), "\n") {
		if strings.Contains(l, s) {
			return l
		}
	}
	return ""
}

// listText is the buddy-list column of the screen.
func (h *harness) listText() string {
	var b strings.Builder
	w := h.m.listWidth()
	for _, l := range strings.Split(h.view(), "\n") {
		b.WriteString(ansi.Truncate(l, w, ""))
		b.WriteByte('\n')
	}
	return b.String()
}
