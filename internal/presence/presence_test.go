package presence

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/transport/ip"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// ---- fakes ----

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	clk            *fakeClock
	c              chan time.Time
	at             time.Time
	fired, stopped bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clk: c, c: make(chan time.Time, 1), at: c.now.Add(d)}
	if d <= 0 {
		t.fired = true
		t.c <- c.now
	} else {
		c.timers = append(c.timers, t)
	}
	return t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	c.timers = slices.DeleteFunc(c.timers, func(t *fakeTimer) bool {
		if t.at.After(c.now) {
			return false
		}
		t.fired = true
		t.c <- c.now
		return true
	})
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

func (t *fakeTimer) Stop() bool {
	t.clk.mu.Lock()
	defer t.clk.mu.Unlock()
	if t.fired || t.stopped {
		return false
	}
	t.stopped = true
	t.clk.timers = slices.DeleteFunc(t.clk.timers, func(x *fakeTimer) bool { return x == t })
	return true
}

type sentMsg struct {
	to identity.PublicKey
	p  *pb.Presence
	at time.Time
}

type fakeSender struct {
	clk  *fakeClock
	mu   sync.Mutex
	sent []sentMsg
	// hook, if set, runs before a send is recorded; an error fails it.
	hook func(to identity.PublicKey) error
}

func (s *fakeSender) SendPresence(ctx context.Context, to Recipient, p *pb.Presence) error {
	s.mu.Lock()
	hook := s.hook
	s.mu.Unlock()
	if hook != nil {
		if err := hook(to.Key()); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, sentMsg{to: to.Key(), p: p, at: s.clk.Now()})
	return nil
}

func (s *fakeSender) to(k identity.PublicKey) []sentMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sentMsg
	for _, m := range s.sent {
		if m.to == k {
			out = append(out, m)
		}
	}
	return out
}

func (s *fakeSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

// ---- harness ----

var (
	alice    = identity.PublicKey{1}
	bob      = identity.PublicKey{2}
	stranger = identity.PublicKey{9}
)

type harness struct {
	t   *testing.T
	clk *fakeClock
	snd *fakeSender
	tr  *Tracker
	seq uint64
}

func newHarness(t *testing.T, mod func(*Config)) *harness {
	t.Helper()
	clk := newFakeClock()
	snd := &fakeSender{clk: clk}
	cfg := Config{Sender: snd, Clock: clk, Rand: rand.New(rand.NewPCG(1, 2)).Float64}
	if mod != nil {
		mod(&cfg)
	}
	tr, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	h := &harness{t: t, clk: clk, snd: snd, tr: tr}
	h.settle()
	return h
}

// settle waits until the loop has handled everything due and every send
// has finished.
func (h *harness) settle() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.tr.flush()
	if err := h.tr.drain(ctx); err != nil && !errors.Is(err, ErrClosed) {
		h.t.Fatalf("drain: %v", err)
	}
	h.tr.flush()
}

func (h *harness) advance(d time.Duration) {
	h.t.Helper()
	h.clk.Advance(d)
	h.settle()
}

// run advances by total in steps.
func (h *harness) run(total, step time.Duration) {
	h.t.Helper()
	for d := time.Duration(0); d < total; d += step {
		h.advance(step)
	}
}

func (h *harness) must(err error) {
	h.t.Helper()
	if err != nil {
		h.t.Fatal(err)
	}
	h.settle()
}

func (h *harness) stamp() Stamp {
	h.seq++
	return Stamp{Time: frame.Timestamp(h.clk.Now()), Seq: h.seq}
}

func (h *harness) recv(k identity.PublicKey, s pb.PresenceState, idle, rev uint32) error {
	err := h.tr.Received(k, h.stamp(), &pb.Presence{State: s, IdleMinutes: idle, AwayRev: rev})
	h.settle()
	return err
}

func (h *harness) events() []Event {
	var out []Event
	for {
		select {
		case e := <-h.tr.Events():
			out = append(out, e)
		default:
			return out
		}
	}
}

func (h *harness) transitions() []Transition {
	var out []Transition
	for _, e := range h.events() {
		if e.Transition != nil {
			out = append(out, *e.Transition)
		}
	}
	return out
}

func (h *harness) status(k identity.PublicKey) BuddyStatus {
	h.t.Helper()
	s, ok := h.tr.Buddy(k)
	if !ok {
		h.t.Fatalf("buddy %v unknown", k.KeyID())
	}
	return s
}

func (h *harness) wantState(k identity.PublicKey, want State) {
	h.t.Helper()
	if got := h.status(k).State; got != want {
		h.t.Fatalf("buddy state = %v, want %v", got, want)
	}
}

func (h *harness) wantNoTransitions() {
	h.t.Helper()
	if tr := h.transitions(); len(tr) != 0 {
		h.t.Fatalf("unexpected transitions: %+v", tr)
	}
}

func wantTransition(t *testing.T, got []Transition, from, to State, reason Reason) Transition {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("got %d transitions %+v, want 1 (%v→%v)", len(got), got, from, to)
	}
	g := got[0]
	if g.From != from || g.To != to || g.Reason != reason {
		t.Fatalf("transition %v→%v (%s), want %v→%v (%s)", g.From, g.To, g.Reason, from, to, reason)
	}
	return g
}

// online brings alice up: accepted, a session, and an ONLINE presence.
func (h *harness) online(k identity.PublicKey) {
	h.t.Helper()
	h.must(h.tr.AddBuddy(k))
	h.must(h.tr.SessionUp(k, "peer-"+k.KeyID()))
	if err := h.recv(k, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0); err != nil {
		h.t.Fatal(err)
	}
	h.events()
}

// ---- tests ----

func TestDefaultsKeepSessionsAlive(t *testing.T) {
	if DefaultHeartbeatInterval+DefaultHeartbeatJitter >= ip.DefaultSessionIdleTimeout {
		t.Fatal("heartbeats would let the session idle timeout close live sessions")
	}
	if DefaultGrace <= 2*time.Minute {
		t.Fatal("door-close grace must exceed the 2-minute relay reset")
	}
	if DefaultBuddyTimeout != DefaultHeartbeatInterval*5/2 {
		t.Fatal("buddy timeout is not 2.5 heartbeat intervals")
	}
}

func TestConfigValidation(t *testing.T) {
	snd := SenderFunc(func(context.Context, Recipient, *pb.Presence) error { return nil })
	for name, c := range map[string]Config{
		"no sender":   {},
		"jitter":      {Sender: snd, HeartbeatInterval: time.Minute, HeartbeatJitter: 30 * time.Second},
		"timeout":     {Sender: snd, BuddyTimeout: 4 * time.Minute},
		"state":       {Sender: snd, State: 7},
		"away length": {Sender: snd, AwayText: string(make([]byte, 2000))},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func TestBuddyOnlineAwayBackOffline(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.AddBuddy(alice))
	h.must(h.tr.SessionUp(alice, "p1"))
	// A session alone shows nothing.
	h.wantNoTransitions()
	h.wantState(alice, Offline)

	if err := h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0); err != nil {
		t.Fatal(err)
	}
	if g := wantTransition(t, h.transitions(), Offline, Online, ReasonPresence); !g.DoorOpen() {
		t.Fatal("not a door open")
	}
	h.advance(time.Minute)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_AWAY, 0, 0)
	wantTransition(t, h.transitions(), Online, Away, ReasonPresence)
	h.advance(time.Minute)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0)
	wantTransition(t, h.transitions(), Away, Online, ReasonPresence)
	// A heartbeat with nothing new is silent.
	h.advance(time.Minute)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0)
	h.wantNoTransitions()
	h.advance(time.Minute)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_OFFLINE, 0, 0)
	if g := wantTransition(t, h.transitions(), Online, Offline, ReasonSignedOff); !g.DoorClose() {
		t.Fatal("not a door close")
	}
	// Idle shows as a same-state transition.
	h.advance(time.Minute)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0)
	h.transitions()
	h.advance(time.Minute)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 12, 0)
	g := wantTransition(t, h.transitions(), Online, Online, ReasonPresence)
	if g.IdleMinutes != 12 || !g.IdleSince.Equal(h.clk.Now().Add(-12*time.Minute)) {
		t.Fatalf("idle %d since %v", g.IdleMinutes, g.IdleSince)
	}
}

func TestRelayResetDoesNotFlap(t *testing.T) {
	h := newHarness(t, nil)
	h.online(alice)
	h.advance(30 * time.Second)
	h.must(h.tr.SessionDown(alice, "peer-"+alice.KeyID()))
	if !h.status(alice).InGrace {
		t.Fatal("no grace after Down")
	}
	h.run(2*time.Minute, 5*time.Second)
	before := len(h.snd.to(alice))
	h.must(h.tr.SessionUp(alice, "peer-"+alice.KeyID()))
	// We say hello again on the new session.
	if len(h.snd.to(alice)) != before+1 {
		t.Fatal("no presence sent on session Up")
	}
	// Well past where the grace would have ended.
	h.run(4*time.Minute, 5*time.Second)
	h.wantNoTransitions()
	h.wantState(alice, Online)
	if h.status(alice).InGrace {
		t.Fatal("grace still running")
	}
}

func TestDoorCloseAfterGrace(t *testing.T) {
	h := newHarness(t, nil)
	h.online(alice)
	h.must(h.tr.SessionDown(alice, "peer-"+alice.KeyID()))
	h.advance(DefaultGrace - time.Second)
	h.wantNoTransitions()
	h.wantState(alice, Online)
	h.advance(time.Second)
	g := wantTransition(t, h.transitions(), Online, Offline, ReasonDoorClose)
	if !g.DoorClose() {
		t.Fatal("not a door close")
	}
}

func TestPresenceDuringGraceCancelsIt(t *testing.T) {
	h := newHarness(t, nil)
	h.online(alice)
	h.must(h.tr.SessionDown(alice, "peer-"+alice.KeyID()))
	h.advance(time.Minute)
	// A PRESENCE that came another way (it is authenticated) cancels it.
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0)
	if h.status(alice).InGrace {
		t.Fatal("grace still running")
	}
	h.run(5*time.Minute, 10*time.Second)
	h.wantNoTransitions()
	// The heartbeat timeout still applies.
	h.run(DefaultBuddyTimeout-5*time.Minute, 10*time.Second)
	wantTransition(t, h.transitions(), Online, Offline, ReasonTimeout)
}

func TestStalePresenceIgnored(t *testing.T) {
	h := newHarness(t, nil)
	h.online(alice)
	h.advance(time.Minute)
	now := frame.Timestamp(h.clk.Now())
	h.must(h.tr.Received(alice, Stamp{Time: now, Seq: 100}, &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_AWAY}))
	h.transitions()
	for _, s := range []Stamp{{Time: now - 1, Seq: 500}, {Time: now, Seq: 100}, {Time: now, Seq: 99}} {
		err := h.tr.Received(alice, s, &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_ONLINE})
		if !errors.Is(err, ErrStale) {
			t.Fatalf("stamp %+v: err %v, want ErrStale", s, err)
		}
	}
	h.settle()
	h.wantNoTransitions()
	h.wantState(alice, Away)
	// Same second, later seq: applied.
	h.must(h.tr.Received(alice, Stamp{Time: now, Seq: 101}, &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_ONLINE}))
	wantTransition(t, h.transitions(), Away, Online, ReasonPresence)
	if st := h.tr.Stats(); st.Stale != 3 {
		t.Fatalf("stale = %d", st.Stale)
	}

	// A late ONLINE after a sign-off is ignored too, but after the grace
	// period a buddy whose clock stepped back is believed again.
	h.must(h.tr.Received(alice, Stamp{Time: now + 10, Seq: 1}, &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_OFFLINE}))
	h.transitions()
	if err := h.tr.Received(alice, Stamp{Time: now + 5, Seq: 1}, &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_ONLINE}); !errors.Is(err, ErrStale) {
		t.Fatalf("late ONLINE after sign-off: %v", err)
	}
	h.advance(DefaultGrace)
	h.must(h.tr.Received(alice, Stamp{Time: now + 5, Seq: 1}, &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_ONLINE}))
	wantTransition(t, h.transitions(), Offline, Online, ReasonPresence)
}

func TestInvalidPresenceRejected(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.AddBuddy(alice))
	if err := h.tr.Received(alice, h.stamp(), &pb.Presence{}); err == nil {
		t.Fatal("UNSPECIFIED state accepted")
	}
}

func TestHeartbeatsWithJitter(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.AddBuddy(alice))
	start := h.clk.Now()
	h.must(h.tr.SessionUp(alice, "p1"))
	if got := h.snd.to(alice); len(got) != 1 || !got[0].at.Equal(start) {
		t.Fatalf("door-open send: %+v", got)
	}
	h.run(40*time.Minute, time.Second)
	sent := h.snd.to(alice)
	if len(sent) < 8 {
		t.Fatalf("%d sends in 40 minutes", len(sent))
	}
	gaps := map[time.Duration]bool{}
	for i := 1; i < len(sent); i++ {
		gap := sent[i].at.Sub(sent[i-1].at)
		if gap < DefaultHeartbeatInterval-DefaultHeartbeatJitter || gap > DefaultHeartbeatInterval+DefaultHeartbeatJitter {
			t.Fatalf("heartbeat gap %v", gap)
		}
		gaps[gap] = true
		if sent[i].p.GetState() != pb.PresenceState_PRESENCE_STATE_ONLINE {
			t.Fatalf("heartbeat state %v", sent[i].p.GetState())
		}
	}
	if len(gaps) < 2 {
		t.Fatal("no jitter")
	}

	// No heartbeats without a session.
	h.must(h.tr.SessionDown(alice, "p1"))
	n := h.snd.count()
	h.run(10*time.Minute, 5*time.Second)
	if h.snd.count() != n {
		t.Fatal("heartbeat without a session")
	}

	// And none after Close.
	h.must(h.tr.SessionUp(alice, "p1"))
	h.tr.Close()
	n = h.snd.count()
	for range 20 {
		h.clk.Advance(time.Minute)
	}
	time.Sleep(10 * time.Millisecond)
	if h.snd.count() != n {
		t.Fatal("heartbeat after Close")
	}
	for range h.tr.Events() { // closed by Close
	}
	if err := h.tr.SetState(Away); !errors.Is(err, ErrClosed) {
		t.Fatalf("SetState after Close: %v", err)
	}
}

func TestMissedHeartbeatsGoOffline(t *testing.T) {
	h := newHarness(t, nil)
	h.online(alice)
	// The session stays up (and we keep sending), but alice goes quiet.
	h.run(DefaultBuddyTimeout-10*time.Second, 10*time.Second)
	h.wantNoTransitions()
	h.advance(10 * time.Second)
	g := wantTransition(t, h.transitions(), Online, Offline, ReasonTimeout)
	if s := h.status(alice); !g.At.Equal(s.Since) || !s.Connected {
		t.Fatalf("status %+v", s)
	}
}

func TestAwayRevFetchSignal(t *testing.T) {
	h := newHarness(t, nil)
	h.online(alice)
	fetches := func() []FetchAway {
		var out []FetchAway
		for _, e := range h.events() {
			if e.FetchAway != nil {
				out = append(out, *e.FetchAway)
			}
		}
		return out
	}
	// Online with a rev: not fetched (on demand, only when away).
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 6)
	if f := fetches(); len(f) != 0 {
		t.Fatalf("fetch while online: %+v", f)
	}
	h.advance(time.Second)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_AWAY, 0, 7)
	if f := fetches(); len(f) != 1 || f[0].Rev != 7 || f[0].Buddy != alice {
		t.Fatalf("fetches %+v", f)
	}
	// A heartbeat soon after does not repeat it...
	h.advance(time.Minute)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_AWAY, 0, 7)
	if f := fetches(); len(f) != 0 {
		t.Fatalf("repeated fetch %+v", f)
	}
	// ...but one after FetchRetry does, if the reply never came.
	h.advance(DefaultFetchRetry)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_AWAY, 0, 7)
	if f := fetches(); len(f) != 1 {
		t.Fatalf("no retry: %+v", f)
	}
	h.must(h.tr.ReceivedAwayMsg(alice, &pb.AwayMsg{Text: "out to lunch", Rev: 7}))
	var am []AwayMessage
	for _, e := range h.events() {
		if e.AwayMessage != nil {
			am = append(am, *e.AwayMessage)
		}
	}
	if len(am) != 1 || am[0].Text != "out to lunch" {
		t.Fatalf("away message events %+v", am)
	}
	if text, rev, ok := h.tr.AwayMessage(alice); !ok || rev != 7 || text != "out to lunch" {
		t.Fatalf("AwayMessage = %q %d %v", text, rev, ok)
	}
	if s := h.status(alice); !s.AwayKnown || s.AwayText != "out to lunch" {
		t.Fatalf("status %+v", s)
	}
	// Cached: no fetch.
	h.advance(DefaultFetchRetry)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_AWAY, 0, 7)
	if f := fetches(); len(f) != 0 {
		t.Fatalf("fetch of a cached rev: %+v", f)
	}
	// A new rev is.
	h.advance(time.Second)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_AWAY, 0, 8)
	if f := fetches(); len(f) != 1 || f[0].Rev != 8 {
		t.Fatalf("fetches %+v", f)
	}
	if _, _, ok := h.tr.AwayMessage(alice); ok {
		t.Fatal("stale away message served for the new rev")
	}
	// Going back to rev 7 uses the cache.
	h.advance(time.Second)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_AWAY, 0, 7)
	if f := fetches(); len(f) != 0 {
		t.Fatalf("fetch of a cached rev: %+v", f)
	}
}

func TestOwnAwayMessageAndRev(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.AddBuddy(alice))
	h.must(h.tr.SessionUp(alice, "p1"))
	n := len(h.snd.to(alice))
	h.must(h.tr.Set(Away, "brb"))
	sent := h.snd.to(alice)
	if len(sent) != n+1 {
		t.Fatalf("%d sends", len(sent)-n)
	}
	rev := sent[len(sent)-1].p.GetAwayRev()
	if rev == 0 || sent[len(sent)-1].p.GetState() != pb.PresenceState_PRESENCE_STATE_AWAY {
		t.Fatalf("sent %v", sent[len(sent)-1].p)
	}
	// Same text: nothing new to say.
	h.must(h.tr.SetAwayMessage("brb"))
	if len(h.snd.to(alice)) != n+1 {
		t.Fatal("broadcast without a change")
	}
	h.must(h.tr.SetAwayMessage("gone fishing"))
	sent = h.snd.to(alice)
	if len(sent) != n+2 || sent[len(sent)-1].p.GetAwayRev() == rev {
		t.Fatal("away_rev did not change with the text")
	}
	m, err := h.tr.AwayReply(alice)
	if err != nil || m.GetText() != "gone fishing" || m.GetRev() != sent[len(sent)-1].p.GetAwayRev() {
		t.Fatalf("AwayReply = %v, %v", m, err)
	}
	// Away text is never in the PRESENCE itself (fetched on demand).
	h.must(h.tr.SetAwayMessage(""))
	if p := h.snd.to(alice); p[len(p)-1].p.GetAwayRev() != 0 {
		t.Fatal("empty away message has a rev")
	}
	if err := h.tr.SetAwayMessage("bad\x1b[2J"); err == nil {
		t.Fatal("control characters accepted")
	}
	if err := h.tr.SetState(0); err == nil {
		t.Fatal("state 0 accepted")
	}
}

func TestNothingForNonAcceptedBuddies(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.SetBuddies([]identity.PublicKey{alice, bob}))
	h.must(h.tr.SessionUp(alice, "pa"))

	if err := h.tr.SessionUp(stranger, "px"); !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("SessionUp(stranger) = %v", err)
	}
	if err := h.recv(stranger, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0); !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("Received(stranger) = %v", err)
	}
	if _, err := h.tr.AwayReply(stranger); !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("AwayReply(stranger) = %v", err)
	}
	if err := h.tr.ReceivedAwayMsg(stranger, &pb.AwayMsg{Text: "x", Rev: 1}); !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("ReceivedAwayMsg(stranger) = %v", err)
	}
	h.must(h.tr.Set(Away, "afk"))
	if len(h.snd.to(stranger)) != 0 {
		t.Fatal("presence sent to a stranger")
	}
	// bob is accepted but has no session: nothing sent until one is up.
	if len(h.snd.to(bob)) != 0 {
		t.Fatal("presence sent without a session")
	}
	if got := h.snd.to(alice); len(got) != 2 {
		t.Fatalf("alice got %d sends, want door open + away", len(got))
	}
	if _, ok := h.tr.Buddy(stranger); ok {
		t.Fatal("stranger tracked")
	}

	// Removal: alice was online, so she leaves with a transition, and
	// nothing more goes to her.
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0)
	h.events()
	h.must(h.tr.SetBuddies([]identity.PublicKey{bob}))
	wantTransition(t, h.transitions(), Online, Offline, ReasonRemoved)
	n := len(h.snd.to(alice))
	h.must(h.tr.SetState(Online))
	h.run(10*time.Minute, 10*time.Second)
	if len(h.snd.to(alice)) != n {
		t.Fatal("presence sent to a removed buddy")
	}
	if _, err := h.tr.AwayReply(alice); !errors.Is(err, ErrNotAccepted) {
		t.Fatal("away message served to a removed buddy")
	}
}

func TestRemovalWinsOverQueuedSend(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.AddBuddy(alice))
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var once sync.Once
	h.snd.mu.Lock()
	h.snd.hook = func(identity.PublicKey) error {
		once.Do(func() { entered <- struct{}{}; <-release })
		return nil
	}
	h.snd.mu.Unlock()
	if err := h.tr.SessionUp(alice, "p1"); err != nil {
		t.Fatal(err)
	}
	<-entered
	// While the door-open send is in flight: a change queues another, then
	// alice is removed.
	if err := h.tr.SetState(Away); err != nil {
		t.Fatal(err)
	}
	if err := h.tr.RemoveBuddy(alice); err != nil {
		t.Fatal(err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for len(h.snd.to(alice)) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // room for a wrong second send
	h.settle()
	if got := h.snd.to(alice); len(got) != 1 {
		t.Fatalf("%d sends to a removed buddy, want only the in-flight one", len(got))
	}
}

func TestOwnChangesCoalesceWhileInFlight(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.AddBuddy(alice))
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var once sync.Once
	h.snd.mu.Lock()
	h.snd.hook = func(identity.PublicKey) error {
		once.Do(func() { entered <- struct{}{}; <-release })
		return nil
	}
	h.snd.mu.Unlock()
	h.tr.SessionUp(alice, "p1")
	<-entered
	h.tr.SetState(Away)
	h.tr.SetAwayMessage("one")
	h.tr.SetAwayMessage("two")
	close(release)
	h.settle()
	got := h.snd.to(alice)
	if len(got) != 2 {
		t.Fatalf("%d sends, want 2 (in-flight + one coalesced)", len(got))
	}
	if last := got[1].p; last.GetState() != pb.PresenceState_PRESENCE_STATE_AWAY || last.GetAwayRev() != awayRev("two") {
		t.Fatalf("coalesced send %v", last)
	}
}

func TestIdleAndAutoAway(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.IdleAfter = 5 * time.Minute
		c.AutoAwayAfter = 10 * time.Minute
	})
	h.must(h.tr.AddBuddy(alice))
	h.must(h.tr.SessionUp(alice, "p1"))
	h.must(h.tr.Activity(h.clk.Now()))
	h.events()
	last := func() *pb.Presence { s := h.snd.to(alice); return s[len(s)-1].p }
	ownChanges := func() []OwnChange {
		var out []OwnChange
		for _, e := range h.events() {
			if e.Own != nil {
				out = append(out, *e.Own)
			}
		}
		return out
	}

	h.advance(5*time.Minute - time.Second)
	if h.tr.Own().Idle {
		t.Fatal("idle early")
	}
	h.advance(time.Second)
	if c := ownChanges(); len(c) != 1 || c[0].Reason != ReasonIdle || !c[0].To.Idle {
		t.Fatalf("own changes %+v", c)
	}
	if p := last(); p.GetIdleMinutes() != 5 || p.GetState() != pb.PresenceState_PRESENCE_STATE_ONLINE {
		t.Fatalf("idle presence %v", p)
	}
	h.advance(5 * time.Minute)
	c := ownChanges()
	if len(c) != 1 || c[0].Reason != ReasonAutoAway || c[0].To.State != Away || !c[0].To.AutoAway {
		t.Fatalf("own changes %+v", c)
	}
	if p := last(); p.GetState() != pb.PresenceState_PRESENCE_STATE_AWAY || p.GetIdleMinutes() != 10 {
		t.Fatalf("auto-away presence %v", p)
	}
	// Heartbeats carry the growing idle time.
	h.run(5*time.Minute, 5*time.Second)
	if p := last(); p.GetIdleMinutes() < 13 {
		t.Fatalf("heartbeat idle minutes %d", p.GetIdleMinutes())
	}
	ownChanges()
	h.must(h.tr.Activity(h.clk.Now()))
	c = ownChanges()
	if len(c) != 1 || c[0].Reason != ReasonActive || c[0].To.State != Online || c[0].To.Idle {
		t.Fatalf("own changes %+v", c)
	}
	if p := last(); p.GetState() != pb.PresenceState_PRESENCE_STATE_ONLINE || p.GetIdleMinutes() != 0 {
		t.Fatalf("active presence %v", p)
	}

	// An explicit Away is not undone by activity.
	h.must(h.tr.SetState(Away))
	h.must(h.tr.Activity(h.clk.Now()))
	if h.tr.Own().State != Away {
		t.Fatal("activity overrode an explicit away")
	}
}

func TestNoIdleWithoutActivityReports(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.AutoAwayAfter = time.Minute })
	h.advance(time.Hour)
	if o := h.tr.Own(); o.Idle || o.State != Online {
		t.Fatalf("own %+v without any activity report", o)
	}
}

func TestSignOffSendsOffline(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.SetBuddies([]identity.PublicKey{alice, bob}))
	h.must(h.tr.SessionUp(alice, "pa"))
	h.must(h.tr.SessionUp(bob, "pb"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.tr.SignOff(ctx); err != nil {
		t.Fatal(err)
	}
	for _, k := range []identity.PublicKey{alice, bob} {
		s := h.snd.to(k)
		if len(s) != 2 || s[1].p.GetState() != pb.PresenceState_PRESENCE_STATE_OFFLINE {
			t.Fatalf("sends to %v: %+v", k.KeyID(), s)
		}
	}
	n := h.snd.count()
	h.run(20*time.Minute, 10*time.Second)
	if h.snd.count() != n {
		t.Fatal("heartbeats after sign-off")
	}
	if h.tr.Own().State != Offline {
		t.Fatal("not offline")
	}
}

func TestSessionRotationNoGrace(t *testing.T) {
	h := newHarness(t, nil)
	h.online(alice)
	n := len(h.snd.to(alice))
	// The buddy's host key rotated: a new peer comes up, the old one drains.
	h.must(h.tr.SessionUp(alice, "new"))
	h.must(h.tr.SessionDown(alice, "peer-"+alice.KeyID()))
	if s := h.status(alice); s.InGrace || !s.Connected {
		t.Fatalf("status %+v", s)
	}
	if len(h.snd.to(alice)) != n {
		t.Fatal("extra send for a second session")
	}
	// Down for an unknown peer or buddy is ignored.
	h.must(h.tr.SessionDown(alice, "nope"))
	h.must(h.tr.SessionDown(stranger, "nope"))
	h.wantNoTransitions()
}

func TestFailedSendRetried(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.AddBuddy(alice))
	var fail sync.Once
	h.snd.mu.Lock()
	h.snd.hook = func(identity.PublicKey) error {
		var err error
		fail.Do(func() { err = errors.New("no route") })
		return err
	}
	h.snd.mu.Unlock()
	h.must(h.tr.SessionUp(alice, "p1"))
	if len(h.snd.to(alice)) != 0 {
		t.Fatal("failed send recorded")
	}
	h.advance(DefaultRetryDelay - time.Second)
	if len(h.snd.to(alice)) != 0 {
		t.Fatal("retried early")
	}
	h.advance(time.Second)
	if len(h.snd.to(alice)) != 1 {
		t.Fatal("not retried")
	}
	if st := h.tr.Stats(); st.SendFailures != 1 || st.Sent != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestAnswerBuddyComingOnline(t *testing.T) {
	h := newHarness(t, nil)
	h.must(h.tr.AddBuddy(alice))
	h.must(h.tr.SessionUp(alice, "p1"))
	n := len(h.snd.to(alice))
	// alice just accepted us, so she may not have our presence: answer her
	// door open with ours.
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_ONLINE, 0, 0)
	if len(h.snd.to(alice)) != n+1 {
		t.Fatal("door open not answered")
	}
	h.advance(time.Second)
	h.recv(alice, pb.PresenceState_PRESENCE_STATE_AWAY, 0, 0)
	if len(h.snd.to(alice)) != n+1 {
		t.Fatal("answered a non-door-open presence")
	}
}

func TestRealClock(t *testing.T) {
	got := make(chan *pb.Presence, 4)
	tr, err := New(Config{Sender: SenderFunc(func(_ context.Context, _ Recipient, p *pb.Presence) error {
		got <- p
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	tr.AddBuddy(alice)
	tr.SessionUp(alice, "p")
	select {
	case p := <-got:
		if p.GetState() != pb.PresenceState_PRESENCE_STATE_ONLINE {
			t.Fatalf("sent %v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no send")
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}
