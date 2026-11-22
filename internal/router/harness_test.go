package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

var bg = context.Background()

// fakeClock is a manual Clock. AfterFunc calls with d ≤ 0 run at once in a
// goroutine; others run (synchronously) from Advance.
type fakeClock struct {
	mu        sync.Mutex
	now       time.Time
	timers    []*fakeTimer
	immediate atomic.Int64
}

type fakeTimer struct {
	c      *fakeClock
	at     time.Time
	f      func()
	done   bool // fired or stopped
	seqNum int
}

func newFakeClock() *fakeClock {
	// Start at the real time: the store stamps created_at with time.Now.
	return &fakeClock{now: time.UnixMilli(time.Now().UnixMilli())}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now.Add(d), f: f, seqNum: len(c.timers)}
	if d <= 0 {
		t.done = true
		c.immediate.Add(1)
		go func() {
			defer c.immediate.Add(-1)
			f()
		}()
		return t
	}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.done
	t.done = true
	return was
}

// Advance moves the clock forward and runs the timers that came due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due, keep []*fakeTimer
	for _, t := range c.timers {
		switch {
		case t.done:
		case !t.at.After(c.now):
			t.done = true
			due = append(due, t)
		default:
			keep = append(keep, t)
		}
	}
	c.timers = keep
	c.mu.Unlock()
	sort.SliceStable(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
	for _, t := range due {
		t.f()
	}
}

// sendRec is one Transport.Send.
type sendRec struct {
	at     time.Time
	route  Route
	frames [][]byte
	err    error
}

var ackPrefix = []byte("ACK:")

// fakeTransport records sends. ACKs sealed by fakeSeal are recognisable by
// their prefix.
type fakeTransport struct {
	clock *fakeClock
	mu    sync.Mutex
	fail  error
	sends []sendRec
	// deliver, if set, is called for each successful send (loopback).
	deliver func(Route, [][]byte)
}

func (f *fakeTransport) Send(ctx context.Context, r Route, frames [][]byte) error {
	cp := make([][]byte, len(frames))
	for i, b := range frames {
		cp[i] = bytes.Clone(b)
	}
	f.mu.Lock()
	err := f.fail
	f.sends = append(f.sends, sendRec{at: f.clock.Now(), route: r, frames: cp, err: err})
	deliver := f.deliver
	f.mu.Unlock()
	if err == nil && deliver != nil {
		deliver(r, cp)
	}
	return err
}

func (f *fakeTransport) setFail(err error) {
	f.mu.Lock()
	f.fail = err
	f.mu.Unlock()
}

func (f *fakeTransport) all() []sendRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sends)
}

// data returns successful sends of DATA frames.
func (f *fakeTransport) data() []sendRec {
	var out []sendRec
	for _, s := range f.all() {
		if s.err == nil && !bytes.HasPrefix(s.frames[0], ackPrefix) {
			out = append(out, s)
		}
	}
	return out
}

// acks returns the ACK bodies sent successfully.
func (f *fakeTransport) acks(t *testing.T) []*pb.Ack {
	t.Helper()
	var out []*pb.Ack
	for _, s := range f.all() {
		if s.err != nil || !bytes.HasPrefix(s.frames[0], ackPrefix) {
			continue
		}
		m, err := body.Unmarshal(frame.Ack, s.frames[0][len(ackPrefix):])
		if err != nil {
			t.Fatalf("router sent an invalid ACK: %v", err)
		}
		out = append(out, m.(*pb.Ack))
	}
	return out
}

func fakeSeal(_ context.Context, _ int64, ct frame.ContentType, b []byte) ([][]byte, error) {
	if ct != frame.Ack {
		return nil, errors.New("unexpected content type")
	}
	return [][]byte{append(bytes.Clone(ackPrefix), b...)}, nil
}

type fakeReach struct {
	mu     sync.Mutex
	routes map[int64]Route
}

func (f *fakeReach) IPRoute(id int64, _ time.Time) (Route, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.routes[id]
	return r, ok
}

func (f *fakeReach) set(id int64, r Route) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.routes == nil {
		f.routes = map[int64]Route{}
	}
	f.routes[id] = r
}

func (f *fakeReach) clear(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.routes, id)
}

type eventLog struct {
	mu sync.Mutex
	ev []Event
}

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	l.ev = append(l.ev, e)
	l.mu.Unlock()
}

func (l *eventLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.ev)
}

func (l *eventLog) states(id int64) []DeliveryState {
	var out []DeliveryState
	for _, e := range l.all() {
		if e.OutboxID == id {
			out = append(out, e.State)
		}
	}
	return out
}

// harness is one router on a real store with fakes around it.
type harness struct {
	t      *testing.T
	st     *store.Store
	clock  *fakeClock
	tr     *fakeTransport
	reach  *fakeReach
	events *eventLog
	jobs   *atomic.Int64
	mod    func(*Config)
	r      *Router
	buddy  int64
	key    frame.ConvKey // our send key toward the buddy
	peer   peer.ID
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(bg, filepath.Join(t.TempDir(), "openaim.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func addBuddy(t *testing.T, s *store.Store, seed byte) int64 {
	t.Helper()
	id, err := identity.FromSeed(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.AddBuddy(bg, store.Buddy{Key: id.Public(), State: store.Accepted})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func randKey(t *testing.T) frame.ConvKey {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return frame.NewConvKey(k)
}

func newHarness(t *testing.T, mod func(*Config)) *harness {
	t.Helper()
	c := newFakeClock()
	h := &harness{t: t, st: openStore(t), clock: c, tr: &fakeTransport{clock: c}, reach: &fakeReach{},
		events: &eventLog{}, jobs: new(atomic.Int64), mod: mod, peer: peer.ID("buddy-peer")}
	h.buddy = addBuddy(t, h.st, 1)
	h.key = randKey(t)
	h.r = h.newRouter()
	return h
}

func (h *harness) config() Config {
	cfg := Config{Store: h.st, Transport: h.tr, Reach: h.reach, Seal: fakeSeal, Clock: h.clock,
		OnEvent: h.events.add, jobs: h.jobs}
	if h.mod != nil {
		h.mod(&cfg)
	}
	return cfg
}

func (h *harness) newRouter() *Router {
	h.t.Helper()
	r, err := New(h.config())
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { r.Close() })
	return r
}

// restart closes the router and starts a new one on the same store.
func (h *harness) restart() {
	h.t.Helper()
	h.r.Close()
	h.r = h.newRouter()
	if err := h.r.Start(bg); err != nil {
		h.t.Fatal(err)
	}
	h.settle()
}

// enqueue seals an IM of n body bytes to the buddy (the mesh layout: up to
// 4 fragments) and kicks the router.
func (h *harness) enqueue(n int) *store.Outgoing {
	h.t.Helper()
	return enqueueTo(h.t, h.st, h.r, h.clock, h.buddy, h.key, n)
}

func enqueueTo(t *testing.T, s *store.Store, r *Router, c Clock, buddy int64, k frame.ConvKey, n int) *store.Outgoing {
	t.Helper()
	b := make([]byte, n)
	rand.Read(b)
	out, err := s.Enqueue(bg, buddy, func(seq uint64) (*frame.Sealed, frame.ContentType, error) {
		now := c.Now()
		in := frame.Inner{Type: frame.IM, Flags: frame.FlagAckRequested, Time: frame.Timestamp(now), Seq: seq, Body: b}
		sealed, err := frame.Seal(k, k.Tag(frame.Day(now)), frame.LayoutMesh, in.Marshal())
		return sealed, frame.IM, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if r != nil {
		r.Kick(buddy)
	}
	return out
}

func (h *harness) settle() { settle(h.t, h.clock, h.jobs) }

// settle waits until no router job is queued or running and no immediate
// timer is pending.
func settle(t *testing.T, c *fakeClock, jobs *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for quiet := 0; quiet < 3; {
		if jobs.Load() == 0 && c.immediate.Load() == 0 && jobs.Load() == 0 {
			quiet++
		} else {
			quiet = 0
		}
		if time.Now().After(deadline) {
			t.Fatalf("router did not settle: %d jobs, %d immediate timers", jobs.Load(), c.immediate.Load())
		}
		time.Sleep(100 * time.Microsecond)
	}
}

// advance moves the clock in steps, settling after each.
func (h *harness) advance(total, step time.Duration) {
	for d := time.Duration(0); d < total; d += step {
		h.clock.Advance(min(step, total-d))
		h.settle()
	}
}

func (h *harness) outgoing(id int64) *store.Outgoing {
	h.t.Helper()
	o, err := h.st.Outgoing(bg, id)
	if err != nil {
		h.t.Fatal(err)
	}
	return o
}

func (h *harness) ack(id frame.MsgID, have uint16) (applied, unknown int) {
	h.t.Helper()
	a, u, err := h.r.HandleAck(bg, h.buddy, &pb.Ack{Entries: []*pb.AckEntry{{MsgId: id[:], Have: uint32(have)}}})
	if err != nil {
		h.t.Fatal(err)
	}
	h.settle()
	return a, u
}

func (h *harness) routeUp() {
	h.reach.set(h.buddy, Route{Peer: h.peer})
	h.r.RouteChanged(h.buddy)
	h.settle()
}

// checkFrames fails unless every frame sent is byte-identical to the
// store's frame for its (msg_id, fragment).
func checkFrames(t *testing.T, s *store.Store, buddy int64, sends []sendRec) {
	t.Helper()
	cache := map[frame.MsgID]*store.Outgoing{}
	for _, rec := range sends {
		for _, f := range rec.frames {
			hd, err := frame.ParseHeader(f)
			if err != nil {
				t.Fatalf("sent a malformed frame: %v", err)
			}
			o := cache[hd.MsgID]
			if o == nil {
				m, err := s.OutgoingByMsgID(bg, buddy, hd.MsgID)
				if err != nil {
					t.Fatalf("sent a frame of unknown message %s: %v", hd.MsgID, err)
				}
				if o, err = s.Outgoing(bg, m.ID); err != nil {
					t.Fatal(err)
				}
				cache[hd.MsgID] = o
			}
			if hd.Count != len(o.Frames) || !bytes.Equal(f, o.Frames[hd.Index]) {
				t.Fatalf("frame %d of %s differs from the stored frame", hd.Index, hd.MsgID)
			}
		}
	}
}
