package router

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

func noJitter(c *Config) { c.Jitter = -1 }

func TestForget(t *testing.T) {
	h := newHarness(t, nil)
	h.routeUp()
	h.r.Received(bg, h.buddy, frame.Result{Status: frame.Partial, Header: frame.Header{MsgID: frame.MsgID{1}}, Have: 1})
	h.r.Forget(h.buddy)
	h.advance(time.Second, DefaultAckDelay)
	if n := len(h.tr.all()); n != 0 {
		t.Fatalf("%d sends after Forget", n)
	}
	h.r.mu.Lock()
	n := len(h.r.buddies)
	h.r.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d buddy states after Forget", n)
	}
}

func TestQueuedOfflineSentWhenRouteAppears(t *testing.T) {
	h := newHarness(t, nil)
	msgs := []*store.Outgoing{h.enqueue(10), h.enqueue(520), h.enqueue(30)}
	h.settle()
	h.advance(time.Minute, 10*time.Second)
	if n := len(h.tr.all()); n != 0 {
		t.Fatalf("%d sends without a route", n)
	}
	for _, m := range msgs {
		if o := h.outgoing(m.ID); o.Attempts != 0 || o.State != store.Queued {
			t.Fatalf("offline message: %d attempts, %s", o.Attempts, o.State)
		}
	}

	h.routeUp()
	sends := h.tr.data()
	if len(sends) != len(msgs) {
		t.Fatalf("%d sends, want %d", len(sends), len(msgs))
	}
	for i, m := range msgs { // oldest first, one batch per message, stored bytes
		if sends[i].route.Peer != h.peer {
			t.Fatalf("sent to %s", sends[i].route.Peer)
		}
		if !slices.EqualFunc(sends[i].frames, m.Frames, bytes.Equal) {
			t.Fatalf("send %d isn't message %d's stored frames", i, i)
		}
		if o := h.outgoing(m.ID); o.Attempts != 1 {
			t.Fatalf("message %d: %d attempts", i, o.Attempts)
		}
		if st := h.events.states(m.ID); !slices.Equal(st, []DeliveryState{Sent}) {
			t.Fatalf("message %d events %v", i, st)
		}
	}
	if len(msgs[1].Frames) != 4 {
		t.Fatalf("test message has %d fragments, want 4", len(msgs[1].Frames))
	}
}

func TestKickSendsAtOnceWithRoute(t *testing.T) {
	h := newHarness(t, nil)
	h.routeUp()
	m := h.enqueue(10) // enqueue kicks
	h.settle()
	if s := h.tr.data(); len(s) != 1 || !bytes.Equal(s[0].frames[0], m.Frames[0]) {
		t.Fatalf("sends %v", s)
	}
}

func TestFullAckMarksAcked(t *testing.T) {
	h := newHarness(t, nil)
	h.routeUp()
	m := h.enqueue(520)
	h.settle()
	if a, u := h.ack(m.MsgID, 0b1111); a != 1 || u != 0 {
		t.Fatalf("applied %d, unknown %d", a, u)
	}
	o := h.outgoing(m.ID)
	if o.State != store.Acked || o.AckedMask != 0b1111 {
		t.Fatalf("after full ACK: %s %04b", o.State, o.AckedMask)
	}
	if st := h.events.states(m.ID); !slices.Equal(st, []DeliveryState{Sent, Acked}) {
		t.Fatalf("events %v", st)
	}
	// A repeated ACK changes nothing and emits nothing.
	h.ack(m.MsgID, 0b1111)
	if st := h.events.states(m.ID); len(st) != 2 {
		t.Fatalf("events after a repeated ACK: %v", st)
	}
	h.advance(time.Hour, time.Minute)
	if n := len(h.tr.data()); n != 1 {
		t.Fatalf("%d sends of an acked message", n)
	}
}

func TestPartialAckResendsOnlyMissing(t *testing.T) {
	h := newHarness(t, noJitter)
	h.routeUp()
	m := h.enqueue(520)
	h.settle()
	h.ack(m.MsgID, 0b0101)
	o := h.outgoing(m.ID)
	if o.State != store.Queued || o.AckedMask != 0b0101 {
		t.Fatalf("after partial ACK: %s %04b", o.State, o.AckedMask)
	}
	ev := h.events.all()
	if last := ev[len(ev)-1]; last.State != Sent || last.AckedMask != 0b0101 || last.FragCount != 4 {
		t.Fatalf("partial ACK event %+v", last)
	}

	h.advance(DefaultAckTimeout, 500*time.Millisecond)
	sends := h.tr.data()
	if len(sends) != 2 {
		t.Fatalf("%d sends, want the first and one retry", len(sends))
	}
	want := [][]byte{m.Frames[1], m.Frames[3]}
	if !slices.EqualFunc(sends[1].frames, want, bytes.Equal) {
		t.Fatalf("retry sent %d frames, not exactly the stored fragments 1 and 3", len(sends[1].frames))
	}

	h.ack(m.MsgID, 0b1010)
	if o := h.outgoing(m.ID); o.State != store.Acked {
		t.Fatalf("state %s after the rest was acked", o.State)
	}
	h.advance(time.Hour, time.Minute)
	if n := len(h.tr.data()); n != 2 {
		t.Fatalf("%d sends after the message was acked", n)
	}
}

func TestTimeoutBackoff(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Jitter = -1
		c.AckTimeout = time.Second
		c.MaxRetryDelay = 8 * time.Second
	})
	h.routeUp()
	m := h.enqueue(10)
	h.settle()
	h.advance(40*time.Second, 250*time.Millisecond)
	sends := h.tr.data()
	var gaps []time.Duration
	for i := 1; i < len(sends); i++ {
		gaps = append(gaps, sends[i].at.Sub(sends[i-1].at))
	}
	want := []time.Duration{1, 2, 4, 8, 8, 8, 8}
	for i := range want {
		want[i] *= time.Second
	}
	if !slices.Equal(gaps, want) {
		t.Fatalf("retry gaps %v, want %v", gaps, want)
	}
	for _, s := range sends {
		if !bytes.Equal(s.frames[0], m.Frames[0]) {
			t.Fatal("a retry differs from the stored frame")
		}
	}
	if o := h.outgoing(m.ID); o.Attempts != len(sends) || !o.LastAttempt.Equal(sends[len(sends)-1].at) {
		t.Fatalf("stored %d attempts, last %v; sent %d", o.Attempts, o.LastAttempt, len(sends))
	}
}

func TestRetryDelayJitter(t *testing.T) {
	h := newHarness(t, nil)
	r := h.r
	seen := map[time.Duration]bool{}
	for id := int64(1); id <= 50; id++ {
		for n := 1; n <= 12; n++ {
			base := min(DefaultAckTimeout<<(n-1), DefaultMaxRetryDelay)
			d := r.RetryDelay(id, n)
			if d < time.Duration(float64(base)*(1-DefaultJitter)) || d >= time.Duration(float64(base)*(1+DefaultJitter)) {
				t.Fatalf("RetryDelay(%d, %d) = %v, base %v", id, n, d, base)
			}
			if d != r.RetryDelay(id, n) {
				t.Fatal("RetryDelay isn't deterministic")
			}
			seen[d] = true
		}
	}
	if len(seen) < 100 {
		t.Fatalf("only %d distinct delays: no jitter?", len(seen))
	}
	if d := r.RetryDelay(1, 1000); d > time.Duration(float64(DefaultMaxRetryDelay)*(1+DefaultJitter)) {
		t.Fatalf("delay not capped: %v", d)
	}
}

func TestGiveUpAfterHorizonOffline(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Horizon = time.Hour })
	m := h.enqueue(10)
	h.settle()
	h.clock.Advance(59 * time.Minute)
	h.settle()
	if o := h.outgoing(m.ID); o.State != store.Queued {
		t.Fatalf("state %s before the horizon", o.State)
	}
	h.clock.Advance(2 * time.Minute) // the give-up timer fires
	h.settle()
	if o := h.outgoing(m.ID); o.State != store.Failed {
		t.Fatalf("state %s after the horizon", o.State)
	}
	if st := h.events.states(m.ID); !slices.Equal(st, []DeliveryState{Failed}) {
		t.Fatalf("events %v", st)
	}
	h.routeUp()
	if n := len(h.tr.all()); n != 0 {
		t.Fatalf("%d sends of a failed message", n)
	}
	if h.r.Stats().Failed != 1 {
		t.Fatalf("stats %+v", h.r.Stats())
	}
}

func TestGiveUpAfterHorizonUnacked(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Horizon = time.Minute
		c.AckTimeout = time.Second
		c.MaxRetryDelay = 4 * time.Second
	})
	h.routeUp()
	m := h.enqueue(10)
	h.settle()
	h.advance(2*time.Minute, time.Second)
	o := h.outgoing(m.ID)
	if o.State != store.Failed {
		t.Fatalf("state %s", o.State)
	}
	sends := h.tr.data()
	if len(sends) < 10 {
		t.Fatalf("only %d attempts in a minute", len(sends))
	}
	if last := sends[len(sends)-1].at; last.Sub(o.CreatedAt) >= time.Minute {
		t.Fatalf("sent %v after creation, past the horizon", last.Sub(o.CreatedAt))
	}
	if st := h.events.states(m.ID); st[len(st)-1] != Failed {
		t.Fatalf("events %v", st)
	}
}

func TestRestartResumes(t *testing.T) {
	h := newHarness(t, noJitter)
	h.routeUp()
	sent := h.enqueue(10)
	h.settle()
	h.r.Close()

	unsent := h.enqueue(10) // queued while no router runs (Kick is a no-op after Close)
	h.r = h.newRouter()
	if err := h.r.Start(bg); err != nil {
		t.Fatal(err)
	}
	h.settle()
	sends := h.tr.data()
	if len(sends) != 2 || !bytes.Equal(sends[1].frames[0], unsent.Frames[0]) {
		t.Fatalf("after restart: %d sends; the unsent message should go out, the in-flight one wait", len(sends))
	}

	// The first message's retry happens on the persisted schedule.
	h.advance(DefaultAckTimeout, 100*time.Millisecond)
	sends = h.tr.data()
	if len(sends) < 3 || !bytes.Equal(sends[2].frames[0], sent.Frames[0]) {
		t.Fatalf("persisted retry not resumed: %d sends", len(sends))
	}
	if got := sends[2].at.Sub(sends[0].at); got != DefaultAckTimeout {
		t.Fatalf("retry %v after the first attempt, want %v", got, DefaultAckTimeout)
	}
	if o := h.outgoing(sent.ID); o.Attempts != 2 {
		t.Fatalf("%d attempts", o.Attempts)
	}

	// Acks still apply after another restart.
	h.restart()
	h.ack(sent.MsgID, 1)
	h.ack(unsent.MsgID, 1)
	if n, _ := h.st.CountOutgoing(bg, store.Acked); n != 2 {
		t.Fatalf("%d acked", n)
	}
}

func TestWindow(t *testing.T) {
	h := newHarness(t, nil)
	var msgs []*store.Outgoing
	for range DefaultWindow + 3 {
		msgs = append(msgs, h.enqueue(10))
	}
	h.settle()
	h.routeUp()
	if n := len(h.tr.data()); n != DefaultWindow {
		t.Fatalf("%d sent at once, want the window of %d", n, DefaultWindow)
	}
	h.ack(msgs[0].MsgID, 1)
	h.ack(msgs[1].MsgID, 1)
	sends := h.tr.data()
	if len(sends) != DefaultWindow+2 {
		t.Fatalf("%d sends after 2 ACKs", len(sends))
	}
	for i, s := range sends {
		if !bytes.Equal(s.frames[0], msgs[i].Frames[0]) {
			t.Fatalf("send %d out of order", i)
		}
	}
}

func TestTransportFailureBacksOff(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Jitter = -1; c.AckTimeout = time.Second })
	h.tr.setFail(errors.New("unreachable"))
	h.reach.set(h.buddy, Route{Peer: h.peer})
	a, b := h.enqueue(10), h.enqueue(10)
	h.settle()
	if s := h.tr.all(); len(s) != 1 {
		t.Fatalf("%d sends: a failed send should stop the round", len(s))
	}
	if o := h.outgoing(a.ID); o.Attempts != 0 {
		t.Fatal("a failed send was recorded as an attempt")
	}
	h.advance(900*time.Millisecond, 100*time.Millisecond)
	if s := h.tr.all(); len(s) != 1 {
		t.Fatalf("%d sends during the route backoff", len(s))
	}
	h.advance(200*time.Millisecond, 100*time.Millisecond)
	if s := h.tr.all(); len(s) != 2 {
		t.Fatalf("%d sends after the route backoff", len(s))
	}
	h.tr.setFail(nil)
	h.r.RouteChanged(h.buddy) // resets the backoff
	h.settle()
	if d := h.tr.data(); len(d) != 2 || !bytes.Equal(d[1].frames[0], b.Frames[0]) {
		t.Fatalf("after the route came back: %d sends", len(d))
	}
	if h.r.Stats().SendFailures != 2 {
		t.Fatalf("stats %+v", h.r.Stats())
	}
}

func TestUnknownAckIgnored(t *testing.T) {
	h := newHarness(t, nil)
	h.routeUp()
	m := h.enqueue(10)
	h.settle()
	other := addBuddy(t, h.st, 2)

	if a, u := h.ack(frame.MsgID{1, 2, 3}, 1); a != 0 || u != 1 {
		t.Fatalf("applied %d, unknown %d", a, u)
	}
	// Our message's msg_id, acked by someone else: ACKs match per buddy.
	if a, u, err := h.r.HandleAck(bg, other, &pb.Ack{Entries: []*pb.AckEntry{{MsgId: m.MsgID[:], Have: 1}}}); err != nil || a != 0 || u != 1 {
		t.Fatalf("other buddy's ACK: applied %d, unknown %d, %v", a, u, err)
	}
	if o := h.outgoing(m.ID); o.State != store.Queued || o.AckedMask != 0 {
		t.Fatalf("unknown ACKs changed the message: %s %b", o.State, o.AckedMask)
	}
	if s := h.r.Stats(); s.UnknownAcks != 2 || s.AckEntriesIn != 2 {
		t.Fatalf("stats %+v", s)
	}
	// Mixed: the unknown entry is skipped, the known one applied.
	a, u, err := h.r.HandleAck(bg, h.buddy, &pb.Ack{Entries: []*pb.AckEntry{
		{MsgId: []byte{9, 9, 9, 9, 9, 9, 9, 9}, Have: 1}, {MsgId: m.MsgID[:], Have: 1}}})
	if err != nil || a != 1 || u != 1 {
		t.Fatalf("mixed ACK: applied %d, unknown %d, %v", a, u, err)
	}
	if o := h.outgoing(m.ID); o.State != store.Acked {
		t.Fatalf("state %s", o.State)
	}
}

// buddySide seals and receives frames as the buddy would.
type buddySide struct {
	t    *testing.T
	h    *harness
	send frame.ConvKey // buddy → us
	recv *frame.Receiver
}

func newBuddySide(t *testing.T, h *harness) *buddySide {
	kr := NewKeyring()
	kr.Now = h.clock.Now
	b := &buddySide{t: t, h: h, send: randKey(t)}
	kr.Set(h.buddy, b.send)
	b.recv = &frame.Receiver{Keys: kr, Dedup: &frame.MemDedup{}, Now: h.clock.Now}
	return b
}

func (b *buddySide) seal(ct frame.ContentType, flags frame.Flags, body []byte) *frame.Sealed {
	now := b.h.clock.Now()
	in := frame.Inner{Type: ct, Flags: flags, Time: frame.Timestamp(now), Seq: 1, Body: body}
	s, err := frame.Seal(b.send, b.send.Tag(frame.Day(now)), frame.LayoutMesh, in.Marshal())
	if err != nil {
		b.t.Fatal(err)
	}
	return s
}

// deliver passes frames through our Receiver into the router.
func (b *buddySide) deliver(frames ...[]byte) []frame.Status {
	var st []frame.Status
	for _, f := range frames {
		res, err := b.recv.Accept(f)
		if err != nil {
			b.t.Fatal(err)
		}
		st = append(st, res.Status)
		b.h.r.Received(bg, b.h.buddy, res)
	}
	return st
}

func TestDuplicateReacked(t *testing.T) {
	h := newHarness(t, nil)
	h.routeUp()
	b := newBuddySide(t, h)
	msg := b.seal(frame.IM, frame.FlagAckRequested, bytes.Repeat([]byte("x"), 200)) // 2 fragments

	if st := b.deliver(msg.Frames[1]); st[0] != frame.Partial {
		t.Fatal(st)
	}
	h.advance(DefaultAckDelay, DefaultAckDelay)
	if st := b.deliver(msg.Frames[0]); st[0] != frame.Delivered {
		t.Fatal(st)
	}
	h.advance(DefaultAckDelay, DefaultAckDelay)
	if st := b.deliver(msg.Frames...); st[0] != frame.Duplicate || st[1] != frame.Duplicate {
		t.Fatal(st)
	}
	h.advance(DefaultAckDelay, DefaultAckDelay)

	acks := h.tr.acks(t)
	if len(acks) != 3 {
		t.Fatalf("%d ACKs, want partial, delivered and re-ack", len(acks))
	}
	for i, want := range []uint32{0b10, 0b11, 0b11} {
		e := acks[i].GetEntries()
		if len(e) != 1 || !bytes.Equal(e[0].GetMsgId(), msg.MsgID[:]) || e[0].GetHave() != want {
			t.Fatalf("ACK %d: %v, want have %b", i, e, want)
		}
	}
	for _, s := range h.tr.all() {
		if s.route.Peer != h.peer {
			t.Fatalf("ACK sent to %s", s.route.Peer)
		}
	}
}

func TestNoAckForAcksOrUnrequested(t *testing.T) {
	h := newHarness(t, nil)
	h.routeUp()
	b := newBuddySide(t, h)
	m := h.enqueue(10)
	h.settle()

	ack := b.seal(frame.Ack, 0, mustMarshalAck(t, m.MsgID, 1))
	presence := b.seal(frame.Presence, 0, []byte{8, 1})
	b.deliver(ack.Frames...)
	b.deliver(presence.Frames...)
	b.deliver(ack.Frames...) // duplicates
	b.deliver(presence.Frames...)
	h.advance(time.Second, DefaultAckDelay)
	if a := h.tr.acks(t); len(a) != 0 {
		t.Fatalf("sent %d ACKs for an ACK or an unrequested message", len(a))
	}
	// The delivered ACK was applied.
	if o := h.outgoing(m.ID); o.State != store.Acked {
		t.Fatalf("our message is %s after the buddy's ACK", o.State)
	}
}

func mustMarshalAck(t *testing.T, id frame.MsgID, have uint16) []byte {
	t.Helper()
	_, b, err := body.Marshal(&pb.Ack{Entries: []*pb.AckEntry{{MsgId: id[:], Have: uint32(have)}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAckCoalescing(t *testing.T) {
	h := newHarness(t, nil)
	h.routeUp()
	const n = 40
	ids := make([]frame.MsgID, n)
	for i := range ids {
		ids[i] = frame.MsgID{byte(i), 0xAA}
		in := frame.Inner{Type: frame.IM, Flags: frame.FlagAckRequested}
		h.r.Received(bg, h.buddy, frame.Result{Status: frame.Delivered, Header: frame.Header{MsgID: ids[i]}, Have: 1,
			Message: &frame.Message{MsgID: ids[i], Inner: in}})
	}
	// Partials of one message merge into one entry.
	pid := frame.MsgID{0xBB}
	h.r.Received(bg, h.buddy, frame.Result{Status: frame.Partial, Header: frame.Header{MsgID: pid}, Have: 0b001})
	h.r.Received(bg, h.buddy, frame.Result{Status: frame.Partial, Header: frame.Header{MsgID: pid}, Have: 0b100})
	h.settle()
	acks := h.tr.acks(t)
	if len(acks) != 1 || len(acks[0].GetEntries()) != 32 {
		t.Fatalf("a full ACK should go out at once: %d ACKs", len(acks))
	}
	h.advance(DefaultAckDelay, DefaultAckDelay)
	acks = h.tr.acks(t)
	if len(acks) != 2 {
		t.Fatalf("%d ACKs after the delay", len(acks))
	}
	seen := map[frame.MsgID]uint32{}
	for _, a := range acks {
		if len(a.GetEntries()) > 32 {
			t.Fatalf("ACK with %d entries", len(a.GetEntries()))
		}
		for _, e := range a.GetEntries() {
			id := frame.MsgID(e.GetMsgId())
			if _, dup := seen[id]; dup {
				t.Fatalf("%s acked twice", id)
			}
			seen[id] = e.GetHave()
		}
	}
	if len(seen) != n+1 || seen[pid] != 0b101 {
		t.Fatalf("%d entries acked, partial have %b", len(seen), seen[pid])
	}
	if s := h.r.Stats(); s.AcksSent != 2 || s.AckEntriesSent != n+1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestAckWithoutRouteDropped(t *testing.T) {
	h := newHarness(t, nil)
	h.r.Received(bg, h.buddy, frame.Result{Status: frame.Partial, Header: frame.Header{MsgID: frame.MsgID{1}}, Have: 1})
	h.advance(time.Second, DefaultAckDelay)
	if n := len(h.tr.all()); n != 0 {
		t.Fatalf("%d sends", n)
	}
	if s := h.r.Stats(); s.AckNoRoute != 1 || s.AckEntriesDropped != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestTakeAcks(t *testing.T) {
	h := newHarness(t, nil)
	h.routeUp()
	h.r.Received(bg, h.buddy, frame.Result{Status: frame.Partial, Header: frame.Header{MsgID: frame.MsgID{1}}, Have: 1})
	got := h.r.TakeAcks(h.buddy, 32)
	if len(got) != 1 || got[0].GetHave() != 1 {
		t.Fatalf("TakeAcks %v", got)
	}
	h.advance(time.Second, DefaultAckDelay)
	if n := len(h.tr.acks(t)); n != 0 {
		t.Fatalf("taken entries were sent too (%d ACKs)", n)
	}
}

// TestNeverResealed is the seal-once property: through random enqueues,
// ACKs, route changes, transport failures, restarts and time, every frame
// the router sends is byte-identical to the store's frame for that
// (message, fragment), and the stored frames never change.
func TestNeverResealed(t *testing.T) {
	for seed := range uint64(12) {
		h := newHarness(t, func(c *Config) {
			c.AckTimeout = time.Second
			c.MaxRetryDelay = 10 * time.Second
			c.Horizon = 10 * time.Minute
			c.Window = 3
		})
		rng := rand.New(rand.NewPCG(seed, 99))
		var msgs []*store.Outgoing
		for range 60 {
			switch op := rng.IntN(10); {
			case op < 3:
				msgs = append(msgs, h.enqueue(1+rng.IntN(650)))
			case op < 5 && len(msgs) > 0:
				m := msgs[rng.IntN(len(msgs))]
				mask := uint16(1 + rng.IntN(1<<len(m.Frames)-1))
				h.r.HandleAck(bg, h.buddy, &pb.Ack{Entries: []*pb.AckEntry{{MsgId: m.MsgID[:], Have: uint32(mask)}}})
			case op == 5:
				if rng.IntN(2) == 0 {
					h.reach.clear(h.buddy)
				} else {
					h.reach.set(h.buddy, Route{Peer: h.peer})
					h.r.RouteChanged(h.buddy)
				}
			case op == 6:
				if rng.IntN(3) == 0 {
					h.tr.setFail(errors.New("flaky"))
				} else {
					h.tr.setFail(nil)
				}
			case op == 7 && rng.IntN(4) == 0:
				h.restart()
			default:
				h.clock.Advance(time.Duration(rng.IntN(5000)) * time.Millisecond)
			}
			h.settle()
		}
		h.tr.setFail(nil)
		h.routeUp()
		h.advance(time.Minute, time.Second)

		sends := h.tr.data()
		checkFrames(t, h.st, h.buddy, sends)
		for _, m := range msgs {
			if o := h.outgoing(m.ID); !slices.EqualFunc(o.Frames, m.Frames, bytes.Equal) {
				t.Fatalf("seed %d: stored frames of %s changed", seed, m.MsgID)
			}
		}
		if len(msgs) > 0 && len(sends) == 0 {
			t.Fatalf("seed %d: nothing sent", seed)
		}
		h.r.Close()
	}
}
