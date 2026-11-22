package router

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/store"
)

// node is one side of a two-daemon test, wired the way the daemon will be:
// Receiver → ReachTable.Heard + Router.Received, ReachTable.OnChange →
// Router.RouteChanged, real sealing for ACKs.
type node struct {
	st    *store.Store
	r     *Router
	reach *ReachTable
	recv  *frame.Receiver
	tr    *fakeTransport
	buddy int64 // the other side, in our store
	send  frame.ConvKey

	mu        sync.Mutex
	delivered map[frame.MsgID]int
}

func newNode(t *testing.T, c *fakeClock, jobs *atomic.Int64, send, recvKey frame.ConvKey, seed byte) *node {
	n := &node{st: openStore(t), reach: NewReachTable(), tr: &fakeTransport{clock: c}, send: send,
		delivered: map[frame.MsgID]int{}}
	n.buddy = addBuddy(t, n.st, seed)
	kr := NewKeyring()
	kr.Now = c.Now
	kr.Set(n.buddy, recvKey)
	n.recv = &frame.Receiver{Keys: kr, Dedup: n.st.Dedup(), Now: c.Now}
	seal := func(_ context.Context, _ int64, ct frame.ContentType, b []byte) ([][]byte, error) {
		now := c.Now()
		in := frame.Inner{Type: ct, Time: frame.Timestamp(now), Body: b}
		s, err := frame.Seal(send, send.Tag(frame.Day(now)), frame.LayoutIP, in.Marshal())
		if err != nil {
			return nil, err
		}
		return s.Frames, nil
	}
	r, err := New(Config{Store: n.st, Transport: n.tr, Reach: n.reach, Seal: seal, Clock: c, jobs: jobs,
		AckTimeout: time.Second, MaxRetryDelay: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	n.r = r
	n.reach.OnChange = r.RouteChanged
	return n
}

// receive is the daemon's inbound path for frames from peer p.
func (n *node) receive(p peer.ID, frames [][]byte, now time.Time) {
	for _, f := range frames {
		res, err := n.recv.Accept(f)
		if err != nil {
			continue
		}
		if res.Status != frame.Duplicate {
			n.reach.Heard(n.buddy, p, now)
		}
		if res.Status == frame.Delivered && res.Message.Inner.Type == frame.IM {
			n.mu.Lock()
			n.delivered[res.Header.MsgID]++
			n.mu.Unlock()
		}
		n.r.Received(context.Background(), n.buddy, res)
	}
}

// TestOfflineBuddyComesBack is the ticket's acceptance test: messages queued
// while the buddy is offline are delivered once it comes back, each exactly
// once, and acked; no frame is ever sealed again.
func TestOfflineBuddyComesBack(t *testing.T) {
	c := newFakeClock()
	jobs := new(atomic.Int64)
	kAB, kBA := randKey(t), randKey(t)
	a := newNode(t, c, jobs, kAB, kBA, 2)
	b := newNode(t, c, jobs, kBA, kAB, 1)
	var bOnline atomic.Bool
	a.tr.deliver = func(r Route, frames [][]byte) {
		if r.Peer == "peerB" && bOnline.Load() {
			b.receive("peerA", frames, c.Now())
		}
	}
	b.tr.deliver = func(r Route, frames [][]byte) {
		if r.Peer == "peerA" {
			a.receive("peerB", frames, c.Now())
		}
	}
	step := func(d time.Duration) {
		c.Advance(d)
		settle(t, c, jobs)
	}

	// B is offline, but A holds a stale (still unexpired) record for it:
	// sends go nowhere and are retried with backoff.
	now := c.Now()
	if err := a.reach.Update(a.buddy, FromRendezvous, IPHint{Peer: "peerB", Seq: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	var msgs []*store.Outgoing
	for i := range 5 {
		msgs = append(msgs, enqueueTo(t, a.st, a.r, c, a.buddy, kAB, 100+130*i))
	}
	settle(t, c, jobs)
	for range 30 {
		step(time.Second)
	}
	if n, _ := a.st.CountOutgoing(context.Background(), store.Queued); n != len(msgs) {
		t.Fatalf("%d queued while B is offline", n)
	}

	// B comes back and announces itself with a REACH.
	bOnline.Store(true)
	now = c.Now()
	if err := a.reach.Update(a.buddy, FromReach, IPHint{Peer: "peerB", Seq: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	settle(t, c, jobs)
	for range 5 {
		step(DefaultAckDelay)
	}

	for _, m := range msgs {
		o, err := a.st.Outgoing(context.Background(), m.ID)
		if err != nil {
			t.Fatal(err)
		}
		if o.State != store.Acked {
			t.Fatalf("message %s is %s (mask %b) after B came back", m.MsgID, o.State, o.AckedMask)
		}
	}
	b.mu.Lock()
	for _, m := range msgs {
		if b.delivered[m.MsgID] != 1 {
			t.Fatalf("message %s delivered %d times", m.MsgID, b.delivered[m.MsgID])
		}
	}
	b.mu.Unlock()
	checkFrames(t, a.st, a.buddy, a.tr.data())

	// B answers over the session A reached it on: B learned A's route from
	// the authenticated frames, not from any advertisement.
	if r, ok := b.reach.IPRoute(b.buddy, c.Now()); !ok || r.Peer != "peerA" || !r.Live {
		t.Fatalf("B's route to A: %+v %v", r, ok)
	}
	reply := enqueueTo(t, b.st, b.r, c, b.buddy, kBA, 10)
	settle(t, c, jobs)
	step(DefaultAckDelay)
	if o, _ := b.st.Outgoing(context.Background(), reply.ID); o.State != store.Acked {
		t.Fatalf("reply is %s", o.State)
	}
	if s := a.r.Stats(); s.UnknownAcks != 0 || s.AcksSent == 0 {
		t.Fatalf("A stats %+v", s)
	}
}

// TestLostFragmentRepaired drops one fragment on the way and checks that
// the retry carries only that fragment and completes the message.
func TestLostFragmentRepaired(t *testing.T) {
	c := newFakeClock()
	jobs := new(atomic.Int64)
	kAB, kBA := randKey(t), randKey(t)
	a := newNode(t, c, jobs, kAB, kBA, 2)
	b := newNode(t, c, jobs, kBA, kAB, 1)
	var dropped atomic.Bool
	a.tr.deliver = func(_ Route, frames [][]byte) {
		var pass [][]byte
		for _, f := range frames {
			if h, _ := frame.ParseHeader(f); h.Index == 2 && dropped.CompareAndSwap(false, true) {
				continue
			}
			pass = append(pass, f)
		}
		b.receive("peerA", pass, c.Now())
	}
	b.tr.deliver = func(_ Route, frames [][]byte) { a.receive("peerB", frames, c.Now()) }
	now := c.Now()
	if err := a.reach.Update(a.buddy, FromReach, IPHint{Peer: "peerB", Seq: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	m := enqueueTo(t, a.st, a.r, c, a.buddy, kAB, 520)
	settle(t, c, jobs)
	c.Advance(DefaultAckDelay)
	settle(t, c, jobs)
	if o, _ := a.st.Outgoing(context.Background(), m.ID); o.AckedMask != 0b1011 {
		t.Fatalf("mask %04b after the first attempt", o.AckedMask)
	}
	for range 20 {
		c.Advance(200 * time.Millisecond)
		settle(t, c, jobs)
	}
	if o, _ := a.st.Outgoing(context.Background(), m.ID); o.State != store.Acked {
		t.Fatalf("state %s", o.State)
	}
	sends := a.tr.data()
	if len(sends) != 2 || len(sends[1].frames) != 1 {
		t.Fatalf("%d sends; the retry should carry exactly the lost fragment", len(sends))
	}
	checkFrames(t, a.st, a.buddy, sends)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.delivered[m.MsgID] != 1 {
		t.Fatalf("delivered %d times", b.delivered[m.MsgID])
	}
}
