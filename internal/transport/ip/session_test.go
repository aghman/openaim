package ip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
)

// sessPeer is a Node with Sessions on it and a log of its events.
type sessPeer struct {
	n *Node
	s *Sessions

	mu  sync.Mutex
	evs []SessionEvent
}

func newSessPeer(t *testing.T, no NodeOptions, so SessionOptions) *sessPeer {
	t.Helper()
	if no.Interval == 0 {
		no.Interval = -1
	}
	n := newTestNode(t, no)
	s, err := NewSessions(n, so)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	sp := &sessPeer{n: n, s: s}
	go func() {
		for e := range s.Events() {
			sp.mu.Lock()
			sp.evs = append(sp.evs, e)
			sp.mu.Unlock()
		}
	}()
	return sp
}

func (sp *sessPeer) info() peer.AddrInfo { return sp.n.Current().AddrInfo() }

func (sp *sessPeer) events() []SessionEvent {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return slices.Clone(sp.evs)
}

// waitEvent waits for an event matching f, at or after index from, and
// returns the index after it.
func (sp *sessPeer) waitEvent(t *testing.T, from int, what string, f func(SessionEvent) bool) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		evs := sp.events()
		for i := from; i < len(evs); i++ {
			if f(evs[i]) {
				return i + 1
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s event within 10s; events: %+v", what, evs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func upFrom(p peer.ID) func(SessionEvent) bool {
	return func(e SessionEvent) bool { return e.Peer == p && e.Up }
}

func downFrom(p peer.ID) func(SessionEvent) bool {
	return func(e SessionEvent) bool { return e.Peer == p && !e.Up }
}

func (sp *sessPeer) send(t *testing.T, to peer.AddrInfo, frames ...[]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := sp.s.Send(ctx, to, frames); err != nil {
		t.Fatal(err)
	}
}

// recv returns the next inbound frame.
func (sp *sessPeer) recv(t *testing.T) InboundFrame {
	t.Helper()
	select {
	case f, ok := <-sp.s.Inbound():
		if !ok {
			t.Fatal("inbound channel closed")
		}
		return f
	case <-time.After(15 * time.Second):
		t.Fatal("no inbound frame within 15s")
	}
	panic("unreachable")
}

// expect receives the next frame and checks it is want.
func (sp *sessPeer) expect(t *testing.T, want []byte) InboundFrame {
	t.Helper()
	f := sp.recv(t)
	if !bytes.Equal(f.Frame, want) {
		t.Fatalf("got frame %q from %s, want %q", f.Frame, f.Peer, want)
	}
	return f
}

func TestSessionsDirect(t *testing.T) {
	a := newSessPeer(t, NodeOptions{}, SessionOptions{})
	b := newSessPeer(t, NodeOptions{}, SessionOptions{})

	a.send(t, b.info(), []byte("one"), []byte("two"), bytes.Repeat([]byte{3}, MaxFrameLen))
	for _, want := range [][]byte{[]byte("one"), []byte("two"), bytes.Repeat([]byte{3}, MaxFrameLen)} {
		f := b.expect(t, want)
		if f.Peer != a.n.ID() || f.Local != b.n.ID() || f.Relayed || f.Path != "direct/tcp" || f.At.IsZero() {
			t.Fatalf("frame metadata %+v", f)
		}
	}
	// B answers knowing only A's peer ID: the connection A made is reused.
	b.send(t, peer.AddrInfo{ID: a.n.ID()}, []byte("back"))
	if f := a.expect(t, []byte("back")); f.Peer != b.n.ID() || f.Relayed {
		t.Fatalf("frame metadata %+v", f)
	}

	a.waitEvent(t, 0, "A up", func(e SessionEvent) bool {
		return e.Peer == b.n.ID() && e.Up && e.Path == "direct/tcp" && e.Local == a.n.ID()
	})
	b.waitEvent(t, 0, "B up", upFrom(a.n.ID()))
	ps, ok := a.s.Peer(b.n.ID())
	if !ok || !ps.Up || ps.Outbound != 1 || ps.Inbound != 1 || ps.InFrames != 1 || ps.Kept {
		t.Fatalf("A's session with B: %+v (found %v)", ps, ok)
	}
	if st := a.s.Stats(); st.Sends != 1 || st.OutFrames != 3 || st.StreamsOpened != 1 || st.InFrames != 1 {
		t.Errorf("A stats %+v", st)
	}
	if st := b.s.Stats(); st.InFrames != 3 || st.InBytes != 6+MaxFrameLen {
		t.Errorf("B stats %+v", st)
	}
}

// TestSessionsConcurrentSends: frames of one Send arrive in order and
// contiguously, whatever other Sends run at the same time.
func TestSessionsConcurrentSends(t *testing.T) {
	a := newSessPeer(t, NodeOptions{}, SessionOptions{FrameRate: -1, ByteRate: -1})
	b := newSessPeer(t, NodeOptions{}, SessionOptions{FrameRate: -1, ByteRate: -1})
	const senders, sends, batch = 8, 25, 3
	var wg sync.WaitGroup
	errs := make(chan error, senders*sends)
	for i := range senders {
		wg.Go(func() {
			for j := range sends {
				var frames [][]byte
				for k := range batch {
					frames = append(frames, fmt.Appendf(nil, "%d/%d/%d", i, j, k))
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				errs <- a.s.Send(ctx, b.info(), frames)
				cancel()
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	next := map[int]int{} // sender → next send index
	for range senders * sends {
		var i, j, k int
		for k0 := range batch {
			f := b.recv(t)
			if _, err := fmt.Sscanf(string(f.Frame), "%d/%d/%d", &i, &j, &k); err != nil {
				t.Fatal(err)
			}
			if k != k0 {
				t.Fatalf("frame %q: batch not contiguous", f.Frame)
			}
		}
		if j != next[i] {
			t.Fatalf("sender %d: send %d arrived, want %d", i, j, next[i])
		}
		next[i]++
	}
}

// relayPair is a relay R, a node B with a reservation on R, and a node A
// that knows B only by its circuit address.
type relayPair struct {
	a, b    *sessPeer
	circuit peer.AddrInfo // B through R
}

func newRelayPair(t *testing.T, limit *relay.RelayLimit, relayOnly bool) *relayPair {
	t.Helper()
	r := newTestHost(t)
	rl, err := StartRelay(r, RelayOptions{Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rl.Close() })
	b := newSessPeer(t, NodeOptions{Relays: []peer.AddrInfo{{ID: r.ID(), Addrs: r.Addrs()[:1]}}}, SessionOptions{})
	ca, err := CircuitAddr(hostAddr(t, r), b.n.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(b.n.Current().Addrs, ca.Equal) {
		t.Fatal("B has no relay reservation")
	}
	var ao NodeOptions
	if relayOnly {
		ao.Host.Gater = RelayOnlyGater{Peer: b.n.ID()}
	}
	a := newSessPeer(t, ao, SessionOptions{})
	return &relayPair{a: a, b: b, circuit: peer.AddrInfo{ID: b.n.ID(), Addrs: []ma.Multiaddr{ca}}}
}

func TestSessionsRelay(t *testing.T) {
	rp := newRelayPair(t, &relay.RelayLimit{Duration: time.Minute, Data: 1 << 20}, true)
	a, b := rp.a, rp.b
	a.send(t, rp.circuit, []byte("via relay"))
	if f := b.expect(t, []byte("via relay")); !f.Relayed || f.Path != "relay (limited)" || f.Peer != a.n.ID() {
		t.Fatalf("frame metadata %+v", f)
	}
	b.send(t, peer.AddrInfo{ID: a.n.ID()}, []byte("and back"))
	if f := a.expect(t, []byte("and back")); !f.Relayed || f.Peer != b.n.ID() {
		t.Fatalf("frame metadata %+v", f)
	}
	a.waitEvent(t, 0, "A up over relay", func(e SessionEvent) bool { return e.Up && e.Relayed && e.Path == "relay (limited)" })
}

// TestSessionsRelayResetReconnects: the relay cuts every circuit after 1 s;
// a kept session notices at once, reconnects, and later sends in both
// directions work.
func TestSessionsRelayResetReconnects(t *testing.T) {
	rp := newRelayPair(t, &relay.RelayLimit{Duration: time.Second, Data: 1 << 20}, true)
	a, b := rp.a, rp.b
	if err := a.s.Keep(rp.circuit); err != nil {
		t.Fatal(err)
	}
	i := a.waitEvent(t, 0, "up", upFrom(b.n.ID()))
	a.send(t, rp.circuit, []byte("before"))
	b.expect(t, []byte("before"))
	b.send(t, peer.AddrInfo{ID: a.n.ID()}, []byte("before, back"))
	a.expect(t, []byte("before, back"))

	i = a.waitEvent(t, i, "down after the relay reset", downFrom(b.n.ID()))
	a.waitEvent(t, i, "up again", upFrom(b.n.ID()))
	a.send(t, rp.circuit, []byte("after"))
	b.expect(t, []byte("after"))
	b.send(t, peer.AddrInfo{ID: a.n.ID()}, []byte("after, back"))
	a.expect(t, []byte("after, back"))
	if st := a.s.Stats(); st.StreamsOpened < 2 || st.Disconnects < 1 {
		t.Errorf("A stats %+v: want ≥ 2 opens and ≥ 1 disconnect", st)
	}
}

// TestSessionsMigrateToDirect: a session that started on a relay moves to a
// direct connection when one appears.
func TestSessionsMigrateToDirect(t *testing.T) {
	rp := newRelayPair(t, &relay.RelayLimit{Duration: time.Minute, Data: 1 << 20}, false)
	a, b := rp.a, rp.b
	a.send(t, rp.circuit, []byte("relayed"))
	if f := b.expect(t, []byte("relayed")); !f.Relayed {
		t.Fatalf("first frame over %s, want relay", f.Path)
	}
	b.send(t, peer.AddrInfo{ID: a.n.ID()}, []byte("relayed back"))
	if f := a.expect(t, []byte("relayed back")); !f.Relayed {
		t.Fatalf("reply over %s, want relay", f.Path)
	}

	// A direct connection appears, as after DCUtR or an identify-driven dial.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ah := a.n.Host()
	ah.Peerstore().AddAddrs(b.n.ID(), b.n.Host().Addrs(), time.Minute)
	if _, err := ah.Network().DialPeer(network.WithForceDirectDial(ctx, "test"), b.n.ID()); err != nil {
		t.Fatal(err)
	}
	direct := func(e SessionEvent) bool { return e.Up && !e.Relayed && e.Path == "direct/tcp" }
	a.waitEvent(t, 0, "A direct", direct)
	b.waitEvent(t, 0, "B direct", direct)
	a.send(t, rp.circuit, []byte("direct"))
	if f := b.expect(t, []byte("direct")); f.Relayed {
		t.Fatalf("frame after migration over %s", f.Path)
	}
	b.send(t, peer.AddrInfo{ID: a.n.ID()}, []byte("direct back"))
	if f := a.expect(t, []byte("direct back")); f.Relayed {
		t.Fatalf("reply after migration over %s", f.Path)
	}
	if a.s.Stats().Migrations != 1 || b.s.Stats().Migrations != 1 {
		t.Errorf("migrations: A %d, B %d; want 1 each", a.s.Stats().Migrations, b.s.Stats().Migrations)
	}
}

// TestSessionsSenderRotation: after A rotates, a kept session moves to the
// new host by itself, new sends leave from it, the old stream drains, and B
// can still reach A's old peer ID during the grace period.
func TestSessionsSenderRotation(t *testing.T) {
	a := newSessPeer(t, NodeOptions{Grace: time.Hour}, SessionOptions{})
	b := newSessPeer(t, NodeOptions{}, SessionOptions{})
	bInfo := b.info()
	oldA := a.n.ID()
	if err := a.s.Keep(bInfo); err != nil {
		t.Fatal(err)
	}
	a.send(t, bInfo, []byte("from old"))
	if f := b.expect(t, []byte("from old")); f.Peer != oldA {
		t.Fatalf("frame from %s, want %s", f.Peer, oldA)
	}

	rotate(t, a.n)
	newA := a.n.ID()
	b.waitEvent(t, 0, "up from A's new host", upFrom(newA))
	b.waitEvent(t, 0, "down from A's old host", downFrom(oldA))
	a.send(t, bInfo, []byte("from new"))
	if f := b.expect(t, []byte("from new")); f.Peer != newA {
		t.Fatalf("frame from %s, want %s", f.Peer, newA)
	}
	if ps, _ := a.s.Peer(b.n.ID()); ps.Outbound != 1 {
		t.Errorf("A holds %d outbound streams to B after rotation, want 1", ps.Outbound)
	}

	b.send(t, peer.AddrInfo{ID: oldA}, []byte("to old"))
	if f := a.expect(t, []byte("to old")); f.Local != oldA || f.Peer != b.n.ID() {
		t.Fatalf("frame metadata %+v", f)
	}
	b.send(t, peer.AddrInfo{ID: newA}, []byte("to new"))
	if f := a.expect(t, []byte("to new")); f.Local != newA {
		t.Fatalf("frame metadata %+v", f)
	}
}

// rawHost is a bare host connected to sp.
func rawHost(t *testing.T, sp *sessPeer) host.Host {
	t.Helper()
	h := newTestHost(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.Connect(ctx, sp.info()); err != nil {
		t.Fatal(err)
	}
	return h
}

// rawStream opens a plain /openaim/msg/1 stream from h to sp.
func rawStream(t *testing.T, h host.Host, sp *sessPeer) network.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := h.NewStream(ctx, sp.n.ID(), MsgProtocol)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Reset() })
	return s
}

// streamEnds waits until reading s fails.
func streamEnds(t *testing.T, s network.Stream) {
	t.Helper()
	s.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := s.Read(make([]byte, 1))
	if err == nil || isTimeout(err) {
		t.Fatalf("stream still open: %v", err)
	}
}

func TestSessionsInboundLimits(t *testing.T) {
	b := newSessPeer(t, NodeOptions{}, SessionOptions{MaxFrameLen: 1024, QueueLen: 8, MaxStreamsPerPeer: 2, FrameRate: -1, ByteRate: -1})

	t.Run("oversize", func(t *testing.T) {
		s := rawStream(t, rawHost(t, b), b)
		if err := WriteFrame(s, make([]byte, 1025)); err != nil {
			t.Fatal(err)
		}
		streamEnds(t, s)
		if st := b.s.Stats(); st.BadFrames != 1 || st.InFrames != 0 {
			t.Errorf("stats %+v", st)
		}
	})
	t.Run("zero length", func(t *testing.T) {
		s := rawStream(t, rawHost(t, b), b)
		if _, err := s.Write([]byte{0, 0}); err != nil {
			t.Fatal(err)
		}
		streamEnds(t, s)
		if st := b.s.Stats(); st.BadFrames != 2 {
			t.Errorf("stats %+v", st)
		}
	})
	t.Run("flood", func(t *testing.T) {
		h := rawHost(t, b)
		s := rawStream(t, h, b)
		var buf bytes.Buffer
		for i := range 20 {
			WriteFrame(&buf, []byte{byte(i)})
		}
		if _, err := s.Write(buf.Bytes()); err != nil {
			t.Fatal(err)
		}
		before := b.s.Stats().InFrames
		waitFor(t, func() bool { return b.s.Stats().InFrames == before+20 })
		if st := b.s.Stats(); st.QueueDrops != 12 {
			t.Errorf("queue drops = %d, want 12", st.QueueDrops)
		}
		for i := range 8 {
			if f := b.recv(t); f.Frame[0] != byte(i) {
				t.Fatalf("queued frame %d is %d", i, f.Frame[0])
			}
		}
		if ps, _ := b.s.Peer(h.ID()); ps.QueueDrops != 12 || ps.InFrames != 20 {
			t.Errorf("peer counters %+v", ps)
		}
	})
	t.Run("streams per peer", func(t *testing.T) {
		h := rawHost(t, b)
		var ss []network.Stream
		for i := range 3 {
			s := rawStream(t, h, b)
			WriteFrame(s, []byte{byte(i)})
			b.recv(t) // the stream is registered once its first frame is read
			ss = append(ss, s)
		}
		streamEnds(t, ss[0]) // the oldest was evicted
		if ps, _ := b.s.Peer(h.ID()); ps.Inbound != 2 || ps.Evicted != 1 {
			t.Errorf("peer %+v", ps)
		}
		if st := b.s.Stats(); st.StreamsEvicted != 1 {
			t.Errorf("stats %+v", st)
		}
		for _, s := range ss[1:] {
			if err := WriteFrame(s, []byte("still open")); err != nil {
				t.Fatal(err)
			}
			b.expect(t, []byte("still open"))
		}
	})
}

func TestSessionsIdleTimeout(t *testing.T) {
	b := newSessPeer(t, NodeOptions{}, SessionOptions{IdleTimeout: 300 * time.Millisecond})
	h := rawHost(t, b)
	s := rawStream(t, h, b)
	WriteFrame(s, []byte("hi"))
	b.expect(t, []byte("hi"))
	start := time.Now()
	streamEnds(t, s)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("idle stream closed after %v", d)
	}
	b.waitEvent(t, 0, "down after idle", downFrom(h.ID()))
	if st := b.s.Stats(); st.IdleCloses != 1 {
		t.Errorf("stats %+v", st)
	}
	if _, ok := b.s.Peer(h.ID()); ok {
		t.Error("idle session not forgotten")
	}
}

func TestSessionsRateLimit(t *testing.T) {
	b := newSessPeer(t, NodeOptions{}, SessionOptions{FrameRate: 50, FrameBurst: 5, ByteRate: -1})
	s := rawStream(t, rawHost(t, b), b)
	var buf bytes.Buffer
	for i := range 30 {
		WriteFrame(&buf, []byte{byte(i)})
	}
	start := time.Now()
	if _, err := s.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		if f := b.recv(t); f.Frame[0] != byte(i) {
			t.Fatalf("frame %d is %d", i, f.Frame[0])
		}
	}
	// 25 frames past the burst at 50/s take 0.5 s.
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Errorf("30 frames took %v; rate limit not applied", d)
	}
	if st := b.s.Stats(); st.RateLimited == 0 || st.QueueDrops != 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestSessionsKeepDrop(t *testing.T) {
	a := newSessPeer(t, NodeOptions{}, SessionOptions{})
	b := newSessPeer(t, NodeOptions{}, SessionOptions{})
	bid := b.n.ID()
	if err := a.s.Keep(b.info()); err != nil {
		t.Fatal(err)
	}
	// No frames needed: the kept stream is opened and B sees it.
	i := a.waitEvent(t, 0, "up", upFrom(bid))
	b.waitEvent(t, 0, "B up", upFrom(a.n.ID()))
	if ps, _ := a.s.Peer(bid); !ps.Kept || ps.Outbound != 1 {
		t.Fatalf("session %+v", ps)
	}

	// Losing the connection is noticed at once and repaired.
	a.n.Host().Network().ClosePeer(bid)
	i = a.waitEvent(t, i, "down", downFrom(bid))
	i = a.waitEvent(t, i, "up again", upFrom(bid))
	a.send(t, peer.AddrInfo{ID: bid}, []byte("still here"))
	b.expect(t, []byte("still here"))

	// After Drop nothing reconnects.
	j := len(b.events())
	a.s.Drop(bid)
	i = a.waitEvent(t, i, "down after drop", downFrom(bid))
	j = b.waitEvent(t, j, "B down after drop", downFrom(a.n.ID()))
	a.n.Host().Network().ClosePeer(bid)
	time.Sleep(500 * time.Millisecond)
	if evs := a.events(); len(evs) != i {
		t.Errorf("events after drop: %+v", evs[i:])
	}
	if evs := b.events(); len(evs) != j {
		t.Errorf("B events after drop: %+v", evs[j:])
	}
	if _, ok := a.s.Peer(bid); ok {
		t.Error("dropped session not forgotten")
	}
	// Sending still works (and opens a stream on demand).
	a.send(t, b.info(), []byte("on demand"))
	b.expect(t, []byte("on demand"))
}

func TestSessionsClose(t *testing.T) {
	a := newSessPeer(t, NodeOptions{}, SessionOptions{})
	b := newSessPeer(t, NodeOptions{}, SessionOptions{})
	if err := a.s.Keep(b.info()); err != nil {
		t.Fatal(err)
	}
	b.waitEvent(t, 0, "B up", upFrom(a.n.ID()))
	if err := a.s.Close(); err != nil {
		t.Fatal(err)
	}
	b.waitEvent(t, 0, "B down", downFrom(a.n.ID()))
	if _, ok := <-a.s.Inbound(); ok {
		t.Error("inbound channel open after Close")
	}
	if err := a.s.Send(context.Background(), b.info(), [][]byte{[]byte("x")}); !errors.Is(err, ErrSessionsClosed) {
		t.Errorf("Send after Close: %v", err)
	}
	if err := a.s.Keep(b.info()); !errors.Is(err, ErrSessionsClosed) {
		t.Errorf("Keep after Close: %v", err)
	}
	if err := a.s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// A no longer speaks /openaim/msg/1.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.s.Send(ctx, peer.AddrInfo{ID: a.n.ID()}, [][]byte{[]byte("x")}); err == nil {
		// The lazy protocol handshake can let the write itself succeed; the
		// stream must still die.
		waitFor(t, func() bool { ps, ok := b.s.Peer(a.n.ID()); return !ok || ps.Outbound == 0 })
	}
}

func TestSessionsSendErrors(t *testing.T) {
	a := newSessPeer(t, NodeOptions{}, SessionOptions{SendTimeout: time.Second, OpenTimeout: 200 * time.Millisecond, ReconnectMin: 50 * time.Millisecond})
	if err := a.s.Send(context.Background(), a.info(), [][]byte{{}}); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("empty frame: %v", err)
	}
	if err := a.s.Send(context.Background(), a.info(), [][]byte{make([]byte, MaxFrameLen+1)}); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("oversize frame: %v", err)
	}
	nobody := newTestHost(t)
	gone := peer.AddrInfo{ID: nobody.ID(), Addrs: nobody.Addrs()}
	nobody.Close()
	start := time.Now()
	err := a.s.Send(context.Background(), gone, [][]byte{[]byte("x")})
	var se *SendError
	if !errors.As(err, &se) || se.Peer != gone.ID || se.Attempts < 1 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("send to a closed host: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("failed send took %v, want about SendTimeout", d)
	}
	if st := a.s.Stats(); st.SendFailures != 1 || st.OpenFailures < 1 {
		t.Errorf("stats %+v", st)
	}
	if _, ok := a.s.Peer(gone.ID); ok {
		t.Error("session for an unreachable peer kept")
	}
	if _, err := NewSessions(a.n, SessionOptions{MaxFrameLen: MaxFrameLen + 1}); err == nil {
		t.Error("MaxFrameLen over the wire limit accepted")
	}
}
