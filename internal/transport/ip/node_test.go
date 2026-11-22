package ip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// fakeClock fires timers only when advanced.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c    *fakeClock
	when time.Time
	ch   chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, when: c.now.Add(d), ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	i := slices.Index(t.c.timers, t)
	if i < 0 {
		return false
	}
	t.c.timers = slices.Delete(t.c.timers, i, i+1)
	return true
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	c.timers = slices.DeleteFunc(c.timers, func(t *fakeTimer) bool {
		if t.when.After(c.now) {
			return false
		}
		t.ch <- c.now
		return true
	})
}

// waitTimer waits until a timer due d from now is pending.
func (c *fakeClock) waitTimer(t *testing.T, d time.Duration) {
	t.Helper()
	waitFor(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return slices.ContainsFunc(c.timers, func(ft *fakeTimer) bool { return ft.when.Equal(c.now.Add(d)) })
	})
}

var loopbackTCP = []string{"/ip4/127.0.0.1/tcp/0"}

func newTestNode(t *testing.T, o NodeOptions) *Node {
	t.Helper()
	if o.Host.Listen == nil && o.Listen == nil {
		o.Host.Listen = loopbackTCP
	}
	n, err := NewNode(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func rotate(t *testing.T, n *Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
}

// changes records HostChange notifications.
type changes struct {
	mu sync.Mutex
	cs []HostChange
}

func (c *changes) add(hc HostChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cs = append(c.cs, hc)
}

func (c *changes) get() []HostChange {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.cs)
}

func TestNodeRotationIsUnlinkable(t *testing.T) {
	n := newTestNode(t, NodeOptions{Interval: -1, Clock: newFakeClock()})
	buddy := newTestHost(t)
	var cs changes
	n.Subscribe(cs.add)

	old := n.Host()
	if n.Generation() != 1 || n.Current().Reason != RotationStart {
		t.Fatalf("start: generation %d, reason %q", n.Generation(), n.Current().Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.Connect(ctx, peer.AddrInfo{ID: buddy.ID(), Addrs: buddy.Addrs()}); err != nil {
		t.Fatal(err)
	}

	rotate(t, n)
	cur := n.Host()
	if cur == old || cur.ID() == old.ID() {
		t.Fatal("rotation kept the peer ID")
	}
	if crypto.KeyEqual(cur.Peerstore().PubKey(cur.ID()), old.Peerstore().PubKey(old.ID())) {
		t.Fatal("rotation kept the key")
	}
	if p := sharedPort(cur, old); p != "" {
		t.Errorf("new host reuses old host's port %s", p)
	}
	// Nothing the old host learned carries over.
	if len(cur.Peerstore().Addrs(buddy.ID())) != 0 || slices.Contains(cur.Peerstore().Peers(), buddy.ID()) {
		t.Error("new host's peerstore knows the buddy the old host talked to")
	}
	if len(cur.Network().Peers()) != 0 {
		t.Errorf("new host has connections: %v", cur.Network().Peers())
	}

	got := cs.get()
	if len(got) != 1 {
		t.Fatalf("subscriber saw %d changes, want 1", len(got))
	}
	c := got[0]
	if c.ID != cur.ID() || c.Host != cur || c.Previous != old.ID() || c.Generation != 2 || c.Reason != RotationManual {
		t.Errorf("change = %+v", c)
	}
	if len(c.Addrs) == 0 || !slices.EqualFunc(c.Addrs, cur.Addrs(), ma.Multiaddr.Equal) {
		t.Errorf("change addrs %v, host addrs %v", c.Addrs, cur.Addrs())
	}
	if n.Current().ID != cur.ID() {
		t.Error("Current() is stale")
	}
	if hs := n.LiveHosts(); len(hs) != 2 || hs[0] != old || hs[1] != cur {
		t.Errorf("live hosts = %v, want [old cur]", hs)
	}
}

// TestNodeRotationKeepsStreams is the ticket's acceptance test: rotation
// keeps live buddy sessions for the grace period, after which the old host
// closes and only the new peer ID answers.
func TestNodeRotationKeepsStreams(t *testing.T) {
	clk := newFakeClock()
	const grace = 5 * time.Minute
	n := newTestNode(t, NodeOptions{Interval: -1, Grace: grace, Clock: clk})
	n.SetStreamHandler(MsgProtocol, echo)
	buddy := newTestHost(t)
	buddy.SetStreamHandler(MsgProtocol, echo)
	var cs changes
	n.Subscribe(cs.add)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	oldInfo := n.Current().AddrInfo()
	if err := buddy.Connect(ctx, oldInfo); err != nil {
		t.Fatal(err)
	}
	in, err := buddy.NewStream(ctx, oldInfo.ID, MsgProtocol) // buddy → node
	if err != nil {
		t.Fatal(err)
	}
	defer in.Reset()
	out, err := n.NewStream(ctx, buddy.ID(), MsgProtocol) // node → buddy
	if err != nil {
		t.Fatal(err)
	}
	defer out.Reset()
	for _, s := range []network.Stream{in, out} {
		s.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := pump(s, 200, 200); err != nil {
			t.Fatalf("before rotation: %v", err)
		}
	}

	rotate(t, n)
	newInfo := cs.get()[0].AddrInfo()

	// Old streams keep working during the grace period.
	for _, s := range []network.Stream{in, out} {
		if _, err := pump(s, 4096, 200); err != nil {
			t.Fatalf("during grace: %v", err)
		}
	}
	// New dials reach the new host, and new outbound streams leave from it.
	if err := buddy.Connect(ctx, newInfo); err != nil {
		t.Fatal(err)
	}
	in2, err := buddy.NewStream(ctx, newInfo.ID, MsgProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer in2.Reset()
	in2.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := pump(in2, 200, 200); err != nil {
		t.Fatal(err)
	}
	out2, err := n.NewStream(ctx, buddy.ID(), MsgProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer out2.Reset()
	if out2.Conn().LocalPeer() != newInfo.ID {
		t.Errorf("new outbound stream from %s, want %s", out2.Conn().LocalPeer(), newInfo.ID)
	}

	// After the grace period the old host is gone.
	clk.waitTimer(t, grace)
	clk.Advance(grace)
	waitFor(t, func() bool { return len(n.LiveHosts()) == 1 })
	for _, s := range []network.Stream{in, out} {
		s.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := pump(s, 200, 200); err == nil {
			t.Error("old stream still works after the grace period")
		}
	}
	if _, err := pump(in2, 200, 200); err != nil {
		t.Fatalf("new stream after grace: %v", err)
	}
	buddy.Network().ClosePeer(oldInfo.ID)
	buddy.Peerstore().AddAddrs(oldInfo.ID, oldInfo.Addrs, time.Minute)
	dctx, dcancel := context.WithTimeout(ctx, 2*time.Second)
	defer dcancel()
	if s, err := buddy.NewStream(dctx, oldInfo.ID, MsgProtocol); err == nil {
		s.Reset()
		t.Error("old peer ID still answers after the grace period")
	}
}

func TestNodeScheduledRotation(t *testing.T) {
	clk := newFakeClock()
	const interval, grace = time.Hour, time.Minute
	var cs changes
	n := newTestNode(t, NodeOptions{Interval: interval, Jitter: -1, Grace: grace, Clock: clk})
	n.Subscribe(cs.add)
	first := n.ID()

	clk.waitTimer(t, interval)
	clk.Advance(interval - time.Second)
	time.Sleep(50 * time.Millisecond)
	if n.Generation() != 1 {
		t.Fatal("rotated early")
	}
	clk.Advance(time.Second)
	waitFor(t, func() bool { return n.Generation() == 2 })
	if c := cs.get()[0]; c.Reason != RotationScheduled || c.Previous != first {
		t.Errorf("change = %+v", c)
	}
	clk.waitTimer(t, grace)
	clk.Advance(grace)
	waitFor(t, func() bool { return len(n.LiveHosts()) == 1 })

	// A manual rotation restarts the schedule from now.
	clk.waitTimer(t, interval-grace)
	clk.Advance(interval / 2)
	rotate(t, n)
	clk.waitTimer(t, interval)
	clk.Advance(interval / 2)
	time.Sleep(50 * time.Millisecond)
	if g := n.Generation(); g != 3 {
		t.Fatalf("generation %d after the old schedule's due time, want 3", g)
	}
	clk.Advance(interval / 2)
	waitFor(t, func() bool { return n.Generation() == 4 })
}

func TestNodeAttach(t *testing.T) {
	clk := newFakeClock()
	n := newTestNode(t, NodeOptions{Interval: -1, Grace: time.Minute, Clock: clk})

	var mu sync.Mutex
	var log []string
	add := func(s string) { mu.Lock(); log = append(log, s); mu.Unlock() }
	getLog := func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(log) }
	fail := false
	ctx := context.Background()
	detach, err := n.Attach(ctx, func(_ context.Context, h host.Host) (func(), error) {
		if fail {
			return nil, errors.New("boom")
		}
		// The new host is not current while it starts up.
		add(fmt.Sprintf("start %d current=%v", len(n.LiveHosts()), n.Host() == h))
		return func() { add(fmt.Sprintf("stop %v", n.Host() == h)) }, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rotate(t, n)
	clk.waitTimer(t, time.Minute)
	clk.Advance(time.Minute)
	waitFor(t, func() bool { return len(n.LiveHosts()) == 1 })
	want := []string{"start 1 current=true", "start 2 current=false", "stop false"}
	if got := getLog(); !slices.Equal(got, want) {
		t.Errorf("log = %q, want %q", got, want)
	}

	// A failing attachment aborts the rotation; the old host stays current.
	fail = true
	before := n.Host()
	if err := n.Rotate(ctx); err == nil {
		t.Fatal("rotation succeeded with a failing attachment")
	}
	if n.Host() != before || len(n.LiveHosts()) != 1 {
		t.Error("failed rotation changed the current host")
	}
	fail = false

	detach()
	if got := getLog(); got[len(got)-1] != "stop true" {
		t.Errorf("detach did not stop on the current host: %q", got)
	}
	rotate(t, n)
	if got := getLog(); len(got) != 4 {
		t.Errorf("attachment ran after detach: %q", got)
	}
}

func TestNodeRotationWithRelay(t *testing.T) {
	r := newTestHost(t)
	rl, err := StartRelay(r, RelayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	relayInfo := peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()[:1]}
	var mu sync.Mutex
	reserved := map[uint64]bool{}
	n := newTestNode(t, NodeOptions{
		Interval: -1,
		Grace:    -1, // close the old host at once
		Relays:   []peer.AddrInfo{relayInfo},
		OnReservation: func(gen uint64, _ peer.ID, e ReservationEvent) {
			mu.Lock()
			reserved[gen] = reserved[gen] || e.Err == nil
			mu.Unlock()
		},
	})
	n.SetStreamHandler(MsgProtocol, echo)
	rotate(t, n)
	mu.Lock()
	ok := reserved[2]
	mu.Unlock()
	if !ok {
		t.Fatal("new host became current before its relay reservation")
	}
	c := n.Current()
	circuit, err := CircuitAddr(hostAddr(t, r), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(c.Addrs, circuit.Equal) {
		t.Fatalf("change addrs %v lack circuit %s", c.Addrs, circuit)
	}
	if len(n.LiveHosts()) != 1 {
		t.Error("old host still running with Grace < 0")
	}

	// A dialer that knows only the circuit address reaches the new host.
	d := newTestHost(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Connect(ctx, peer.AddrInfo{ID: c.ID, Addrs: []ma.Multiaddr{circuit}}); err != nil {
		t.Fatal(err)
	}
	s, err := d.NewStream(network.WithAllowLimitedConn(ctx, "test"), c.ID, MsgProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Reset()
	s.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pump(s, 200, 200); err != nil {
		t.Fatal(err)
	}
	if !IsRelayed(s.Conn()) {
		t.Errorf("stream over %s, want relay", PathOf(s.Conn()))
	}
}

func TestNodeListenPorts(t *testing.T) {
	p1, p2 := freePort(t), freePort(t)
	fixed := func(p int) []string { return []string{fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", p)} }

	// One fixed port can't be used by overlapping generations.
	n := newTestNode(t, NodeOptions{Interval: -1, Clock: newFakeClock(), Listen: func(uint64) []string { return fixed(p1) }})
	err := n.Rotate(context.Background())
	if err == nil {
		t.Fatal("rotation onto the same port succeeded")
	}
	if !errors.Is(err, ErrPortReuse) && !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("err = %v, want ErrPortReuse", err)
	}
	if n.Generation() != 1 || len(n.LiveHosts()) != 1 {
		t.Error("failed rotation left a second host")
	}
	n.Close()

	// Alternating two forwarded ports works.
	n = newTestNode(t, NodeOptions{Interval: -1, Grace: -1, Listen: func(g uint64) []string {
		return fixed([]int{p1, p2}[g%2])
	}})
	for range 2 {
		rotate(t, n)
		want := []int{p1, p2}[n.Generation()%2]
		if got := n.Host().Addrs()[0].String(); !strings.HasSuffix(got, fmt.Sprintf("/tcp/%d", want)) {
			t.Errorf("generation %d listens on %s, want port %d", n.Generation(), got, want)
		}
	}
}

func TestNodeOptionsAndClose(t *testing.T) {
	key, _, _ := crypto.GenerateEd25519Key(nil)
	if _, err := NewNode(NodeOptions{Host: HostOptions{Key: key}}); err == nil {
		t.Error("NewNode accepted Host.Key")
	}
	if _, err := NewNode(NodeOptions{Interval: time.Hour, Jitter: time.Hour}); err == nil {
		t.Error("NewNode accepted jitter ≥ interval")
	}

	fixed := newTestNode(t, NodeOptions{FixedKey: key})
	want, _ := peer.IDFromPrivateKey(key)
	if fixed.ID() != want {
		t.Error("FixedKey not used")
	}
	if err := fixed.Rotate(context.Background()); !errors.Is(err, ErrFixedKey) {
		t.Errorf("Rotate on a fixed-key node: %v", err)
	}

	n := newTestNode(t, NodeOptions{Grace: time.Hour, Clock: newFakeClock()})
	rotate(t, n)
	hs := n.LiveHosts()
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	for _, h := range hs {
		if len(h.Network().ListenAddresses()) != 0 {
			t.Error("host still listening after Close")
		}
	}
	if err := n.Rotate(context.Background()); !errors.Is(err, ErrNodeClosed) {
		t.Errorf("Rotate after Close: %v", err)
	}
	if err := n.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestJitter(t *testing.T) {
	lo := jitter(24*time.Hour, time.Hour, func(int64) int64 { return 0 })
	hi := jitter(24*time.Hour, time.Hour, func(k int64) int64 { return k - 1 })
	if lo != 23*time.Hour || hi != 25*time.Hour {
		t.Errorf("jitter range [%v, %v], want [23h, 25h]", lo, hi)
	}
	if d := jitter(time.Hour, -1, nil); d != time.Hour {
		t.Errorf("no jitter: %v", d)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
