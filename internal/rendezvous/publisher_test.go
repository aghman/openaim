package rendezvous

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/frame"
)

// self is a mutable "where we are now".
type self struct {
	mu sync.Mutex
	ai peer.AddrInfo
}

func (s *self) get() peer.AddrInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ai
}

func (s *self) set(id peer.ID, addrs []ma.Multiaddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ai = peer.AddrInfo{ID: id, Addrs: addrs}
}

// events collects PublishEvents.
type events struct {
	mu sync.Mutex
	es []PublishEvent
}

func (e *events) add(ev PublishEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.es = append(e.es, ev)
}

func (e *events) len() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.es)
}

// since waits until there are n events after the first from, and returns
// them.
func (e *events) wait(t *testing.T, from, n int) []PublishEvent {
	t.Helper()
	waitFor(t, func() bool { return e.len() >= from+n })
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]PublishEvent(nil), e.es[from:]...)
}

func newTestPublisher(t *testing.T, o PublisherOptions) *Publisher {
	t.Helper()
	p, err := NewPublisher(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// idle waits until the publisher sleeps on its run-loop timer until want,
// and checks no put happened meanwhile beyond the n events so far.
func idle(t *testing.T, clk *fakeClock, ev *events, n int, want time.Time) {
	t.Helper()
	clk.waitTimer(t, want)
	time.Sleep(10 * time.Millisecond) // nothing more is coming
	if got := ev.len(); got != n {
		t.Fatalf("%d puts, want %d", got, n)
	}
	if at, _ := clk.nextTimer(); !at.Equal(want) {
		t.Fatalf("next wake %v, want %v", at, want)
	}
}

func TestPublisherSchedule(t *testing.T) {
	ab, ba := newPair(t, 0xA1, 0xB0)
	ac, ca := newPair(t, 0xA1, 0xC2)
	clk := newFakeClock(testNow)
	d := newMemDHT()
	var me self
	me.set(testPeer(t, 1), maddrs(t, "/ip4/192.0.2.1/tcp/4001"))
	var ev events
	p := newTestPublisher(t, PublisherOptions{Store: d, Self: me.get, Clock: clk, PutInterval: -1, OnPublish: ev.add})
	day := frame.Day(testNow)
	pre := dayStart(day + 1).Add(-DefaultPrepublish)

	p.SetPair(ab)
	p.SetPair(ac)
	es := ev.wait(t, 0, 2)
	for _, e := range es {
		if e.Err != nil || e.Day != day || e.ID != testPeer(t, 1) || e.Seq != uint64(testNow.UnixMilli()) {
			t.Errorf("event %+v", e)
		}
	}
	idle(t, clk, &ev, 2, pre)
	ctx := context.Background()
	for _, kdir := range [][32]byte{ba.Recv, ca.Recv} {
		f, err := Lookup(ctx, d, kdir, testNow)
		if err != nil || f.ID != testPeer(t, 1) || !f.ExpiresAt.Equal(testNow.Add(DefaultTTL)) {
			t.Fatalf("lookup: %+v, %v", f, err)
		}
	}

	// Republish with nothing changed puts nothing; with new addresses, it
	// puts both records again, with a higher seq in the same millisecond.
	p.Republish()
	idle(t, clk, &ev, 2, pre)
	me.set(testPeer(t, 1), maddrs(t, "/ip4/192.0.2.1/tcp/4001", "/ip4/192.0.2.1/udp/4001/quic-v1"))
	p.Republish()
	for _, e := range ev.wait(t, 2, 2) {
		if e.Seq != uint64(testNow.UnixMilli())+1 {
			t.Errorf("republish seq %d", e.Seq)
		}
	}
	idle(t, clk, &ev, 4, pre)
	if f, _ := Lookup(ctx, d, ba.Recv, testNow); len(f.Addrs) != 2 {
		t.Errorf("lookup after address change: %v", f.Addrs)
	}

	// An hour before midnight, tomorrow's records; today's are not refreshed.
	clk.Set(pre)
	for _, e := range ev.wait(t, 4, 2) {
		if e.Day != day+1 {
			t.Errorf("prepublish event %+v", e)
		}
	}
	midnight := dayStart(day + 1)
	idle(t, clk, &ev, 6, midnight)
	// A buddy looking up across midnight finds a record either side.
	for _, at := range []time.Time{midnight.Add(-time.Minute), midnight.Add(time.Minute)} {
		if _, err := Lookup(ctx, d, ba.Recv, at); err != nil {
			t.Errorf("lookup at %v: %v", at, err)
		}
	}

	// Midnight: nothing to do, tomorrow's became today's. 12 h after the
	// prepublish, it is refreshed.
	clk.Set(midnight)
	refresh := pre.Add(DefaultRefresh)
	idle(t, clk, &ev, 6, refresh)
	p.RemovePair(ac.Them)
	clk.Set(refresh)
	es = ev.wait(t, 6, 1)
	if len(es) != 1 || es[0].Buddy != ab.Them || es[0].Day != day+1 {
		t.Errorf("refresh events %+v", es)
	}
	idle(t, clk, &ev, 7, dayStart(day+2).Add(-DefaultPrepublish))
}

func TestPublisherRetry(t *testing.T) {
	ab, ba := newPair(t, 0xA1, 0xB0)
	clk := newFakeClock(testNow)
	d := newMemDHT()
	d.setFail(errors.New("no peers"))
	var me self
	me.set(testPeer(t, 1), nil)
	var ev events
	p := newTestPublisher(t, PublisherOptions{Store: d, Self: me.get, Clock: clk, PutInterval: -1, OnPublish: ev.add})
	p.SetPair(ab)

	n := 0
	for _, backoff := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		if es := ev.wait(t, n, 1); es[0].Err == nil {
			t.Fatal("put should have failed")
		}
		n++
		next := clk.Now().Add(backoff)
		idle(t, clk, &ev, n, next)
		if backoff == 4*time.Minute {
			d.setFail(nil)
		}
		clk.Set(next)
	}
	if es := ev.wait(t, n, 1); es[0].Err != nil {
		t.Fatal(es[0].Err)
	}
	if _, err := Lookup(context.Background(), d, ba.Recv, clk.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestPublisherBackoffCap(t *testing.T) {
	ab, _ := newPair(t, 0xA1, 0xB0)
	clk := newFakeClock(testNow)
	d := newMemDHT()
	d.setFail(errors.New("no peers"))
	var me self
	me.set(testPeer(t, 1), nil)
	var ev events
	p := newTestPublisher(t, PublisherOptions{Store: d, Self: me.get, Clock: clk, PutInterval: -1,
		Retry: time.Minute, MaxRetry: 5 * time.Minute, OnPublish: ev.add})
	p.SetPair(ab)
	waits := []time.Duration{1, 2, 4, 5, 5}
	for i, w := range waits {
		ev.wait(t, i, 1)
		next := clk.Now().Add(w * time.Minute)
		idle(t, clk, &ev, i+1, next)
		clk.Set(next)
	}
}

func TestPublisherRateLimit(t *testing.T) {
	clk := newFakeClock(testNow)
	d := newMemDHT()
	var me self
	me.set(testPeer(t, 1), nil)
	var ev events
	p := newTestPublisher(t, PublisherOptions{Store: d, Self: me.get, Clock: clk, PutInterval: time.Second, OnPublish: ev.add})
	for b := byte(0xB0); b < 0xB3; b++ {
		ab, _ := newPair(t, 0xA1, b)
		p.SetPair(ab)
	}
	// SetPair kicks a round each time; whichever round runs, puts start one
	// second apart.
	waitFor(t, func() bool { return ev.len() >= 1 })
	for i := 1; i < 3; i++ {
		next := testNow.Add(time.Duration(i) * time.Second)
		clk.waitTimer(t, next)
		time.Sleep(10 * time.Millisecond)
		if ev.len() != i {
			t.Fatalf("%d puts before %v", ev.len(), next)
		}
		clk.Set(next)
		waitFor(t, func() bool { return ev.len() >= i+1 })
	}
}

// blockingStore blocks puts until ctx ends or release is closed.
type blockingStore struct {
	release        chan struct{}
	inFlight, peak atomic.Int32
	done           atomic.Int32
}

func (s *blockingStore) PutRendezvous(ctx context.Context, _ ed25519.PrivateKey, _ uint64, _ []byte) (string, error) {
	n := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for {
		p := s.peak.Load()
		if n <= p || s.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-s.release:
		s.done.Add(1)
		return "", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestPublisherConcurrencyAndClose(t *testing.T) {
	s := &blockingStore{release: make(chan struct{})}
	var me self // no peer ID until every pair is in, so one round has them all
	p, err := NewPublisher(PublisherOptions{Store: s, Self: me.get, PutInterval: -1, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	for b := byte(0xB0); b < 0xB6; b++ {
		ab, _ := newPair(t, 0xA1, b)
		p.SetPair(ab)
	}
	me.set(testPeer(t, 1), nil)
	p.Republish()
	waitFor(t, func() bool { return s.inFlight.Load() == 2 })
	time.Sleep(20 * time.Millisecond)
	if s.peak.Load() != 2 {
		t.Errorf("peak %d puts in flight, want 2", s.peak.Load())
	}
	// Close cancels the puts in flight and returns.
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung")
	}
	if s.inFlight.Load() != 0 || s.done.Load() != 0 {
		t.Errorf("after Close: %d in flight, %d done", s.inFlight.Load(), s.done.Load())
	}
	p.Close() // idempotent
}

func TestPublisherOptions(t *testing.T) {
	d := newMemDHT()
	self := func() peer.AddrInfo { return peer.AddrInfo{} }
	for name, o := range map[string]PublisherOptions{
		"no store":            {Self: self},
		"no self":             {Store: d},
		"TTL too long":        {Store: d, Self: self, TTL: MaxTTL + time.Second},
		"refresh ≥ TTL":       {Store: d, Self: self, TTL: time.Hour, Refresh: time.Hour},
		"prepublish 24 h":     {Store: d, Self: self, Prepublish: 24 * time.Hour},
		"max retry < retry":   {Store: d, Self: self, Retry: time.Hour, MaxRetry: time.Minute},
		"negative refresh":    {Store: d, Self: self, Refresh: -time.Hour},
		"negative TTL":        {Store: d, Self: self, TTL: -time.Hour},
		"negative prepublish": {Store: d, Self: self, Prepublish: -time.Hour},
	} {
		if p, err := NewPublisher(o); err == nil {
			p.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	// No peer ID yet: nothing is published.
	ab, _ := newPair(t, 0xA1, 0xB0)
	clk := newFakeClock(testNow)
	var ev events
	p := newTestPublisher(t, PublisherOptions{Store: d, Self: self, Clock: clk, PutInterval: -1, OnPublish: ev.add})
	p.SetPair(ab)
	idle(t, clk, &ev, 0, testNow.Add(DefaultRetry))
}
