package rendezvous

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/transport/ip"
)

// fakeClock is a manual clock. Timers fire when Advance passes them.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c    *fakeClock
	at   time.Time
	ch   chan time.Time
	done bool
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) ip.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		t.done = true
		t.ch <- c.now
		return t
	}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.done
	t.done = true
	t.c.timers = slices.DeleteFunc(t.c.timers, func(x *fakeTimer) bool { return x == t })
	return was
}

// Set moves the clock to at, firing every timer due by then.
func (c *fakeClock) Set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = at
	c.timers = slices.DeleteFunc(c.timers, func(t *fakeTimer) bool {
		if t.at.After(at) {
			return false
		}
		t.done = true
		t.ch <- at
		return true
	})
}

func (c *fakeClock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

// waitTimer waits until a timer is pending that fires at want.
func (c *fakeClock) waitTimer(t *testing.T, want time.Time) {
	t.Helper()
	waitFor(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return slices.ContainsFunc(c.timers, func(x *fakeTimer) bool { return x.at.Equal(want) })
	})
}

// nextTimer is the earliest pending timer's deadline.
func (c *fakeClock) nextTimer() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.timers) == 0 {
		return time.Time{}, false
	}
	at := c.timers[0].at
	for _, t := range c.timers[1:] {
		if t.at.Before(at) {
			at = t.at
		}
	}
	return at, true
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// memDHT is an in-memory stand-in for the DHT: it validates and selects
// values with the real validator.
type memDHT struct {
	mu   sync.Mutex
	vals map[string][]byte
	puts int
	fail error // returned by puts while set
}

func newMemDHT() *memDHT { return &memDHT{vals: map[string][]byte{}} }

func (m *memDHT) PutRendezvous(_ context.Context, priv ed25519.PrivateKey, seq uint64, payload []byte) (string, error) {
	v, err := ip.SignRendezvousRecord(priv, seq, payload)
	if err != nil {
		return "", err
	}
	key := ip.RendezvousKey(priv.Public().(ed25519.PublicKey))
	return key, m.PutValue(key, v)
}

func (m *memDHT) PutValue(key string, v []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if m.fail != nil {
		return m.fail
	}
	val := ip.DHTValidator()
	if err := val.Validate(key, v); err != nil {
		return err
	}
	if old, ok := m.vals[key]; ok && !bytes.Equal(old, v) {
		if i, _ := val.Select(key, [][]byte{v, old}); i != 0 {
			return errors.New("older value")
		}
	}
	m.vals[key] = v
	return nil
}

func (m *memDHT) GetRendezvous(_ context.Context, key string) (ip.RendezvousRecord, error) {
	m.mu.Lock()
	v, ok := m.vals[key]
	m.mu.Unlock()
	if !ok {
		return ip.RendezvousRecord{}, routing.ErrNotFound
	}
	return ip.ParseRendezvousRecord(key, v)
}

func (m *memDHT) setFail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = err
}

func (m *memDHT) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.puts
}

func (m *memDHT) value(key string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.vals[key])
}

// pairs makes identities from fixed seeds and returns pub(a→b) and b's view.
func newPair(t testing.TB, a, b byte) (ab, ba *identity.Pair) {
	t.Helper()
	ia, err := identity.FromSeed(bytes.Repeat([]byte{a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ib, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if ab, err = ia.Pair(ib.Public()); err != nil {
		t.Fatal(err)
	}
	if ba, err = ib.Pair(ia.Public()); err != nil {
		t.Fatal(err)
	}
	return ab, ba
}

// testPeer is a peer ID from a fixed seed.
func testPeer(t testing.TB, seed byte) peer.ID {
	t.Helper()
	priv, err := crypto.UnmarshalEd25519PrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func maddrs(t testing.TB, ss ...string) []ma.Multiaddr {
	t.Helper()
	var out []ma.Multiaddr
	for _, s := range ss {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}
