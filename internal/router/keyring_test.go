package router

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/frame"
)

var t0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

// clock is a settable time source.
type clock struct{ ns atomic.Int64 }

func newClock(t time.Time) *clock { c := &clock{}; c.set(t); return c }
func (c *clock) set(t time.Time)  { c.ns.Store(t.UnixNano()) }
func (c *clock) now() time.Time   { return time.Unix(0, c.ns.Load()).UTC() }

func ck(b byte) frame.ConvKey { return frame.NewConvKey([32]byte{b}) }

func TestKeyringWindow(t *testing.T) {
	c := newClock(t0)
	k := NewKeyring()
	k.Now = c.now
	k.Set("bob", ck(1))

	from, to := Window(t0)
	if to-from != 14 {
		t.Fatalf("window at noon is %d..%d (%d days), want 15", from, to, to-from+1)
	}
	// Within MaxFuture of midnight, the next day's tag is accepted too.
	if f, l := Window(time.Date(2026, 11, 21, 23, 55, 0, 0, time.UTC)); l-f != 15 {
		t.Fatalf("window at 23:55 is %d days, want 16", l-f+1)
	}
	for d := from; d <= to; d++ {
		if got := k.Lookup(ck(1).Tag(d)); len(got) != 1 || got[0].ID != "bob" {
			t.Fatalf("day %d: %v", d, got)
		}
	}
	for _, d := range []uint32{from - 1, to + 1} {
		if got := k.Lookup(ck(1).Tag(d)); got != nil {
			t.Fatalf("day %d outside the window resolved", d)
		}
	}

	// Move forward a day: the oldest day leaves, a new one enters, and the
	// result matches a keyring built from scratch.
	c.set(t0.Add(24 * time.Hour))
	if k.Lookup(ck(1).Tag(from)) != nil {
		t.Fatal("expired day still resolves")
	}
	if len(k.Lookup(ck(1).Tag(to+1))) != 1 {
		t.Fatal("new day doesn't resolve")
	}
	fresh := NewKeyring()
	fresh.Now = c.now
	fresh.Set("bob", ck(1))
	fresh.Lookup(frame.ConvTag{})
	if len(fresh.tags) != len(k.tags) {
		t.Fatalf("incremental rebuild has %d tags, fresh build %d", len(k.tags), len(fresh.tags))
	}

	// A jump far ahead rebuilds from scratch.
	c.set(t0.Add(90 * 24 * time.Hour))
	nf, nt := Window(c.now())
	if len(k.Lookup(ck(1).Tag(nt))) != 1 || k.Lookup(ck(1).Tag(to)) != nil || nf <= to {
		t.Fatal("jump rebuild wrong")
	}
}

func TestKeyringSetRemove(t *testing.T) {
	k := NewKeyring()
	k.Now = func() time.Time { return t0 }
	day := frame.Day(t0)
	k.Set("bob", ck(1))
	k.Set("carol", ck(2))
	k.Set("bob", ck(3)) // key change
	if k.Lookup(ck(1).Tag(day)) != nil || len(k.Lookup(ck(3).Tag(day))) != 1 {
		t.Fatal("replaced key still resolves, or new key doesn't")
	}
	k.Remove("carol")
	k.Remove("nobody")
	if k.Lookup(ck(2).Tag(day)) != nil || k.Len() != 1 {
		t.Fatal("removed conversation still resolves")
	}
	// Two conversations sharing a key (a tag collision) both resolve.
	k.Set("dave", ck(3))
	if got := k.Lookup(ck(3).Tag(day)); len(got) != 2 {
		t.Fatalf("collision: %d convs", len(got))
	}
}

// TestKeyringWithReceiver: frames sealed 13 days ago are accepted; frames
// sealed 15 days ago fail at the tag lookup, before any crypto.
func TestKeyringWithReceiver(t *testing.T) {
	k := NewKeyring()
	k.Now = func() time.Time { return t0 }
	key := ck(5)
	k.Set("bob", key)
	r := &frame.Receiver{Keys: k, Dedup: &frame.MemDedup{}, Now: k.Now}
	for _, tc := range []struct {
		age  time.Duration
		want error
	}{{13 * 24 * time.Hour, nil}, {15 * 24 * time.Hour, frame.ErrUnknownTag}} {
		sent := t0.Add(-tc.age)
		s, err := frame.Seal(key, key.Tag(frame.Day(sent)), frame.LayoutMesh,
			frame.Inner{Type: frame.IM, Time: frame.Timestamp(sent), Seq: 1, Body: []byte("hi")}.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Accept(s.Frames[0]); err != tc.want {
			t.Errorf("sealed %v ago: %v, want %v", tc.age, err, tc.want)
		}
	}
}

func TestKeyringConcurrent(t *testing.T) {
	c := newClock(t0)
	k := NewKeyring()
	k.Now = c.now
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for j := range 200 {
				k.Set(i*1000+j, ck(byte(j)))
				k.Lookup(ck(byte(j)).Tag(frame.Day(c.now())))
				if j%50 == 0 {
					c.set(c.now().Add(24 * time.Hour))
				}
			}
		})
	}
	wg.Wait()
}

func TestKeyringScales(t *testing.T) {
	k := NewKeyring()
	k.Now = func() time.Time { return t0 }
	start := time.Now()
	for i := range 1000 {
		var b [32]byte
		b[0], b[1] = byte(i), byte(i>>8)
		k.Set(i, frame.NewConvKey(b))
	}
	if n := len(k.tags); n != 15000 {
		t.Fatalf("%d tags for 1000 buddies × 15 days", n)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("building tags for 1000 buddies took %v", d)
	}
}

func BenchmarkKeyringDayRollover(b *testing.B) {
	c := newClock(t0)
	k := NewKeyring()
	k.Now = c.now
	for i := range 1000 {
		var kb [32]byte
		kb[0], kb[1] = byte(i), byte(i>>8)
		k.Set(i, frame.NewConvKey(kb))
	}
	for i := 0; b.Loop(); i++ {
		c.set(t0.Add(time.Duration(i+1) * 24 * time.Hour))
		k.Lookup(frame.ConvTag{})
	}
}
