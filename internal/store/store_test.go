package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
)

var ctx = context.Background()

var testNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func key(t *testing.T, b byte) identity.PublicKey {
	t.Helper()
	id, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id.Public()
}

func addBuddy(t *testing.T, s *Store, b byte) int64 {
	t.Helper()
	id, err := s.AddBuddy(ctx, Buddy{Key: key(t, b), Petname: "bud", State: Accepted})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// sealIM returns a SealFunc that seals an IM with the allocated seq.
func sealIM(k frame.ConvKey, body string) SealFunc {
	return func(seq uint64) (*frame.Sealed, frame.ContentType, error) {
		in := frame.Inner{Type: frame.IM, Time: frame.Timestamp(testNow), Seq: seq, Body: []byte(body)}
		s, err := frame.Seal(k, k.Tag(frame.Day(testNow)), frame.LayoutMesh, in.Marshal())
		return s, frame.IM, err
	}
}

func TestMigrationsAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openaim.db")
	s := open(t, path)
	if v, err := s.SchemaVersion(ctx); err != nil || v != 1 {
		t.Fatalf("schema version %d, %v", v, err)
	}
	if err := s.SetMeta(ctx, "identity", []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open(t, path) // migrations must be idempotent
	if v, err := s.Meta(ctx, "identity"); err != nil || !bytes.Equal(v, []byte{1, 2}) {
		t.Fatalf("meta after reopen: %v %v", v, err)
	}
	if _, err := s.Meta(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing meta: %v", err)
	}
}

func TestPathWithSpecialCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "my ?db#1%.db")
	open(t, path).SetMeta(ctx, "k", []byte("v"))
	if s := open(t, path); s != nil {
		if v, err := s.Meta(ctx, "k"); err != nil || string(v) != "v" {
			t.Fatalf("reopen %q: %v", path, err)
		}
	}
}

func TestBuddies(t *testing.T) {
	s := open(t, ":memory:")
	rk := key(t, 9)
	id, err := s.AddBuddy(ctx, Buddy{Key: key(t, 1), Handle: "skaterdude99.example", State: PendingOut, RecoveryKey: &rk})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddBuddy(ctx, Buddy{Key: key(t, 1), State: Accepted}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate key: %v", err)
	}
	b, err := s.BuddyByKey(ctx, key(t, 1))
	if err != nil || b.ID != id || b.Handle != "skaterdude99.example" || b.Group != "Buddies" || b.State != PendingOut || *b.RecoveryKey != rk {
		t.Fatalf("got %+v, %v", b, err)
	}
	if err := s.SetBuddyState(ctx, id, Accepted); err != nil {
		t.Fatal(err)
	}
	if err := s.SetBuddyState(ctx, 999, Accepted); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing buddy: %v", err)
	}
	addBuddy(t, s, 2)
	if all, err := s.Buddies(ctx); err != nil || len(all) != 2 {
		t.Fatalf("list: %d, %v", len(all), err)
	}
	if err := s.DeleteBuddy(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Buddy(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted buddy: %v", err)
	}
}

// TestSealOncePersisted: frames come back byte-for-byte after a restart, and
// seqs are never reused, even when sealing fails mid-transaction.
func TestSealOncePersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openaim.db")
	s := open(t, path)
	bid := addBuddy(t, s, 1)
	k := frame.NewConvKey([32]byte{7})

	long := string(bytes.Repeat([]byte("m"), 400)) // 3 fragments
	o1, err := s.Enqueue(ctx, bid, sealIM(k, long))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(ctx, bid, func(uint64) (*frame.Sealed, frame.ContentType, error) {
		return nil, 0, errors.New("sealing failed")
	}); err == nil {
		t.Fatal("failed seal was enqueued")
	}
	o2, err := s.Enqueue(ctx, bid, sealIM(k, "short"))
	if err != nil {
		t.Fatal(err)
	}
	if o1.Seq != 1 || o2.Seq != 2 {
		t.Fatalf("seqs %d, %d; a failed seal must not consume a seq", o1.Seq, o2.Seq)
	}
	if _, err := s.Enqueue(ctx, 999, sealIM(k, "x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown buddy: %v", err)
	}
	s.Close()

	s = open(t, path)
	pend, err := s.Pending(ctx, bid)
	if err != nil || len(pend) != 2 {
		t.Fatalf("pending: %d, %v", len(pend), err)
	}
	for i, want := range []*Outgoing{o1, o2} {
		got := pend[i]
		if got.MsgID != want.MsgID || got.Tag != want.Tag || got.Seq != want.Seq || len(got.Frames) != len(want.Frames) {
			t.Fatalf("message %d differs after reopen", i)
		}
		for j := range want.Frames {
			if !bytes.Equal(got.Frames[j], want.Frames[j]) {
				t.Fatalf("message %d frame %d changed after reopen", i, j)
			}
		}
	}
	// The persisted frames still open at the receiver.
	r := &frame.Receiver{Keys: ring{k.Tag(frame.Day(testNow)): {{Key: k}}}, Dedup: s.Dedup(), Now: func() time.Time { return testNow }}
	var res frame.Result
	for _, f := range pend[0].Frames {
		if res, err = r.Accept(f); err != nil {
			t.Fatal(err)
		}
	}
	if res.Status != frame.Delivered || string(res.Message.Inner.Body) != long {
		t.Fatalf("persisted frames didn't deliver: %v", res.Status)
	}
	s2 := open(t, filepath.Join(t.TempDir(), "x.db"))
	b2 := addBuddy(t, s2, 1)
	if o, _ := s2.Enqueue(ctx, b2, sealIM(k, "x")); o.Seq != 1 {
		t.Fatal("seq is per buddy and starts at 1")
	}
}

func TestAcks(t *testing.T) {
	s := open(t, ":memory:")
	bid := addBuddy(t, s, 1)
	k := frame.NewConvKey([32]byte{7})
	o, err := s.Enqueue(ctx, bid, sealIM(k, string(bytes.Repeat([]byte("a"), 400)))) // 3 fragments
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttempt(ctx, o.ID, testNow); err != nil {
		t.Fatal(err)
	}
	got, err := s.Ack(ctx, o.Tag, o.MsgID, 0b101)
	if err != nil || got.State != Queued || got.AckedMask != 0b101 || got.Attempts != 1 {
		t.Fatalf("partial ack: %+v %v", got, err)
	}
	got, err = s.Ack(ctx, o.Tag, o.MsgID, 0b1111_0010) // bits beyond frag_count are ignored
	if err != nil || got.State != Acked || got.AckedMask != 0b111 {
		t.Fatalf("full ack: %+v %v", got, err)
	}
	if pend, _ := s.Pending(ctx, bid); len(pend) != 0 {
		t.Fatalf("acked message still pending")
	}
	if _, err := s.Ack(ctx, o.Tag, frame.MsgID{1}, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ack of unknown message: %v", err)
	}
	o2, _ := s.Enqueue(ctx, bid, sealIM(k, "give up"))
	if err := s.MarkFailed(ctx, o2.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Outgoing(ctx, o2.ID); got.State != Failed || len(got.Frames) != 1 {
		t.Fatalf("failed message: %+v", got)
	}
}

func TestIncomingHistory(t *testing.T) {
	s := open(t, ":memory:")
	bid := addBuddy(t, s, 1)
	for i := range 5 {
		m := &frame.Message{Tag: frame.ConvTag{1}, MsgID: frame.MsgID{byte(i)},
			Inner: frame.Inner{Type: frame.IM, Time: 100, Seq: uint64(i), Body: []byte{byte('a' + i)}}}
		ok, err := s.SaveIncoming(ctx, bid, m, testNow.Add(time.Duration(i)*time.Second))
		if err != nil || !ok {
			t.Fatal(err)
		}
		if ok, _ := s.SaveIncoming(ctx, bid, m, testNow); ok {
			t.Fatal("duplicate message saved twice")
		}
	}
	h, err := s.History(ctx, bid, 3)
	if err != nil || len(h) != 3 || string(h[0].Inner.Body) != "c" || string(h[2].Inner.Body) != "e" {
		t.Fatalf("history: %+v %v", h, err)
	}
}

// ring is a fixed frame.Keyring.
type ring map[frame.ConvTag][]frame.Conv

func (r ring) Lookup(t frame.ConvTag) []frame.Conv { return r[t] }

func TestDedupSemantics(t *testing.T) {
	s := open(t, ":memory:")
	d := s.Dedup()
	id := frame.FragmentID{Tag: frame.ConvTag{1}, MsgID: frame.MsgID{2}, Frag: 0x01}
	if !d.Insert(id, testNow) {
		t.Fatal("first insert not fresh")
	}
	if d.Insert(id, testNow.Add(frame.DedupTTL-time.Second)) {
		t.Fatal("duplicate within TTL reported fresh")
	}
	if !d.Insert(id, testNow.Add(frame.DedupTTL+time.Second)) {
		t.Fatal("entry past TTL not refreshed")
	}
	other := id
	other.Frag = 0x11
	if !d.Insert(other, testNow) {
		t.Fatal("different fragment not fresh")
	}
	n, err := s.ExpireDedup(ctx, testNow.Add(frame.DedupTTL+time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("expired %d, %v; want the one old entry", n, err)
	}
}

func TestDedupFailsClosed(t *testing.T) {
	s := open(t, ":memory:")
	d := s.Dedup()
	var got error
	d.OnError = func(err error) { got = err }
	s.Close()
	if d.Insert(frame.FragmentID{}, testNow) || got == nil {
		t.Fatal("database error must report a duplicate and call OnError")
	}
}

// TestReceiverWithStoreDedup runs concurrent duplicate deliveries through a
// frame.Receiver backed by the persistent dedup: exactly one delivery.
func TestReceiverWithStoreDedup(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "d.db"))
	k := frame.NewConvKey([32]byte{3})
	sealed, err := frame.Seal(k, k.Tag(frame.Day(testNow)), frame.LayoutMesh,
		frame.Inner{Type: frame.IM, Time: frame.Timestamp(testNow), Seq: 1, Body: []byte("once")}.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	r := &frame.Receiver{Keys: ring{sealed.Tag: {{Key: k}}}, Dedup: s.Dedup(), Now: func() time.Time { return testNow }}
	var delivered atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if res, err := r.Accept(sealed.Frames[0]); err == nil && res.Status == frame.Delivered {
				delivered.Add(1)
			}
		})
	}
	wg.Wait()
	if delivered.Load() != 1 {
		t.Fatalf("delivered %d times", delivered.Load())
	}
	// After a restart the fragment is still known.
	path := filepath.Join(t.TempDir(), "p.db")
	s1 := open(t, path)
	s1.Dedup().Insert(frame.FragmentID{Tag: sealed.Tag, MsgID: sealed.MsgID}, testNow)
	s1.Close()
	if open(t, path).Dedup().Insert(frame.FragmentID{Tag: sealed.Tag, MsgID: sealed.MsgID}, testNow.Add(time.Hour)) {
		t.Fatal("dedup entry lost across restart")
	}
}
