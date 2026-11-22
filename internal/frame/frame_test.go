package frame

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func testKey(b byte) ConvKey { return NewConvKey([32]byte{b}) }

// keyring is a fixed tag → conversations map.
type keyring map[ConvTag][]Conv

func (k keyring) Lookup(t ConvTag) []Conv { return k[t] }

func newReceiver(k ConvKey, days ...uint32) *Receiver {
	kr := keyring{}
	for _, d := range days {
		kr[k.Tag(d)] = append(kr[k.Tag(d)], Conv{Key: k, ID: "alice"})
	}
	return &Receiver{Keys: kr, Dedup: &MemDedup{}, Now: func() time.Time { return testNow }}
}

func im(body string) Inner {
	return Inner{Type: IM, Time: Timestamp(testNow), Seq: 1, Body: []byte(body)}
}

func seal(t *testing.T, k ConvKey, l Layout, in Inner) *Sealed {
	t.Helper()
	s, err := Seal(k, k.Tag(Day(testNow)), l, in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCapacities(t *testing.T) {
	// spec/wire.md §5.1, §6: 34 B overhead, 166 B per mesh fragment, 664 B
	// of inner payload (657 B of body after a 7 B inner header).
	if Overhead != 34 || LayoutMesh.FragmentCapacity() != 166 || LayoutMesh.MaxInner() != 664 {
		t.Fatalf("overhead %d, capacity %d, max inner %d", Overhead, LayoutMesh.FragmentCapacity(), LayoutMesh.MaxInner())
	}
}

func TestSealAcceptRoundTrip(t *testing.T) {
	k := testKey(1)
	for _, l := range []Layout{LayoutMesh, LayoutIP} {
		capacity := l.FragmentCapacity()
		hdr := len(im("").Marshal())
		for _, n := range []int{1, capacity - hdr, capacity - hdr + 1, l.MaxInner() - hdr} {
			body := bytes.Repeat([]byte("x"), n)
			s := seal(t, k, l, im(string(body)))
			wantFrags := (hdr + n + capacity - 1) / capacity
			if len(s.Frames) != wantFrags {
				t.Fatalf("%s %d B: %d fragments, want %d", l, n, len(s.Frames), wantFrags)
			}
			for i, f := range s.Frames {
				if len(f) > l.FrameLen() || (i < len(s.Frames)-1 && len(f) != l.FrameLen()) {
					t.Fatalf("%s %d B: fragment %d is %d bytes", l, n, i, len(f))
				}
			}
			r := newReceiver(k, Day(testNow))
			var got *Message
			for i := len(s.Frames) - 1; i >= 0; i-- { // out of order
				res, err := r.Accept(s.Frames[i])
				if err != nil {
					t.Fatalf("%s %d B fragment %d: %v", l, n, i, err)
				}
				if res.Conv != "alice" {
					t.Fatalf("conv = %v", res.Conv)
				}
				if i > 0 && res.Status != Partial || i == 0 && res.Status != Delivered {
					t.Fatalf("fragment %d: status %v", i, res.Status)
				}
				got = res.Message
			}
			if got == nil || !bytes.Equal(got.Inner.Body, body) || got.MsgID != s.MsgID {
				t.Fatalf("%s %d B: bad delivery", l, n)
			}
		}
		if _, err := Seal(k, k.Tag(0), l, make([]byte, l.MaxInner()+1)); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: oversize message: %v", l, err)
		}
	}
}

func TestSealDeterministic(t *testing.T) {
	k := testKey(1)
	a, b := seal(t, k, LayoutMesh, im("same")), seal(t, k, LayoutMesh, im("same"))
	if !bytes.Equal(a.Frames[0], b.Frames[0]) {
		t.Fatal("sealing the same payload twice gave different bytes")
	}
	c := seal(t, k, LayoutMesh, im("diff"))
	if a.MsgID == c.MsgID {
		t.Fatal("different payloads, same msg_id")
	}
}

func TestTamperingDetected(t *testing.T) {
	k := testKey(1)
	s := seal(t, k, LayoutMesh, im(string(bytes.Repeat([]byte("y"), 300))))
	for fi, f := range s.Frames {
		for i := range f {
			for _, bit := range []byte{0x01, 0x80} {
				r := newReceiver(k, Day(testNow))
				bad := bytes.Clone(f)
				bad[i] ^= bit
				if res, err := r.Accept(bad); err == nil {
					t.Fatalf("frame %d byte %d ^%#x accepted: %v", fi, i, bit, res.Status)
				}
			}
		}
		if _, err := newReceiver(k, Day(testNow)).Accept(f[:len(f)-1]); err == nil {
			t.Fatalf("truncated frame %d accepted", fi)
		}
	}
}

func TestWrongKeyAndUnknownTag(t *testing.T) {
	s := seal(t, testKey(1), LayoutMesh, im("hi"))
	r := newReceiver(testKey(2), Day(testNow))
	r.Keys.(keyring)[s.Tag] = []Conv{{Key: testKey(2)}} // tag collision, wrong key
	if _, err := r.Accept(s.Frames[0]); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := newReceiver(testKey(1), Day(testNow)-1).Accept(s.Frames[0]); !errors.Is(err, ErrUnknownTag) {
		t.Errorf("unknown tag: %v", err)
	}
	// With a real collision, the right key is still found.
	r.Keys.(keyring)[s.Tag] = []Conv{{Key: testKey(2), ID: "x"}, {Key: testKey(1), ID: "alice"}}
	if res, err := r.Accept(s.Frames[0]); err != nil || res.Conv != "alice" {
		t.Errorf("collision: %v %v", res.Conv, err)
	}
}

func TestReplayWindow(t *testing.T) {
	k := testKey(1)
	for _, tc := range []struct {
		at time.Time
		ok bool
	}{
		{testNow, true},
		{testNow.Add(-MaxAge + time.Minute), true},
		{testNow.Add(-MaxAge - time.Minute), false},
		{testNow.Add(MaxFuture - time.Second), true},
		{testNow.Add(MaxFuture + time.Minute), false},
	} {
		in := im("t")
		in.Time = Timestamp(tc.at)
		s := seal(t, k, LayoutMesh, in)
		_, err := newReceiver(k, Day(testNow)).Accept(s.Frames[0])
		if tc.ok != (err == nil) || !tc.ok && !errors.Is(err, ErrStale) {
			t.Errorf("timestamp %v: err = %v", tc.at.Sub(testNow), err)
		}
	}
}

func TestDuplicates(t *testing.T) {
	k := testKey(1)
	s := seal(t, k, LayoutMesh, im(string(bytes.Repeat([]byte("z"), 400)))) // 3 fragments
	r := newReceiver(k, Day(testNow))
	r.Accept(s.Frames[0])
	res, err := r.Accept(s.Frames[0])
	if err != nil || res.Status != Duplicate || res.Have != 0b001 {
		t.Fatalf("dup of partial: %v %03b %v", res.Status, res.Have, err)
	}
	r.Accept(s.Frames[2])
	if res, _ := r.Accept(s.Frames[1]); res.Status != Delivered || res.Have != 0b111 {
		t.Fatalf("completion: %v %03b", res.Status, res.Have)
	}
	for i, f := range s.Frames {
		if res, _ := r.Accept(f); res.Status != Duplicate || res.Have != 0b111 {
			t.Fatalf("dup of delivered fragment %d: %v %03b", i, res.Status, res.Have)
		}
	}
	// Past the dedup TTL the entry is gone, and the replay window rejects it.
	r.Now = func() time.Time { return testNow.Add(DedupTTL + time.Hour) }
	r.Keys.(keyring)[s.Tag] = []Conv{{Key: k}}
	if _, err := r.Accept(s.Frames[0]); !errors.Is(err, ErrStale) {
		t.Fatalf("31-day-old replay of fragment 0: %v, want ErrStale", err)
	}
	if len(r.partials[s.Tag]) != 0 {
		t.Fatal("stale fragment created a reassembly buffer")
	}
}

func TestConcurrentDuplicatesDeliverOnce(t *testing.T) {
	k := testKey(1)
	s := seal(t, k, LayoutMesh, im("once"))
	r := newReceiver(k, Day(testNow))
	var delivered atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if res, err := r.Accept(s.Frames[0]); err == nil && res.Status == Delivered {
				delivered.Add(1)
			}
		})
	}
	wg.Wait()
	if n := delivered.Load(); n != 1 {
		t.Fatalf("delivered %d times", n)
	}
}

func TestReassemblyBounded(t *testing.T) {
	k := testKey(1)
	r := newReceiver(k, Day(testNow))
	var first *Sealed
	for i := range MaxPartialsPerTag + 4 {
		in := im(string(bytes.Repeat([]byte("p"), 300)))
		in.Seq = uint64(i)
		s := seal(t, k, LayoutMesh, in)
		if i == 0 {
			first = s
		}
		r.Now = func() time.Time { return testNow.Add(time.Duration(i) * time.Second) }
		r.Accept(s.Frames[0])
	}
	if n := len(r.partials[first.Tag]); n != MaxPartialsPerTag {
		t.Fatalf("%d partial buffers, want %d", n, MaxPartialsPerTag)
	}
	// The oldest was evicted, so its second fragment can't complete it.
	if res, _ := r.Accept(first.Frames[1]); res.Status == Delivered {
		t.Fatal("evicted message completed")
	}
}

func TestInnerParsing(t *testing.T) {
	in := Inner{Type: Ack, Flags: FlagAckRequested | FlagClockUnsynced, Time: 12345, Seq: 300, Body: []byte{9, 9}}
	got, err := ParseInner(in.Marshal())
	if err != nil || got.Type != in.Type || got.Flags != in.Flags || got.Time != in.Time || got.Seq != in.Seq || !bytes.Equal(got.Body, in.Body) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	b := in.Marshal()
	for name, bad := range map[string][]byte{
		"short":         b[:6],
		"unknown flag":  append([]byte{1, 0x80}, b[2:]...),
		"long varint":   append(append(bytes.Clone(b[:6]), 0x80, 0x00), 'x'), // 0 encoded in 2 bytes
		"varint at end": append(bytes.Clone(b[:6]), 0x80),
	} {
		if _, err := ParseInner(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseHeaderChecks(t *testing.T) {
	s := seal(t, testKey(1), LayoutMesh, im(string(bytes.Repeat([]byte("h"), 200))))
	f0 := s.Frames[0]
	mod := func(fn func([]byte) []byte) []byte { return fn(bytes.Clone(f0)) }
	for name, b := range map[string][]byte{
		"version 2":       mod(func(b []byte) []byte { b[0] = 2<<5 | 1; return b }),
		"unknown kind":    mod(func(b []byte) []byte { b[0] = VerKind(KindBeacon); return b }),
		"index ≥ count":   mod(func(b []byte) []byte { b[17] = 0x21; return b }),
		"5 mesh frags":    mod(func(b []byte) []byte { b[17] = 0x04; return b }),
		"oversize":        append(bytes.Clone(f0), 0),
		"short non-final": f0[:199],
		"tiny":            f0[:Overhead],
	} {
		if _, err := ParseHeader(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestSealOnceInvariant is the design's seal-once property (§8.2, §13): no
// (K_msg, nonce) pair ever encrypts two different (plaintext, associated
// data) pairs, across repeated sends, both directions, many days and both
// layouts, including identical payloads sealed under different tags.
func TestSealOnceInvariant(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	keys := []ConvKey{testKey(1), testKey(2)}
	type use struct{ pt, ad string }
	seen := map[string]use{}
	bodies := []string{"hi", "ok", "lol", "", "brb"}
	for range 3000 {
		k := keys[rng.IntN(2)]
		day := uint32(rng.IntN(4))
		l := []Layout{LayoutMesh, LayoutIP}[rng.IntN(2)]
		in := Inner{Type: IM, Time: uint32(rng.IntN(3)), Seq: uint64(rng.IntN(3))}
		if rng.IntN(10) == 0 {
			in.Body = bytes.Repeat([]byte("L"), 100+rng.IntN(500))
		} else {
			in.Body = []byte(bodies[rng.IntN(len(bodies))])
		}
		tag := k.Tag(day)
		s, err := Seal(k, tag, l, in.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		for i, f := range s.Frames {
			h, err := ParseHeader(f)
			if err != nil {
				t.Fatal(err)
			}
			km := k.msgKey(h.Tag, h.MsgID, h.Count, h.Layout)
			pt, err := OpenFragment(k, h, f)
			if err != nil {
				t.Fatal(err)
			}
			id := string(km) + string(nonce(i))
			u := use{string(pt), string(f[:headerLen])}
			if prev, ok := seen[id]; ok && prev != u {
				t.Fatalf("(K_msg, nonce) reused for different input:\n prev %x / %x\n now  %x / %x", prev.ad, prev.pt, u.ad, u.pt)
			}
			seen[id] = u
		}
	}
}

func FuzzParseHeader(f *testing.F) {
	s, _ := Seal(testKey(1), testKey(1).Tag(1), LayoutMesh, im("seed").Marshal())
	f.Add(s.Frames[0])
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseHeader(b)
		if err != nil {
			return
		}
		if h.Index >= h.Count || h.Count > h.Layout.MaxFragments() || len(b) > h.Layout.FrameLen() {
			t.Fatalf("accepted bad header %+v for %d bytes", h, len(b))
		}
	})
}

func FuzzParseInner(f *testing.F) {
	f.Add(im("seed").Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		in, err := ParseInner(b)
		if err != nil {
			return
		}
		if !bytes.Equal(in.Marshal(), b) {
			t.Fatalf("parse/marshal not canonical: %x → %x", b, in.Marshal())
		}
	})
}

// FuzzAccept feeds arbitrary bytes, and mutations of real frames, to a
// receiver that knows the key. Nothing may panic, and anything delivered
// must be exactly what was sealed.
func FuzzAccept(f *testing.F) {
	k := testKey(1)
	s, _ := Seal(k, k.Tag(Day(testNow)), LayoutMesh, im(string(bytes.Repeat([]byte("f"), 250))).Marshal())
	for _, fr := range s.Frames {
		f.Add(fr)
	}
	want := im(string(bytes.Repeat([]byte("f"), 250)))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := newReceiver(k, Day(testNow))
		r.Accept(s.Frames[1]) // so fragment 0 variants can complete a message
		res, err := r.Accept(b)
		if err == nil && res.Status == Delivered && !bytes.Equal(res.Message.Inner.Body, want.Body) {
			t.Fatalf("delivered forged body %q", res.Message.Inner.Body)
		}
	})
}
