package frame

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/identity"
)

func fcIdentity(t testing.TB, b byte) *identity.Identity {
	t.Helper()
	id, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// ephemeral is a fixed source for the 32-byte ephemeral seed.
func ephemeral(b byte) io.Reader { return bytes.NewReader(bytes.Repeat([]byte{b}, 32)) }

func sealFC(t testing.TB, from *identity.Identity, to identity.PublicKey, l Layout, in Inner, eb byte) *SealedFirstContact {
	t.Helper()
	s, err := SealFirstContact(from, to, l, in.Marshal(), ephemeral(eb))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newFCReceiver(me *identity.Identity) *FirstContactReceiver {
	return &FirstContactReceiver{Me: me, Dedup: &MemDedup{}, Now: func() time.Time { return testNow }}
}

func request(body string) Inner {
	return Inner{Type: BuddyRequest, Time: Timestamp(testNow), Body: []byte(body)}
}

func TestFirstContactCapacities(t *testing.T) {
	// spec/wire.md §11.1: 106 B overhead on fragment 0 (94 B of payload in a
	// 200 B frame), 58 B on fragment 1 (142 B), 236 B in all.
	if FirstContactOverhead != 106 || FirstContactTailOverhead != 58 {
		t.Fatalf("overheads %d, %d", FirstContactOverhead, FirstContactTailOverhead)
	}
	for _, c := range []struct {
		l          Layout
		c0, c1, mx int
	}{{LayoutMesh, 94, 142, 236}, {LayoutIP, 3990, 4038, 3990}} {
		if got := [3]int{FirstContactCapacity(c.l, 0), FirstContactCapacity(c.l, 1), FirstContactMaxInner(c.l)}; got != [3]int{c.c0, c.c1, c.mx} {
			t.Errorf("%s: capacities %v", c.l, got)
		}
	}
}

func TestFirstContactRoundTrip(t *testing.T) {
	alice, bob := fcIdentity(t, 0xA1), fcIdentity(t, 0xB0)
	hdr := len(request("").Marshal())
	for _, l := range []Layout{LayoutMesh, LayoutIP} {
		c0, max := FirstContactCapacity(l, 0), FirstContactMaxInner(l)
		for _, n := range []int{1, c0 - hdr, c0 - hdr + 1, max - hdr} {
			if n <= 0 || hdr+n > max {
				continue
			}
			body := bytes.Repeat([]byte("g"), n)
			s := sealFC(t, alice, bob.Public(), l, request(string(body)), 0xE1)
			want := fcCount(l, hdr+n)
			if len(s.Frames) != want {
				t.Fatalf("%s %d B: %d fragments, want %d", l, n, len(s.Frames), want)
			}
			for i, f := range s.Frames {
				if fl := fcLayouts[l].frameLen; len(f) > fl || (i < len(s.Frames)-1 && len(f) != fl) {
					t.Fatalf("%s %d B: fragment %d is %d bytes", l, n, i, len(f))
				}
			}
			for _, order := range [][]int{{0, 1}, {1, 0}} {
				r := newFCReceiver(bob)
				var got *FirstContact
				for _, i := range order {
					if i >= len(s.Frames) {
						continue
					}
					res, err := r.Accept(s.Frames[i])
					if err != nil {
						t.Fatalf("%s %d B fragment %d: %v", l, n, i, err)
					}
					got = res.Message
				}
				if got == nil || got.Sender != alice.Public() || !bytes.Equal(got.Inner.Body, body) || got.MsgID != s.MsgID || got.Inner.Type != BuddyRequest {
					t.Fatalf("%s %d B order %v: bad delivery %+v", l, n, order, got)
				}
			}
		}
		if _, err := SealFirstContact(alice, bob.Public(), l, request(string(make([]byte, max-hdr+1))).Marshal(), ephemeral(1)); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: oversize request: %v", l, err)
		}
	}
	if _, err := SealFirstContact(alice, bob.Public(), LayoutMesh, []byte{1, 0, 0}, ephemeral(1)); !errors.Is(err, ErrMalformed) {
		t.Errorf("short inner: %v", err)
	}
}

func TestFirstContactDeterministicGivenEphemeral(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	a := sealFC(t, alice, bob.Public(), LayoutMesh, request("hi"), 7)
	b := sealFC(t, alice, bob.Public(), LayoutMesh, request("hi"), 7)
	c := sealFC(t, alice, bob.Public(), LayoutMesh, request("hi"), 8)
	if !bytes.Equal(a.Frames[0], b.Frames[0]) {
		t.Fatal("same inputs, different frames")
	}
	if a.MsgID == c.MsgID || a.E == c.E {
		t.Fatal("a new ephemeral key should give an unlinkable message")
	}
	// A real source never repeats.
	d, err := SealFirstContact(alice, bob.Public(), LayoutMesh, request("hi").Marshal(), nil)
	if err != nil || d.E == a.E {
		t.Fatalf("crypto/rand ephemeral: %v", err)
	}
	if _, err := SealFirstContact(alice, bob.Public(), LayoutMesh, request("hi").Marshal(), bytes.NewReader(make([]byte, 31))); err == nil {
		t.Fatal("short randomness accepted")
	}
}

func TestFirstContactTampering(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	s := sealFC(t, alice, bob.Public(), LayoutMesh, request(string(bytes.Repeat([]byte("t"), 150))), 3)
	if len(s.Frames) != 2 {
		t.Fatalf("%d fragments", len(s.Frames))
	}
	for fi, f := range s.Frames {
		for i := range f {
			for _, bit := range []byte{0x01, 0x80} {
				bad := bytes.Clone(f)
				bad[i] ^= bit
				if res, err := newFCReceiver(bob).Accept(bad); err == nil {
					t.Fatalf("frame %d byte %d ^%#x accepted: %v", fi, i, bit, res.Status)
				}
			}
		}
		if _, err := newFCReceiver(bob).Accept(f[:len(f)-1]); err == nil {
			t.Fatalf("truncated frame %d accepted", fi)
		}
		if _, err := newFCReceiver(bob).Accept(append(bytes.Clone(f), 0)); err == nil {
			t.Fatalf("extended frame %d accepted", fi)
		}
	}
	// Swapping the fragments' headers is caught too.
	sw := bytes.Clone(s.Frames[1])
	sw[41] = fragByte(0, 2)
	if _, err := newFCReceiver(bob).Accept(sw); err == nil {
		t.Fatal("fragment 1 relabelled as 0 accepted")
	}
}

// A frame for someone else fails exactly like a forgery and touches no
// state.
func TestFirstContactWrongRecipient(t *testing.T) {
	alice, bob, carol := fcIdentity(t, 1), fcIdentity(t, 2), fcIdentity(t, 3)
	s := sealFC(t, alice, bob.Public(), LayoutMesh, request(string(bytes.Repeat([]byte("w"), 150))), 4)
	r := newFCReceiver(carol)
	for i, f := range s.Frames {
		if _, err := r.Accept(f); err != ErrAuth {
			t.Fatalf("carol opened fragment %d: %v", i, err)
		}
	}
	if r.Dedup.(*MemDedup).Len() != 0 || len(r.partials) != 0 {
		t.Fatal("failed frames touched receiver state")
	}
	// The sender can't open its own request either: it lacks Bob's key.
	if _, err := newFCReceiver(alice).Accept(s.Frames[0]); err != ErrAuth {
		t.Fatalf("sender opened its own request: %v", err)
	}
}

// Observers see neither the sender's nor the recipient's key, in either
// form (design §8.5).
func TestFirstContactHidesIdentities(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	var keys [][]byte
	for _, id := range []*identity.Identity{alice, bob} {
		ed := id.Public()
		x, _ := ed.X25519()
		keys = append(keys, ed[:], x.Bytes())
	}
	for _, l := range []Layout{LayoutMesh, LayoutIP} {
		s := sealFC(t, alice, bob.Public(), l, request(string(bytes.Repeat([]byte("h"), 200))), 5)
		for fi, f := range s.Frames {
			for _, k := range keys {
				for i := 0; i+8 <= len(k); i++ {
					if bytes.Contains(f, k[i:i+8]) {
						t.Fatalf("%s fragment %d contains key bytes %x", l, fi, k[i:i+8])
					}
				}
			}
		}
	}
}

func TestFirstContactReplay(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	s := sealFC(t, alice, bob.Public(), LayoutMesh, request(string(bytes.Repeat([]byte("r"), 150))), 6)
	r := newFCReceiver(bob)
	if res, err := r.Accept(s.Frames[0]); err != nil || res.Status != Partial || res.Have != 0b01 {
		t.Fatalf("fragment 0: %v %v", res.Status, err)
	}
	if res, err := r.Accept(s.Frames[0]); err != nil || res.Status != Duplicate || res.Have != 0b01 {
		t.Fatalf("dup of partial: %v %02b %v", res.Status, res.Have, err)
	}
	if res, err := r.Accept(s.Frames[1]); err != nil || res.Status != Delivered {
		t.Fatalf("completion: %v %v", res.Status, err)
	}
	for i, f := range s.Frames {
		if res, err := r.Accept(f); err != nil || res.Status != Duplicate || res.Have != 0b11 {
			t.Fatalf("replay of fragment %d: %v %02b %v", i, res.Status, res.Have, err)
		}
	}
	// Past the dedup TTL the entry is gone, and the window rejects it.
	r.Now = func() time.Time { return testNow.Add(DedupTTL + time.Hour) }
	if _, err := r.Accept(s.Frames[0]); !errors.Is(err, ErrStale) {
		t.Fatalf("31-day-old replay: %v, want ErrStale", err)
	}
	if len(r.partials) != 0 {
		t.Fatal("stale fragment created a reassembly buffer")
	}
}

func TestFirstContactWindow(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
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
		in := request("t")
		in.Time = Timestamp(tc.at)
		r := newFCReceiver(bob)
		_, err := r.Accept(sealFC(t, alice, bob.Public(), LayoutMesh, in, 9).Frames[0])
		if tc.ok != (err == nil) || !tc.ok && !errors.Is(err, ErrStale) {
			t.Errorf("timestamp %v: err = %v", tc.at.Sub(testNow), err)
		}
		if !tc.ok && r.Dedup.(*MemDedup).Len() != 0 {
			t.Error("stale frame recorded in dedup")
		}
	}
}

// Small-order points as X25519 u-coordinates (the list libsodium blocks),
// plus non-canonical encodings.
var badEphemerals = []struct {
	name string
	u    string
	err  error
}{
	{"0", "0000000000000000000000000000000000000000000000000000000000000000", ErrAuth},
	{"1", "0100000000000000000000000000000000000000000000000000000000000000", ErrAuth},
	{"order 8 (a)", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", ErrAuth},
	{"order 8 (b)", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", ErrAuth},
	{"p−1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ErrAuth},
	{"p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ErrMalformed},
	{"p+1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ErrMalformed},
	{"top bit", "0900000000000000000000000000000000000000000000000000000000000080", ErrMalformed},
}

// A hostile sender builds frames around a small-order e, under the keys a
// receiver that skipped the all-zero check would derive. They are refused.
func TestFirstContactBadEphemeral(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	bx, _ := bob.Public().X25519()
	ss, err := alice.DH(bx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range badEphemerals {
		u, _ := hex.DecodeString(c.u)
		if c.err == ErrAuth { // a canonical small-order point: DH itself must refuse it
			if p, err := ecdh.X25519().NewPublicKey(u); err != nil {
				t.Fatal(err)
			} else if _, err := bob.DH(p); err == nil {
				t.Fatalf("e = %s: DH accepted a small-order point", c.name)
			}
		}
		s := sealFirstContact(alice.Public(), bob.Public(), LayoutMesh, request("x").Marshal(), u, make([]byte, 32), ss)
		r := newFCReceiver(bob)
		if _, err := r.Accept(s.Frames[0]); !errors.Is(err, c.err) {
			t.Errorf("e = %s: %v, want %v", c.name, err, c.err)
		}
		if r.Dedup.(*MemDedup).Len() != 0 {
			t.Errorf("e = %s: touched dedup", c.name)
		}
	}
	// Flipping the ignored top bit of a real e is caught before any DH.
	s := sealFC(t, alice, bob.Public(), LayoutMesh, request("x"), 1)
	f := bytes.Clone(s.Frames[0])
	f[32] |= 0x80
	if _, err := ParseFirstContactHeader(f); !errors.Is(err, ErrMalformed) {
		t.Errorf("top bit set: %v", err)
	}
}

// Requests from oneself, from a key with the same X25519 form, or from an
// invalid key are refused on both sides.
func TestFirstContactBadSender(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	ak := alice.Public()
	neg := ak
	neg[31] ^= 0x80 // −A: same X25519 key
	if _, err := identity.ParsePublicKey(neg[:]); err != nil {
		t.Fatal(err)
	}
	for _, to := range []identity.PublicKey{ak, neg} {
		if _, err := SealFirstContact(alice, to, LayoutMesh, request("me").Marshal(), ephemeral(1)); !errors.Is(err, ErrSelf) {
			t.Errorf("seal to %s: %v", to.KeyID(), err)
		}
	}

	bk := bob.Public()
	bx, _ := bk.X25519()
	eSeed := bytes.Repeat([]byte{4}, 32)
	ePriv, _ := ecdh.X25519().NewPrivateKey(eSeed)
	es, _ := ePriv.ECDH(bx)
	selfSS, _ := bob.DH(bx)
	negB := bk
	negB[31] ^= 0x80
	smallOrder := identity.PublicKey{1} // the identity point
	for name, c := range map[string]struct {
		sender identity.PublicKey
		ss     []byte
	}{
		"bob to bob":  {bk, selfSS},
		"−bob to bob": {negB, selfSS},
		"small order": {smallOrder, make([]byte, 32)},
	} {
		s := sealFirstContact(c.sender, bk, LayoutMesh, request("x").Marshal(), ePriv.PublicKey().Bytes(), es, c.ss)
		if _, err := newFCReceiver(bob).Accept(s.Frames[0]); err != ErrAuth {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Fragment 1 is opened under es alone. Someone who knows e's private key but
// not the sender's static key can make a fragment 1 that authenticates, but
// the msg_id check (keyed through ss) stops it completing a message.
func TestFirstContactTailBoundToSender(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	in := request(string(bytes.Repeat([]byte("a"), 150))).Marshal()
	s, err := SealFirstContact(alice, bob.Public(), LayoutMesh, in, ephemeral(0x42))
	if err != nil {
		t.Fatal(err)
	}
	ePriv, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	bx, _ := bob.Public().X25519()
	es, _ := ePriv.ECDH(bx)
	ck1 := fcCK1(bob.Public(), s.E[:], es)
	forged := bytes.Clone(fcChunk(LayoutMesh, in, 1))
	forged[0] ^= 1
	hdr := s.Frames[1][:fcHeaderLen]
	f1 := aeadFor(fcKey(ck1, labelFCTail, s.MsgID, 2, LayoutMesh)).Seal(bytes.Clone(hdr), nonce(1), forged, hdr)

	r := newFCReceiver(bob)
	if res, err := r.Accept(f1); err != nil || res.Status != Partial {
		t.Fatalf("forged tail: %v %v", res.Status, err)
	}
	if _, err := r.Accept(s.Frames[0]); !errors.Is(err, ErrMsgID) {
		t.Fatalf("completion with forged tail: %v, want ErrMsgID", err)
	}
}

func TestFirstContactReassemblyBounded(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	r := newFCReceiver(bob)
	var first *SealedFirstContact
	for i := range MaxFirstContactPartials + 4 {
		s := sealFC(t, alice, bob.Public(), LayoutMesh, request(string(bytes.Repeat([]byte("p"), 150))), byte(i))
		if i == 0 {
			first = s
		}
		r.Now = func() time.Time { return testNow.Add(time.Duration(i) * time.Second) }
		if _, err := r.Accept(s.Frames[0]); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.partials) != MaxFirstContactPartials {
		t.Fatalf("%d partial buffers, want %d", len(r.partials), MaxFirstContactPartials)
	}
	if res, _ := r.Accept(first.Frames[1]); res.Status == Delivered {
		t.Fatal("evicted message completed")
	}
	r.Now = func() time.Time { return testNow.Add(PartialTTL + time.Hour) }
	r.Sweep()
	if len(r.partials) != 0 {
		t.Fatal("sweep left expired buffers")
	}
}

// FIRST_CONTACT and DATA frames are never confused.
func TestFirstContactKinds(t *testing.T) {
	alice, bob := fcIdentity(t, 1), fcIdentity(t, 2)
	for _, l := range []Layout{LayoutMesh, LayoutIP} {
		fc := sealFC(t, alice, bob.Public(), l, request("k"), 1).Frames[0]
		if _, err := ParseHeader(fc); !errors.Is(err, ErrNotData) {
			t.Errorf("%s: DATA parser on FIRST_CONTACT: %v", l, err)
		}
		data := seal(t, testKey(1), l, im("k")).Frames[0]
		if _, err := ParseFirstContactHeader(data); !errors.Is(err, ErrNotFirstContact) {
			t.Errorf("%s: FIRST_CONTACT parser on DATA: %v", l, err)
		}
	}
	s := sealFC(t, alice, bob.Public(), LayoutMesh, request(string(bytes.Repeat([]byte("h"), 150))), 1)
	f0 := s.Frames[0]
	mod := func(fn func([]byte) []byte) []byte { return fn(bytes.Clone(f0)) }
	for name, b := range map[string][]byte{
		"version 2":       mod(func(b []byte) []byte { b[0] = 2<<5 | 3; return b }),
		"index ≥ count":   mod(func(b []byte) []byte { b[41] = 0x21; return b }),
		"3 mesh frags":    mod(func(b []byte) []byte { b[41] = 0x02; return b }),
		"2 IP frags":      mod(func(b []byte) []byte { b[0] = VerKind(KindFirstContactIP); b[41] = 0x01; return b }),
		"oversize":        append(bytes.Clone(f0), 0),
		"short non-final": f0[:199],
		"tiny":            f0[:FirstContactTailOverhead],
		"short frag 0":    mod(func(b []byte) []byte { b[41] = 0x00; return b[:FirstContactOverhead+minInner-1] }),
	} {
		if _, err := ParseFirstContactHeader(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestFirstContactSealOnce is the seal-once property for first contacts
// (spec/wire.md §11.4): no (key, nonce) pair ever encrypts two different
// (plaintext, associated data) pairs, across senders, recipients, layouts
// and repeated payloads, even when the ephemeral randomness repeats.
func TestFirstContactSealOnce(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	ids := []*identity.Identity{fcIdentity(t, 1), fcIdentity(t, 2), fcIdentity(t, 3)}
	type use struct{ pt, ad string }
	seen := map[string]use{}
	record := func(key, n, pt, ad []byte) {
		id := string(key) + string(n)
		u := use{string(pt), string(ad)}
		if prev, ok := seen[id]; ok && prev != u {
			t.Fatalf("(key, nonce) reused for different input:\n prev %x / %x\n now  %x / %x", prev.ad, prev.pt, u.ad, u.pt)
		}
		seen[id] = u
	}
	bodies := []string{"hi", "hey", "", "add me"}
	for range 1500 {
		si := rng.IntN(3)
		ri := (si + 1 + rng.IntN(2)) % 3
		from, to := ids[si], ids[ri]
		l := []Layout{LayoutMesh, LayoutIP}[rng.IntN(2)]
		in := Inner{Type: BuddyRequest, Time: uint32(rng.IntN(2)), Body: []byte(bodies[rng.IntN(len(bodies))])}
		if rng.IntN(4) == 0 {
			in.Body = bytes.Repeat([]byte("L"), 80+rng.IntN(140))
		}
		// A broken RNG: only three ephemeral keys, ever.
		s, err := SealFirstContact(from, to.Public(), l, in.Marshal(), ephemeral(byte(rng.IntN(3))))
		if err != nil {
			t.Fatal(err)
		}
		ex, _ := ecdh.X25519().NewPublicKey(s.E[:])
		es, _ := to.DH(ex)
		fx, _ := from.Public().X25519()
		ss, _ := to.DH(fx)
		ck1 := fcCK1(to.Public(), s.E[:], es)
		ck2 := fcCK2(ck1, ss, from.Public())
		n := len(s.Frames)
		for i, f := range s.Frames {
			h, err := ParseFirstContactHeader(f)
			if err != nil {
				t.Fatal(err)
			}
			o, err := openFirstContact(to, h, f)
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				sk := from.Public()
				record(fcKey(ck1, labelFCEncS, h.MsgID, n, l), nonce(0), sk[:], f[:fcHeaderLen])
				record(fcKey(ck2, labelFCPayload, h.MsgID, n, l), nonce(0), o.pt, f[:fcHeaderLen+fcEncSLen])
			} else {
				record(fcKey(ck1, labelFCTail, h.MsgID, n, l), nonce(i), o.pt, f[:fcHeaderLen])
			}
		}
	}
}

func FuzzParseFirstContactHeader(f *testing.F) {
	alice, bob := fcIdentity(f, 1), fcIdentity(f, 2)
	for _, l := range []Layout{LayoutMesh, LayoutIP} {
		for _, fr := range sealFC(f, alice, bob.Public(), l, request(string(bytes.Repeat([]byte("s"), 120))), 1).Frames {
			f.Add(fr)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseFirstContactHeader(b)
		if err != nil {
			return
		}
		li := fcLayouts[h.Layout]
		if h.Index >= h.Count || h.Count > li.maxFrags || len(b) > li.frameLen || !canonicalU(h.E[:]) ||
			(h.Index == 0 && len(b) < FirstContactOverhead+minInner) {
			t.Fatalf("accepted bad header %+v for %d bytes", h, len(b))
		}
	})
}

// FuzzFirstContactAccept feeds arbitrary bytes, and mutations of real
// frames, to the recipient. Nothing may panic, and anything delivered must
// be exactly what Alice sealed.
func FuzzFirstContactAccept(f *testing.F) {
	alice, bob := fcIdentity(f, 1), fcIdentity(f, 2)
	want := request(string(bytes.Repeat([]byte("f"), 150)))
	s := sealFC(f, alice, bob.Public(), LayoutMesh, want, 1)
	for _, fr := range s.Frames {
		f.Add(fr)
	}
	f.Add(sealFC(f, alice, bob.Public(), LayoutIP, want, 2).Frames[0])
	f.Fuzz(func(t *testing.T, b []byte) {
		r := newFCReceiver(bob)
		r.Accept(s.Frames[1]) // so fragment 0 variants can complete a message
		res, err := r.Accept(b)
		if err != nil || res.Status != Delivered {
			return
		}
		if m := res.Message; m.Sender != alice.Public() || !bytes.Equal(m.Inner.Body, want.Body) || m.Inner.Type != want.Type {
			t.Fatalf("delivered forged request from %s: %q", m.Sender.KeyID(), m.Inner.Body)
		}
	})
}
