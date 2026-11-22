package rendezvous

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/transport/ip"
	pb "github.com/aghman/openaim/internal/wirepb"
)

var testNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func testLocator(t testing.TB) Locator {
	return Locator{
		ID: testPeer(t, 0x9E),
		Addrs: maddrs(t, "/ip4/192.0.2.7/udp/4001/quic-v1", "/ip6/2001:db8::7/tcp/4001",
			"/ip4/198.51.100.1/tcp/4001/p2p/"+testPeer(t, 0x7A).String()+"/p2p-circuit"),
		IssuedAt:  testNow,
		ExpiresAt: testNow.Add(MaxTTL),
	}
}

func equalLocators(a, b Locator) bool {
	return a.ID == b.ID && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt) &&
		slices.EqualFunc(a.Addrs, b.Addrs, func(x, y ma.Multiaddr) bool { return x.Equal(y) })
}

func TestDerive(t *testing.T) {
	ab, ba := newPair(t, 0xA1, 0xB0)
	day := frame.Day(testNow)
	k := Derive(ab.Send, day)
	if kb := Derive(ba.Recv, day); kb.Key != k.Key || kb.L != k.L || !kb.Pub.Equal(k.Pub) {
		t.Fatal("publisher and buddy derive different keys")
	}
	if !strings.HasPrefix(k.Key, "/oa-rdv/") || k.Key != ip.RendezvousKey(k.Pub) {
		t.Fatalf("key %q", k.Key)
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(k.Seed[:]), k.Priv) {
		t.Error("private key is not the seed's")
	}
	// Every direction, day and pair gives unrelated keys.
	others := []Keys{Derive(ab.Recv, day), Derive(ab.Send, day+1), Derive(ab.Send, day-1)}
	ac, _ := newPair(t, 0xA1, 0xC2)
	others = append(others, Derive(ac.Send, day))
	for i, o := range others {
		if o.Key == k.Key || o.L == k.L || o.Seed == k.Seed || bytes.Equal(o.L[:], k.Seed[:]) {
			t.Errorf("case %d: keys collide", i)
		}
	}
	if k.L == k.Seed {
		t.Error("L equals the seed")
	}
}

func TestPlaintextRoundTrip(t *testing.T) {
	l := testLocator(t)
	pt, err := EncodePlaintext(l)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != PadBlock {
		t.Errorf("plaintext is %d bytes, want one %d-byte block", len(pt), PadBlock)
	}
	got, err := DecodePlaintext(pt)
	if err != nil {
		t.Fatal(err)
	}
	if !equalLocators(got, l) {
		t.Errorf("got %+v, want %+v", got, l)
	}
	// Deterministic.
	if pt2, _ := EncodePlaintext(l); !bytes.Equal(pt, pt2) {
		t.Error("encoding is not deterministic")
	}

	// The biggest locator still fits a record, in the last bucket.
	big := l
	big.Addrs = nil
	for i := range MaxAddrs {
		big.Addrs = append(big.Addrs, maddrs(t, "/dns/"+strings.Repeat(string(rune('a'+i)), 80)+".example/tcp/4001")...)
	}
	pt, err = EncodePlaintext(big)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != MaxPlaintext {
		t.Errorf("big plaintext is %d bytes", len(pt))
	}
	payload, err := SealPayload(Derive([32]byte{1}, 1), 1, big, nil)
	if err != nil || len(payload) > ip.MaxRendezvousPayload {
		t.Fatalf("big payload: %d bytes, %v", len(payload), err)
	}
}

func TestPlaintextLimits(t *testing.T) {
	l := testLocator(t)
	enc := func(f func(*Locator)) error {
		c := l
		c.Addrs = slices.Clone(l.Addrs)
		f(&c)
		_, err := EncodePlaintext(c)
		return err
	}
	long := maddrs(t, "/dns/"+strings.Repeat("x", 130)+"/tcp/1")[0]
	for name, f := range map[string]func(*Locator){
		"no peer ID":       func(c *Locator) { c.ID = "" },
		"bad peer ID":      func(c *Locator) { c.ID = "nope" },
		"9 addresses":      func(c *Locator) { c.Addrs = slices.Repeat(c.Addrs[:1], 9) },
		"long address":     func(c *Locator) { c.Addrs = []ma.Multiaddr{long} },
		"expires first":    func(c *Locator) { c.ExpiresAt = c.IssuedAt },
		"TTL too long":     func(c *Locator) { c.ExpiresAt = c.IssuedAt.Add(MaxTTL + time.Second) },
		"before the epoch": func(c *Locator) { c.IssuedAt = frame.Epoch.Add(-time.Hour) },
	} {
		if err := enc(f); !errors.Is(err, ErrBadLocator) {
			t.Errorf("%s: %v", name, err)
		}
	}

	good, _ := EncodePlaintext(l)
	raw := func(m *pb.RendezvousLocator) []byte {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		pt := make([]byte, 2+len(b))
		pt[0], pt[1] = byte(len(b)>>8), byte(len(b))
		copy(pt[2:], b)
		return pt
	}
	id := []byte(l.ID)
	ok := func() *pb.RendezvousLocator {
		return &pb.RendezvousLocator{Ip: &pb.IPHint{PeerId: id, Addrs: [][]byte{l.Addrs[0].Bytes()}}, IssuedAt: 100, ExpiresAt: 200}
	}
	if _, err := DecodePlaintext(raw(ok())); err != nil {
		t.Fatalf("valid raw locator: %v", err)
	}
	mod := func(f func(m *pb.RendezvousLocator)) []byte { m := ok(); f(m); return raw(m) }
	for name, pt := range map[string][]byte{
		"empty":            nil,
		"one byte":         {0},
		"too long":         make([]byte, MaxPlaintext+1),
		"length overruns":  append([]byte{0xff, 0xff}, good[2:]...),
		"nonzero padding":  append(slices.Clone(good[:len(good)-1]), 1),
		"not protobuf":     {0, 2, 0xff, 0xff},
		"no IP hint":       mod(func(m *pb.RendezvousLocator) { m.Ip = nil }),
		"empty peer ID":    mod(func(m *pb.RendezvousLocator) { m.Ip.PeerId = nil }),
		"long peer ID":     mod(func(m *pb.RendezvousLocator) { m.Ip.PeerId = make([]byte, 65) }),
		"bad peer ID":      mod(func(m *pb.RendezvousLocator) { m.Ip.PeerId = []byte("not a multihash") }),
		"9 addresses":      mod(func(m *pb.RendezvousLocator) { m.Ip.Addrs = slices.Repeat(m.Ip.Addrs, 9) }),
		"empty address":    mod(func(m *pb.RendezvousLocator) { m.Ip.Addrs = [][]byte{{}} }),
		"129-byte address": mod(func(m *pb.RendezvousLocator) { m.Ip.Addrs = [][]byte{make([]byte, 129)} }),
		"no times":         mod(func(m *pb.RendezvousLocator) { m.IssuedAt, m.ExpiresAt = 0, 0 }),
		"expires first":    mod(func(m *pb.RendezvousLocator) { m.ExpiresAt = 50 }),
		"TTL > 36 h":       mod(func(m *pb.RendezvousLocator) { m.ExpiresAt = 100 + 129601 }),
	} {
		if _, err := DecodePlaintext(pt); !errors.Is(err, ErrBadLocator) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Exactly 36 h is fine; an address we can't parse is skipped.
	got, err := DecodePlaintext(mod(func(m *pb.RendezvousLocator) {
		m.ExpiresAt = 100 + 129600
		m.Ip.Addrs = append(m.Ip.Addrs, []byte{0xfe, 0xff, 0xff, 0x7f, 1})
	}))
	if err != nil || len(got.Addrs) != 1 {
		t.Errorf("36 h and an unknown address: %+v, %v", got, err)
	}
}

func TestPayload(t *testing.T) {
	ab, ba := newPair(t, 0xA1, 0xB0)
	day := frame.Day(testNow)
	k := Derive(ab.Send, day)
	l := testLocator(t)
	payload, err := SealPayload(k, 42, l, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPayload(Derive(ba.Recv, day), 42, payload)
	if err != nil || !equalLocators(got, l) {
		t.Fatalf("buddy opens: %+v, %v", got, err)
	}
	if p2, _ := SealPayload(k, 42, l, nil); bytes.Equal(p2[:NonceSize], payload[:NonceSize]) {
		t.Error("nonce repeated")
	}

	bad := map[string]struct {
		k       Keys
		seq     uint64
		payload []byte
	}{
		"other seq":       {k, 43, payload},
		"other day":       {Derive(ab.Send, day+1), 42, payload},
		"other direction": {Derive(ab.Recv, day), 42, payload},
		"truncated":       {k, 42, payload[:len(payload)-1]},
		"too short":       {k, 42, payload[:NonceSize+15]},
	}
	for i := range payload {
		p := slices.Clone(payload)
		p[i] ^= 0x01
		if _, err := OpenPayload(k, 42, p); err == nil {
			t.Fatalf("flipped byte %d opened", i)
		}
	}
	for name, c := range bad {
		if _, err := OpenPayload(c.k, c.seq, c.payload); !errors.Is(err, ErrBadLocator) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The AD binds the key, so a record under another key does not open even
	// with the right L (only possible for someone holding K_dir anyway).
	k2 := k
	k2.KeyHash[0] ^= 1
	if _, err := OpenPayload(k2, 42, payload); err == nil {
		t.Error("opened with another key hash")
	}

	// Open checks the record's public key.
	v, _ := ip.SignRendezvousRecord(k.Priv, 42, payload)
	r, err := ip.ParseRendezvousRecord(k.Key, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(k, r); err != nil {
		t.Fatal(err)
	}
	r.PublicKey = Derive(ab.Send, day+1).Pub
	if _, err := Open(k, r); !errors.Is(err, ErrBadLocator) {
		t.Errorf("record with another public key: %v", err)
	}
}

func TestSelectAddrs(t *testing.T) {
	self := testPeer(t, 1)
	relay := testPeer(t, 2)
	in := maddrs(t,
		"/ip4/127.0.0.1/tcp/4001",
		"/ip4/192.168.1.5/tcp/4001",
		"/ip4/192.0.2.9/tcp/4001", // documentation range: not public
		"/ip4/8.8.8.8/udp/4001/quic-v1",
		"/ip4/8.8.4.4/tcp/4001/p2p/"+relay.String()+"/p2p-circuit/p2p/"+self.String(),
		"/ip4/8.8.8.8/udp/4001/quic-v1/p2p/"+self.String(), // duplicate once /p2p is stripped
		"/dns/"+strings.Repeat("x", 130)+"/tcp/1",          // too long
	)
	got := selectAddrs(peer.AddrInfo{ID: self, Addrs: in})
	var ss []string
	for _, a := range got {
		ss = append(ss, a.String())
	}
	want := []string{
		"/ip4/8.8.4.4/tcp/4001/p2p/" + relay.String() + "/p2p-circuit",
		"/ip4/8.8.8.8/udp/4001/quic-v1",
		"/ip4/192.168.1.5/tcp/4001",
		"/ip4/127.0.0.1/tcp/4001",
		"/ip4/192.0.2.9/tcp/4001",
	}
	if !slices.Equal(ss, want) {
		t.Errorf("got\n%v\nwant\n%v", strings.Join(ss, "\n"), strings.Join(want, "\n"))
	}

	// Many long addresses: at most 8, and they fit.
	var many []ma.Multiaddr
	for i := range 12 {
		many = append(many, maddrs(t, "/ip4/8.8.8."+string(rune('0'+i%10))+"/tcp/4001/p2p/"+relay.String()+"/p2p-circuit")...)
	}
	got = selectAddrs(peer.AddrInfo{ID: self, Addrs: many})
	if len(got) == 0 || len(got) > MaxAddrs {
		t.Fatalf("%d addresses", len(got))
	}
	if _, err := EncodePlaintext(Locator{ID: self, Addrs: got, IssuedAt: testNow, ExpiresAt: testNow.Add(time.Hour)}); err != nil {
		t.Error(err)
	}
}

// publishOne puts a record the way a publisher does.
func publishOne(t *testing.T, d *memDHT, kdir [32]byte, day uint32, seq uint64, l Locator) Keys {
	t.Helper()
	k := Derive(kdir, day)
	payload, err := SealPayload(k, seq, l, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutRendezvous(context.Background(), k.Priv, seq, payload); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestLookupChecks(t *testing.T) {
	ab, ba := newPair(t, 0xA1, 0xB0)
	ctx := context.Background()
	day := frame.Day(testNow)
	l := testLocator(t)
	l.IssuedAt, l.ExpiresAt = testNow, testNow.Add(time.Hour)

	d := newMemDHT()
	if _, err := Lookup(ctx, d, ba.Recv, testNow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty DHT: %v", err)
	}
	k := publishOne(t, d, ab.Send, day, 1000, l)

	f, err := Lookup(ctx, d, ba.Recv, testNow.Add(time.Minute))
	if err != nil || f.ID != l.ID || f.Day != day || f.Seq != 1000 {
		t.Fatalf("lookup: %+v, %v", f, err)
	}
	// A wrong key finds nothing: not the other direction, not someone else's.
	if _, err := Lookup(ctx, d, ab.Recv, testNow); !errors.Is(err, ErrNotFound) {
		t.Errorf("other direction: %v", err)
	}
	if _, err := Lookup(ctx, d, [32]byte{9}, testNow); !errors.Is(err, ErrNotFound) {
		t.Errorf("stranger: %v", err)
	}

	// Expired.
	if _, err := Lookup(ctx, d, ba.Recv, l.ExpiresAt); !errors.Is(err, ErrNotFound) || !errors.Is(err, ErrBadLocator) {
		t.Errorf("at expiry: %v", err)
	}
	// Issued too far in our future.
	if _, err := Lookup(ctx, d, ba.Recv, testNow.Add(-MaxSkew-time.Second)); !errors.Is(err, ErrNotFound) {
		t.Errorf("issued in the future: %v", err)
	}
	if _, err := Lookup(ctx, d, ba.Recv, testNow.Add(-MaxSkew)); err != nil {
		t.Errorf("issued within the skew: %v", err)
	}

	// Tampered ciphertext, validly re-signed (only the pair could), is
	// rejected by the AEAD; tampered without re-signing, by the DHT.
	r, _ := d.GetRendezvous(ctx, k.Key)
	tampered := slices.Clone(r.Payload)
	tampered[len(tampered)-20] ^= 0x80
	v, _ := ip.SignRendezvousRecord(k.Priv, 1001, tampered)
	if err := d.PutValue(k.Key, v); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(ctx, d, ba.Recv, testNow); !errors.Is(err, ErrBadLocator) {
		t.Errorf("tampered ciphertext: %v", err)
	}
	unsigned := d.value(k.Key)
	unsigned[len(unsigned)-80] ^= 1
	if err := d.PutValue(k.Key, unsigned); err == nil {
		t.Error("DHT accepted a tampered record")
	}
	// A payload moved to another seq doesn't open either.
	v, _ = ip.SignRendezvousRecord(k.Priv, 1002, r.Payload)
	if err := d.PutValue(k.Key, v); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(ctx, d, ba.Recv, testNow); !errors.Is(err, ErrBadLocator) {
		t.Errorf("payload under another seq: %v", err)
	}
	// A new good record fixes it.
	publishOne(t, d, ab.Send, day, 1003, l)
	if f, err := Lookup(ctx, d, ba.Recv, testNow); err != nil || f.Seq != 1003 {
		t.Errorf("after repair: %+v, %v", f, err)
	}
}

func TestLookupDayRollover(t *testing.T) {
	ab, ba := newPair(t, 0xA1, 0xB0)
	ctx := context.Background()
	day := frame.Day(testNow)
	midnight := dayStart(day + 1)
	loc := func(id peer.ID, at time.Time) Locator {
		return Locator{ID: id, IssuedAt: at, ExpiresAt: at.Add(MaxTTL)}
	}
	if got := LookupDays(testNow); !slices.Equal(got, []uint32{day, day - 1}) {
		t.Errorf("days at noon: %v", got)
	}
	if got := LookupDays(midnight.Add(-MaxSkew)); !slices.Equal(got, []uint32{day, day - 1, day + 1}) {
		t.Errorf("days just before midnight: %v", got)
	}

	// Only yesterday's record exists: found the next morning.
	d := newMemDHT()
	idOld, idNew := testPeer(t, 1), testPeer(t, 2)
	publishOne(t, d, ab.Send, day, 10, loc(idOld, testNow))
	if f, err := Lookup(ctx, d, ba.Recv, midnight.Add(6*time.Hour)); err != nil || f.ID != idOld || f.Day != day {
		t.Errorf("yesterday's record: %+v, %v", f, err)
	}
	// Two days later it's not tried any more.
	if _, err := Lookup(ctx, d, ba.Recv, midnight.Add(24*time.Hour+time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Errorf("record from two days ago: %v", err)
	}

	// The publisher's clock is ahead: it already wrote tomorrow's record,
	// which we find a few minutes before midnight, and which wins over
	// today's by seq.
	publishOne(t, d, ab.Send, day+1, 20, loc(idNew, midnight.Add(-2*time.Minute)))
	if f, err := Lookup(ctx, d, ba.Recv, midnight.Add(-5*time.Minute)); err != nil || f.ID != idNew || f.Day != day+1 {
		t.Errorf("tomorrow's record before midnight: %+v, %v", f, err)
	}
	if f, err := Lookup(ctx, d, ba.Recv, midnight.Add(-MaxSkew-time.Second)); err != nil || f.ID != idOld {
		t.Errorf("tomorrow's record should not be tried yet: %+v, %v", f, err)
	}
	// After midnight both today's (day+1) and yesterday's exist; the newest wins.
	if f, err := Lookup(ctx, d, ba.Recv, midnight.Add(time.Second)); err != nil || f.ID != idNew {
		t.Errorf("after midnight: %+v, %v", f, err)
	}
}

func FuzzDecodePlaintext(f *testing.F) {
	good, _ := EncodePlaintext(testLocator(f))
	f.Add(slices.Clone(good))
	f.Add(slices.Clone(good[:40]))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, pt []byte) {
		l, err := DecodePlaintext(pt)
		if err != nil {
			if !errors.Is(err, ErrBadLocator) {
				t.Fatalf("unwrapped error %v", err)
			}
			return
		}
		if l.ID == "" || len(l.Addrs) > MaxAddrs || !l.IssuedAt.Before(l.ExpiresAt) || l.ExpiresAt.Sub(l.IssuedAt) > MaxTTL {
			t.Fatalf("accepted a bad locator: %+v", l)
		}
		// What we accept, we can re-encode, and it decodes the same.
		pt2, err := EncodePlaintext(l)
		if err != nil {
			t.Fatalf("accepted locator does not re-encode: %v", err)
		}
		l2, err := DecodePlaintext(pt2)
		if err != nil || !equalLocators(l, l2) {
			t.Fatalf("re-encoded locator differs: %+v, %v", l2, err)
		}
	})
}

func FuzzOpenPayload(f *testing.F) {
	k := Derive([32]byte{0xAB}, 700)
	// A fixed nonce: fuzz workers rerun this setup and must get the same bytes.
	good, _ := SealPayload(k, 7, testLocator(f), bytes.NewReader(make([]byte, NonceSize)))
	// Seeds get copies: the fuzzing engine may mutate them in place.
	f.Add(uint64(7), slices.Clone(good))
	f.Add(uint64(8), slices.Clone(good))
	f.Add(uint64(0), slices.Clone(good[:NonceSize+16]))
	f.Fuzz(func(t *testing.T, seq uint64, payload []byte) {
		l, err := OpenPayload(k, seq, payload)
		if err != nil {
			if !errors.Is(err, ErrBadLocator) {
				t.Fatalf("unwrapped error %v", err)
			}
			return
		}
		// Only the sealed payload opens.
		if seq != 7 || !bytes.Equal(payload, good) || !equalLocators(l, testLocator(t)) {
			t.Fatalf("forged payload opened: seq %d", seq)
		}
	})
}
