package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// neg returns −pk: flipping the sign bit negates x, keeping y.
func neg(pk PublicKey) PublicKey {
	pk[31] ^= 0x80
	return pk
}

func testStatement(t *testing.T) (*Identity, RotationStatement) {
	t.Helper()
	return mustID(t, 0xC3), RotationStatement{Old: mustID(t, 0xA1).Public(), New: mustID(t, 0xA2).Public(), IssuedAt: 59572860}
}

func TestRotationSignedMessage(t *testing.T) {
	_, st := testStatement(t)
	m := st.SignedMessage()
	if len(m) != RotationMessageSize || RotationMessageSize != 85 {
		t.Fatalf("signed message is %d bytes", len(m))
	}
	want := append([]byte("openaim/v1/rotate"), st.Old[:]...)
	want = append(want, st.New[:]...)
	want = binary.BigEndian.AppendUint32(want, st.IssuedAt)
	if !bytes.Equal(m, want) {
		t.Fatalf("signed message %x, want %x", m, want)
	}
}

func TestRotationRoundTrip(t *testing.T) {
	rec, st := testStatement(t)
	sig, err := SignRotation(rec, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRotation(rec.Public(), st, sig); err != nil {
		t.Fatal(err)
	}
	// The signature is an ordinary Ed25519 signature over SignedMessage, and
	// the same as Sign with the rotate label.
	rk := rec.Public()
	if !ed25519.Verify(rk[:], st.SignedMessage(), sig) {
		t.Fatal("not an Ed25519 signature over SignedMessage")
	}
	if !Verify(rec.Public(), "openaim/v1/rotate", st.SignedMessage()[17:], sig) {
		t.Fatal("not a Sign(\"openaim/v1/rotate\", …) signature")
	}
	if fresh, _ := GenerateRecovery(); fresh == nil || fresh.Public() == rec.Public() {
		t.Fatal("GenerateRecovery")
	}
}

func TestRotationRejects(t *testing.T) {
	rec, st := testStatement(t)
	sig, err := SignRotation(rec, st)
	if err != nil {
		t.Fatal(err)
	}
	other := mustID(t, 0xC4)
	otherSig, _ := SignRotation(other, st)
	old := mustID(t, 0xA1)
	oldSig := ed25519.Sign(old.priv, st.SignedMessage()) // signed by the old identity key itself

	small := PublicKey{1} // the identity point
	bad := st
	bad.Old = small

	tamper := func(f func(*RotationStatement)) RotationStatement {
		s := st
		f(&s)
		return s
	}
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 1
		return c
	}
	cases := []struct {
		name string
		rk   PublicKey
		st   RotationStatement
		sig  []byte
	}{
		{"wrong recovery key", other.Public(), st, sig},
		{"signed by another recovery key", rec.Public(), st, otherSig},
		{"signed by the old identity key", rec.Public(), st, oldSig},
		{"old identity key as recovery key", old.Public(), st, oldSig},
		{"tampered old", rec.Public(), tamper(func(s *RotationStatement) { s.Old = mustID(t, 0xA3).Public() }), sig},
		{"tampered new", rec.Public(), tamper(func(s *RotationStatement) { s.New = mustID(t, 0xA3).Public() }), sig},
		{"tampered issued_at", rec.Public(), tamper(func(s *RotationStatement) { s.IssuedAt++ }), sig},
		{"swapped keys", rec.Public(), tamper(func(s *RotationStatement) { s.Old, s.New = s.New, s.Old }), sig},
		{"tampered R", rec.Public(), st, flip(sig, 0)},
		{"tampered S", rec.Public(), st, flip(sig, 40)},
		{"S + ℓ", rec.Public(), st, addL(sig)},
		{"short signature", rec.Public(), st, sig[:63]},
		{"long signature", rec.Public(), st, append(bytes.Clone(sig), 0)},
		{"no signature", rec.Public(), st, nil},
		{"old == new", rec.Public(), tamper(func(s *RotationStatement) { s.New = s.Old }), sig},
		{"new == −old", rec.Public(), tamper(func(s *RotationStatement) { s.New = neg(s.Old) }), sig},
		{"recovery == old", st.Old, st, sig},
		{"recovery == new", st.New, st, sig},
		{"recovery == −old", neg(st.Old), st, sig},
		{"recovery == −new", neg(st.New), st, sig},
		{"small-order old", rec.Public(), bad, sig},
		{"small-order new", rec.Public(), tamper(func(s *RotationStatement) { s.New = small }), sig},
		{"small-order recovery", small, st, sig},
		{"off-curve old", rec.Public(), tamper(func(s *RotationStatement) { s.Old = PublicKey{2} }), sig},
		{"issued_at 0", rec.Public(), tamper(func(s *RotationStatement) { s.IssuedAt = 0 }), sig},
	}
	for _, c := range cases {
		if err := VerifyRotation(c.rk, c.st, c.sig); !errors.Is(err, ErrInvalidRotation) {
			t.Errorf("%s: err = %v, want ErrInvalidRotation", c.name, err)
		}
	}
}

// addL returns sig with ℓ added to S, the classic malleation. S + ℓ still
// fits in 253 bits, so it is a 32-byte value Verify must refuse.
func addL(sig []byte) []byte {
	l := [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	out := bytes.Clone(sig)
	var carry uint16
	for i := range 32 {
		v := uint16(out[32+i]) + uint16(l[i]) + carry
		out[32+i], carry = byte(v), v>>8
	}
	return out
}

func TestSignRotationRefuses(t *testing.T) {
	rec, st := testStatement(t)
	for name, c := range map[string]struct {
		rec *Identity
		st  RotationStatement
	}{
		"nil recovery":    {nil, st},
		"old == new":      {rec, RotationStatement{Old: st.Old, New: st.Old, IssuedAt: 1}},
		"new == −old":     {rec, RotationStatement{Old: st.Old, New: neg(st.Old), IssuedAt: 1}},
		"recovery is old": {mustID(t, 0xA1), st},
		"recovery is new": {mustID(t, 0xA2), st},
		"invalid new":     {rec, RotationStatement{Old: st.Old, New: PublicKey{1}, IssuedAt: 1}},
		"issued_at 0":     {rec, RotationStatement{Old: st.Old, New: st.New}},
	} {
		if sig, err := SignRotation(c.rec, c.st); err == nil {
			t.Errorf("%s: signed %x", name, sig)
		}
	}
}

func TestCheckRecoveryKey(t *testing.T) {
	id, rec := mustID(t, 1).Public(), mustID(t, 2).Public()
	if err := CheckRecoveryKey(id, rec); err != nil {
		t.Fatal(err)
	}
	for name, rk := range map[string]PublicKey{"same": id, "negated": neg(id), "small order": {1}, "off curve": {2}} {
		if err := CheckRecoveryKey(id, rk); !errors.Is(err, ErrInvalidRotation) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRotationCheckTime(t *testing.T) {
	st := RotationStatement{IssuedAt: 1000}
	issued := time.Date(2025, 1, 1, 0, 16, 40, 0, time.UTC)
	if !st.IssuedTime().Equal(issued) {
		t.Fatalf("IssuedTime = %v", st.IssuedTime())
	}
	day := 24 * time.Hour
	for _, c := range []struct {
		name   string
		now    time.Time
		maxAge time.Duration
		ok     bool
	}{
		{"now", issued, day, true},
		{"exactly max future ahead", issued.Add(-RotationMaxFuture), day, true},
		{"just past max future", issued.Add(-RotationMaxFuture - time.Second), day, false},
		{"exactly max age old", issued.Add(day), day, true},
		{"just past max age", issued.Add(day + time.Second), day, false},
		{"years old, no age limit", issued.Add(3 * 365 * day), 0, true},
		{"far future, no age limit", issued.Add(-time.Hour), 0, false},
	} {
		err := st.CheckTime(c.now, c.maxAge, RotationMaxFuture)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrRotationTime)) {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
	// The largest issued_at doesn't overflow.
	if got := (RotationStatement{IssuedAt: ^uint32(0)}).IssuedTime(); got.Year() != 2161 {
		t.Errorf("max issued_at = %v", got)
	}
}

// FuzzVerifyRotation: under a fixed recovery key, the only (statement,
// signature) that verifies is the one that was signed. Any change to a key,
// the time or the signature is rejected, so signatures aren't malleable.
func FuzzVerifyRotation(f *testing.F) {
	rec, _ := FromSeed(bytes.Repeat([]byte{0xC3}, 32))
	a, _ := FromSeed(bytes.Repeat([]byte{0xA1}, 32))
	b, _ := FromSeed(bytes.Repeat([]byte{0xA2}, 32))
	orig := RotationStatement{Old: a.Public(), New: b.Public(), IssuedAt: 59572860}
	origSig, err := SignRotation(rec, orig)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(orig.Old[:], orig.New[:], orig.IssuedAt, origSig)
	f.Add(orig.New[:], orig.Old[:], orig.IssuedAt, origSig)
	f.Fuzz(func(t *testing.T, old, nw []byte, at uint32, sig []byte) {
		var st RotationStatement
		copy(st.Old[:], old)
		copy(st.New[:], nw)
		st.IssuedAt = at
		if VerifyRotation(rec.Public(), st, sig) != nil {
			return
		}
		if st != orig || !bytes.Equal(sig, origSig) {
			t.Fatalf("accepted a statement that wasn't signed: %+v %x", st, sig)
		}
	})
}
