package identity

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"regexp"
	"testing"
)

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func mustID(t *testing.T, b byte) *Identity {
	t.Helper()
	id, err := FromSeed(seed(b))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFromSeedDeterministic(t *testing.T) {
	a, b := mustID(t, 1), mustID(t, 1)
	if a.Public() != b.Public() || !bytes.Equal(a.Seed(), seed(1)) {
		t.Fatal("same seed, different identity")
	}
	if _, err := FromSeed(make([]byte, 31)); err == nil {
		t.Error("31-byte seed accepted")
	}
}

// The X25519 form of the public key must match the X25519 private scalar.
func TestX25519Conversion(t *testing.T) {
	for i := range 20 {
		id := mustID(t, byte(i))
		x, err := id.Public().X25519()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(x.Bytes(), id.x.PublicKey().Bytes()) {
			t.Fatalf("seed %d: converted public key != scalar·base", i)
		}
	}
}

func TestPairSymmetric(t *testing.T) {
	a, b := mustID(t, 1), mustID(t, 2)
	ab, err := a.Pair(b.Public())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := b.Pair(a.Public())
	if err != nil {
		t.Fatal(err)
	}
	if ab.Send != ba.Recv || ab.Recv != ba.Send {
		t.Fatal("directional keys don't match across the pair")
	}
	if ab.Send == ab.Recv {
		t.Fatal("both directions share a key")
	}
	c := mustID(t, 3)
	ac, _ := a.Pair(c.Public())
	if ac.Send == ab.Send {
		t.Fatal("different buddies, same key")
	}
	if _, err := a.Pair(a.Public()); err == nil {
		t.Error("pairing with self allowed")
	}
}

func TestRejectsBadKeys(t *testing.T) {
	identityPoint := append([]byte{1}, make([]byte, 31)...)
	// y = p + 1 encodes the identity non-canonically.
	nonCanonical := append([]byte{0xEE}, bytes.Repeat([]byte{0xFF}, 30)...)
	nonCanonical = append(nonCanonical, 0x7F)
	for name, b := range map[string][]byte{
		"short":         make([]byte, 31),
		"identity":      identityPoint,
		"non-canonical": nonCanonical,
		"not on curve":  append([]byte{2}, make([]byte, 31)...),
	} {
		if _, err := ParsePublicKey(b); !errors.Is(err, ErrBadPublicKey) {
			t.Errorf("%s: err = %v, want ErrBadPublicKey", name, err)
		}
	}
	a := mustID(t, 1)
	var small PublicKey
	copy(small[:], identityPoint)
	if _, err := a.Pair(small); err == nil {
		t.Error("paired with a small-order key")
	}
}

func TestSignatureLabels(t *testing.T) {
	a := mustID(t, 1)
	sig := a.Sign("openaim/v1/handle-claim", []byte("msg"))
	if !Verify(a.Public(), "openaim/v1/handle-claim", []byte("msg"), sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(a.Public(), "openaim/v1/nearby", []byte("msg"), sig) {
		t.Fatal("signature verified under another label")
	}
}

func TestSafetyNumber(t *testing.T) {
	a, b, c := mustID(t, 1).Public(), mustID(t, 2).Public(), mustID(t, 3).Public()
	sn := SafetyNumber(a, b)
	if sn != SafetyNumber(b, a) {
		t.Fatal("safety number depends on order")
	}
	if !regexp.MustCompile(`^(\d{5} ){7}\d{5}$`).MatchString(sn) {
		t.Fatalf("bad format %q", sn)
	}
	if sn == SafetyNumber(a, c) {
		t.Fatal("different pairs, same safety number")
	}
}

func TestKeyStrings(t *testing.T) {
	pk := mustID(t, 1).Public()
	got, err := ParsePublicKeyString(pk.String())
	if err != nil || got != pk {
		t.Fatalf("round trip: %v", err)
	}
	if !regexp.MustCompile(`^~[a-z2-7]{4}$`).MatchString(pk.KeyID()) {
		t.Fatalf("bad key ID %q", pk.KeyID())
	}
}

// DH agrees with an ephemeral key's own ECDH, and refuses small-order
// points (spec/wire.md §4.2).
func TestDH(t *testing.T) {
	id := mustID(t, 1)
	e, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	mine, err := id.DH(e.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	x, _ := id.Public().X25519()
	theirs, _ := e.ECDH(x)
	if !bytes.Equal(mine, theirs) {
		t.Fatal("DH disagrees with the ephemeral side")
	}
	for _, u := range [][]byte{make([]byte, 32), append([]byte{1}, make([]byte, 31)...)} {
		p, _ := ecdh.X25519().NewPublicKey(u)
		if _, err := id.DH(p); err == nil {
			t.Errorf("DH accepted small-order point %x", u[:1])
		}
	}
	if _, err := id.DH(nil); err == nil {
		t.Error("DH accepted nil")
	}
}
