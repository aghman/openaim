// Package identity holds a user's long-term identity key and the keys derived
// from it (design §5.1, §5.2, §8.2). spec/wire.md is normative for every
// label and byte layout used here.
//
// One Ed25519 key does both signing and static Diffie-Hellman: its X25519
// form (the birational map used by libsodium) does the DH. Every derivation
// binds the Ed25519 public keys, because two Ed25519 keys can share an X25519
// form.
package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"filippo.io/edwards25519"
)

// Labels (spec/wire.md §2). Each use has its own label.
const (
	labelPairSalt     = "openaim/v1"
	labelPair         = "openaim/v1/pair"
	labelDir          = "openaim/v1/dir"
	labelSafetyNumber = "openaim/v1/safety-number"
)

// PublicKey is an Ed25519 identity public key.
type PublicKey [ed25519.PublicKeySize]byte

// ErrBadPublicKey is returned for keys that are not canonical encodings of
// points of large prime order.
var ErrBadPublicKey = errors.New("identity: invalid public key")

// ParsePublicKey checks that b is a usable identity key: a canonical point
// encoding, not of small order. It returns ErrBadPublicKey otherwise.
func ParsePublicKey(b []byte) (PublicKey, error) {
	var pk PublicKey
	if len(b) != len(pk) {
		return pk, fmt.Errorf("%w: %d bytes", ErrBadPublicKey, len(b))
	}
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return pk, fmt.Errorf("%w: %v", ErrBadPublicKey, err)
	}
	if !bytes.Equal(p.Bytes(), b) {
		return pk, fmt.Errorf("%w: non-canonical encoding", ErrBadPublicKey)
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return pk, fmt.Errorf("%w: small-order point", ErrBadPublicKey)
	}
	copy(pk[:], b)
	return pk, nil
}

// X25519 returns the Montgomery (X25519) form of the key.
func (pk PublicKey) X25519() (*ecdh.PublicKey, error) {
	p, err := new(edwards25519.Point).SetBytes(pk[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadPublicKey, err)
	}
	return ecdh.X25519().NewPublicKey(p.BytesMontgomery())
}

// String is the key in lowercase unpadded base32, as in handle records and
// invite links.
func (pk PublicKey) String() string { return b32.EncodeToString(pk[:]) }

// KeyID is the short UI label for a key, e.g. "~k3f9" (design §5.2). It is
// not a security check and never appears in frames.
func (pk PublicKey) KeyID() string {
	h := sha256.Sum256(pk[:])
	return "~" + b32.EncodeToString(h[:])[:4]
}

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ParsePublicKeyString parses the base32 form produced by String.
func ParsePublicKeyString(s string) (PublicKey, error) {
	b, err := b32.DecodeString(strings.ToLower(s))
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: %v", ErrBadPublicKey, err)
	}
	return ParsePublicKey(b)
}

// Identity is a user's long-term identity key pair.
type Identity struct {
	seed [ed25519.SeedSize]byte
	priv ed25519.PrivateKey
	pub  PublicKey
	x    *ecdh.PrivateKey
}

// Generate creates a new identity from fresh randomness.
func Generate() (*Identity, error) {
	var seed [ed25519.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return FromSeed(seed[:])
}

// FromSeed rebuilds an identity from its 32-byte seed (what the recovery
// phrase encodes).
func FromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: seed must be %d bytes", ed25519.SeedSize)
	}
	id := &Identity{priv: ed25519.NewKeyFromSeed(seed)}
	copy(id.seed[:], seed)
	copy(id.pub[:], id.priv.Public().(ed25519.PublicKey))

	// The X25519 scalar is the clamped first half of SHA-512(seed), the same
	// scalar Ed25519 signs with. crypto/ecdh clamps it.
	h := sha512.Sum512(seed)
	x, err := ecdh.X25519().NewPrivateKey(h[:32])
	if err != nil {
		return nil, err
	}
	id.x = x
	return id, nil
}

// Public returns the identity public key.
func (id *Identity) Public() PublicKey { return id.pub }

// Seed returns the 32-byte seed. Handle with care.
func (id *Identity) Seed() []byte { return bytes.Clone(id.seed[:]) }

// Sign signs label ‖ msg. Labels come from spec/wire.md §2 and must never be
// shared between uses. Only public artifacts are signed (design §10.2).
func (id *Identity) Sign(label string, msg []byte) []byte {
	return ed25519.Sign(id.priv, append([]byte(label), msg...))
}

// Verify checks a signature made by Sign.
func Verify(pk PublicKey, label string, msg, sig []byte) bool {
	return ed25519.Verify(pk[:], append([]byte(label), msg...), sig)
}

// DH returns X25519(identity scalar, pub), the static Diffie-Hellman output
// used by first contact (spec/wire.md §11). It fails on an all-zero result,
// which is what a small-order pub produces (§4.2). The private scalar never
// leaves the Identity; callers must feed the output through a KDF.
func (id *Identity) DH(pub *ecdh.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("identity: nil DH public key")
	}
	shared, err := id.x.ECDH(pub) // crypto/ecdh rejects an all-zero output
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return shared, nil
}

// Pair holds the pairwise keys between an identity and one buddy (design
// §8.2): one directional key each way.
type Pair struct {
	Me, Them PublicKey
	// Send is K_dir for frames we send; Recv is K_dir for frames they send.
	Send, Recv [32]byte
}

// Pair derives the pairwise keys with buddy:
//
//	K_pair = HKDF-SHA256(ikm = X25519(my_x, their_x), salt = "openaim/v1",
//	                     info = "openaim/v1/pair" ‖ sorted(Ed_A, Ed_B))
//	K_dir  = HKDF-Expand(K_pair, "openaim/v1/dir" ‖ Ed_sender)
func (id *Identity) Pair(buddy PublicKey) (*Pair, error) {
	if buddy == id.pub {
		return nil, errors.New("identity: cannot pair with self")
	}
	if _, err := ParsePublicKey(buddy[:]); err != nil {
		return nil, err
	}
	bx, err := buddy.X25519()
	if err != nil {
		return nil, err
	}
	shared, err := id.x.ECDH(bx) // errors on an all-zero result
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	lo, hi := sorted(id.pub, buddy)
	kpair, err := hkdf.Key(sha256.New, shared, []byte(labelPairSalt), labelPair+string(lo[:])+string(hi[:]), 32)
	if err != nil {
		return nil, err
	}
	p := &Pair{Me: id.pub, Them: buddy}
	if p.Send, err = dirKey(kpair, id.pub); err != nil {
		return nil, err
	}
	if p.Recv, err = dirKey(kpair, buddy); err != nil {
		return nil, err
	}
	return p, nil
}

func dirKey(kpair []byte, sender PublicKey) ([32]byte, error) {
	var k [32]byte
	b, err := hkdf.Expand(sha256.New, kpair, labelDir+string(sender[:]), 32)
	copy(k[:], b)
	return k, err
}

func sorted(a, b PublicKey) (lo, hi PublicKey) {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return a, b
	}
	return b, a
}

// SafetyNumber is the out-of-band verification code for two keys (design
// §5.2): SHA-256("openaim/v1/safety-number" ‖ sorted(Ed_A, Ed_B)) read as a
// big-endian integer, reduced mod 10^40, shown as 8 groups of 5 digits
// (≈132.9 bits). Both sides compute the same number.
func SafetyNumber(a, b PublicKey) string {
	lo, hi := sorted(a, b)
	h := sha256.New()
	h.Write([]byte(labelSafetyNumber))
	h.Write(lo[:])
	h.Write(hi[:])
	n := new(big.Int).SetBytes(h.Sum(nil))
	n.Mod(n, new(big.Int).Exp(big.NewInt(10), big.NewInt(40), nil))
	digits := fmt.Sprintf("%040s", n.String())
	groups := make([]string, 8)
	for i := range groups {
		groups[i] = digits[i*5 : i*5+5]
	}
	return strings.Join(groups, " ")
}
