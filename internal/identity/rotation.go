package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// labelRotate is the signature label of a rotation statement (spec/wire.md
// §2, §4.6).
const labelRotate = "openaim/v1/rotate"

// RotationMessageSize is the length of the bytes a rotation signature
// covers: the 17-byte label, two 32-byte keys and a 4-byte timestamp.
const RotationMessageSize = len(labelRotate) + 32 + 32 + 4

// RotationMaxFuture is how far ahead of the receiver's clock a statement's
// issued_at may be (spec/wire.md §4.6). It matches the clock-skew allowance
// for inner payloads (§7 step 4). There is no default maximum age: replays
// are stopped by the old-key match and the issued_at ordering, not by
// expiry.
const RotationMaxFuture = 10 * time.Minute

// openaimEpoch is spec/wire.md §8's time origin (internal/frame.Epoch;
// identity can't import frame).
var openaimEpoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

var (
	// ErrInvalidRotation is wrapped by every rotation statement, recovery
	// key or signature that fails spec/wire.md §4.6.
	ErrInvalidRotation = errors.New("identity: invalid rotation statement")
	// ErrRotationTime is wrapped when a statement's issued_at is outside
	// the caller's window (CheckTime).
	ErrRotationTime = errors.New("identity: rotation statement out of time window")
)

// RotationStatement says that the identity key Old has been replaced by New
// (design §5.5). It is signed by the user's recovery key, never by Old or
// New, and travels in a ROTATE body (spec/wire.md §6.1).
type RotationStatement struct {
	Old, New PublicKey
	// IssuedAt is seconds since the OpenAIM epoch, 2025-01-01T00:00:00Z
	// (spec/wire.md §8), as in the inner payload's timestamp.
	IssuedAt uint32
}

// SignedMessage returns the exact bytes the recovery key signs:
//
//	"openaim/v1/rotate" ‖ old (32) ‖ new (32) ‖ issued_at_be32 (4)
//
// 85 bytes. Every field after the fixed label has a fixed length, so the
// encoding is unambiguous.
func (st RotationStatement) SignedMessage() []byte {
	b := make([]byte, 0, RotationMessageSize)
	b = append(b, labelRotate...)
	b = append(b, st.Old[:]...)
	b = append(b, st.New[:]...)
	return binary.BigEndian.AppendUint32(b, st.IssuedAt)
}

// Check applies the rules that don't need the recovery key (spec/wire.md
// §4.6 rules 1–3): Old and New are valid identity keys (§4.2), they don't
// share an X25519 form (which covers Old = New and New = −Old), and
// IssuedAt is set.
func (st RotationStatement) Check() error {
	if _, err := ParsePublicKey(st.Old[:]); err != nil {
		return fmt.Errorf("%w: old key: %w", ErrInvalidRotation, err)
	}
	if _, err := ParsePublicKey(st.New[:]); err != nil {
		return fmt.Errorf("%w: new key: %w", ErrInvalidRotation, err)
	}
	if sameX25519(st.Old, st.New) {
		return fmt.Errorf("%w: old and new keys are the same key or share an X25519 form", ErrInvalidRotation)
	}
	if st.IssuedAt == 0 {
		return fmt.Errorf("%w: issued_at not set", ErrInvalidRotation)
	}
	return nil
}

// checkRecovery applies rule 4: the recovery key is a valid identity key
// that doesn't share an X25519 form with the old or the new key.
func (st RotationStatement) checkRecovery(recovery PublicKey) error {
	if _, err := ParsePublicKey(recovery[:]); err != nil {
		return fmt.Errorf("%w: recovery key: %w", ErrInvalidRotation, err)
	}
	if sameX25519(recovery, st.Old) || sameX25519(recovery, st.New) {
		return fmt.Errorf("%w: recovery key is the old or new identity key", ErrInvalidRotation)
	}
	return nil
}

// SignRotation signs st with the recovery key. It refuses a statement that
// VerifyRotation would reject, so it never makes a valid signature over an
// invalid statement.
func SignRotation(recovery *Identity, st RotationStatement) ([]byte, error) {
	if recovery == nil {
		return nil, errors.New("identity: nil recovery key")
	}
	if err := st.Check(); err != nil {
		return nil, err
	}
	if err := st.checkRecovery(recovery.Public()); err != nil {
		return nil, err
	}
	return ed25519.Sign(recovery.priv, st.SignedMessage()), nil
}

// VerifyRotation checks st and its signature against the recovery key the
// caller pinned for this buddy (spec/wire.md §4.6 rules 1–5). It doesn't
// check issued_at against a clock (CheckTime does), nor that st.Old is the
// identity key pinned for the buddy, nor issued_at ordering against earlier
// rotations: those are the caller's (rules 6–8).
func VerifyRotation(pinnedRecovery PublicKey, st RotationStatement, sig []byte) error {
	if err := st.Check(); err != nil {
		return err
	}
	if err := st.checkRecovery(pinnedRecovery); err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature of %d bytes", ErrInvalidRotation, len(sig))
	}
	// crypto/ed25519 rejects S ≥ ℓ and compares R byte for byte, so a
	// signature has one accepted encoding.
	if !ed25519.Verify(pinnedRecovery[:], st.SignedMessage(), sig) {
		return fmt.Errorf("%w: signature does not verify under the pinned recovery key", ErrInvalidRotation)
	}
	return nil
}

// IssuedTime returns IssuedAt as a time.
func (st RotationStatement) IssuedTime() time.Time {
	return openaimEpoch.Add(time.Duration(st.IssuedAt) * time.Second)
}

// CheckTime checks st.IssuedAt against now: at most maxFuture ahead (use
// RotationMaxFuture) and, if maxAge > 0, at most maxAge old. maxAge = 0
// means no age limit, which is what buddies use (spec/wire.md §4.6): a buddy
// who was offline for months must still accept the statement.
func (st RotationStatement) CheckTime(now time.Time, maxAge, maxFuture time.Duration) error {
	issued := st.IssuedTime()
	if issued.After(now.Add(maxFuture)) {
		return fmt.Errorf("%w: issued %v, more than %v after %v", ErrRotationTime, issued, maxFuture, now)
	}
	if maxAge > 0 && issued.Before(now.Add(-maxAge)) {
		return fmt.Errorf("%w: issued %v, more than %v before %v", ErrRotationTime, issued, maxAge, now)
	}
	return nil
}

// GenerateRecovery creates a new recovery key (design §5.5). It is an
// ordinary Ed25519 key pair used only to sign rotation statements. Its seed
// goes only into the backup file (spec/backup.md), never into the keystore
// or the OS keychain, and the 24-word phrase doesn't encode it: the phrase
// restores the identity key alone. Only its public key is shared, in
// BUDDY_REQUEST and BUDDY_ACCEPT bodies.
func GenerateRecovery() (*Identity, error) { return Generate() }

// CheckRecoveryKey checks a buddy's recovery key before it is pinned
// (spec/wire.md §4.6): a valid identity key (§4.2) that doesn't share an
// X25519 form with the buddy's identity key. An identity key that doubles as
// its own recovery key would let whoever steals the device sign a rotation.
func CheckRecoveryKey(identityKey, recovery PublicKey) error {
	if _, err := ParsePublicKey(recovery[:]); err != nil {
		return fmt.Errorf("%w: recovery key: %w", ErrInvalidRotation, err)
	}
	if sameX25519(identityKey, recovery) {
		return fmt.Errorf("%w: recovery key is the identity key", ErrInvalidRotation)
	}
	return nil
}

// sameX25519 reports whether a and b have the same X25519 form, that is
// a = b or a = −b. The birational map depends only on y, which is the
// encoding with the sign bit (bit 255) cleared; callers pass canonical keys
// (§4.2).
func sameX25519(a, b PublicKey) bool {
	a[31] &= 0x7F
	b[31] &= 0x7F
	return bytes.Equal(a[:], b[:])
}
