package ip

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	record "github.com/libp2p/go-libp2p-record"
)

// Rendezvous records (design §6.1) live in the private DHT under their own
// namespace. The format is in spec/dht-records.md.
//
// A record is self-certifying: its DHT key is a hash of an Ed25519 public
// key, and the value carries that key and a signature. Only someone holding
// the private key (derived later from the pairwise K_dir and the day) can
// write it, so the DHT nodes that store a record, and who therefore learn
// its key, can't overwrite it with junk. The payload is opaque here; the
// rendezvous layer encrypts it.
const (
	// RendezvousNamespace is the DHT record namespace: keys are
	// "/oa-rdv/<64 lowercase hex digits>".
	RendezvousNamespace = "oa-rdv"
	// RendezvousVersion is the only record version v1 nodes accept.
	RendezvousVersion = 1
	// MaxRendezvousValue caps a whole record value. An encrypted locator
	// (peer ID, a few direct and circuit addresses, timestamps, AEAD
	// overhead) needs well under half of it.
	MaxRendezvousValue = 1024
	// MaxRendezvousPayload is the largest payload that fits.
	MaxRendezvousPayload = MaxRendezvousValue - rdvHeaderLen - ed25519.SignatureSize

	rdvHeaderLen = 1 + 8 + ed25519.PublicKeySize // version, seq, public key
	rdvKeyPrefix = "/" + RendezvousNamespace + "/"
	// Domain-separation labels (design §10.2).
	rdvKeyLabel = "openaim/v1/dht-rdv-key"
	rdvSigLabel = "openaim/v1/dht-rdv-sig"
)

// ErrBadRendezvousRecord wraps every validation failure.
var ErrBadRendezvousRecord = errors.New("ip: bad rendezvous record")

// RendezvousRecord is a parsed, verified record.
type RendezvousRecord struct {
	// Seq orders records under one key: the highest wins. Publishers use the
	// signing time in Unix milliseconds, so no counter has to be stored, and
	// it says nothing a DHT node doesn't already see from the time of the
	// put. It must not be a per-user counter, which would link records for
	// different buddies.
	Seq       uint64
	PublicKey ed25519.PublicKey
	Payload   []byte
}

// RendezvousKey is the DHT key of records signed with pub.
func RendezvousKey(pub ed25519.PublicKey) string {
	h := rendezvousKeyHash(pub)
	return rdvKeyPrefix + hex.EncodeToString(h[:])
}

func rendezvousKeyHash(pub ed25519.PublicKey) [32]byte {
	return sha256.Sum256(append([]byte(rdvKeyLabel), pub...))
}

// SignRendezvousRecord builds a record value with seq and payload, signed by
// priv. Store it under RendezvousKey(priv.Public()).
func SignRendezvousRecord(priv ed25519.PrivateKey, seq uint64, payload []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: bad private key", ErrBadRendezvousRecord)
	}
	if len(payload) == 0 || len(payload) > MaxRendezvousPayload {
		return nil, fmt.Errorf("%w: payload is %d bytes, want 1–%d", ErrBadRendezvousRecord, len(payload), MaxRendezvousPayload)
	}
	pub := priv.Public().(ed25519.PublicKey)
	v := make([]byte, rdvHeaderLen, rdvHeaderLen+len(payload)+ed25519.SignatureSize)
	v[0] = RendezvousVersion
	binary.BigEndian.PutUint64(v[1:9], seq)
	copy(v[9:], pub)
	v = append(v, payload...)
	kh := rendezvousKeyHash(pub)
	return append(v, ed25519.Sign(priv, rendezvousSigInput(kh, v))...), nil
}

// rendezvousSigInput is label ‖ key hash ‖ version ‖ seq ‖ public key ‖
// payload, i.e. everything but the signature, bound to the key.
func rendezvousSigInput(kh [32]byte, unsigned []byte) []byte {
	b := make([]byte, 0, len(rdvSigLabel)+len(kh)+len(unsigned))
	b = append(b, rdvSigLabel...)
	b = append(b, kh[:]...)
	return append(b, unsigned...)
}

// ParseRendezvousRecord checks value against key and returns its contents.
// The payload aliases value.
func ParseRendezvousRecord(key string, value []byte) (RendezvousRecord, error) {
	kh, err := parseRendezvousKey(key)
	if err != nil {
		return RendezvousRecord{}, err
	}
	if len(value) > MaxRendezvousValue {
		return RendezvousRecord{}, fmt.Errorf("%w: %d bytes, max %d", ErrBadRendezvousRecord, len(value), MaxRendezvousValue)
	}
	if len(value) < rdvHeaderLen+1+ed25519.SignatureSize {
		return RendezvousRecord{}, fmt.Errorf("%w: %d bytes is too short", ErrBadRendezvousRecord, len(value))
	}
	if value[0] != RendezvousVersion {
		return RendezvousRecord{}, fmt.Errorf("%w: version %d", ErrBadRendezvousRecord, value[0])
	}
	pub := ed25519.PublicKey(value[9:rdvHeaderLen])
	if rendezvousKeyHash(pub) != kh {
		return RendezvousRecord{}, fmt.Errorf("%w: public key does not match the record key", ErrBadRendezvousRecord)
	}
	split := len(value) - ed25519.SignatureSize
	if !ed25519.Verify(pub, rendezvousSigInput(kh, value[:split]), value[split:]) {
		return RendezvousRecord{}, fmt.Errorf("%w: bad signature", ErrBadRendezvousRecord)
	}
	return RendezvousRecord{
		Seq:       binary.BigEndian.Uint64(value[1:9]),
		PublicKey: pub,
		Payload:   value[rdvHeaderLen:split],
	}, nil
}

func parseRendezvousKey(key string) ([32]byte, error) {
	var kh [32]byte
	h, ok := strings.CutPrefix(key, rdvKeyPrefix)
	if !ok || len(h) != 2*len(kh) || strings.ToLower(h) != h {
		return kh, fmt.Errorf("%w: key %q is not %s<64 lowercase hex digits>", ErrBadRendezvousRecord, truncate(key, 80), rdvKeyPrefix)
	}
	if _, err := hex.Decode(kh[:], []byte(h)); err != nil {
		return kh, fmt.Errorf("%w: key: %v", ErrBadRendezvousRecord, err)
	}
	return kh, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RendezvousValidator validates records in RendezvousNamespace for the DHT.
type RendezvousValidator struct{}

var _ record.Validator = RendezvousValidator{}

// Validate implements record.Validator.
func (RendezvousValidator) Validate(key string, value []byte) error {
	_, err := ParseRendezvousRecord(key, value)
	return err
}

// Select implements record.Validator: the valid record with the highest seq
// wins; equal seqs go to the bytewise greater value, so every node picks the
// same one whatever order it sees them in. Invalid values are never picked.
func (RendezvousValidator) Select(key string, values [][]byte) (int, error) {
	best := -1
	var bestSeq uint64
	for i, v := range values {
		r, err := ParseRendezvousRecord(key, v)
		if err != nil {
			continue
		}
		if best < 0 || r.Seq > bestSeq || (r.Seq == bestSeq && bytes.Compare(v, values[best]) > 0) {
			best, bestSeq = i, r.Seq
		}
	}
	if best < 0 {
		return 0, fmt.Errorf("%w: no valid record among %d", ErrBadRendezvousRecord, len(values))
	}
	return best, nil
}

// DHTValidator is the validator for the OpenAIM DHT: only the rendezvous
// namespace. The IPFS /pk and /ipns namespaces are not accepted.
func DHTValidator() record.Validator {
	return record.NamespacedValidator{RendezvousNamespace: RendezvousValidator{}}
}
