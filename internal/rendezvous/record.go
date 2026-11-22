package rendezvous

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aghman/openaim/internal/transport/ip"
)

// AssociatedData is the payload AEAD's associated data: the record's key hash
// followed by its 41-byte header,
//
//	kh ‖ version ‖ seq_be64 ‖ pk
//
// so a ciphertext opens only in the record (key, version, seq) it was made
// for.
func AssociatedData(k Keys, seq uint64) []byte {
	ad := make([]byte, 0, 32+1+8+len(k.Pub))
	ad = append(ad, k.KeyHash[:]...)
	ad = append(ad, ip.RendezvousVersion)
	ad = binary.BigEndian.AppendUint64(ad, seq)
	return append(ad, k.Pub...)
}

// SealPayload encrypts l into a record payload for seq:
//
//	nonce (24 random bytes) ‖ XChaCha20-Poly1305(L, nonce, plaintext, ad)
//
// rnd supplies the nonce; nil means crypto/rand. Sign the result with
// k.Priv and the same seq (ip.DHT.PutRendezvous does).
func SealPayload(k Keys, seq uint64, l Locator, rnd io.Reader) ([]byte, error) {
	pt, err := EncodePlaintext(l)
	if err != nil {
		return nil, err
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	aead, err := chacha20poly1305.NewX(k.L[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, NonceSize, NonceSize+len(pt)+aead.Overhead())
	if _, err := io.ReadFull(rnd, out); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[:NonceSize], pt, AssociatedData(k, seq)), nil
}

// OpenPayload decrypts and decodes a record payload made by SealPayload. It
// doesn't check the locator's times against the clock; Lookup does.
func OpenPayload(k Keys, seq uint64, payload []byte) (Locator, error) {
	pt, err := openPlaintext(k, seq, payload)
	if err != nil {
		return Locator{}, err
	}
	return DecodePlaintext(pt)
}

func openPlaintext(k Keys, seq uint64, payload []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.L[:])
	if err != nil {
		return nil, err
	}
	if len(payload) < NonceSize+aead.Overhead() {
		return nil, bad("payload of %d bytes", len(payload))
	}
	pt, err := aead.Open(nil, payload[:NonceSize], payload[NonceSize:], AssociatedData(k, seq))
	if err != nil {
		return nil, bad("payload does not open")
	}
	return pt, nil
}

// Open checks that a verified DHT record (ip.ParseRendezvousRecord) is the
// one k describes and decrypts its locator.
func Open(k Keys, r ip.RendezvousRecord) (Locator, error) {
	if !k.Pub.Equal(r.PublicKey) {
		return Locator{}, bad("record public key is not the derived one")
	}
	return OpenPayload(k, r.Seq, r.Payload)
}
