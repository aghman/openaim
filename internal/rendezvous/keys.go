// Package rendezvous publishes and finds buddies' current network addresses
// through the private DHT (design §6.1; spec/dht-records.md, "Rendezvous
// derivation" and the sections after it).
//
// For each buddy and each UTC day a publisher stores one record. Its signing
// key, its DHT key and the key encrypting its payload all derive from the
// pairwise directional key K_dir and the day, so only the buddy pair can
// find, write or read it. DHT nodes see a random-looking key and public key,
// a timestamp-valued seq, a signature and a padded ciphertext.
package rendezvous

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/aghman/openaim/internal/transport/ip"
)

// Labels (spec/wire.md §2, spec/dht-records.md).
const (
	labelRdv = "openaim/v1/rdv"
	labelLoc = "openaim/v1/loc"
)

// Keys are everything derived from one K_dir and one day.
type Keys struct {
	Day  uint32
	Seed [32]byte // HMAC-SHA256(K_dir, "openaim/v1/rdv" ‖ day_be32)
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
	// Key is the DHT key, "/oa-rdv/" ‖ hex(KeyHash).
	Key     string
	KeyHash [32]byte // SHA-256("openaim/v1/dht-rdv-key" ‖ Pub)
	L       [32]byte // HKDF-Expand(K_dir, "openaim/v1/loc" ‖ day_be32, 32)
}

// Derive computes the keys of the record published under kdir on day
// (spec/wire.md §5.2). The publisher passes its Pair.Send, the buddy looking
// it up its Pair.Recv.
func Derive(kdir [32]byte, day uint32) Keys {
	var d [4]byte
	binary.BigEndian.PutUint32(d[:], day)
	k := Keys{Day: day}

	m := hmac.New(sha256.New, kdir[:])
	m.Write([]byte(labelRdv))
	m.Write(d[:])
	copy(k.Seed[:], m.Sum(nil))
	k.Priv = ed25519.NewKeyFromSeed(k.Seed[:])
	k.Pub = k.Priv.Public().(ed25519.PublicKey)

	k.Key = ip.RendezvousKey(k.Pub)
	if _, err := hex.Decode(k.KeyHash[:], []byte(strings.TrimPrefix(k.Key, "/"+ip.RendezvousNamespace+"/"))); err != nil {
		panic(err) // RendezvousKey always gives 64 hex digits
	}

	l, err := hkdf.Expand(sha256.New, kdir[:], labelLoc+string(d[:]), 32)
	if err != nil {
		panic(err) // only fails for absurd lengths
	}
	copy(k.L[:], l)
	return k
}
