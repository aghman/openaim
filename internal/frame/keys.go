package frame

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Labels (spec/wire.md §2).
const (
	labelSIV = "openaim/v1/siv"
	labelTag = "openaim/v1/tag"
	labelMsg = "openaim/v1/msg"
)

// Epoch is the OpenAIM time origin, 2025-01-01T00:00:00Z. Inner timestamps
// and day numbers count from it.
var Epoch = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// Day is the number of whole UTC days since Epoch. Conversation tags rotate
// on it. Times before Epoch map to day 0.
func Day(t time.Time) uint32 {
	if t.Before(Epoch) {
		return 0
	}
	return uint32(t.Sub(Epoch) / (24 * time.Hour))
}

// Timestamp is t in whole seconds since Epoch (the inner payload's clock).
func Timestamp(t time.Time) uint32 {
	if t.Before(Epoch) {
		return 0
	}
	return uint32(t.Sub(Epoch) / time.Second)
}

// TimeOf converts an inner timestamp back to a time.
func TimeOf(ts uint32) time.Time { return Epoch.Add(time.Duration(ts) * time.Second) }

// ConvKey is the key material for one direction of one conversation: K_dir
// for a buddy pair, or the epoch content key for a room.
type ConvKey struct {
	Enc [32]byte // K_dir (or K_room_epoch)
	SIV [32]byte // K_siv = HKDF-Expand(Enc, "openaim/v1/siv")
}

// NewConvKey derives the SIV key from a directional key.
func NewConvKey(kdir [32]byte) ConvKey {
	k := ConvKey{Enc: kdir}
	siv, err := hkdf.Expand(sha256.New, kdir[:], labelSIV, 32)
	if err != nil {
		panic(err) // only fails for absurd lengths
	}
	copy(k.SIV[:], siv)
	return k
}

// Tag is the conversation tag for a day: HMAC-SHA256(Enc, "openaim/v1/tag" ‖
// day_be32)[:8].
func (k ConvKey) Tag(day uint32) ConvTag {
	m := hmac.New(sha256.New, k.Enc[:])
	m.Write([]byte(labelTag))
	var d [4]byte
	binary.BigEndian.PutUint32(d[:], day)
	m.Write(d[:])
	var t ConvTag
	copy(t[:], m.Sum(nil))
	return t
}

// msgID is the synthetic message ID: HMAC-SHA256(SIV, inner)[:8].
func (k ConvKey) msgID(inner []byte) MsgID {
	m := hmac.New(sha256.New, k.SIV[:])
	m.Write(inner)
	var id MsgID
	copy(id[:], m.Sum(nil))
	return id
}

// msgKey is K_msg = HKDF-Expand(Enc, "openaim/v1/msg" ‖ conv_tag ‖ msg_id ‖
// frag_count ‖ layout, 32). Binding conv_tag means the same plaintext sealed
// under two tags (two days) never reuses a key and nonce with different
// associated data (spec/wire.md §5).
func (k ConvKey) msgKey(tag ConvTag, id MsgID, count int, l Layout) []byte {
	info := make([]byte, 0, len(labelMsg)+18)
	info = append(info, labelMsg...)
	info = append(info, tag[:]...)
	info = append(info, id[:]...)
	info = append(info, byte(count), byte(l))
	km, err := hkdf.Expand(sha256.New, k.Enc[:], string(info), 32)
	if err != nil {
		panic(err)
	}
	return km
}

// nonce is the fragment index as a 12-byte big-endian number.
func nonce(index int) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[8:], uint32(index))
	return n
}
