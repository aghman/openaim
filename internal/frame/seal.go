package frame

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Sealed is a message sealed into frames. The frames are the message from
// then on: retries, route fallbacks and restarts re-send exactly these bytes
// and never seal again (design §8.2, "seal once").
type Sealed struct {
	Tag    ConvTag
	MsgID  MsgID
	Layout Layout
	Frames [][]byte
}

// Seal encrypts an inner payload (Inner.Marshal output) into DATA frames for
// the conversation key k under tag (k.Tag(day) on the day of sending).
//
// Fragmentation is a pure function of (inner, layout): every fragment but the
// last carries exactly FragmentCapacity bytes. Each fragment is encrypted
// with ChaCha20-Poly1305 under K_msg, nonce = fragment index, and the whole
// 18-byte header as associated data.
func Seal(k ConvKey, tag ConvTag, l Layout, inner []byte) (*Sealed, error) {
	if !l.valid() {
		return nil, fmt.Errorf("frame: unknown layout %d", l)
	}
	if len(inner) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrMalformed)
	}
	if len(inner) > l.MaxInner() {
		return nil, fmt.Errorf("%w: %d bytes, %s layout carries %d", ErrTooLarge, len(inner), l, l.MaxInner())
	}
	capacity := l.FragmentCapacity()
	count := (len(inner) + capacity - 1) / capacity

	id := k.msgID(inner)
	aead, err := chacha20poly1305.New(k.msgKey(tag, id, count, l))
	if err != nil {
		return nil, err
	}
	s := &Sealed{Tag: tag, MsgID: id, Layout: l, Frames: make([][]byte, count)}
	for i := range count {
		chunk := inner[i*capacity : min((i+1)*capacity, len(inner))]
		f := make([]byte, headerLen, headerLen+len(chunk)+tagLen)
		f[0] = VerKind(layouts[l].kind)
		copy(f[1:9], tag[:])
		copy(f[9:17], id[:])
		f[17] = fragByte(i, count)
		s.Frames[i] = aead.Seal(f, nonce(i), chunk, f[:headerLen])
	}
	return s, nil
}

// OpenFragment authenticates and decrypts one DATA frame whose header h was
// parsed from it, returning that fragment's slice of the inner payload.
func OpenFragment(k ConvKey, h Header, b []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(k.msgKey(h.Tag, h.MsgID, h.Count, h.Layout))
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce(h.Index), b[headerLen:], b[:headerLen])
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}
