// Package frame is the OpenAIM frame layer (design §8): sealing messages once
// into canonical fragments, opening and authenticating each fragment,
// reassembly, the replay window and dedup. spec/wire.md is normative for
// every byte layout and label here.
package frame

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// Version is the wire version carried in the top 3 bits of ver_kind.
const Version = 1

// Kind is a frame kind, the low 5 bits of ver_kind.
type Kind uint8

const (
	// KindData is a buddy or room DATA frame in the mesh layout.
	KindData Kind = 1
	// KindDataIP is a DATA frame in the IP-only layout (larger fragments). It
	// can never be routed to mesh.
	KindDataIP Kind = 2
	// Reserved for later in M1/M2 (spec/wire.md §3).
	KindFirstContact Kind = 3
	KindBeacon       Kind = 4
	KindNearby       Kind = 5
	KindGatewayAd    Kind = 6
)

// VerKind packs the version and kind into the first frame byte.
func VerKind(k Kind) byte { return Version<<5 | byte(k)&0x1F }

// Layout fixes the fragment size of DATA frames, which keeps fragmentation a
// pure function of the plaintext (design §8.2, §8.3).
type Layout uint8

const (
	LayoutMesh Layout = 1 // canonical 200 B frames, up to 4 fragments
	LayoutIP   Layout = 2 // 4096 B frames, up to 16 fragments
)

const (
	headerLen = 1 + 8 + 8 + 1 // ver_kind | conv_tag | msg_id | frag
	tagLen    = 16            // Poly1305
	// Overhead is the per-frame cost of a DATA frame.
	Overhead = headerLen + tagLen
)

type layoutInfo struct {
	kind     Kind
	frameLen int
	maxFrags int
}

var layouts = map[Layout]layoutInfo{
	LayoutMesh: {KindData, 200, 4},
	LayoutIP:   {KindDataIP, 4096, 16},
}

// FrameLen is the largest frame the layout produces (the canonical size).
func (l Layout) FrameLen() int { return layouts[l].frameLen }

// FragmentCapacity is the plaintext bytes one fragment carries.
func (l Layout) FragmentCapacity() int { return layouts[l].frameLen - Overhead }

// MaxFragments is the most fragments one message may use in this layout.
func (l Layout) MaxFragments() int { return layouts[l].maxFrags }

// MaxInner is the largest inner payload (header + body) the layout carries.
func (l Layout) MaxInner() int { return l.FragmentCapacity() * l.MaxFragments() }

func (l Layout) valid() bool { _, ok := layouts[l]; return ok }

func (l Layout) String() string {
	switch l {
	case LayoutMesh:
		return "mesh"
	case LayoutIP:
		return "ip"
	}
	return fmt.Sprintf("layout(%d)", uint8(l))
}

func layoutOf(k Kind) (Layout, bool) {
	switch k {
	case KindData:
		return LayoutMesh, true
	case KindDataIP:
		return LayoutIP, true
	}
	return 0, false
}

// ConvTag identifies a conversation, direction and day to its recipient only.
type ConvTag [8]byte

func (t ConvTag) String() string { return hex.EncodeToString(t[:]) }

// MsgID is a message's synthetic ID: HMAC(K_siv, inner)[:8].
type MsgID [8]byte

func (m MsgID) String() string { return hex.EncodeToString(m[:]) }

// Header is the cleartext, authenticated part of a DATA frame.
type Header struct {
	Kind   Kind
	Layout Layout
	Tag    ConvTag
	MsgID  MsgID
	Index  int // fragment index, 0-based
	Count  int // fragments in the message, 1–16
}

// Errors returned when parsing or opening frames.
var (
	ErrMalformed  = errors.New("frame: malformed")
	ErrNotData    = errors.New("frame: not a DATA frame")
	ErrTooLarge   = errors.New("frame: message too large for layout")
	ErrAuth       = errors.New("frame: authentication failed")
	ErrUnknownTag = errors.New("frame: unknown conversation tag")
)

func fragByte(index, count int) byte { return byte(index<<4 | (count - 1)) }

// ParseHeader reads and checks a DATA frame's header without any crypto. It
// rejects frames whose size can't belong to their layout.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < Overhead+1 {
		return h, fmt.Errorf("%w: %d bytes", ErrMalformed, len(b))
	}
	if v := b[0] >> 5; v != Version {
		return h, fmt.Errorf("%w: version %d", ErrMalformed, v)
	}
	h.Kind = Kind(b[0] & 0x1F)
	l, ok := layoutOf(h.Kind)
	if !ok {
		return h, fmt.Errorf("%w: kind %d", ErrNotData, h.Kind)
	}
	h.Layout = l
	copy(h.Tag[:], b[1:9])
	copy(h.MsgID[:], b[9:17])
	h.Index, h.Count = int(b[17]>>4), int(b[17]&0x0F)+1
	switch {
	case h.Count > l.MaxFragments():
		return h, fmt.Errorf("%w: %d fragments in %s layout", ErrMalformed, h.Count, l)
	case h.Index >= h.Count:
		return h, fmt.Errorf("%w: fragment %d of %d", ErrMalformed, h.Index, h.Count)
	case len(b) > l.FrameLen():
		return h, fmt.Errorf("%w: %d bytes in %s layout", ErrMalformed, len(b), l)
	case h.Index < h.Count-1 && len(b) != l.FrameLen():
		// Every fragment but the last is full-size.
		return h, fmt.Errorf("%w: short non-final fragment", ErrMalformed)
	}
	return h, nil
}
