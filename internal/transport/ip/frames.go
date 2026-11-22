// Package ip is the IP transport (design §6.1), built on go-libp2p.
//
// It holds host construction, Node (a host whose network key rotates; see
// docs/ip-rotation-and-dht.md), a circuit relay v2 service with configurable
// limits, relay reservations, and the length-prefixed frame stream used by
// /openaim/msg/1.
package ip

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MsgProtocol carries OpenAIM frames between buddies (design §6.1).
const MsgProtocol = "/openaim/msg/1"

// MaxFrameLen is the largest frame /openaim/msg/1 carries. Mesh-routable
// frames are ≤ 233 B; IP-only layouts (design §8.3) use larger fragments, up
// to this bound.
const MaxFrameLen = 0xFFFF

// ErrFrameTooLarge is returned when writing a frame over MaxFrameLen.
var ErrFrameTooLarge = errors.New("ip: frame too large")

// WriteFrame writes one frame as a 16-bit big-endian length followed by the
// frame bytes. Empty frames are not allowed.
func WriteFrame(w io.Writer, frame []byte) error {
	if len(frame) == 0 || len(frame) > MaxFrameLen {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(frame))
	}
	buf := make([]byte, 2+len(frame))
	binary.BigEndian.PutUint16(buf, uint16(len(frame)))
	copy(buf[2:], frame)
	_, err := w.Write(buf)
	return err
}

// FrameReader reads frames written by WriteFrame.
type FrameReader struct {
	r *bufio.Reader
}

// NewFrameReader wraps r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: bufio.NewReader(r)}
}

// ReadFrame returns the next frame. It returns io.EOF at a clean end of
// stream and io.ErrUnexpectedEOF if the stream ends mid-frame.
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, errors.New("ip: zero-length frame")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(fr.r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}
