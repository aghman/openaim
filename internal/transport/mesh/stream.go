// Package mesh talks to a Meshtastic radio over its client API ("stream API"),
// used for both USB serial and TCP (port 4403) connections.
//
// Framing (from the Meshtastic client API docs):
//
//	0x94 0xC3 <len MSB> <len LSB> <protobuf ToRadio/FromRadio, len bytes>
//
// Bytes outside a frame are the firmware's debug log output and are surfaced
// as text, not discarded silently.
package mesh

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	start1 = 0x94
	start2 = 0xC3

	// MaxFrameLen is the firmware's MAX_TO_FROM_RADIO_SIZE. A header announcing
	// more than this is treated as line noise and the reader resynchronizes.
	MaxFrameLen = 512

	headerLen = 4
)

// ErrFrameTooLarge is returned by FrameWriter.WriteFrame for oversize payloads.
var ErrFrameTooLarge = errors.New("mesh: frame exceeds MaxFrameLen")

// FrameReader extracts protobuf frames from a radio byte stream.
type FrameReader struct {
	r *bufio.Reader
	// debug accumulates out-of-frame bytes until a newline.
	debug bytes.Buffer
	// OnDebugLine, if set, receives each complete line of firmware log output
	// seen between frames.
	OnDebugLine func(line string)
}

// NewFrameReader wraps r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: bufio.NewReaderSize(r, 4096)}
}

// ReadFrame returns the next frame's payload. The returned slice is owned by
// the caller.
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	for {
		b, err := fr.r.ReadByte()
		if err != nil {
			fr.flushDebug()
			return nil, err
		}
		if b != start1 {
			fr.debugByte(b)
			continue
		}
		// Peek rather than consume so that a 0x94 inside debug text followed
		// by something else doesn't swallow the following byte.
		next, err := fr.r.Peek(1)
		if err != nil {
			fr.debugByte(b)
			fr.flushDebug()
			return nil, err
		}
		if next[0] != start2 {
			fr.debugByte(b)
			continue
		}
		hdr, err := fr.r.Peek(3)
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		n := int(hdr[1])<<8 | int(hdr[2])
		if n > MaxFrameLen {
			// Corrupt or false header: treat the 0x94 as noise and resync on
			// the bytes after it.
			fr.debugByte(b)
			continue
		}
		if _, err := fr.r.Discard(3); err != nil {
			return nil, unexpectedEOF(err)
		}
		fr.flushDebug()
		payload := make([]byte, n)
		if _, err := io.ReadFull(fr.r, payload); err != nil {
			return nil, unexpectedEOF(err)
		}
		return payload, nil
	}
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func (fr *FrameReader) debugByte(b byte) {
	if b == '\n' {
		fr.flushDebug()
		return
	}
	if b == '\r' {
		return
	}
	// Cap a runaway line (binary garbage with no newlines).
	if fr.debug.Len() >= 1024 {
		fr.flushDebug()
	}
	fr.debug.WriteByte(b)
}

func (fr *FrameReader) flushDebug() {
	if fr.debug.Len() == 0 {
		return
	}
	if fr.OnDebugLine != nil {
		fr.OnDebugLine(fr.debug.String())
	}
	fr.debug.Reset()
}

// FrameWriter writes framed payloads. It is safe for concurrent use.
type FrameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewFrameWriter wraps w.
func NewFrameWriter(w io.Writer) *FrameWriter { return &FrameWriter{w: w} }

// WriteFrame writes one frame containing payload.
func (fw *FrameWriter) WriteFrame(payload []byte) error {
	if len(payload) > MaxFrameLen {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	buf := make([]byte, headerLen+len(payload))
	buf[0], buf[1] = start1, start2
	buf[2], buf[3] = byte(len(payload)>>8), byte(len(payload))
	copy(buf[headerLen:], payload)

	fw.mu.Lock()
	defer fw.mu.Unlock()
	_, err := fw.w.Write(buf)
	return err
}

// WakeSequence is sent before the first frame on a serial link: a run of
// START2 bytes lets the firmware's parser resynchronize and wakes some devices
// (this mirrors the official Python client).
var WakeSequence = bytes.Repeat([]byte{start2}, 32)
