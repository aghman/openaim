package mesh

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func frame(payload []byte) []byte {
	var b bytes.Buffer
	if err := NewFrameWriter(&b).WriteFrame(payload); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func TestRoundTrip(t *testing.T) {
	payloads := [][]byte{{}, {0x01}, bytes.Repeat([]byte{0xAB}, MaxFrameLen), []byte{start1, start2, 0xFF, 0xFF}}
	var stream bytes.Buffer
	for _, p := range payloads {
		stream.Write(frame(p))
	}
	// One byte at a time exercises every partial-read path.
	fr := NewFrameReader(iotest.OneByteReader(&stream))
	for i, want := range payloads {
		got, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: got %x want %x", i, got, want)
		}
	}
	if _, err := fr.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF at end, got %v", err)
	}
}

func TestDebugTextBetweenFrames(t *testing.T) {
	var stream bytes.Buffer
	stream.WriteString("INFO  | booting\r\nDEBUG | lora ok\n")
	stream.Write(frame([]byte("one")))
	stream.WriteString("partial line then frame")
	stream.Write(frame([]byte("two")))

	var lines []string
	fr := NewFrameReader(&stream)
	fr.OnDebugLine = func(l string) { lines = append(lines, l) }

	for _, want := range []string{"one", "two"} {
		got, err := fr.ReadFrame()
		if err != nil || string(got) != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	}
	wantLines := []string{"INFO  | booting", "DEBUG | lora ok", "partial line then frame"}
	if len(lines) != len(wantLines) {
		t.Fatalf("debug lines = %q, want %q", lines, wantLines)
	}
	for i := range lines {
		if lines[i] != wantLines[i] {
			t.Fatalf("debug line %d = %q, want %q", i, lines[i], wantLines[i])
		}
	}
}

func TestResyncAfterFalseHeaders(t *testing.T) {
	var stream bytes.Buffer
	stream.Write([]byte{start1, 'x'})                // START1 not followed by START2
	stream.Write([]byte{start1, start2, 0x7F, 0xFF}) // length > MaxFrameLen
	stream.Write([]byte{start1})                     // lone START1 right before a real frame
	stream.Write(frame([]byte("ok")))

	got, err := NewFrameReader(&stream).ReadFrame()
	if err != nil || string(got) != "ok" {
		t.Fatalf("got %q, %v; want \"ok\"", got, err)
	}
}

func TestTruncatedFrame(t *testing.T) {
	f := frame([]byte("hello"))
	_, err := NewFrameReader(bytes.NewReader(f[:len(f)-2])).ReadFrame()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want ErrUnexpectedEOF, got %v", err)
	}
}

func TestWriteTooLarge(t *testing.T) {
	err := NewFrameWriter(io.Discard).WriteFrame(make([]byte, MaxFrameLen+1))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
}

// FuzzFrameReader checks that arbitrary radio bytes never panic the reader,
// never yield an oversize frame, and that a valid frame appended after any
// garbage is still recovered.
func FuzzFrameReader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{start1, start2, 0x00, 0x03, 'a', 'b', 'c'})
	f.Add([]byte{start1, start1, start2, 0x02, 0x00})
	f.Add([]byte("log line\n\x94"))
	f.Fuzz(func(t *testing.T, garbage []byte) {
		fr := NewFrameReader(bytes.NewReader(garbage))
		for {
			p, err := fr.ReadFrame()
			if err != nil {
				break
			}
			if len(p) > MaxFrameLen {
				t.Fatalf("frame of %d bytes exceeds max", len(p))
			}
		}

		// Garbage containing a frame header can legitimately swallow what
		// follows it as payload. Without START1 bytes it is pure log noise,
		// and a following frame must always be recovered intact.
		if bytes.IndexByte(garbage, start1) >= 0 {
			return
		}
		stream := append(append([]byte{}, garbage...), frame([]byte("sentinel"))...)
		p, err := NewFrameReader(bytes.NewReader(stream)).ReadFrame()
		if err != nil || !bytes.Equal(p, []byte("sentinel")) {
			t.Fatalf("after garbage %x: got %q, %v", garbage, p, err)
		}
	})
}
