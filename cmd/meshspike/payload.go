package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// Test payload layout (big-endian):
//
//	magic[4] ("OAM0" probe/request, "OAM1" echo reply) | seq u32 | sent unix-ms i64 | fill…
//
// The fill is a counting pattern so truncation or corruption is visible.
const (
	minPayload = 16
	magicReq   = "OAM0"
	magicEcho  = "OAM1"
)

type testPayload struct {
	Echo   bool
	Seq    uint32
	SentAt time.Time
	Size   int
}

func encodePayload(seq uint32, size int, sent time.Time) []byte {
	if size < minPayload {
		size = minPayload
	}
	b := make([]byte, size)
	copy(b, magicReq)
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint64(b[8:], uint64(sent.UnixMilli()))
	for i := minPayload; i < size; i++ {
		b[i] = byte(i)
	}
	return b
}

// echoOf turns a request payload into its echo reply, same length.
func echoOf(req []byte) []byte {
	b := append([]byte(nil), req...)
	copy(b, magicEcho)
	return b
}

var errNotTestPayload = errors.New("not a meshspike payload")

func decodePayload(b []byte) (testPayload, error) {
	if len(b) < minPayload {
		return testPayload{}, errNotTestPayload
	}
	var p testPayload
	switch string(b[:4]) {
	case magicReq:
	case magicEcho:
		p.Echo = true
	default:
		return testPayload{}, errNotTestPayload
	}
	p.Seq = binary.BigEndian.Uint32(b[4:])
	p.SentAt = time.UnixMilli(int64(binary.BigEndian.Uint64(b[8:])))
	p.Size = len(b)
	for i := minPayload; i < len(b); i++ {
		if b[i] != byte(i) {
			return testPayload{}, errors.New("meshspike payload fill corrupted")
		}
	}
	return p, nil
}

// recorder appends one JSON object per line, for later analysis of M0 runs.
type recorder struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

func openRecorder(path string) (*recorder, error) {
	if path == "" {
		return &recorder{}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &recorder{f: f, enc: json.NewEncoder(f)}, nil
}

func (r *recorder) write(v any) {
	if r.enc == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.enc.Encode(v)
}

func (r *recorder) Close() error {
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}

// radioContext is recorded with every measurement so runs on different
// presets/firmware can be compared.
type radioContext struct {
	Node        string `json:"node"`
	Firmware    string `json:"firmware"`
	Region      string `json:"region"`
	Preset      string `json:"preset"`
	Rebroadcast string `json:"rebroadcast"`
}
