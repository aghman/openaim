package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Replay and reassembly limits (design §8.9, §7.5).
const (
	MaxAge     = 14 * 24 * time.Hour // oldest inner timestamp accepted
	MaxFuture  = 10 * time.Minute    // furthest-ahead inner timestamp accepted
	DedupTTL   = 30 * 24 * time.Hour // how long fragment IDs are remembered
	PartialTTL = 6 * time.Hour       // how long an incomplete message is kept
	// MaxPartialsPerTag bounds reassembly buffers per conversation tag.
	MaxPartialsPerTag = 8
)

var (
	// ErrStale: the message's timestamp is outside the acceptance window.
	ErrStale = errors.New("frame: timestamp outside acceptance window")
	// ErrMsgID: the reassembled payload doesn't hash to its msg_id.
	ErrMsgID = errors.New("frame: msg_id does not match payload")
)

// Conv is one conversation direction a receiver expects frames on.
type Conv struct {
	Key ConvKey
	// ID is the caller's handle for the conversation (a buddy, a room).
	ID any
}

// Keyring maps a conversation tag to the conversations that use it.
// Normally there is one; a tag collision yields more, and each is tried.
type Keyring interface {
	Lookup(ConvTag) []Conv
}

// Status is what happened to an accepted frame.
type Status int

const (
	// Partial: the fragment was valid and stored; the message isn't complete.
	Partial Status = iota
	// Delivered: this fragment completed a message.
	Delivered
	// Duplicate: this fragment was seen before. The caller may re-ack it.
	Duplicate
)

func (s Status) String() string {
	return [...]string{"partial", "delivered", "duplicate"}[s]
}

// Result describes an accepted frame.
type Result struct {
	Status Status
	Conv   any
	Header Header
	// Have is a bitmap of the fragments held for this message (bit i =
	// fragment i), for ACKs. All bits are set once Delivered.
	Have uint16
	// Message is set when Status is Delivered.
	Message *Message
}

// Message is a reassembled, authenticated, in-window message.
type Message struct {
	Tag   ConvTag
	MsgID MsgID
	Inner Inner
}

// Receiver authenticates incoming DATA frames, drops replays and reassembles
// messages. It is safe for concurrent use.
//
// Order of checks (design §8.9, verify first): header syntax, tag lookup,
// AEAD, and for fragment 0 the acceptance window. Only a fragment that passes
// touches dedup or reassembly state. Later fragments carry no timestamp; a
// message is delivered only once its fragment 0 has passed the window.
type Receiver struct {
	Keys  Keyring
	Dedup Dedup
	Now   func() time.Time // defaults to time.Now

	mu       sync.Mutex
	partials map[ConvTag]map[partialKey]*partial
}

type partialKey struct {
	id    MsgID
	count int
}

type partial struct {
	conv  any
	parts [][]byte
	have  uint16
	first time.Time
}

func (r *Receiver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Accept processes one frame. Errors mean the frame was dropped:
// ErrMalformed/ErrNotData (syntax), ErrUnknownTag, ErrAuth, ErrMsgID,
// ErrStale.
func (r *Receiver) Accept(b []byte) (Result, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Result{}, err
	}
	convs := r.Keys.Lookup(h.Tag)
	if len(convs) == 0 {
		return Result{Header: h}, ErrUnknownTag
	}
	var pt []byte
	var conv *Conv
	for i := range convs {
		if pt, err = OpenFragment(convs[i].Key, h, b); err == nil {
			conv = &convs[i]
			break
		}
	}
	if conv == nil {
		return Result{Header: h}, ErrAuth
	}

	now := r.now()
	// Fragment 0 carries the timestamp: reject a stale one before it touches
	// any state. (The check is repeated on the whole message below.)
	if h.Index == 0 && len(pt) >= 6 {
		if err := checkWindow(binary.BigEndian.Uint32(pt[2:6]), now); err != nil {
			return Result{Conv: conv.ID, Header: h}, err
		}
	}
	fid := FragmentID{Tag: h.Tag, MsgID: h.MsgID, Frag: fragByte(h.Index, h.Count)}
	res := Result{Conv: conv.ID, Header: h}

	// Dedup and reassembly change together under one lock, so two copies of
	// a fragment arriving at once can't both be counted.
	r.mu.Lock()
	if !r.Dedup.Insert(fid, now) {
		res.Status = Duplicate
		res.Have = r.haveLocked(h)
		r.mu.Unlock()
		return res, nil
	}
	p := r.partialFor(h, conv.ID, now)
	p.parts[h.Index] = pt
	p.have |= 1 << h.Index
	res.Have = p.have
	complete := p.have == fullMask(h.Count)
	if complete {
		delete(r.partials[h.Tag], partialKey{h.MsgID, h.Count})
	}
	r.mu.Unlock()

	if !complete {
		res.Status = Partial
		return res, nil
	}
	inner := bytes.Join(p.parts, nil)
	if conv.Key.msgID(inner) != h.MsgID {
		return res, ErrMsgID
	}
	in, err := ParseInner(inner)
	if err != nil {
		return res, err
	}
	if err := checkWindow(in.Time, now); err != nil {
		return res, err
	}
	res.Status = Delivered
	res.Message = &Message{Tag: h.Tag, MsgID: h.MsgID, Inner: in}
	return res, nil
}

func checkWindow(ts uint32, now time.Time) error {
	t := TimeOf(ts)
	if t.Before(now.Add(-MaxAge)) || t.After(now.Add(MaxFuture)) {
		return fmt.Errorf("%w: %s", ErrStale, t.Format(time.RFC3339))
	}
	return nil
}

// partialFor returns the reassembly buffer for h, creating it (and evicting
// the oldest buffer for the tag if it is full). Caller holds r.mu.
func (r *Receiver) partialFor(h Header, conv any, now time.Time) *partial {
	if r.partials == nil {
		r.partials = map[ConvTag]map[partialKey]*partial{}
	}
	m := r.partials[h.Tag]
	if m == nil {
		m = map[partialKey]*partial{}
		r.partials[h.Tag] = m
	}
	k := partialKey{h.MsgID, h.Count}
	if p := m[k]; p != nil {
		return p
	}
	for k, p := range m { // drop expired buffers
		if now.Sub(p.first) > PartialTTL {
			delete(m, k)
		}
	}
	if len(m) >= MaxPartialsPerTag {
		var oldest partialKey
		var ot time.Time
		for k, p := range m {
			if ot.IsZero() || p.first.Before(ot) {
				oldest, ot = k, p.first
			}
		}
		delete(m, oldest)
	}
	p := &partial{conv: conv, parts: make([][]byte, h.Count), first: now}
	m[k] = p
	return p
}

// haveLocked reports the fragment bitmap for a duplicate: what's buffered if
// the message is still incomplete, else everything. Caller holds r.mu.
func (r *Receiver) haveLocked(h Header) uint16 {
	if p := r.partials[h.Tag][partialKey{h.MsgID, h.Count}]; p != nil {
		return p.have
	}
	return fullMask(h.Count)
}

func fullMask(count int) uint16 { return uint16(1<<count - 1) }

// Sweep drops reassembly buffers older than PartialTTL.
func (r *Receiver) Sweep() {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for tag, m := range r.partials {
		for k, p := range m {
			if now.Sub(p.first) > PartialTTL {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(r.partials, tag)
		}
	}
}

// FragmentID is the dedup key (design §8.9): (conv_tag, msg_id, frag).
type FragmentID struct {
	Tag   ConvTag
	MsgID MsgID
	Frag  byte
}

// Dedup remembers fragment IDs for DedupTTL. The daemon persists it; tests
// and tools use MemDedup.
type Dedup interface {
	// Insert records id and reports whether it was new (not seen within
	// DedupTTL). It must be atomic.
	Insert(id FragmentID, now time.Time) (fresh bool)
}

// MemDedup is an in-memory Dedup.
type MemDedup struct {
	mu sync.Mutex
	m  map[FragmentID]time.Time
}

func (d *MemDedup) Insert(id FragmentID, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.m[id]; ok && now.Sub(t) < DedupTTL {
		return false
	}
	if d.m == nil {
		d.m = map[FragmentID]time.Time{}
	}
	d.m[id] = now
	return true
}

// Expire forgets entries older than DedupTTL.
func (d *MemDedup) Expire(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, t := range d.m {
		if now.Sub(t) >= DedupTTL {
			delete(d.m, id)
		}
	}
}

// Len is the number of remembered fragments.
func (d *MemDedup) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.m)
}
