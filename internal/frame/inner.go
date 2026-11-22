package frame

import (
	"encoding/binary"
	"fmt"
)

// ContentType says what an inner payload is. It is encrypted, so observers
// can't tell an IM from an ack (design §8.1).
type ContentType uint8

const (
	IM          ContentType = 1
	Ack         ContentType = 2
	Presence    ContentType = 3
	ProfileReq  ContentType = 4
	Profile     ContentType = 5
	AwayMsg     ContentType = 6
	Typing      ContentType = 7 // IP only
	RoomMsg     ContentType = 8
	RoomInvite  ContentType = 9
	RoomRekey   ContentType = 10
	BuddyAccept ContentType = 11
	Reach       ContentType = 12
	Caps        ContentType = 13
	Rotate      ContentType = 14
	// BuddyRequest travels only in FIRST_CONTACT frames (spec/wire.md §11.6).
	BuddyRequest ContentType = 15
)

var contentNames = map[ContentType]string{
	IM: "IM", Ack: "ACK", Presence: "PRESENCE", ProfileReq: "PROFILE_REQ", Profile: "PROFILE",
	AwayMsg: "AWAY_MSG", Typing: "TYPING", RoomMsg: "ROOM_MSG", RoomInvite: "ROOM_INVITE",
	RoomRekey: "ROOM_REKEY", BuddyAccept: "BUDDY_ACCEPT", Reach: "REACH", Caps: "CAPS", Rotate: "ROTATE",
	BuddyRequest: "BUDDY_REQUEST",
}

func (c ContentType) String() string {
	if s, ok := contentNames[c]; ok {
		return s
	}
	return fmt.Sprintf("content(%d)", uint8(c))
}

// Flags are inner-payload flag bits.
type Flags uint8

const (
	FlagCompressed    Flags = 1 << 0
	FlagAckRequested  Flags = 1 << 1
	FlagClockUnsynced Flags = 1 << 2

	knownFlags = FlagCompressed | FlagAckRequested | FlagClockUnsynced
)

// Inner is the encrypted payload of a message (design §8.4):
//
//	content_type (1) | flags (1) | timestamp (4, BE) | seq (uvarint) | body
type Inner struct {
	Type  ContentType
	Flags Flags
	Time  uint32 // seconds since Epoch
	Seq   uint64 // per-direction counter
	Body  []byte
}

// Marshal encodes the payload. Encoding is canonical (minimal varint), so a
// given Inner always yields the same bytes and therefore the same msg_id.
func (in Inner) Marshal() []byte {
	b := make([]byte, 6, 6+binary.MaxVarintLen64+len(in.Body))
	b[0], b[1] = byte(in.Type), byte(in.Flags)
	binary.BigEndian.PutUint32(b[2:], in.Time)
	b = binary.AppendUvarint(b, in.Seq)
	return append(b, in.Body...)
}

// ParseInner decodes a payload, rejecting unknown flags and non-minimal
// varints. Unknown content types are allowed (the router decides).
func ParseInner(b []byte) (Inner, error) {
	var in Inner
	if len(b) < 7 {
		return in, fmt.Errorf("%w: inner payload of %d bytes", ErrMalformed, len(b))
	}
	in.Type, in.Flags = ContentType(b[0]), Flags(b[1])
	if in.Flags&^knownFlags != 0 {
		return in, fmt.Errorf("%w: unknown flags %#x", ErrMalformed, uint8(in.Flags&^knownFlags))
	}
	in.Time = binary.BigEndian.Uint32(b[2:6])
	seq, n := binary.Uvarint(b[6:])
	if n <= 0 || n != len(binary.AppendUvarint(nil, seq)) {
		return in, fmt.Errorf("%w: bad seq varint", ErrMalformed)
	}
	in.Seq = seq
	in.Body = b[6+n:]
	return in, nil
}
