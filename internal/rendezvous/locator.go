package rendezvous

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/transport/ip"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Locator limits (spec/dht-records.md, "Locator").
const (
	// MaxTTL bounds expires_at − issued_at: the DHT keeps a record for at
	// most 36 hours, so a locator never claims to be valid for longer.
	MaxTTL = 36 * time.Hour
	// MaxAddrs, MaxAddrLen and MaxPeerIDLen are the REACH limits.
	MaxAddrs     = body.MaxAddrs
	MaxAddrLen   = body.MaxAddrLen
	MaxPeerIDLen = body.MaxPeerIDLen

	// NonceSize is the XChaCha20-Poly1305 nonce at the start of a payload.
	NonceSize = chacha20poly1305.NonceSizeX
	// MaxPlaintext is the largest padded plaintext that fits in a record:
	// 919 − 24 − 16 = 879 bytes.
	MaxPlaintext = ip.MaxRendezvousPayload - NonceSize - chacha20poly1305.Overhead
	// MaxLocator is the largest encoded RendezvousLocator: the plaintext
	// starts with a 2-byte length.
	MaxLocator = MaxPlaintext - 2
	// PadBlock is the padding bucket.
	PadBlock = 256
)

// ErrBadLocator wraps every failure to decode, decrypt or check a locator.
var ErrBadLocator = errors.New("rendezvous: bad locator")

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadLocator, fmt.Sprintf(format, args...))
}

// Locator is the plaintext of a rendezvous record: where the publisher is
// now (design §7.1, IP hint). Times are whole seconds.
type Locator struct {
	ID        peer.ID
	Addrs     []ma.Multiaddr
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// AddrInfo is the locator's peer ID and addresses, ready to dial.
func (l Locator) AddrInfo() peer.AddrInfo { return peer.AddrInfo{ID: l.ID, Addrs: l.Addrs} }

// EncodePlaintext encodes l as a padded record plaintext:
//
//	len_be16 ‖ RendezvousLocator (deterministic protobuf) ‖ zeros
//
// padded to the next multiple of PadBlock, at most MaxPlaintext. It checks
// the same limits DecodePlaintext does.
func EncodePlaintext(l Locator) ([]byte, error) {
	loc, err := marshalLocator(l)
	if err != nil {
		return nil, err
	}
	n := 2 + len(loc)
	size := min((n+PadBlock-1)/PadBlock*PadBlock, MaxPlaintext)
	pt := make([]byte, size)
	binary.BigEndian.PutUint16(pt, uint16(len(loc)))
	copy(pt[2:], loc)
	return pt, nil
}

func marshalLocator(l Locator) ([]byte, error) {
	id := []byte(l.ID)
	if len(id) == 0 || len(id) > MaxPeerIDLen {
		return nil, bad("peer ID of %d bytes", len(id))
	}
	if _, err := peer.IDFromBytes(id); err != nil {
		return nil, bad("peer ID: %v", err)
	}
	if len(l.Addrs) > MaxAddrs {
		return nil, bad("%d addresses (max %d)", len(l.Addrs), MaxAddrs)
	}
	addrs := make([][]byte, len(l.Addrs))
	for i, a := range l.Addrs {
		addrs[i] = a.Bytes()
		if len(addrs[i]) == 0 || len(addrs[i]) > MaxAddrLen {
			return nil, bad("address of %d bytes", len(addrs[i]))
		}
	}
	if l.IssuedAt.Before(frame.Epoch) {
		return nil, bad("issued before the OpenAIM epoch")
	}
	m := &pb.RendezvousLocator{
		Ip:        &pb.IPHint{PeerId: id, Addrs: addrs},
		IssuedAt:  frame.Timestamp(l.IssuedAt),
		ExpiresAt: frame.Timestamp(l.ExpiresAt),
	}
	if err := checkTimes(m.IssuedAt, m.ExpiresAt); err != nil {
		return nil, err
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, bad("%v", err)
	}
	if len(b) > MaxLocator {
		return nil, bad("%d bytes encoded (max %d)", len(b), MaxLocator)
	}
	return b, nil
}

func checkTimes(issued, expires uint32) error {
	if expires <= issued || uint64(expires-issued) > uint64(MaxTTL/time.Second) {
		return bad("issued at %d, expires at %d (want issued < expires ≤ issued + %v)", issued, expires, MaxTTL)
	}
	return nil
}

// DecodePlaintext decodes and checks a record plaintext (spec/dht-records.md,
// "Locator"). Addresses that aren't valid multiaddrs are skipped, so that
// publishers can list transports this version doesn't know.
func DecodePlaintext(pt []byte) (Locator, error) {
	if len(pt) < 2 || len(pt) > MaxPlaintext {
		return Locator{}, bad("plaintext of %d bytes", len(pt))
	}
	n := int(binary.BigEndian.Uint16(pt))
	if 2+n > len(pt) {
		return Locator{}, bad("length %d overruns a %d-byte plaintext", n, len(pt))
	}
	for _, c := range pt[2+n:] {
		if c != 0 {
			return Locator{}, bad("nonzero padding")
		}
	}
	var m pb.RendezvousLocator
	if err := proto.Unmarshal(pt[2:2+n], &m); err != nil {
		return Locator{}, bad("%v", err)
	}
	h := m.GetIp()
	if h == nil {
		return Locator{}, bad("no IP hint")
	}
	if n := len(h.GetPeerId()); n == 0 || n > MaxPeerIDLen {
		return Locator{}, bad("peer ID of %d bytes", n)
	}
	id, err := peer.IDFromBytes(h.GetPeerId())
	if err != nil {
		return Locator{}, bad("peer ID: %v", err)
	}
	if n := len(h.GetAddrs()); n > MaxAddrs {
		return Locator{}, bad("%d addresses (max %d)", n, MaxAddrs)
	}
	if err := checkTimes(m.GetIssuedAt(), m.GetExpiresAt()); err != nil {
		return Locator{}, err
	}
	l := Locator{ID: id, IssuedAt: frame.TimeOf(m.GetIssuedAt()), ExpiresAt: frame.TimeOf(m.GetExpiresAt())}
	for _, b := range h.GetAddrs() {
		if len(b) == 0 || len(b) > MaxAddrLen {
			return Locator{}, bad("address of %d bytes", len(b))
		}
		a, err := ma.NewMultiaddrBytes(b)
		if err != nil {
			continue
		}
		l.Addrs = append(l.Addrs, a)
	}
	return l, nil
}
