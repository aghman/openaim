package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// The outbound frame path. The daemon seals and persists frames; transports
// (internal/transport, wired in later) take them from here through a
// FrameSink. Frames are always persisted before a sink sees them, and a
// failed delivery leaves them queued, so a sink may drop or fail freely.

// TargetKind says what a delivery is addressed to.
type TargetKind int

const (
	// TargetFirstContact: FIRST_CONTACT frames to a key that isn't a buddy
	// yet, through ContactHint if known. Transports must never answer or
	// retry such a request on mesh on the recipient's behalf.
	TargetFirstContact TargetKind = iota + 1
	// TargetBuddy: DATA frames to a buddy, routed by the send policy
	// (design §7.2) using Reach.
	TargetBuddy
)

func (k TargetKind) String() string {
	switch k {
	case TargetFirstContact:
		return "first-contact"
	case TargetBuddy:
		return "buddy"
	}
	return "unknown"
}

// DeliveryTarget says where frames should go.
type DeliveryTarget struct {
	Kind TargetKind
	// Key is the recipient's identity key.
	Key identity.PublicKey
	// Layout is the frames' layout: IP-layout frames must never go on mesh.
	Layout frame.Layout
	// ContactHint, for a first contact, is a multiaddr to deliver to (an
	// invite's relay circuit or mailbox, or a handle's inbox hint), or "".
	ContactHint string
	// Reach is the recipient's best-known reachability, learnt only from
	// authenticated frame content (design §7.1), or nil.
	Reach *pb.Reach
}

// FrameSink sends frames. Transports implement it. Deliver should hand the
// frames off (queue them) rather than wait for the far end; an error means
// they weren't taken, and the daemon keeps them for a later attempt.
// Deliver may be called concurrently, and may call back into the node
// (HandleFrame), since the node holds no lock while calling it.
type FrameSink interface {
	Deliver(ctx context.Context, to DeliveryTarget, frames [][]byte) error
}

// ErrNoSink: no transport is attached; frames stay queued.
var ErrNoSink = errors.New("daemon: no transport attached; frames stay queued")

// SetFrameSink attaches the transports' sink (nil detaches it). Frames
// sealed while none is attached stay queued; RedeliverRequests resends
// queued requests.
func (n *Node) SetFrameSink(s FrameSink) {
	n.sinkMu.Lock()
	n.sinkV = s
	n.sinkMu.Unlock()
}

func (n *Node) sink() FrameSink {
	n.sinkMu.Lock()
	defer n.sinkMu.Unlock()
	return n.sinkV
}

// deliver hands frames to the sink. It must be called without writeMu held.
func (n *Node) deliver(ctx context.Context, to DeliveryTarget, frames [][]byte) error {
	s := n.sink()
	if s == nil {
		return ErrNoSink
	}
	return s.Deliver(ctx, to, frames)
}

// ---- first-contact rate limiting (design §5.4, §7.5; spec/wire.md §11.5)

// Default first-contact limits, per transport: a burst of
// DefaultFirstContactBurst frames, refilled at DefaultFirstContactRate per
// second. Every first-contact frame costs an X25519 to try, whoever it is
// for, so the limit applies before trial decryption.
const (
	DefaultFirstContactRate  = 0.5
	DefaultFirstContactBurst = 32
	// maxBuckets bounds the per-transport table; transports are few.
	maxBuckets = 64
)

// ErrRateLimited: a first-contact frame was dropped by the rate limit.
var ErrRateLimited = errors.New("daemon: first-contact frame rate-limited")

// tokenBuckets is a token bucket per transport name.
type tokenBuckets struct {
	rate  float64
	burst float64
	mu    sync.Mutex
	b     map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newTokenBuckets(rate float64, burst int) *tokenBuckets {
	if rate <= 0 {
		rate = DefaultFirstContactRate
	}
	if burst <= 0 {
		burst = DefaultFirstContactBurst
	}
	return &tokenBuckets{rate: rate, burst: float64(burst), b: map[string]*bucket{}}
}

// allow takes a token from transport's bucket, if it has one.
func (t *tokenBuckets) allow(transport string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.b[transport]
	if b == nil && len(t.b) >= maxBuckets {
		// Many names: share one bucket rather than grow without bound.
		transport = "\x00overflow"
		b = t.b[transport]
	}
	if b == nil {
		b = &bucket{tokens: t.burst, last: now}
		t.b[transport] = b
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(t.burst, b.tokens+d.Seconds()*t.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// FirstContactStats count what happened to first-contact frames, for
// metrics (design §9).
type FirstContactStats struct {
	Frames      uint64 // first-contact frames handed in
	RateLimited uint64 // dropped by the per-transport limit
	Dropped     uint64 // malformed, not for us, forged or stale
	Duplicates  uint64
	Requests    uint64 // complete requests from new requesters
	Merged      uint64 // complete repeat requests, merged into one
	Blocked     uint64 // complete requests from blocked keys, dropped
	WrongType   uint64 // complete first contacts that weren't BUDDY_REQUEST
	Overflow    uint64 // requests from new keys dropped: too many waiting
	// DataRequests counts BUDDY_REQUEST bodies found in DATA frames, which
	// are always dropped.
	DataRequests uint64
}

type fcCounters struct {
	frames, rateLimited, dropped, duplicates, requests, merged, blocked, wrongType, overflow, dataRequests atomic.Uint64
}

// FirstContactStats returns the first-contact counters since Open.
func (n *Node) FirstContactStats() FirstContactStats {
	c := &n.fcStats
	return FirstContactStats{
		Frames: c.frames.Load(), RateLimited: c.rateLimited.Load(), Dropped: c.dropped.Load(),
		Duplicates: c.duplicates.Load(), Requests: c.requests.Load(), Merged: c.merged.Load(),
		Blocked: c.blocked.Load(), WrongType: c.wrongType.Load(), Overflow: c.overflow.Load(), DataRequests: c.dataRequests.Load(),
	}
}

// ---- what we tell others about ourselves

// reachTTL is how long a REACH we build from the contact hint is valid:
// the acceptance window, so a request still in flight carries a live one.
const reachTTL = frame.MaxAge

// ourReach is our current reachability for requests and accepts: the
// configured REACH (Config.Reach) or the network's, else one built from the
// contact hint, else nil.
func (n *Node) ourReach() *pb.Reach {
	reach := n.cfg.Reach
	if reach == nil && n.net != nil {
		reach = n.net.reachBody
	}
	if reach != nil {
		if r := reach(); r != nil {
			if err := body.Validate(r); err != nil {
				n.log.Warn("ignoring invalid REACH from the transports", "err", err)
				return nil
			}
			return proto.Clone(r).(*pb.Reach)
		}
	}
	hint := n.contactHint()
	if hint == "" {
		return nil
	}
	return reachFromContact(hint, n.now())
}

// reachFromContact makes a REACH from a relay-circuit contact hint that ends
// in our own peer ID (…/p2p-circuit/p2p/<id>): the peer ID and the circuit.
// Other hints (a mailbox) can't be expressed as a REACH yet (M3): nil.
func reachFromContact(hint string, now time.Time) *pb.Reach {
	a, err := ma.NewMultiaddr(hint)
	if err != nil {
		return nil
	}
	rest, last := ma.SplitLast(a)
	if last == nil || last.Code() != ma.P_P2P || len(rest) == 0 || rest[len(rest)-1].Code() != ma.P_CIRCUIT {
		return nil
	}
	ts := frame.Timestamp(now)
	r := &pb.Reach{
		Seq: uint64(ts), IssuedAt: ts, ExpiresAt: frame.Timestamp(now.Add(reachTTL)),
		Ip: []*pb.IPHint{{PeerId: last.RawValue(), Addrs: [][]byte{rest.Bytes()}}},
	}
	if body.Validate(r) != nil {
		return nil
	}
	return r
}

// caps is our CAPS.
func caps() *pb.Caps {
	ua := "openaimd/" + BuildVersion()
	if len(ua) > body.MaxUserAgent {
		ua = ua[:body.MaxUserAgent]
	}
	c := &pb.Caps{WireVersion: frame.Version, Features: uint64(pb.Feature_FEATURE_IP_LAYOUT), UserAgent: ua}
	if body.Validate(c) != nil {
		c.UserAgent = ""
	}
	return c
}
