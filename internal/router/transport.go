package router

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/transport/ip"
)

// Route is where a buddy can be reached over IP right now: a libp2p peer and
// its addresses (none means "use an existing connection or remembered
// addresses").
type Route struct {
	Peer  peer.ID
	Addrs []ma.Multiaddr
	// Live is set when the route comes from a session we heard the buddy on
	// (design §7.2 rule 1) rather than from an advertised record.
	Live bool
}

// AddrInfo is the route as a libp2p peer.AddrInfo.
func (r Route) AddrInfo() peer.AddrInfo { return peer.AddrInfo{ID: r.Peer, Addrs: r.Addrs} }

// Transport sends frames along a route. Send is best effort: nil means the
// frames were written, not that they arrived, and a failed Send may still
// have delivered some of them. Receivers deduplicate (design §7.2).
type Transport interface {
	Send(ctx context.Context, r Route, frames [][]byte) error
}

// Reachability tells the router where a buddy is (design §7.1). It must be
// fed only from authenticated content; ReachTable is the implementation.
type Reachability interface {
	// IPRoute returns the buddy's current IP route at now, if any.
	IPRoute(buddyID int64, now time.Time) (Route, bool)
}

// Sealer seals a one-off control message (an ACK) to a buddy: under the
// buddy's send ConvKey and today's tag, in a layout the route carries. The
// result is sent once and never persisted, so the router never holds
// identity or conversation keys. The sealer picks the inner seq; ACKs are
// unordered, so 0 is fine and saves a database write.
type Sealer func(ctx context.Context, buddyID int64, ct frame.ContentType, body []byte) ([][]byte, error)

// Clock is the router's time source. Tests inject a fake one.
type Clock interface {
	Now() time.Time
	// AfterFunc calls f in its own goroutine once d has passed.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a pending AfterFunc call.
type Timer interface {
	// Stop prevents the call if it hasn't started.
	Stop() bool
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// SessionsTransport sends over /openaim/msg/1 sessions.
func SessionsTransport(s *ip.Sessions) Transport { return sessionsTransport{s} }

type sessionsTransport struct{ s *ip.Sessions }

func (t sessionsTransport) Send(ctx context.Context, r Route, frames [][]byte) error {
	return t.s.Send(ctx, r.AddrInfo(), frames)
}
