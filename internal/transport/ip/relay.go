package ip

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
)

// Relay limit profiles. Circuit relay v2 limits apply per relayed connection
// (not per protocol), in each direction.
var (
	// LibP2PDefaultLimit is go-libp2p's default: reset after 2 min or 128 KiB.
	LibP2PDefaultLimit = relay.DefaultLimit()
	// OpenAIMLimit is the raised limit `openaimd --public` relays start with
	// (design §6.1). It is a first guess for M0 to confirm or revise: long
	// enough that an idle IM session rarely resets, and enough data for a long
	// conversation, without making relays a bulk-transfer service.
	OpenAIMLimit = &relay.RelayLimit{Duration: time.Hour, Data: 16 << 20}
)

// RelayOptions configures StartRelay.
type RelayOptions struct {
	// Limit applies to every relayed connection. Nil means unlimited, in
	// which case clients do not mark the connection as limited.
	Limit *relay.RelayLimit
	// Tracer, if set, sees reservations, circuits and bytes.
	Tracer relay.MetricsTracer
	// MaxReservations and MaxCircuits override the go-libp2p defaults
	// (128 and 16 per peer) when non-zero.
	MaxReservations, MaxCircuits int
}

// StartRelay runs a circuit relay v2 service on h. Unlike
// libp2p.EnableRelayService it starts immediately, without waiting for
// AutoNAT to decide the host is public.
func StartRelay(h host.Host, o RelayOptions) (*relay.Relay, error) {
	rc := relay.DefaultResources()
	rc.Limit = o.Limit
	if o.MaxReservations > 0 {
		rc.MaxReservations = o.MaxReservations
	}
	if o.MaxCircuits > 0 {
		rc.MaxCircuits = o.MaxCircuits
	}
	opts := []relay.Option{relay.WithResources(rc)}
	if o.Tracer != nil {
		opts = append(opts, relay.WithMetricsTracer(o.Tracer))
	}
	return relay.New(h, opts...)
}

// DescribeLimit formats a relay limit for logs.
func DescribeLimit(l *relay.RelayLimit) string {
	if l == nil {
		return "unlimited"
	}
	return fmt.Sprintf("%v or %s per direction", l.Duration, FormatBytes(l.Data))
}

// FormatBytes formats n as B, KiB or MiB.
func FormatBytes(n int64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// ReservationEvent reports one reservation attempt by KeepReservation.
type ReservationEvent struct {
	At          time.Time
	Reservation *client.Reservation // nil on failure
	Err         error
	// Reason is why this attempt happened: "initial", "refresh", "retry" or
	// "relay disconnected".
	Reason string
}

// KeepReservation reserves a slot on the relay and keeps it until ctx ends.
// It refreshes when about a quarter of the reservation's TTL is left,
// re-reserves at once if the connection to the relay drops (the relay forgets
// reservations of disconnected peers), and retries failures with backoff
// (5 s doubling to 1 min). onEvent is called after every attempt.
func KeepReservation(ctx context.Context, h host.Host, relayInfo peer.AddrInfo, onEvent func(ReservationEvent)) {
	lost := make(chan struct{}, 1)
	nb := &network.NotifyBundle{DisconnectedF: func(n network.Network, c network.Conn) {
		if c.RemotePeer() == relayInfo.ID && n.Connectedness(relayInfo.ID) != network.Connected {
			select {
			case lost <- struct{}{}:
			default:
			}
		}
	}}
	h.Network().Notify(nb)
	defer h.Network().StopNotify(nb)

	backoff := 5 * time.Second
	reason := "initial"
	for {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		rsvp, err := client.Reserve(rctx, h, relayInfo)
		cancel()
		if ctx.Err() != nil {
			return
		}
		onEvent(ReservationEvent{At: time.Now(), Reservation: rsvp, Err: err, Reason: reason})

		wait, lostCh := backoff, lost
		if err == nil {
			// A disconnect before this reservation succeeded is stale.
			select {
			case <-lost:
			default:
			}
			backoff = 5 * time.Second
			wait = max(time.Until(rsvp.Expiration)*3/4, 10*time.Second)
			reason = "refresh"
		} else {
			backoff = min(backoff*2, time.Minute)
			reason = "retry"
			lostCh = nil // keep backing off; a failed dial also "disconnects"
		}
		select {
		case <-time.After(wait):
		case <-lostCh:
			reason = "relay disconnected"
			// Brief pause so a flapping link doesn't spin.
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
