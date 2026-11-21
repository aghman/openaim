package main

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	pbv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/pb"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/aghman/openaim/internal/transport/ip"
)

func runRelay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	key := fs.String("key", "relay.key", "network key file, created if missing, so the relay's address stays stable")
	port := fs.Int("port", 4001, "TCP and UDP port to listen on")
	profile := fs.String("limits", "openaim", "relay limit profile: openaim (raised), libp2p (2 min / 128 KiB defaults) or none")
	dur := fs.Duration("limit-duration", 0, "override the profile's per-connection duration limit")
	var data byteSize
	fs.Var(&data, "limit-data", "override the profile's per-direction data limit (e.g. 128KiB, 16MiB)")
	every := fs.Duration("status", time.Minute, "how often to print a status line")
	jsonl := fs.String("jsonl", "", "append event records to this JSONL file")
	fs.Parse(args)

	var limit *relay.RelayLimit
	switch *profile {
	case "openaim":
		l := *ip.OpenAIMLimit
		limit = &l
	case "libp2p":
		l := *ip.LibP2PDefaultLimit
		limit = &l
	case "none":
		if *dur != 0 || data != 0 {
			return fmt.Errorf("--limit-duration/--limit-data need a limited profile, not --limits none")
		}
	default:
		return fmt.Errorf("unknown --limits %q (openaim, libp2p or none)", *profile)
	}
	if limit != nil {
		if *dur != 0 {
			if *dur < time.Second {
				return fmt.Errorf("--limit-duration must be at least 1s (the protocol carries whole seconds)")
			}
			limit.Duration = *dur
		}
		if data != 0 {
			limit.Data = int64(data)
		}
	}

	rec, err := openRecorder(*jsonl)
	if err != nil {
		return err
	}
	defer rec.Close()

	k, err := ip.LoadOrCreateKey(*key)
	if err != nil {
		return err
	}
	h, err := ip.NewHost(ip.HostOptions{Key: k, Listen: ip.DefaultListen(*port), PublicReachability: true})
	if err != nil {
		return err
	}
	defer h.Close()

	tr := &relayTracer{rec: rec, statuses: map[string]int{}}
	rl, err := ip.StartRelay(h, ip.RelayOptions{Limit: limit, Tracer: tr})
	if err != nil {
		return err
	}
	defer rl.Close()

	fmt.Printf("relay %s, limits: %s\n", h.ID(), ip.DescribeLimit(limit))
	addrs, _ := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
	fmt.Println("give listen/dial one of these (a public one, unless everything is on one LAN):")
	for _, a := range addrs {
		scope := "private"
		if manet.IsPublicAddr(a) {
			scope = "public"
		}
		fmt.Printf("  %-7s %s\n", scope, a)
	}
	rec.write("relay-start", map[string]any{"id": h.ID().String(), "limit": ip.DescribeLimit(limit), "addrs": addrs})

	t := time.NewTicker(*every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			logf("status: %s", tr.status())
		case <-ctx.Done():
			logf("final: %s", tr.status())
			return nil
		}
	}
}

// relayTracer implements relay.MetricsTracer to log what the relay does.
type relayTracer struct {
	rec *recorder

	mu           sync.Mutex
	reservations int // currently held, approximately
	circuits     int // open now
	opened       int
	bytes        int64
	statuses     map[string]int
}

var _ relay.MetricsTracer = (*relayTracer)(nil)

func (t *relayTracer) RelayStatus(enabled bool) {
	logf("relay service enabled=%v", enabled)
}

func (t *relayTracer) ConnectionOpened() {
	t.mu.Lock()
	t.circuits++
	t.opened++
	n := t.circuits
	t.mu.Unlock()
	logf("circuit opened (%d open)", n)
	t.rec.write("circuit-open", map[string]any{"open": n})
}

func (t *relayTracer) ConnectionClosed(d time.Duration) {
	t.mu.Lock()
	t.circuits--
	n := t.circuits
	t.mu.Unlock()
	logf("circuit closed after %v (%d open)", d.Round(time.Millisecond), n)
	t.rec.write("circuit-close", map[string]any{"age_ms": ms(d), "open": n})
}

func (t *relayTracer) ConnectionRequestHandled(s pbv2.Status) {
	t.count("connect " + s.String())
	if s != pbv2.Status_OK {
		logf("circuit request refused: %s", s)
	}
}

func (t *relayTracer) ReservationAllowed(isRenewal bool) {
	t.mu.Lock()
	if !isRenewal {
		t.reservations++
	}
	n := t.reservations
	t.mu.Unlock()
	logf("reservation %s (%d held)", map[bool]string{false: "new", true: "renewed"}[isRenewal], n)
	t.rec.write("reservation", map[string]any{"renewal": isRenewal, "held": n})
}

func (t *relayTracer) ReservationClosed(cnt int) {
	t.mu.Lock()
	t.reservations -= cnt
	n := t.reservations
	t.mu.Unlock()
	logf("%d reservation(s) closed (%d held)", cnt, n)
	t.rec.write("reservation-close", map[string]any{"closed": cnt, "held": n})
}

func (t *relayTracer) ReservationRequestHandled(s pbv2.Status) {
	t.count("reserve " + s.String())
	if s != pbv2.Status_OK {
		logf("reservation refused: %s", s)
	}
}

func (t *relayTracer) BytesTransferred(cnt int) {
	t.mu.Lock()
	t.bytes += int64(cnt)
	t.mu.Unlock()
}

func (t *relayTracer) count(k string) {
	t.mu.Lock()
	t.statuses[k]++
	t.mu.Unlock()
}

func (t *relayTracer) status() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return fmt.Sprintf("%d reservations, %d circuits open (%d total), %s relayed, requests %v",
		t.reservations, t.circuits, t.opened, ip.FormatBytes(t.bytes), t.statuses)
}
