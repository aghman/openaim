package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/transport/ip"
)

func runListen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	var hf hostFlags
	hf.register(fs)
	relayAddr := fs.String("relay", "", "relay multiaddr ending in /p2p/<relay ID> (required)")
	fs.Parse(args)

	relayInfo, relayMA, err := parseRelay(*relayAddr)
	if err != nil {
		return err
	}
	rec, err := openRecorder(hf.jsonl)
	if err != nil {
		return err
	}
	defer rec.Close()

	var hp *hpTracer
	if !hf.noHolePunch {
		hp = &hpTracer{rec: rec}
	}
	h, err := hf.newHost(hp, nil)
	if err != nil {
		return err
	}
	defer h.Close()
	watchConns(h, rec, nil, nil)
	go watchNAT(ctx, h, rec)
	h.SetStreamHandler(ip.MsgProtocol, func(s network.Stream) { serveEcho(s, rec) })

	circuit, err := ip.CircuitAddr(relayMA, h.ID())
	if err != nil {
		return err
	}
	fmt.Printf("listener %s (hole punching %s)\n", h.ID(), onOff(!hf.noHolePunch))

	announced := false
	go ip.KeepReservation(ctx, h, relayInfo, func(e ip.ReservationEvent) {
		if e.Err != nil {
			logf("reservation (%s) failed: %v", e.Reason, e.Err)
			rec.write("reservation", map[string]any{"reason": e.Reason, "error": e.Err.Error()})
			return
		}
		r := e.Reservation
		logf("reservation (%s) ok until %s, limits %s, relay sees us at %v",
			e.Reason, r.Expiration.Format("15:04:05"), describeRsvpLimit(r.LimitDuration, r.LimitData), r.Addrs)
		rec.write("reservation", map[string]any{"reason": e.Reason, "expires": r.Expiration, "limit_duration_s": r.LimitDuration.Seconds(), "limit_data": r.LimitData, "observed_addrs": r.Addrs})
		if !announced {
			announced = true
			fmt.Printf("\nreachable through the relay. on the other machine run:\n\n  p2pspike dial --to %s\n\n", circuit)
			rec.write("listening", map[string]any{"id": h.ID().String(), "circuit": circuit.String()})
		}
	})

	<-ctx.Done()
	return nil
}

// serveEcho echoes /openaim/msg/1 frames back byte-for-byte.
func serveEcho(s network.Stream, rec *recorder) {
	defer s.Close()
	path := ip.PathOf(s.Conn())
	peerID := s.Conn().RemotePeer().String()
	start := time.Now()
	logf("stream from %s over %s", shortID(peerID), path)

	fr := ip.NewFrameReader(s)
	var frames, bytes int
	var err error
	for {
		var b []byte
		if b, err = fr.ReadFrame(); err != nil {
			break
		}
		if err = ip.WriteFrame(s, b); err != nil {
			break
		}
		frames++
		bytes += len(b)
	}
	reason := "closed by dialer"
	if !errors.Is(err, io.EOF) {
		reason = err.Error()
	}
	age := time.Since(start)
	logf("stream from %s over %s ended after %v, %d frames / %d B echoed: %s", shortID(peerID), path, age.Round(time.Millisecond), frames, bytes, reason)
	rec.write("stream-end", map[string]any{"peer": peerID, "path": path, "age_ms": ms(age), "frames": frames, "bytes": bytes, "reason": reason})
}

// watchNAT logs what the host learns about its own reachability and NAT type,
// which explains hole-punch results (symmetric NATs rarely punch).
func watchNAT(ctx context.Context, h host.Host, rec *recorder) {
	sub, err := h.EventBus().Subscribe([]any{new(event.EvtLocalReachabilityChanged), new(event.EvtNATDeviceTypeChanged)})
	if err != nil {
		return
	}
	defer sub.Close()
	for {
		select {
		case e := <-sub.Out():
			switch v := e.(type) {
			case event.EvtLocalReachabilityChanged:
				logf("reachability: %s", v.Reachability)
				rec.write("reachability", map[string]any{"reachability": v.Reachability.String()})
			case event.EvtNATDeviceTypeChanged:
				logf("NAT type (%s): %s", v.TransportProtocol, v.NatDeviceType)
				rec.write("nat-type", map[string]any{"transport": v.TransportProtocol.String(), "type": v.NatDeviceType.String()})
			}
		case <-ctx.Done():
			return
		}
	}
}

func parseRelay(s string) (peer.AddrInfo, ma.Multiaddr, error) {
	if s == "" {
		return peer.AddrInfo{}, nil, fmt.Errorf("--relay is required (an address printed by p2pspike relay)")
	}
	m, err := ma.NewMultiaddr(s)
	if err != nil {
		return peer.AddrInfo{}, nil, fmt.Errorf("--relay: %w", err)
	}
	ai, err := peer.AddrInfoFromP2pAddr(m)
	if err != nil {
		return peer.AddrInfo{}, nil, fmt.Errorf("--relay must end in /p2p/<relay ID>: %w", err)
	}
	return *ai, m, nil
}

func describeRsvpLimit(d time.Duration, data uint64) string {
	if d == 0 && data == 0 {
		return "none"
	}
	return fmt.Sprintf("%v / %s per direction", d, ip.FormatBytes(int64(data)))
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
