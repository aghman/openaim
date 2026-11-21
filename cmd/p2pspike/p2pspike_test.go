package main

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	"github.com/aghman/openaim/internal/transport/ip"
)

func TestByteSize(t *testing.T) {
	for in, want := range map[string]int64{"4096": 4096, "128KiB": 128 << 10, "16MiB": 16 << 20, "1GiB": 1 << 30, "10B": 10} {
		var b byteSize
		if err := b.Set(in); err != nil || int64(b) != want {
			t.Errorf("Set(%q) = %d, %v; want %d", in, b, err, want)
		}
	}
	for _, bad := range []string{"", "x", "-1", "1.5MiB"} {
		var b byteSize
		if b.Set(bad) == nil {
			t.Errorf("Set(%q) accepted", bad)
		}
	}
}

func TestParseAddrs(t *testing.T) {
	const r = "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWKZRbnqKmMM8PekmZaRSixq6RfGUFW2BeNk6vW4VMZnbT"
	const b = "12D3KooWRGoAACv7UtaZP7b8bxNp2oLwFSaXkyLM5SshGkJNYUPL"
	ri, _, err := parseRelay(r)
	if err != nil || ri.ID.String() != "12D3KooWKZRbnqKmMM8PekmZaRSixq6RfGUFW2BeNk6vW4VMZnbT" {
		t.Fatalf("parseRelay: %v %v", ri, err)
	}
	if _, _, err := parseRelay("/ip4/203.0.113.7/tcp/4001"); err == nil {
		t.Error("relay address without /p2p/ accepted")
	}
	ti, err := parseTarget(r + "/p2p-circuit/p2p/" + b)
	if err != nil || ti.ID.String() != b || len(ti.Addrs) != 1 {
		t.Fatalf("parseTarget: %v %v", ti, err)
	}
	if _, err := parseTarget(r); err == nil {
		t.Error("non-circuit --to accepted")
	}
}

// TestDialerSurvivesRelayResets runs the dial loop against an in-process
// relay with a 1 s duration limit: every relayed stream is reset, and the
// dialer must notice, reconnect, and keep pinging over the relay.
func TestDialerSurvivesRelayResets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	newHost := func(o ip.HostOptions) *hostT {
		o.Listen = []string{"/ip4/127.0.0.1/tcp/0"}
		h, err := ip.NewHost(o)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { h.Close() })
		return &hostT{h}
	}
	rec := &recorder{}

	r := newHost(ip.HostOptions{})
	rl, err := ip.StartRelay(r.Host, ip.RelayOptions{Limit: &relay.RelayLimit{Duration: time.Second, Data: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	l := newHost(ip.HostOptions{})
	l.SetStreamHandler(ip.MsgProtocol, func(s network.Stream) { serveEcho(s, rec) })
	if _, err := client.Reserve(ctx, l.Host, peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()}); err != nil {
		t.Fatal(err)
	}
	relayAddrs, _ := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()[:1]})
	circuit, err := ip.CircuitAddr(relayAddrs[0], l.ID())
	if err != nil {
		t.Fatal(err)
	}
	target, err := parseTarget(circuit.String())
	if err != nil {
		t.Fatal(err)
	}

	dh := newHost(ip.HostOptions{Gater: ip.RelayOnlyGater{Peer: l.ID()}})
	dh.Peerstore().AddAddrs(target.ID, target.Addrs, peerstore.PermanentAddrTTL)
	if err := dh.Connect(ctx, target); err != nil {
		t.Fatal(err)
	}
	d := &dialer{h: dh.Host, rec: rec, target: target.ID, size: 200, timeout: 2 * time.Second, bulk: 8 << 10,
		direct: make(chan struct{}, 1), lost: make(chan struct{}, 1), rtts: map[string][]float64{}, connected: time.Now()}
	watchConns(dh.Host, rec, nil, func(c network.Conn) {
		if c.RemotePeer() == target.ID {
			notify(d.lost)
		}
	})
	rctx, rcancel := context.WithTimeout(ctx, 3500*time.Millisecond)
	defer rcancel()
	d.run(rctx, 200*time.Millisecond)

	if len(d.resets) < 2 {
		t.Errorf("saw %d stream losses in 3.5 s with a 1 s relay limit, want ≥ 2", len(d.resets))
	}
	if len(d.downs) != len(d.resets) {
		t.Errorf("%d reconnects for %d losses", len(d.downs), len(d.resets))
	}
	// A ping can race the close event, but the event path must work.
	byEvent := 0
	for _, r := range d.resets {
		if r.err == "connection closed" {
			byEvent++
		}
	}
	if byEvent == 0 {
		t.Error("no loss was noticed through the connection-closed event")
	}
	if n := len(d.rtts["relay (limited)"]); n < 5 || len(d.rtts) != 1 {
		t.Errorf("rtts = %v, want ≥ 5 pings, all over the relay", d.rtts)
	}
	if len(d.bulks) != len(d.resets)+1 {
		t.Errorf("%d bulk runs for %d streams", len(d.bulks), len(d.resets)+1)
	}
	for _, b := range d.bulks {
		if b.err != "" || b.echoed != 8<<10 {
			t.Errorf("bulk %+v, want 8 KiB echoed", b)
		}
	}
}

type hostT struct{ host.Host }
