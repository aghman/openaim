package ip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frames := [][]byte{{1}, bytes.Repeat([]byte{2}, 200), bytes.Repeat([]byte{3}, MaxFrameLen)}
	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	fr := NewFrameReader(&buf)
	for i, want := range frames {
		got, err := fr.ReadFrame()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("frame %d: len %d, %v", i, len(got), err)
		}
	}
	if _, err := fr.ReadFrame(); err != io.EOF {
		t.Fatalf("at end: %v, want io.EOF", err)
	}
}

func TestFrameErrors(t *testing.T) {
	if err := WriteFrame(io.Discard, nil); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("empty frame: %v", err)
	}
	if err := WriteFrame(io.Discard, make([]byte, MaxFrameLen+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("oversize frame: %v", err)
	}
	if _, err := NewFrameReader(bytes.NewReader([]byte{0, 5, 1, 2})).ReadFrame(); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated: %v", err)
	}
	if _, err := NewFrameReader(bytes.NewReader([]byte{0, 0})).ReadFrame(); err == nil {
		t.Error("zero-length frame accepted")
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 1, 9})
	f.Add([]byte{0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, b []byte) {
		fr := NewFrameReader(bytes.NewReader(b))
		for {
			fb, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if len(fb) == 0 || len(fb) > MaxFrameLen {
				t.Fatalf("bad frame length %d", len(fb))
			}
		}
	})
}

func TestCircuitAddrAndPath(t *testing.T) {
	r := newTestHost(t)
	b := newTestHost(t)
	ca, err := CircuitAddr(hostAddr(t, r), b.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.ValueForProtocol(ma.P_CIRCUIT); err != nil {
		t.Fatalf("%s has no p2p-circuit", ca)
	}
	if _, err := CircuitAddr(r.Addrs()[0], b.ID()); err == nil {
		t.Error("relay address without /p2p/ accepted")
	}
}

// relayTrio is a relay R, a listener B with a reservation on R running an echo
// handler for MsgProtocol, and a dialer A connected to B only through R.
type relayTrio struct {
	r, a, b host.Host
	rsvp    *client.Reservation
	conn    network.Conn // A's connection to B
}

func newRelayTrio(t *testing.T, limit *relay.RelayLimit) *relayTrio {
	return newRelayTrioOpts(t, limit, func(peer.ID) HostOptions { return HostOptions{} })
}

// newRelayTrioOpts is newRelayTrio with options for A, which may depend on
// B's peer ID.
func newRelayTrioOpts(t *testing.T, limit *relay.RelayLimit, aOptsFor func(b peer.ID) HostOptions) *relayTrio {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := &relayTrio{r: newTestHost(t), b: newTestHost(t)}
	aOpts := aOptsFor(tr.b.ID())
	aOpts.Listen = []string{"/ip4/127.0.0.1/tcp/0"}
	a, err := NewHost(aOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	tr.a = a
	rl, err := StartRelay(tr.r, RelayOptions{Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rl.Close() })

	tr.b.SetStreamHandler(MsgProtocol, echo)
	relayInfo := peer.AddrInfo{ID: tr.r.ID(), Addrs: tr.r.Addrs()}
	if tr.rsvp, err = client.Reserve(ctx, tr.b, relayInfo); err != nil {
		t.Fatal(err)
	}

	circuit, err := CircuitAddr(hostAddr(t, tr.r), tr.b.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.a.Connect(ctx, peer.AddrInfo{ID: tr.b.ID(), Addrs: []ma.Multiaddr{circuit}}); err != nil {
		t.Fatal(err)
	}
	conns := tr.a.Network().ConnsToPeer(tr.b.ID())
	if len(conns) != 1 || !IsRelayed(conns[0]) {
		t.Fatalf("A→B conns = %v, want one relayed conn", conns)
	}
	tr.conn = conns[0]
	return tr
}

func (tr *relayTrio) stream(t *testing.T) network.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := tr.a.NewStream(network.WithAllowLimitedConn(ctx, "openaim msg"), tr.b.ID(), MsgProtocol)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Reset() })
	return s
}

// pump sends total bytes in frames of frameLen through the echo handler,
// with up to 16 frames in flight, and returns how many bytes came back.
func pump(s network.Stream, total, frameLen int) (int, error) {
	frame := bytes.Repeat([]byte{0xA5}, frameLen)
	fr := NewFrameReader(s)
	sent, got := 0, 0
	inflight := 0
	for got < total {
		for sent < total && inflight < 16 {
			if err := WriteFrame(s, frame); err != nil {
				return got, err
			}
			sent += frameLen
			inflight++
		}
		b, err := fr.ReadFrame()
		if err != nil {
			return got, err
		}
		if !bytes.Equal(b, frame) {
			return got, errors.New("echo mismatch")
		}
		got += len(b)
		inflight--
	}
	return got, nil
}

func TestRelayedEchoUnlimited(t *testing.T) {
	tr := newRelayTrio(t, nil)
	if tr.conn.Stat().Limited {
		t.Error("connection through an unlimited relay is marked limited")
	}
	if tr.rsvp.LimitDuration != 0 || tr.rsvp.LimitData != 0 {
		t.Errorf("reservation limits = %v / %d, want none", tr.rsvp.LimitDuration, tr.rsvp.LimitData)
	}
	s := tr.stream(t)
	s.SetDeadline(time.Now().Add(20 * time.Second))
	const total = 1 << 20 // 8× the go-libp2p default data limit
	if got, err := pump(s, total, 4096); err != nil || got != total {
		t.Fatalf("echoed %d of %d bytes: %v", got, total, err)
	}
}

func TestRelayDataLimitResets(t *testing.T) {
	const limit = 16 << 10
	tr := newRelayTrio(t, &relay.RelayLimit{Duration: time.Minute, Data: limit})
	if !tr.conn.Stat().Limited || PathOf(tr.conn) != "relay (limited)" {
		t.Errorf("path = %q, want relay (limited)", PathOf(tr.conn))
	}
	if tr.rsvp.LimitData != limit {
		t.Errorf("reservation LimitData = %d, want %d", tr.rsvp.LimitData, limit)
	}
	s := tr.stream(t)
	s.SetDeadline(time.Now().Add(10 * time.Second))
	got, err := pump(s, 4*limit, 1024)
	if err == nil {
		t.Fatalf("echoed all %d bytes past a %d B relay limit", got, limit)
	}
	if got > limit {
		t.Errorf("echoed %d bytes, more than the %d B limit", got, limit)
	}
	t.Logf("reset after %d bytes echoed: %v", got, err)
}

func TestRelayDurationLimitResets(t *testing.T) {
	tr := newRelayTrio(t, &relay.RelayLimit{Duration: time.Second, Data: 1 << 20})
	s := tr.stream(t)
	s.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pump(s, 200, 200); err != nil {
		t.Fatalf("first ping: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := pump(s, 200, 200); err == nil {
		t.Fatal("ping succeeded after the relay's 1 s duration limit")
	}
	// The relayed connection is gone; a fresh one works again.
	waitFor(t, func() bool { return len(tr.a.Network().ConnsToPeer(tr.b.ID())) == 0 })
}

// TestLimitedConnNeedsAllowance: without WithAllowLimitedConn, NewStream
// waits for a direct connection (which is how it rides a DCUtR upgrade) and
// fails if none appears.
func TestLimitedConnNeedsAllowance(t *testing.T) {
	tr := newRelayTrio(t, LibP2PDefaultLimit)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if s, err := tr.a.NewStream(ctx, tr.b.ID(), MsgProtocol); err == nil {
		s.Reset()
		t.Fatal("stream opened on a limited connection without WithAllowLimitedConn")
	}
}

// TestRelayOnlyGater: after identify, A knows B's own addresses and would
// normally connect directly; the gater keeps it on the relay.
func TestRelayOnlyGater(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, gated := range []bool{false, true} {
		tr := newRelayTrioOpts(t, nil, func(b peer.ID) HostOptions {
			if gated {
				return HostOptions{Gater: RelayOnlyGater{Peer: b}}
			}
			return HostOptions{}
		})
		// Connect is a no-op while the relayed connection exists, so force a
		// direct dial, as DCUtR and swarm upgrades do.
		tr.a.Peerstore().AddAddrs(tr.b.ID(), tr.b.Addrs(), time.Minute)
		_, err := tr.a.Network().DialPeer(network.WithForceDirectDial(ctx, "test"), tr.b.ID())
		var direct bool
		for _, c := range tr.a.Network().ConnsToPeer(tr.b.ID()) {
			direct = direct || !IsRelayed(c)
		}
		if gated && direct {
			t.Error("gated: A has a direct connection to B")
		}
		if !gated && (err != nil || !direct) {
			t.Errorf("ungated: direct connect failed: %v", err)
		}
		if s := tr.stream(t); gated && !IsRelayed(s.Conn()) {
			t.Errorf("gated: stream over %s, want relay", PathOf(s.Conn()))
		}
	}
}

func TestKeepReservationRecovers(t *testing.T) {
	r, b := newTestHost(t), newTestHost(t)
	rl, err := StartRelay(r, RelayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	var mu sync.Mutex
	var events []ReservationEvent
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		KeepReservation(ctx, b, peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()}, func(e ReservationEvent) {
			mu.Lock()
			events = append(events, e)
			mu.Unlock()
		})
	}()
	defer func() { cancel(); <-done }()

	okCount := func() (n int, last string) {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range events {
			if e.Err == nil {
				n++
				last = e.Reason
			}
		}
		return n, last
	}
	waitFor(t, func() bool { n, _ := okCount(); return n == 1 })
	r.Network().ClosePeer(b.ID())
	waitFor(t, func() bool { n, last := okCount(); return n == 2 && last == "relay disconnected" })
}

func newTestHost(t *testing.T) host.Host {
	t.Helper()
	h, err := NewHost(HostOptions{Listen: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// hostAddr is h's first address with /p2p/<id> appended.
func hostAddr(t *testing.T, h host.Host) ma.Multiaddr {
	t.Helper()
	addrs, err := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()[:1]})
	if err != nil {
		t.Fatal(err)
	}
	return addrs[0]
}

func echo(s network.Stream) {
	defer s.Close()
	fr := NewFrameReader(s)
	for {
		b, err := fr.ReadFrame()
		if err != nil {
			return
		}
		if WriteFrame(s, b) != nil {
			return
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
