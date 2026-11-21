package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/transport/ip"
)

const (
	pingMagic   = "OAI0"
	minPingSize = 16 // magic 4 | seq 4 | sent unix-ms 8
	bulkFrame   = 4096
)

func runDial(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	var hf hostFlags
	hf.register(fs)
	to := fs.String("to", "", "listener's circuit address, as printed by p2pspike listen (required)")
	interval := fs.Duration("interval", 10*time.Second, "time between pings")
	duration := fs.Duration("duration", 10*time.Minute, "how long to run (0 = until interrupted)")
	size := fs.Int("size", 200, fmt.Sprintf("ping frame size in bytes (%d–%d; 200 is the canonical mesh frame)", minPingSize, ip.MaxFrameLen))
	timeout := fs.Duration("timeout", 10*time.Second, "per-ping and per-stream-open timeout")
	relayOnly := fs.Bool("relay-only", false, "refuse direct connections to the listener, so every stream uses the relay (implies --no-holepunch)")
	var bulk byteSize
	fs.Var(&bulk, "bulk", "on every new stream, first echo this much data in 4 KiB frames (e.g. 256KiB) to probe the relay's data limit")
	fs.Parse(args)

	target, err := parseTarget(*to)
	if err != nil {
		return err
	}
	if *size < minPingSize || *size > ip.MaxFrameLen {
		return fmt.Errorf("--size must be %d–%d", minPingSize, ip.MaxFrameLen)
	}
	if *interval < 100*time.Millisecond {
		return fmt.Errorf("--interval must be at least 100ms")
	}
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	rec, err := openRecorder(hf.jsonl)
	if err != nil {
		return err
	}
	defer rec.Close()

	var gater connmgr.ConnectionGater
	if *relayOnly {
		hf.noHolePunch = true
		gater = ip.RelayOnlyGater{Peer: target.ID}
	}
	var hp *hpTracer
	if !hf.noHolePunch {
		hp = &hpTracer{rec: rec}
	}
	h, err := hf.newHost(hp, gater)
	if err != nil {
		return err
	}
	defer h.Close()

	d := &dialer{
		h: h, rec: rec, target: target.ID,
		size: *size, timeout: *timeout, bulk: int(bulk),
		direct: make(chan struct{}, 1),
		lost:   make(chan struct{}, 1),
		rtts:   map[string][]float64{},
	}
	watchConns(h, rec, func(c network.Conn) {
		if c.RemotePeer() == target.ID && !ip.IsRelayed(c) {
			d.firstDirect.CompareAndSwap(0, time.Now().UnixNano())
			notify(d.direct)
		}
	}, func(c network.Conn) {
		if c.RemotePeer() == target.ID {
			notify(d.lost)
		}
	})
	fmt.Printf("dialer %s (hole punching %s) → %s\n", h.ID(), onOff(!hf.noHolePunch), shortID(target.ID.String()))

	// Keep the circuit address for reconnects after the dial's temporary TTL.
	h.Peerstore().AddAddrs(target.ID, target.Addrs, peerstore.PermanentAddrTTL)
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 2**timeout)
	err = h.Connect(cctx, target)
	cancel()
	if err != nil {
		return fmt.Errorf("connect through relay: %w", err)
	}
	d.connected = time.Now()
	logf("connected through relay in %.0f ms", ms(d.connected.Sub(start)))
	rec.write("connect", map[string]any{"target": target.ID.String(), "ms": ms(d.connected.Sub(start))})

	d.run(ctx, *interval)
	d.printSummary(hp)
	return nil
}

func parseTarget(s string) (peer.AddrInfo, error) {
	if s == "" {
		return peer.AddrInfo{}, fmt.Errorf("--to is required (the circuit address printed by p2pspike listen)")
	}
	m, err := ma.NewMultiaddr(s)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("--to: %w", err)
	}
	if _, err := m.ValueForProtocol(ma.P_CIRCUIT); err != nil {
		return peer.AddrInfo{}, fmt.Errorf("--to must be a circuit address (…/p2p/<relay>/p2p-circuit/p2p/<listener>)")
	}
	ai, err := peer.AddrInfoFromP2pAddr(m)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("--to: %w", err)
	}
	return *ai, nil
}

type dialer struct {
	h       host.Host
	rec     *recorder
	target  peer.ID
	size    int
	timeout time.Duration
	bulk    int

	direct      chan struct{} // a direct connection to target appeared
	lost        chan struct{} // a connection to target closed
	connected   time.Time
	firstDirect atomic.Int64 // unix nanos; set from the network notifier

	s       network.Stream
	fr      *ip.FrameReader
	opened  time.Time
	sbytes  int // bytes echoed on the current stream
	seq     uint32
	sent    int
	failed  int
	rtts    map[string][]float64 // by path
	resets  []resetInfo
	downs   []float64 // ms from a stream failure to a working stream
	migrate int
	bulks   []bulkResult
}

type resetInfo struct {
	path string
	age  time.Duration
	err  string
}

type bulkResult struct {
	path   string
	sent   int
	echoed int
	took   time.Duration
	err    string
}

func (d *dialer) run(ctx context.Context, interval time.Duration) {
	if err := d.open(ctx, "initial"); err != nil {
		d.reconnect(ctx, time.Now())
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if d.s == nil {
				d.reconnect(ctx, time.Now())
				continue
			}
			if err := d.ping(); err != nil {
				d.failed++
				d.fail(err)
				d.reconnect(ctx, time.Now())
			}
		case <-d.lost:
			// React to the close itself, as the daemon will, rather than
			// waiting for the next ping to fail.
			if d.s != nil && d.s.Conn().IsClosed() {
				d.fail(errors.New("connection closed"))
				d.reconnect(ctx, time.Now())
			}
		case <-d.direct:
			if d.s != nil && ip.IsRelayed(d.s.Conn()) {
				old := d.s
				if err := d.open(ctx, "migrate to direct"); err == nil {
					old.Close()
					d.migrate++
				}
			}
		case <-ctx.Done():
			if d.s != nil {
				d.s.Close()
			}
			return
		}
	}
}

// open opens a fresh /openaim/msg/1 stream; on success it replaces d.s.
func (d *dialer) open(ctx context.Context, reason string) error {
	start := time.Now()
	sctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	s, err := d.h.NewStream(network.WithAllowLimitedConn(sctx, "openaim msg"), d.target, ip.MsgProtocol)
	if err != nil {
		logf("stream open (%s) failed after %.0f ms: %v", reason, ms(time.Since(start)), err)
		d.rec.write("stream-open", map[string]any{"reason": reason, "ms": ms(time.Since(start)), "error": err.Error()})
		return err
	}
	path := ip.PathOf(s.Conn())
	logf("stream open (%s) over %s in %.0f ms", reason, path, ms(time.Since(start)))
	d.rec.write("stream-open", map[string]any{"reason": reason, "ms": ms(time.Since(start)), "path": path})
	d.s, d.fr, d.opened, d.sbytes = s, ip.NewFrameReader(s), time.Now(), 0
	if d.bulk > 0 {
		d.runBulk()
	}
	return nil
}

// reconnect retries open with backoff until it works or ctx ends, and
// records how long the buddy was unreachable since failedAt.
func (d *dialer) reconnect(ctx context.Context, failedAt time.Time) {
	backoff := 500 * time.Millisecond
	for ctx.Err() == nil {
		if err := d.open(ctx, "reconnect"); err == nil && d.s != nil {
			down := time.Since(failedAt)
			d.downs = append(d.downs, ms(down))
			logf("back after %.0f ms", ms(down))
			d.rec.write("reconnected", map[string]any{"down_ms": ms(down), "path": ip.PathOf(d.s.Conn())})
			return
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (d *dialer) ping() error {
	d.seq++
	d.sent++
	now := time.Now()
	frame := make([]byte, d.size)
	copy(frame, pingMagic)
	binary.BigEndian.PutUint32(frame[4:], d.seq)
	binary.BigEndian.PutUint64(frame[8:], uint64(now.UnixMilli()))
	for i := minPingSize; i < len(frame); i++ {
		frame[i] = byte(i)
	}

	d.s.SetDeadline(now.Add(d.timeout))
	defer d.s.SetDeadline(time.Time{})
	if err := ip.WriteFrame(d.s, frame); err != nil {
		return err
	}
	b, err := d.fr.ReadFrame()
	if err != nil {
		return err
	}
	if !bytes.Equal(b, frame) {
		return errors.New("echo does not match ping")
	}
	rtt := time.Since(now)
	path := ip.PathOf(d.s.Conn())
	d.sbytes += len(b)
	d.rtts[path] = append(d.rtts[path], ms(rtt))
	logf("ping %d over %s: %.1f ms", d.seq, path, ms(rtt))
	d.rec.write("ping", map[string]any{"seq": d.seq, "path": path, "rtt_ms": ms(rtt), "size": d.size, "stream_age_ms": ms(time.Since(d.opened))})
	return nil
}

// fail records the loss of the current stream (a relay reset, usually).
func (d *dialer) fail(err error) {
	path := ip.PathOf(d.s.Conn())
	age := time.Since(d.opened)
	d.resets = append(d.resets, resetInfo{path: path, age: age, err: err.Error()})
	logf("stream over %s lost after %v and %d B echoed: %v", path, age.Round(time.Millisecond), d.sbytes, err)
	d.rec.write("stream-lost", map[string]any{"path": path, "age_ms": ms(age), "bytes": d.sbytes, "error": err.Error()})
	d.s.Reset()
	d.s = nil
}

// runBulk echoes d.bulk bytes through the new stream, 16 frames in flight.
// A failure here is recorded but leaves the stream for ping to discover.
func (d *dialer) runBulk() {
	start := time.Now()
	path := ip.PathOf(d.s.Conn())
	d.s.SetDeadline(start.Add(10 * d.timeout))
	defer d.s.SetDeadline(time.Time{})

	frame := bytes.Repeat([]byte{0xB5}, bulkFrame)
	sent, got, inflight := 0, 0, 0
	var err error
loop:
	for got < d.bulk {
		for sent < d.bulk && inflight < 16 {
			if err = ip.WriteFrame(d.s, frame); err != nil {
				break loop
			}
			sent += len(frame)
			inflight++
		}
		var b []byte
		if b, err = d.fr.ReadFrame(); err != nil {
			break
		}
		if !bytes.Equal(b, frame) {
			err = errors.New("bulk echo mismatch")
			break
		}
		got += len(b)
		inflight--
	}
	took := time.Since(start)
	d.sbytes += got
	r := bulkResult{path: path, sent: sent, echoed: got, took: took}
	if err != nil {
		r.err = err.Error()
	}
	d.bulks = append(d.bulks, r)
	rate := float64(got) / took.Seconds() / 1024
	logf("bulk over %s: %s of %s echoed (%s sent) in %.1f ms (%.0f KiB/s) %s", path, ip.FormatBytes(int64(got)), ip.FormatBytes(int64(d.bulk)), ip.FormatBytes(int64(sent)), ms(took), rate, r.err)
	d.rec.write("bulk", map[string]any{"path": path, "want": d.bulk, "sent": sent, "echoed": got, "ms": ms(took), "error": r.err})
}

func (d *dialer) printSummary(hp *hpTracer) {
	fmt.Println("\nsummary")
	fmt.Printf("  pings: %d sent, %d failed (a ping fails when it is the first to hit a reset)\n", d.sent, d.failed)
	for path, v := range d.rtts {
		fmt.Printf("  rtt over %-16s %s\n", path+":", stats(v))
	}
	fmt.Printf("  stream losses: %d", len(d.resets))
	for _, r := range d.resets {
		fmt.Printf("\n    over %s after %v: %s", r.path, r.age.Round(time.Second), shortErr(r.err))
	}
	fmt.Println()
	if len(d.downs) > 0 {
		fmt.Printf("  time to working stream after a loss: %s\n", stats(d.downs))
	}
	for _, b := range d.bulks {
		fmt.Printf("  bulk over %s: %s echoed (%s sent) in %.1f ms %s\n", b.path, ip.FormatBytes(int64(b.echoed)), ip.FormatBytes(int64(b.sent)), ms(b.took), shortErr(b.err))
	}
	if hp != nil {
		fmt.Printf("  hole punching: %s\n", hp.summary())
	} else {
		fmt.Println("  hole punching: disabled")
	}
	if fd := d.firstDirect.Load(); fd != 0 {
		fmt.Printf("  first direct connection %.0f ms after the relayed connect; %d stream migration(s)\n", ms(time.Unix(0, fd).Sub(d.connected)), d.migrate)
	}
}

// shortErr trims libp2p's long nested reset errors for the summary.
func shortErr(s string) string {
	if len(s) > 70 {
		return s[:70] + "…"
	}
	return s
}

func notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
