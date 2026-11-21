// Command p2pspike is the M0 libp2p relay spike (design §6.1, §14). It runs a
// circuit relay v2 with configurable limits, a listener that is reachable only
// through that relay, and a dialer that pings the listener over
// /openaim/msg/1 and records relay resets and DCUtR hole-punch outcomes.
//
// See docs/m0-libp2p-relay-spike.md for the experiments.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"

	"github.com/aghman/openaim/internal/transport/ip"
)

const usage = `p2pspike: M0 libp2p relay spike

Usage:
  p2pspike relay  [flags]                  run a circuit relay v2 (on a public host)
  p2pspike listen --relay <relay addr>     reserve a slot on the relay and echo pings
  p2pspike dial   --to <circuit addr>      ping a listener through the relay

Run "p2pspike <command> -h" for a command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "relay":
		err = runRelay(ctx, args)
	case "listen":
		err = runListen(ctx, args)
	case "dial":
		err = runDial(ctx, args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "p2pspike:", err)
		os.Exit(1)
	}
}

// hostFlags are shared by listen and dial.
type hostFlags struct {
	key         string
	port        int
	noHolePunch bool
	upnp        bool
	jsonl       string
}

func (f *hostFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.key, "key", "", "network key file (default: a fresh key every run, as the design wants)")
	fs.IntVar(&f.port, "port", 0, "TCP and UDP port to listen on (0 = random)")
	fs.BoolVar(&f.noHolePunch, "no-holepunch", false, "disable DCUtR, so traffic stays on the relay")
	fs.BoolVar(&f.upnp, "upnp", false, "try UPnP / NAT-PMP port mapping (off by default: it hides the NAT behaviour we want to measure)")
	fs.StringVar(&f.jsonl, "jsonl", "", "append event records to this JSONL file")
}

func (f *hostFlags) newHost(hp *hpTracer, gater connmgr.ConnectionGater) (host.Host, error) {
	o := ip.HostOptions{
		Gater:        gater,
		Listen:       ip.DefaultListen(f.port),
		HolePunching: !f.noHolePunch,
		NATPortMap:   f.upnp,
	}
	if hp != nil {
		o.Tracer = hp
	}
	if f.key != "" {
		k, err := ip.LoadOrCreateKey(f.key)
		if err != nil {
			return nil, err
		}
		o.Key = k
	}
	return ip.NewHost(o)
}

// logf prints a timestamped line to stdout.
func logf(format string, args ...any) {
	fmt.Printf("%s %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func shortID(s string) string {
	if len(s) > 12 {
		return "…" + s[len(s)-8:]
	}
	return s
}

// recorder appends one JSON object per line, for later analysis of M0 runs.
type recorder struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

func openRecorder(path string) (*recorder, error) {
	if path == "" {
		return &recorder{}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &recorder{f: f, enc: json.NewEncoder(f)}, nil
}

// write records kind plus fields, stamped with the current time.
func (r *recorder) write(kind string, fields map[string]any) {
	if r.enc == nil {
		return
	}
	m := map[string]any{"kind": kind, "at": time.Now().UTC().Format(time.RFC3339Nano)}
	for k, v := range fields {
		m[k] = v
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.enc.Encode(m)
}

func (r *recorder) Close() error {
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}

// hpTracer logs and records DCUtR events, and remembers the outcome.
type hpTracer struct {
	rec *recorder

	mu       sync.Mutex
	attempts int
	ends     []holepunch.EndHolePunchEvt
	onEnd    func(holepunch.EndHolePunchEvt)
}

func (t *hpTracer) Trace(e *holepunch.Event) {
	remote := shortID(e.Remote.String())
	switch v := e.Evt.(type) {
	case *holepunch.StartHolePunchEvt:
		logf("holepunch: start with %s, rtt %.0f ms via relay, their addrs %v", remote, ms(v.RTT), v.RemoteAddrs)
		t.rec.write("holepunch-start", map[string]any{"remote": e.Remote.String(), "relay_rtt_ms": ms(v.RTT), "remote_addrs": v.RemoteAddrs})
	case *holepunch.HolePunchAttemptEvt:
		t.mu.Lock()
		t.attempts++
		t.mu.Unlock()
		logf("holepunch: attempt %d with %s", v.Attempt, remote)
		t.rec.write("holepunch-attempt", map[string]any{"remote": e.Remote.String(), "attempt": v.Attempt})
	case *holepunch.EndHolePunchEvt:
		logf("holepunch: end with %s: success=%v after %.0f ms %s", remote, v.Success, ms(v.EllapsedTime), v.Error)
		t.rec.write("holepunch-end", map[string]any{"remote": e.Remote.String(), "success": v.Success, "elapsed_ms": ms(v.EllapsedTime), "error": v.Error})
		t.mu.Lock()
		t.ends = append(t.ends, *v)
		f := t.onEnd
		t.mu.Unlock()
		if f != nil {
			f(*v)
		}
	case *holepunch.DirectDialEvt:
		logf("holepunch: direct dial to %s: success=%v after %.0f ms %s", remote, v.Success, ms(v.EllapsedTime), v.Error)
		t.rec.write("direct-dial", map[string]any{"remote": e.Remote.String(), "success": v.Success, "elapsed_ms": ms(v.EllapsedTime), "error": v.Error})
	case *holepunch.ProtocolErrorEvt:
		logf("holepunch: protocol error with %s: %s", remote, v.Error)
		t.rec.write("holepunch-error", map[string]any{"remote": e.Remote.String(), "error": v.Error})
	}
}

func (t *hpTracer) summary() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.ends) == 0 {
		return fmt.Sprintf("no hole punch completed (%d attempts seen)", t.attempts)
	}
	ok := 0
	for _, e := range t.ends {
		if e.Success {
			ok++
		}
	}
	return fmt.Sprintf("%d of %d hole punches succeeded (%d attempts)", ok, len(t.ends), t.attempts)
}

// watchConns logs and records every connection opening and closing, and
// calls onUp / onDown (if set) for each.
func watchConns(h host.Host, rec *recorder, onUp, onDown func(network.Conn)) {
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			logf("conn up:   %s %s %s", shortID(c.RemotePeer().String()), ip.PathOf(c), c.RemoteMultiaddr())
			rec.write("conn-up", map[string]any{"peer": c.RemotePeer().String(), "path": ip.PathOf(c), "addr": c.RemoteMultiaddr().String(), "dir": c.Stat().Direction.String()})
			if onUp != nil {
				onUp(c)
			}
		},
		DisconnectedF: func(_ network.Network, c network.Conn) {
			age := time.Since(c.Stat().Opened)
			logf("conn down: %s %s after %v", shortID(c.RemotePeer().String()), ip.PathOf(c), age.Round(time.Millisecond))
			rec.write("conn-down", map[string]any{"peer": c.RemotePeer().String(), "path": ip.PathOf(c), "age_ms": ms(age)})
			if onDown != nil {
				onDown(c)
			}
		},
	})
}

// byteSize is a flag value accepting 1000, 128KiB, 16MiB, ….
type byteSize int64

func (b *byteSize) String() string { return ip.FormatBytes(int64(*b)) }

func (b *byteSize) Set(s string) error {
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("bad size %q (use e.g. 4096, 128KiB, 16MiB)", s)
	}
	*b = byteSize(n * mult)
	return nil
}

func stats(v []float64) string {
	if len(v) == 0 {
		return "n=0"
	}
	v = append([]float64(nil), v...)
	sort.Float64s(v)
	pct := func(p float64) float64 { return v[int(p*float64(len(v)-1)+0.5)] }
	return fmt.Sprintf("min %.1f  median %.1f  p90 %.1f  max %.1f ms  (n=%d)", v[0], pct(0.5), pct(0.9), v[len(v)-1], len(v))
}
