package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	pb "github.com/aghman/openaim/internal/meshpb"
	"github.com/aghman/openaim/internal/transport/mesh"
)

// Airtime courtesy limits for a shared mesh. A 200-byte LongFast frame is ~2 s
// on air, before rebroadcasts.
const (
	minInterval = 5 * time.Second
	maxCount    = 100
)

type txRecord struct {
	Kind      string       `json:"kind"` // "tx"
	At        time.Time    `json:"at"`
	Seq       uint32       `json:"seq"`
	ID        string       `json:"id"`
	To        string       `json:"to"`
	Channel   uint32       `json:"channel"`
	Size      int          `json:"size"`
	WantAck   bool         `json:"want_ack"`
	HopLimit  uint32       `json:"hop_limit"` // as requested; 0 = radio.hop_limit
	QueuedMS  *float64     `json:"queued_ms,omitempty"`
	QueueRes  *int32       `json:"queue_res,omitempty"`
	Ack       string       `json:"ack"`
	AckFrom   string       `json:"ack_from,omitempty"`
	Reason    string       `json:"reason,omitempty"`
	AckMS     *float64     `json:"ack_ms,omitempty"`
	EchoRTTMS *float64     `json:"echo_rtt_ms,omitempty"`
	Radio     radioContext `json:"radio"`
}

func runSend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	portnum := portNumFlag(fs)
	to := fs.String("to", "", "destination: broadcast, !hex node ID, or decimal (required)")
	channel := fs.Uint("channel", 0, "channel index")
	size := fs.Int("size", 64, fmt.Sprintf("payload bytes (%d–%d)", minPayload, pb.Constants_DATA_PAYLOAD_LEN))
	count := fs.Int("count", 3, fmt.Sprintf("packets to send (max %d)", maxCount))
	interval := fs.Duration("interval", 30*time.Second, fmt.Sprintf("time between sends (min %v)", minInterval))
	wantAck := fs.Bool("want-ack", true, "set want_ack (firmware retries; DMs get a destination ack)")
	hopLimit := hopLimitFlag(fs, "the test packets")
	ackTimeout := fs.Duration("ack-timeout", 90*time.Second, "how long to wait for an ack/echo per packet")
	expectEcho := fs.Bool("expect-echo", false, "wait for an echo from a 'meshspike listen --echo' peer and report round-trip time")
	logs := fs.Bool("logs", false, "print firmware log lines")
	jsonl := fs.String("jsonl", "", "append per-packet records to this JSONL file")
	fs.Parse(args)

	if *to == "" {
		return fmt.Errorf("--to is required (use --to broadcast to broadcast)")
	}
	dest, err := parseNode(*to)
	if err != nil {
		return err
	}
	if err := checkPortNum(*portnum); err != nil {
		return err
	}
	if err := checkHopLimit(*hopLimit); err != nil {
		return err
	}
	if *size < minPayload || *size > int(pb.Constants_DATA_PAYLOAD_LEN) {
		return fmt.Errorf("--size must be %d–%d", minPayload, pb.Constants_DATA_PAYLOAD_LEN)
	}
	if *count < 1 || *count > maxCount {
		return fmt.Errorf("--count must be 1–%d", maxCount)
	}
	if *interval < minInterval {
		fmt.Fprintf(os.Stderr, "raising --interval to %v to be kind to the mesh\n", minInterval)
		*interval = minInterval
	}
	if *expectEcho && dest == mesh.BroadcastAddr {
		return fmt.Errorf("--expect-echo needs a specific --to node (echo peers don't answer broadcasts)")
	}

	rec, err := openRecorder(*jsonl)
	if err != nil {
		return err
	}
	defer rec.Close()

	c, err := cf.connect(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	s := c.Snapshot()
	rc := contextOf(&s)
	if s.Self().GetUser().GetIsLicensed() {
		fmt.Fprintln(os.Stderr, "warning: radio is in licensed (ham) mode")
	}
	if dest != mesh.BroadcastAddr {
		if n, ok := s.Nodes[dest]; !ok {
			fmt.Fprintf(os.Stderr, "warning: %s is not in this radio's NodeDB\n", nodeID(dest))
		} else if len(n.GetUser().GetPublicKey()) != 32 {
			fmt.Fprintf(os.Stderr, "note: no public key for %s, so this DM won't use PKC\n", nodeID(dest))
		}
	}

	echoes := newEchoWaiter()
	go pumpEvents(c, uint32(*portnum), dest, echoes, *logs)

	var results []txRecord
	for i := 0; i < *count; i++ {
		if ctx.Err() != nil {
			break
		}
		seq := uint32(i)
		echoCh := echoes.expect(seq)
		sent := time.Now()
		p, err := c.Send(mesh.SendRequest{
			To: dest, Channel: uint32(*channel), PortNum: pb.PortNum(*portnum),
			Payload: encodePayload(seq, *size, sent), WantAck: *wantAck, HopLimit: uint32(*hopLimit),
		})
		if err != nil {
			return fmt.Errorf("send seq %d: %w", seq, err)
		}

		wctx, cancel := context.WithTimeout(ctx, *ackTimeout)
		var echoAt time.Time
		if *wantAck {
			p.Wait(wctx)
		} else {
			select {
			case <-p.Queued():
			case <-p.Done(): // e.g. TOO_LARGE NAK without a QueueStatus
			case <-wctx.Done():
			}
		}
		if *expectEcho {
			select {
			case echoAt = <-echoCh:
			case <-wctx.Done():
			}
		}
		cancel()
		c.Forget(p)
		echoes.forget(seq)

		r := toRecord(p.Result(), seq, dest, uint32(*channel), *size, *wantAck, uint32(*hopLimit), echoAt, rc)
		results = append(results, r)
		rec.write(r)
		fmt.Println(formatTx(r))

		if i < *count-1 {
			select {
			case <-time.After(time.Until(sent.Add(*interval))):
			case <-ctx.Done():
			}
		}
	}
	printSummary(results)
	return nil
}

func toRecord(res mesh.Result, seq, dest, channel uint32, size int, wantAck bool, hopLimit uint32, echoAt time.Time, rc radioContext) txRecord {
	r := txRecord{
		Kind: "tx", At: res.SentAt, Seq: seq, ID: fmt.Sprintf("%08x", res.ID), To: nodeID(dest),
		Channel: channel, Size: size, WantAck: wantAck, HopLimit: hopLimit, Ack: res.Ack.String(), Radio: rc,
	}
	if !res.QueuedAt.IsZero() {
		q, qr := ms(res.QueuedAt.Sub(res.SentAt)), res.QueueRes
		r.QueuedMS, r.QueueRes = &q, &qr
	}
	if !res.AckAt.IsZero() {
		a := ms(res.AckAt.Sub(res.SentAt))
		r.AckMS, r.AckFrom = &a, nodeID(res.AckFrom)
		if res.Reason != pb.Routing_NONE {
			r.Reason = res.Reason.String()
		}
	}
	if !echoAt.IsZero() {
		e := ms(echoAt.Sub(res.SentAt))
		r.EchoRTTMS = &e
	}
	return r
}

func formatTx(r txRecord) string {
	line := fmt.Sprintf("tx   seq %-3d id %s %3dB → %s", r.Seq, r.ID, r.Size, r.To)
	if r.QueuedMS != nil {
		line += fmt.Sprintf("  queued %.0fms (res %d)", *r.QueuedMS, *r.QueueRes)
	} else {
		line += "  not queued"
	}
	switch {
	case r.AckMS != nil && r.Reason != "":
		line += fmt.Sprintf("  NAK %s from %s after %.0fms", r.Reason, r.AckFrom, *r.AckMS)
	case r.AckMS != nil:
		line += fmt.Sprintf("  %s from %s after %.0fms", r.Ack, r.AckFrom, *r.AckMS)
	case r.WantAck:
		line += "  no ack"
	}
	if r.EchoRTTMS != nil {
		line += fmt.Sprintf("  echo RTT %.0fms", *r.EchoRTTMS)
	}
	return line
}

func printSummary(rs []txRecord) {
	if len(rs) == 0 {
		return
	}
	var queued int
	kinds := map[string]int{}
	reasons := map[string]int{}
	var ackMS, echoMS []float64
	for _, r := range rs {
		if r.QueuedMS != nil && *r.QueueRes == 0 {
			queued++
		}
		kinds[r.Ack]++
		if r.Reason != "" {
			reasons[r.Reason]++
		}
		if r.AckMS != nil && r.Reason == "" {
			ackMS = append(ackMS, *r.AckMS)
		}
		if r.EchoRTTMS != nil {
			echoMS = append(echoMS, *r.EchoRTTMS)
		}
	}
	fmt.Printf("\nsummary: %d sent, %d queued OK, acks %v", len(rs), queued, kinds)
	if len(reasons) > 0 {
		fmt.Printf(", NAK reasons %v", reasons)
	}
	fmt.Println()
	if len(ackMS) > 0 {
		fmt.Printf("ack latency ms: %s\n", stats(ackMS))
	}
	if len(echoMS) > 0 {
		fmt.Printf("echo RTT ms:    %s\n", stats(echoMS))
	}
}

func stats(v []float64) string {
	sort.Float64s(v)
	pct := func(p float64) float64 { return v[int(p*float64(len(v)-1)+0.5)] }
	return fmt.Sprintf("min %.0f  median %.0f  p90 %.0f  max %.0f  (n=%d)", v[0], pct(0.5), pct(0.9), v[len(v)-1], len(v))
}

// echoWaiter routes echo replies to the send loop by sequence number.
type echoWaiter struct {
	mu sync.Mutex
	m  map[uint32]chan time.Time
}

func newEchoWaiter() *echoWaiter { return &echoWaiter{m: map[uint32]chan time.Time{}} }

func (w *echoWaiter) expect(seq uint32) <-chan time.Time {
	ch := make(chan time.Time, 1)
	w.mu.Lock()
	w.m[seq] = ch
	w.mu.Unlock()
	return ch
}

func (w *echoWaiter) forget(seq uint32) {
	w.mu.Lock()
	delete(w.m, seq)
	w.mu.Unlock()
}

func (w *echoWaiter) deliver(seq uint32, at time.Time) {
	w.mu.Lock()
	ch := w.m[seq]
	w.mu.Unlock()
	if ch != nil {
		select {
		case ch <- at:
		default:
		}
	}
}

func pumpEvents(c *mesh.Client, portnum, peer uint32, echoes *echoWaiter, logs bool) {
	for e := range c.Events() {
		switch e := e.(type) {
		case mesh.LogEvent:
			if logs {
				fmt.Fprintf(os.Stderr, "log  %s\n", e.Line)
			}
		case mesh.PacketEvent:
			d := e.Packet.GetDecoded()
			if d == nil || uint32(d.GetPortnum()) != portnum || e.Packet.GetFrom() != peer {
				continue
			}
			if tp, err := decodePayload(d.GetPayload()); err == nil && tp.Echo {
				echoes.deliver(tp.Seq, e.At)
			}
		}
	}
}
