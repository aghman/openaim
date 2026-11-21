package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	pb "github.com/aghman/openaim/internal/meshpb"
	"github.com/aghman/openaim/internal/transport/mesh"
)

type outcome int

const (
	accepted outcome = iota
	tooLarge
	rejected // some other refusal (queue full, no channel, …)
)

func (o outcome) String() string {
	return [...]string{"accepted", "too-large", "rejected"}[o]
}

type probeStep struct {
	Kind    string       `json:"kind"` // "probe"
	At      time.Time    `json:"at"`
	To      string       `json:"to"`
	Channel uint32       `json:"channel"`
	Size    int          `json:"size"`
	Outcome string       `json:"outcome"`
	Detail  string       `json:"detail,omitempty"`
	Radio   radioContext `json:"radio"`
}

// errNoAnswer means the radio neither queued nor refused a probe.
var errNoAnswer = errors.New("radio gave no queue status or routing response")

// searchMaxPayload binary-searches the largest size in [lo, hi] for which try
// reports accepted. It assumes acceptance is monotone in size. It returns 0 if
// even lo is too large.
func searchMaxPayload(ctx context.Context, lo, hi int, try func(ctx context.Context, size int) (outcome, string, error)) (int, error) {
	best := 0
	for lo <= hi {
		if err := ctx.Err(); err != nil {
			return best, err
		}
		mid := lo + (hi-lo+1)/2 // bias upwards: the common case is "fits"
		o, detail, err := try(ctx, mid)
		if err != nil {
			return best, err
		}
		switch o {
		case accepted:
			best, lo = mid, mid+1
		case tooLarge:
			hi = mid - 1
		default:
			return best, fmt.Errorf("probe at %d bytes refused for a reason other than size: %s", mid, detail)
		}
	}
	return best, nil
}

// probeOnce sends one probe without want_ack (so accepted probes cost one
// transmission and no retries) and classifies the radio's reaction.
// settle bounds the wait for any verdict; grace is how long to keep listening
// for a late NAK after the radio has queued the probe.
func probeOnce(ctx context.Context, c *mesh.Client, dest, channel uint32, portnum pb.PortNum, size int, settle, grace time.Duration) (outcome, string, error) {
	p, err := c.Send(mesh.SendRequest{To: dest, Channel: channel, PortNum: portnum, Payload: encodePayload(0, size, time.Now())})
	if err != nil {
		return 0, "", err
	}
	defer c.Forget(p)

	wctx, cancel := context.WithTimeout(ctx, settle)
	defer cancel()
	select {
	case <-p.Done():
	case <-p.Queued():
		// A size failure can be reported just after queueing (the firmware
		// encrypts after accepting the packet), so give it a moment.
		select {
		case <-p.Done():
		case <-time.After(grace):
		case <-ctx.Done():
		}
	case <-wctx.Done():
		if ctx.Err() != nil {
			return 0, "", ctx.Err()
		}
		return 0, "", fmt.Errorf("%d bytes: %w", size, errNoAnswer)
	}

	r := p.Result()
	switch {
	case r.Ack == mesh.AckNak && r.Reason == pb.Routing_TOO_LARGE:
		return tooLarge, r.Reason.String(), nil
	case r.Ack == mesh.AckNak:
		return rejected, r.Reason.String(), nil
	case !r.QueuedAt.IsZero() && r.QueueRes != 0:
		return rejected, fmt.Sprintf("queue res %d", r.QueueRes), nil
	default:
		return accepted, "", nil
	}
}

func runProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe-size", flag.ExitOnError)
	var cf connFlags
	cf.register(fs)
	portnum := portNumFlag(fs)
	to := fs.String("to", "", "destination: broadcast, !hex node ID, or decimal (required)")
	channel := fs.Uint("channel", 0, "channel index")
	lo := fs.Int("min", 150, "smallest size to consider")
	hi := fs.Int("max", int(pb.Constants_DATA_PAYLOAD_LEN), "largest size to consider")
	interval := fs.Duration("interval", 15*time.Second, fmt.Sprintf("wait after each probe that went on air (min %v)", minInterval))
	settle := fs.Duration("settle", 10*time.Second, "how long to wait for the radio's verdict on each probe")
	grace := fs.Duration("nak-grace", 2*time.Second, "after a probe is queued, how long to keep waiting for a late TOO_LARGE")
	jsonl := fs.String("jsonl", "", "append probe records to this JSONL file")
	fs.Parse(args)

	if *to == "" {
		return fmt.Errorf("--to is required (use --to broadcast to probe the broadcast path)")
	}
	dest, err := parseNode(*to)
	if err != nil {
		return err
	}
	if err := checkPortNum(*portnum); err != nil {
		return err
	}
	if *lo < minPayload || *hi > int(pb.Constants_DATA_PAYLOAD_LEN) || *lo > *hi {
		return fmt.Errorf("need %d ≤ --min ≤ --max ≤ %d", minPayload, pb.Constants_DATA_PAYLOAD_LEN)
	}
	if *interval < minInterval {
		*interval = minInterval
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
	go func() {
		for range c.Events() { // drain; probe results come via Pending
		}
	}()

	route := "broadcast"
	if dest != mesh.BroadcastAddr {
		route = "DM"
		if n := s.Nodes[dest]; len(n.GetUser().GetPublicKey()) == 32 {
			route = "DM (PKC: destination public key known)"
		} else {
			route = "DM (no public key known: channel encryption)"
		}
	}
	fmt.Fprintf(os.Stderr, "probing %s to %s on channel %d, sizes %d–%d (each accepted probe transmits once)\n", route, nodeID(dest), *channel, *lo, *hi)

	try := func(ctx context.Context, size int) (outcome, string, error) {
		o, detail, err := probeOnce(ctx, c, dest, uint32(*channel), pb.PortNum(*portnum), size, *settle, *grace)
		if err != nil {
			return o, detail, err
		}
		step := probeStep{Kind: "probe", At: time.Now(), To: nodeID(dest), Channel: uint32(*channel), Size: size, Outcome: o.String(), Detail: detail, Radio: rc}
		rec.write(step)
		fmt.Printf("probe %3dB → %s %s\n", size, o, detail)
		if o == accepted {
			select {
			case <-time.After(*interval):
			case <-ctx.Done():
			}
		}
		return o, detail, nil
	}
	best, err := searchMaxPayload(ctx, *lo, *hi, try)
	if err != nil {
		return err
	}
	if best == 0 {
		fmt.Printf("\neven %d bytes was too large on this route; retry with a lower --min\n", *lo)
		return nil
	}
	fmt.Printf("\nlargest accepted payload on this route: %d bytes", best)
	if best == *hi {
		fmt.Printf(" (the --max bound; the real limit may be higher)")
	}
	fmt.Println()
	return nil
}
