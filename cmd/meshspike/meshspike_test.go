package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/aghman/openaim/internal/meshpb"
	"github.com/aghman/openaim/internal/transport/mesh"
	"github.com/aghman/openaim/internal/transport/mesh/meshtest"
)

func TestPayloadRoundTrip(t *testing.T) {
	now := time.UnixMilli(time.Now().UnixMilli())
	b := encodePayload(7, 200, now)
	if len(b) != 200 {
		t.Fatalf("len = %d", len(b))
	}
	p, err := decodePayload(b)
	if err != nil || p.Seq != 7 || !p.SentAt.Equal(now) || p.Echo {
		t.Fatalf("got %+v, %v", p, err)
	}
	e, err := decodePayload(echoOf(b))
	if err != nil || !e.Echo || e.Seq != 7 {
		t.Fatalf("echo: got %+v, %v", e, err)
	}
	b[150] ^= 0xFF
	if _, err := decodePayload(b); err == nil {
		t.Fatal("corrupted fill not detected")
	}
	if _, err := decodePayload([]byte("hello, not ours!")); err == nil {
		t.Fatal("foreign payload accepted")
	}
}

func TestParseNode(t *testing.T) {
	for in, want := range map[string]uint32{"broadcast": mesh.BroadcastAddr, "!0a0b0c0d": 0x0a0b0c0d, "168496141": 168496141} {
		got, err := parseNode(in)
		if err != nil || got != want {
			t.Errorf("parseNode(%q) = %x, %v; want %x", in, got, err, want)
		}
	}
	if _, err := parseNode("!zz"); err == nil {
		t.Error("bad hex accepted")
	}
}

func TestSearchMaxPayload(t *testing.T) {
	for _, limit := range []int{150, 151, 199, 221, 232, 233} {
		var tries int
		got, err := searchMaxPayload(context.Background(), 150, 233, func(_ context.Context, size int) (outcome, string, error) {
			tries++
			if size <= limit {
				return accepted, "", nil
			}
			return tooLarge, "", nil
		})
		if err != nil || got != limit {
			t.Errorf("limit %d: got %d, %v", limit, got, err)
		}
		if tries > 8 {
			t.Errorf("limit %d: %d probes, want ≤ 8", limit, tries)
		}
	}
	got, _ := searchMaxPayload(context.Background(), 150, 233, func(context.Context, int) (outcome, string, error) { return tooLarge, "", nil })
	if got != 0 {
		t.Errorf("all too large: got %d, want 0", got)
	}
}

// TestProbeAgainstFakeRadio runs the real probe path against the fake radio,
// which rejects broadcasts over 233 B and PKC DMs over 221 B.
func TestProbeAgainstFakeRadio(t *testing.T) {
	r := meshtest.New()
	c := mesh.NewClient(r.Start())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		for range c.Events() {
		}
	}()

	for _, tc := range []struct {
		dest uint32
		want int
	}{{mesh.BroadcastAddr, 233}, {r.Peers[0], 221}} {
		got, err := searchMaxPayload(ctx, 150, 233, func(ctx context.Context, size int) (outcome, string, error) {
			return probeOnce(ctx, c, tc.dest, 0, pb.PortNum_PRIVATE_APP, size, time.Second, 20*time.Millisecond)
		})
		if err != nil || got != tc.want {
			t.Errorf("%s: got %d, %v; want %d", nodeID(tc.dest), got, err, tc.want)
		}
	}
}

func TestInfoWarnsAboutBlockers(t *testing.T) {
	r := meshtest.New()
	r.Lora.TxEnabled = false
	c := mesh.NewClient(r.Start())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := c.Snapshot()
	var out bytes.Buffer
	printInfo(&out, &s, true)
	for _, want := range []string{"LONG_FAST", "TX is disabled", "default (publicly known)", "!0a0b0c0d"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("info output missing %q:\n%s", want, out.String())
		}
	}
}
