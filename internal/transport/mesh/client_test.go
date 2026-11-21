package mesh_test

import (
	"context"
	"testing"
	"time"

	pb "github.com/aghman/openaim/internal/meshpb"
	"github.com/aghman/openaim/internal/transport/mesh"
	"github.com/aghman/openaim/internal/transport/mesh/meshtest"
)

func startClient(t *testing.T, r *meshtest.FakeRadio) *mesh.Client {
	t.Helper()
	c := mesh.NewClient(r.Start())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func waitResult(t *testing.T, p *mesh.Pending) mesh.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-p.Done():
	case <-ctx.Done():
		t.Fatalf("no routing response for packet %08x", p.ID)
	}
	return p.Result()
}

func TestHandshakeSnapshot(t *testing.T) {
	r := meshtest.New()
	c := startClient(t, r)
	s := c.Snapshot()
	if s.MyNodeNum() != r.MyNode {
		t.Errorf("MyNodeNum = %08x, want %08x", s.MyNodeNum(), r.MyNode)
	}
	if s.Self() == nil {
		t.Error("Self() is nil")
	}
	if len(s.Nodes) != 1+len(r.Peers) {
		t.Errorf("got %d nodes, want %d", len(s.Nodes), 1+len(r.Peers))
	}
	if s.LoRa().GetModemPreset() != pb.Config_LoRaConfig_LONG_FAST {
		t.Errorf("LoRa preset = %v", s.LoRa().GetModemPreset())
	}
	if s.Metadata.GetFirmwareVersion() == "" || s.ConfigDoneAt.IsZero() {
		t.Error("metadata or ConfigDoneAt missing")
	}
}

func TestSendAckKinds(t *testing.T) {
	r := meshtest.New()
	r.Silent[0x22222222] = true
	r.Peers = append(r.Peers, 0x22222222)
	c := startClient(t, r)

	cases := []struct {
		name   string
		to     uint32
		size   int
		want   mesh.AckKind
		reason pb.Routing_Error
		queued bool
	}{
		{"dm acked by destination", r.Peers[0], 100, mesh.AckDestination, pb.Routing_NONE, true},
		{"broadcast implicit ack", mesh.BroadcastAddr, 100, mesh.AckImplicit, pb.Routing_NONE, true},
		{"unreachable dm", 0x22222222, 100, mesh.AckNak, pb.Routing_MAX_RETRANSMIT, true},
		{"dm too large for PKC", r.Peers[0], 225, mesh.AckNak, pb.Routing_TOO_LARGE, false},
		{"broadcast fits at 233", mesh.BroadcastAddr, 233, mesh.AckImplicit, pb.Routing_NONE, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := c.Send(mesh.SendRequest{
				To: tc.to, PortNum: pb.PortNum_PRIVATE_APP, Payload: make([]byte, tc.size), WantAck: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Forget(p)
			res := waitResult(t, p)
			if res.Ack != tc.want || res.Reason != tc.reason {
				t.Errorf("got %v/%v, want %v/%v", res.Ack, res.Reason, tc.want, tc.reason)
			}
			if got := !res.QueuedAt.IsZero(); got != tc.queued {
				t.Errorf("queued = %v, want %v", got, tc.queued)
			}
		})
	}
}

func TestReceivedPacketsAndDebugText(t *testing.T) {
	r := meshtest.New()
	c := startClient(t, r)

	r.WriteDebug("DEBUG | radio log line\n")
	r.Deliver(&pb.MeshPacket{
		From: r.Peers[0], To: r.MyNode, Id: 42,
		PayloadVariant: &pb.MeshPacket_Decoded{Decoded: &pb.Data{Portnum: pb.PortNum_PRIVATE_APP, Payload: []byte("hi")}},
	})

	var gotLog, gotPkt bool
	timeout := time.After(5 * time.Second)
	for !gotLog || !gotPkt {
		select {
		case e := <-c.Events():
			switch e := e.(type) {
			case mesh.LogEvent:
				gotLog = gotLog || e.Line == "DEBUG | radio log line"
			case mesh.PacketEvent:
				gotPkt = gotPkt || string(e.Packet.GetDecoded().GetPayload()) == "hi"
			}
		case <-timeout:
			t.Fatalf("log=%v packet=%v", gotLog, gotPkt)
		}
	}
}
