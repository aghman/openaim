package router

import (
	"os"
	"slices"
	"testing"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// TestAckDuringSendEventOrder reproduces a race found while wiring the
// daemon (openaim-nxb.32): on a fast link the buddy's ACK can arrive, and be
// applied, while Transport.Send is still returning. send then records the
// attempt and emits Sent, after HandleAck already emitted Acked, so clients
// see the message go back from acked to sent. The daemon drops a Sent event
// for a row that is no longer queued; the router should not emit it.
//
// It fails today, so it runs only with OPENAIM_KNOWN_BUGS=1.
func TestAckDuringSendEventOrder(t *testing.T) {
	if os.Getenv("OPENAIM_KNOWN_BUGS") == "" {
		t.Skip("known router bug (Sent emitted after Acked); set OPENAIM_KNOWN_BUGS=1 to run")
	}
	h := newHarness(t, nil)
	h.routeUp()
	var acked bool
	h.tr.deliver = func(_ Route, frames [][]byte) {
		if acked {
			return
		}
		acked = true
		hd, err := frame.ParseHeader(frames[0])
		if err != nil {
			t.Error(err)
			return
		}
		// The ACK arrives before Send returns.
		if _, _, err := h.r.HandleAck(bg, h.buddy, &pb.Ack{Entries: []*pb.AckEntry{{MsgId: hd.MsgID[:], Have: 1}}}); err != nil {
			t.Error(err)
		}
	}
	m := h.enqueue(10)
	h.settle()
	if o := h.outgoing(m.ID); o.State != store.Acked {
		t.Fatalf("state %s", o.State)
	}
	if st := h.events.states(m.ID); !slices.Equal(st, []DeliveryState{Acked}) && !slices.Equal(st, []DeliveryState{Sent, Acked}) {
		t.Fatalf("events %v: Sent came after Acked", st)
	}
}
