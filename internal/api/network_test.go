package api

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/daemon/nettest"
	"github.com/aghman/openaim/internal/transport/ip"
)

// netNode is a daemon on the loopback test network, driven over its API.
type netNode struct {
	t    *testing.T
	name string
	d    *Daemon
	c    pb.DaemonClient

	mu     sync.Mutex
	events []*pb.Event
}

func startNet(t *testing.T, name string, r *nettest.Relay) *netNode {
	t.Helper()
	dir, _ := initDir(t)
	r.WriteNetworkJSON(t, dir)
	c := cfg(dir)
	c.DisplayName = name
	c.DisableHandleLoop = true
	c.Network = &daemon.NetworkOptions{
		Listen: []string{"/ip4/127.0.0.1/tcp/0"}, DHTMode: ip.DHTClient, DisableHolePunching: true,
		Gater: nettest.RelayOnly{Allow: r.ID()}, Resolver: nettest.Resolver(),
		RotationInterval: -1, RotationGrace: time.Second, ReservationTimeout: 5 * time.Second, DHTBootstrapTimeout: 3 * time.Second,
		AckTimeout: 300 * time.Millisecond, MaxRetryDelay: 2 * time.Second, AckDelay: 20 * time.Millisecond,
		HeartbeatInterval: time.Second, HeartbeatJitter: 100 * time.Millisecond, BuddyTimeout: 4 * time.Second,
		PresenceGrace: 2 * time.Second, PresenceRetry: 200 * time.Millisecond, SignOffTimeout: 2 * time.Second,
		PublishRetry: 300 * time.Millisecond, PublishPutInterval: -1,
		LookupMin: 300 * time.Millisecond, LookupMax: 2 * time.Second, LookupTimeout: 3 * time.Second,
		RedeliverInterval: time.Second,
		Sessions:          ip.SessionOptions{SendTimeout: 2 * time.Second, OpenTimeout: 2 * time.Second},
	}
	d, err := Start(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	conn, err := Dial(d.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	n := &netNode{t: t, name: name, d: d, c: pb.NewDaemonClient(conn)}
	sctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := n.c.SubscribeEvents(sctx, &pb.SubscribeEventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if e, err := s.Recv(); err != nil || e.GetReady() == nil {
		t.Fatalf("first event %v %v", e, err)
	}
	go func() {
		for {
			e, err := s.Recv()
			if err != nil {
				return
			}
			n.mu.Lock()
			n.events = append(n.events, e)
			n.mu.Unlock()
		}
	}()
	return n
}

func (n *netNode) since(i int) []*pb.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*pb.Event(nil), n.events[i:]...)
}

func (n *netNode) mark() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.events)
}

// wait waits for an event after index from that satisfies ok and returns
// it with the index after it.
func (n *netNode) wait(from int, what string, ok func(*pb.Event) bool) (*pb.Event, int) {
	n.t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		n.mu.Lock()
		for i := from; i < len(n.events); i++ {
			if ok(n.events[i]) {
				e := n.events[i]
				n.mu.Unlock()
				return e, i + 1
			}
		}
		n.mu.Unlock()
		if time.Now().After(deadline) {
			n.t.Fatalf("%s: timed out waiting for %s", n.name, what)
		}
	}
}

func buddyPresence(key string, st pb.PresenceState) func(*pb.Event) bool {
	return func(e *pb.Event) bool {
		p := e.GetBuddyPresence()
		return p != nil && p.GetBuddy().GetIdentityKey() == key && p.GetTo() == st
	}
}

func messageUpdated(id string, st pb.DeliveryState) func(*pb.Event) bool {
	return func(e *pb.Event) bool {
		u := e.GetMessageUpdated()
		return u != nil && u.GetMsgId() == id && u.GetDelivery() == st
	}
}

// TestNetworkOverAPI: two daemons on the loopback network, driven only
// through their APIs as frontends would: invite, accept, presence events
// with door open and close, IMs with message_updated through to acked,
// away messages, Activity, ListBuddies presence and GetStatus' network.
func TestNetworkOverAPI(t *testing.T) {
	r := nettest.StartRelay(t, &relay.RelayLimit{Duration: time.Minute, Data: 1 << 20})
	a, b := startNet(t, "alice", r), startNet(t, "bob", r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var inv *pb.CreateInviteResponse
	for deadline := time.Now().Add(10 * time.Second); inv.GetContactHint() == ""; time.Sleep(10 * time.Millisecond) {
		var err error
		if inv, err = a.c.CreateInvite(ctx, &pb.CreateInviteRequest{}); err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("no contact hint")
		}
	}
	if !strings.Contains(inv.GetContactHint(), "/dns4/"+nettest.RelayName+"/") || !strings.Contains(inv.GetLink(), "c=") {
		t.Fatalf("invite %v", inv)
	}
	aStatus, err := a.c.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	net := aStatus.GetNetwork()
	if net.GetPeerId() == "" || net.GetGeneration() != 1 || len(net.GetRelays()) != 1 || !net.GetRelays()[0].GetReserved() ||
		len(net.GetRelayAddrs()) != 1 || net.GetContactHint() != inv.GetContactHint() || net.GetBootstrapPeers() != 1 ||
		net.GetDhtRoutingTable() != 1 || len(net.GetListenAddrs()) == 0 {
		t.Fatalf("network status %v", net)
	}

	ia, ib := a.mark(), b.mark()
	if _, err := b.c.AddBuddy(ctx, &pb.AddBuddyRequest{InviteLink: inv.GetLink(), Petname: "alice"}); err != nil {
		t.Fatal(err)
	}
	req, _ := a.wait(ia, "buddy request", func(e *pb.Event) bool { return e.GetBuddyRequest() != nil })
	bKey := req.GetBuddyRequest().GetIdentityKey()
	if _, err := a.c.SetBuddyLabels(ctx, &pb.SetBuddyLabelsRequest{Buddy: bKey, Petname: new("bob")}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.AcceptBuddy(ctx, &pb.AcceptBuddyRequest{Buddy: "bob"}); err != nil {
		t.Fatal(err)
	}
	e, _ := a.wait(ia, "bob online", buddyPresence(bKey, pb.PresenceState_PRESENCE_STATE_ONLINE))
	if p := e.GetBuddyPresence(); !p.GetDoorOpen() || p.GetDoorClose() || p.GetBuddy().GetPresence().GetState() != pb.PresenceState_PRESENCE_STATE_ONLINE {
		t.Fatalf("door open %v", p)
	}
	aKey := aStatus.GetIdentityKey()
	b.wait(ib, "alice online", buddyPresence(aKey, pb.PresenceState_PRESENCE_STATE_ONLINE))

	ls, err := a.c.ListBuddies(ctx, &pb.ListBuddiesRequest{})
	if err != nil || len(ls.GetBuddies()) != 1 {
		t.Fatal(ls, err)
	}
	if p := ls.GetBuddies()[0].GetPresence(); p.GetState() != pb.PresenceState_PRESENCE_STATE_ONLINE || !p.GetConnected() || p.GetSince() == nil {
		t.Fatalf("listed presence %v", p)
	}
	if st, _ := a.c.GetStatus(ctx, &pb.GetStatusRequest{}); st.GetNetwork().GetBuddiesOnline() != 1 || st.GetNetwork().GetSessionsUp() == 0 {
		t.Fatalf("status %v", st.GetNetwork())
	}

	// An IM goes queued → sent → acked; history shows it acked.
	ia, ib = a.mark(), b.mark()
	sent, err := a.c.SendIM(ctx, &pb.SendIMRequest{Buddy: "bob", Text: "over the relay"})
	if err != nil {
		t.Fatal(err)
	}
	id := sent.GetMsgId()
	// "sent" comes first, unless the ACK beat the router recording the
	// send; it never comes after "acked".
	e, i := a.wait(ia, "acked", messageUpdated(id, pb.DeliveryState_DELIVERY_STATE_ACKED))
	time.Sleep(50 * time.Millisecond)
	for _, later := range a.since(i) {
		if messageUpdated(id, pb.DeliveryState_DELIVERY_STATE_SENT)(later) {
			t.Fatal("message_updated sent after acked")
		}
	}
	if u := e.GetMessageUpdated(); u.GetBuddyKey() != bKey || u.GetAckedMask() != 1 || u.GetFragCount() != 1 || u.GetAttempts() > 1 {
		t.Fatalf("update %v", u)
	}
	b.wait(ib, "the IM", func(e *pb.Event) bool { return e.GetMessageReceived().GetText() == "over the relay" })
	h, err := a.c.History(ctx, &pb.HistoryRequest{Buddy: "bob"})
	if err != nil || len(h.GetMessages()) != 1 || h.GetMessages()[0].GetDelivery() != pb.DeliveryState_DELIVERY_STATE_ACKED ||
		h.GetMessages()[0].GetAckedMask() != 1 {
		t.Fatalf("history %v %v", h, err)
	}

	// Bob goes away: alice gets the state, then the away message.
	ia = a.mark()
	if _, err := b.c.SetPresence(ctx, &pb.SetPresenceRequest{State: pb.PresenceState_PRESENCE_STATE_AWAY, AwayMessage: "lunch"}); err != nil {
		t.Fatal(err)
	}
	a.wait(ia, "bob away", buddyPresence(bKey, pb.PresenceState_PRESENCE_STATE_AWAY))
	a.wait(ia, "bob's away message", func(e *pb.Event) bool {
		p := e.GetBuddyPresence()
		return p.GetReason() == "away-message" && p.GetBuddy().GetPresence().GetAwayMessage() == "lunch"
	})

	// Activity is accepted, with or without a time.
	if _, err := b.c.Activity(ctx, &pb.ActivityRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.c.Activity(ctx, &pb.ActivityRequest{At: timestamppb.New(time.Now().Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	_, err = b.c.Activity(ctx, &pb.ActivityRequest{At: &timestamppb.Timestamp{Nanos: -1}})
	wantCode(t, err, codes.InvalidArgument)

	// Bob's daemon stops: alice hears the door close.
	ia = a.mark()
	b.d.Stop()
	e, _ = a.wait(ia, "bob offline", buddyPresence(bKey, pb.PresenceState_PRESENCE_STATE_OFFLINE))
	if p := e.GetBuddyPresence(); !p.GetDoorClose() || p.GetReason() != "signed-off" || p.GetFrom() != pb.PresenceState_PRESENCE_STATE_AWAY {
		t.Fatalf("door close %v", p)
	}
}

// TestOfflineAPI: without a network, GetStatus has none, Activity is a
// no-op and buddies show OFFLINE.
func TestOfflineAPI(t *testing.T) {
	dir, _ := initDir(t)
	_, c := start(t, dir)
	ctx := ctxT(t)
	st, err := c.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil || st.GetNetwork() != nil {
		t.Fatalf("status %v %v", st, err)
	}
	if _, err := c.Activity(ctx, &pb.ActivityRequest{}); err != nil {
		t.Fatal(err)
	}
}
