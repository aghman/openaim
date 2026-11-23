package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lpeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/daemon/nettest"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/router"
	"github.com/aghman/openaim/internal/store"
	"github.com/aghman/openaim/internal/transport/ip"
	pb "github.com/aghman/openaim/internal/wirepb"
)

func TestPickAddrs(t *testing.T) {
	self, err := lpeer.Decode(testPeerID(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	relayID := testPeerID(t, 2)
	in := []string{
		"/ip4/127.0.0.1/tcp/4001",
		"/ip4/192.168.1.5/tcp/4001",
		"/ip4/1.2.3.4/udp/4001/quic-v1",
		"/dns4/relay.example.org/tcp/4001/p2p/" + relayID + "/p2p-circuit/p2p/" + self.String(),
		"/ip4/192.168.1.5/tcp/4001", // duplicate
	}
	var addrs []ma.Multiaddr
	for _, s := range in {
		addrs = append(addrs, ma.StringCast(s))
	}
	for range 10 {
		addrs = append(addrs, ma.StringCast("/ip4/10.0.0.1/tcp/1"+strings.Repeat("0", 3)))
	}
	got := pickAddrs(self, addrs)
	want := []string{
		"/dns4/relay.example.org/tcp/4001/p2p/" + relayID + "/p2p-circuit", // circuits first, our /p2p/ dropped
		"/ip4/1.2.3.4/udp/4001/quic-v1",
		"/ip4/192.168.1.5/tcp/4001",
		"/ip4/10.0.0.1/tcp/1000",
		"/ip4/127.0.0.1/tcp/4001",
	}
	if len(got) != len(want) {
		t.Fatalf("picked %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("addr %d = %s, want %s", i, got[i], want[i])
		}
	}
	// A REACH made from them is valid.
	r := &pb.Reach{Seq: 1, IssuedAt: 1, ExpiresAt: 2, Ip: []*pb.IPHint{{PeerId: []byte(self)}}}
	for _, a := range got {
		r.Ip[0].Addrs = append(r.Ip[0].Addrs, a.Bytes())
	}
	if err := body.Validate(r); err != nil {
		t.Fatal(err)
	}
}

func TestFirstContactAddr(t *testing.T) {
	id := testPeerID(t, 1)
	hint := "/dns4/relay.example.org/tcp/4001/p2p/" + testPeerID(t, 2) + "/p2p-circuit/p2p/" + id
	ai, err := firstContactAddr(DeliveryTarget{Kind: TargetFirstContact, ContactHint: hint})
	if err != nil || ai.ID.String() != id || len(ai.Addrs) != 1 || !strings.HasSuffix(ai.Addrs[0].String(), "/p2p-circuit") {
		t.Fatalf("relay hint: %v %v", ai, err)
	}
	// No hint: the target's REACH.
	p, _ := lpeer.Decode(id)
	r := &pb.Reach{Seq: 1, IssuedAt: 1, ExpiresAt: 2, Ip: []*pb.IPHint{{PeerId: []byte(p), Addrs: [][]byte{ma.StringCast("/ip4/203.0.113.9/tcp/1").Bytes()}}}}
	if ai, err := firstContactAddr(DeliveryTarget{Kind: TargetFirstContact, Reach: r}); err != nil || ai.ID != p || len(ai.Addrs) != 1 {
		t.Fatalf("reach: %v %v", ai, err)
	}
	// A mailbox hint can't be dialled yet; nothing at all stays queued.
	if _, err := firstContactAddr(DeliveryTarget{Kind: TargetFirstContact, ContactHint: "/dns4/mbox.example.org/tcp/1"}); err == nil {
		t.Fatal("mailbox hint accepted")
	}
	if _, err := firstContactAddr(DeliveryTarget{Kind: TargetFirstContact}); err == nil {
		t.Fatal("no address accepted")
	}
}

// TestNetworkSingleDaemon: one daemon on the network on its own: its seq
// counter, REACH, contact hint, status and the offline-only calls.
func TestNetworkSingleDaemon(t *testing.T) {
	r := nettest.StartRelay(t, nil)
	a := newNetDaemon(t, "alice", r)
	s := a.net

	prev := s.nextSeq()
	if now := uint64(time.Now().UnixMilli()); prev+1000 < now || prev > now+1000 {
		t.Fatalf("seq %d is not the clock (%d)", prev, now)
	}
	for range 1000 {
		if v := s.nextSeq(); v <= prev {
			t.Fatalf("seq went from %d to %d", prev, v)
		} else {
			prev = v
		}
	}

	st := a.Network()
	if st == nil || st.PeerID != s.node.ID() || st.Generation != 1 || st.Bootstrap != 1 || len(st.Relays) != 1 {
		t.Fatalf("status %+v", st)
	}
	if !st.Relays[0].Reserved || len(st.Circuits) != 1 || st.ContactHint != st.Circuits[0].String() || st.DHTPeers != 1 {
		t.Fatalf("status %+v", st)
	}
	inv, err := a.CreateInvite(InviteOptions{})
	if err != nil || inv.Invite.Contact != st.ContactHint || inv.Note != "" {
		t.Fatalf("invite %+v %v", inv, err)
	}
	reach := a.ourReach()
	h, ok := router.HintFromReach(reach)
	if !ok || h.Peer != st.PeerID || len(h.Addrs) == 0 || !isCircuitAddr(h.Addrs[0]) {
		t.Fatalf("our REACH %v", reach)
	}
	if exp := frame.TimeOf(reach.GetExpiresAt()).Sub(frame.TimeOf(reach.GetIssuedAt())); exp != OurReachTTL {
		t.Fatalf("REACH lasts %v", exp)
	}

	// Rotating changes the peer ID, the REACH and the contact hint.
	if err := a.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	st2 := a.Network()
	if st2.PeerID == st.PeerID || st2.Generation != 2 {
		t.Fatalf("after rotation %+v", st2)
	}
	waitUntil(t, "a reservation on the new host", func() bool {
		st2 = a.Network()
		return st2.ContactHint != "" && st2.ContactHint != st.ContactHint
	})

	// Our own presence goes to the tracker.
	if _, err := a.SetPresence(ctx, Away, "brb"); err != nil {
		t.Fatal(err)
	}
	if o := s.pres.Own(); o.State != 2 || o.AwayText != "brb" {
		t.Fatalf("tracker has %+v", o)
	}
	if err := a.Activity(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LookupBuddy(ctx, "nobody"); !errors.Is(err, ErrUnknownBuddy) {
		t.Fatalf("lookup of nobody: %v", err)
	}
}

// TestOfflineCalls: without a network, the network calls say so.
func TestOfflineCalls(t *testing.T) {
	dir := tempDir(t)
	if _, err := Init(ctx, initCfg(dir)); err != nil {
		t.Fatal(err)
	}
	n := open(t, dir)
	if n.Network() != nil {
		t.Fatal("offline node reports a network")
	}
	if err := n.Rotate(ctx); !errors.Is(err, ErrOffline) {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := n.LookupBuddy(ctx, "x"); !errors.Is(err, ErrOffline) {
		t.Fatalf("lookup: %v", err)
	}
	if err := n.Activity(time.Now()); err != nil {
		t.Fatal(err)
	}
	if p := n.BuddyPresence(peer(t, 1).Public()); p.State != Offline {
		t.Fatalf("presence %+v", p)
	}
}

// TestBlockFailsQueued: blocking a buddy gives up on what is queued for them
// and says so.
func TestBlockFailsQueued(t *testing.T) {
	dir := tempDir(t)
	if _, err := Init(ctx, initCfg(dir)); err != nil {
		t.Fatal(err)
	}
	n := open(t, dir)
	bob := peer(t, 9)
	if _, err := n.store.AddBuddy(ctx, store.Buddy{Key: bob.Public(), Petname: "bob", State: store.Accepted}); err != nil {
		t.Fatal(err)
	}
	m, err := n.SendIM(ctx, "bob", "hello?")
	if err != nil {
		t.Fatal(err)
	}
	sub := n.Subscribe()
	defer sub.Close()
	if _, err := n.BlockBuddy(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	var got *MessageUpdate
	for got == nil {
		select {
		case e := <-sub.C:
			if e.Kind == EventMessageUpdated {
				got = e.Update
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no message_updated")
		}
	}
	if got.MsgID != m.MsgID || got.State != DeliveryFailed || got.Buddy != bob.Public() || got.FragCount != 1 {
		t.Fatalf("update %+v", got)
	}
	h, err := n.History(ctx, "bob", 10)
	if err != nil || len(h) != 1 || h[0].State != store.Failed {
		t.Fatalf("history %+v %v", h, err)
	}
}

// TestNetworkPublic: --public mode keeps one peer ID across restarts (in
// network.key), never rotates, and serves relay reservations.
func TestNetworkPublic(t *testing.T) {
	dir := tempDir(t)
	if _, err := Init(ctx, initCfg(dir)); err != nil {
		t.Fatal(err)
	}
	opts := &NetworkOptions{Public: true, Listen: []string{"/ip4/127.0.0.1/tcp/0"}, Config: &ip.NetworkConfig{}}
	openPublic := func() *Node {
		n, err := Open(ctx, Config{DataDir: dir, Passphrase: testPass, KeystoreParams: fast, DisableHandleLoop: true, Network: opts})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	n := openPublic()
	st := n.Network()
	if !st.Public || st.PeerID == "" {
		t.Fatalf("status %+v", st)
	}
	if err := n.Rotate(ctx); !errors.Is(err, ip.ErrFixedKey) {
		t.Fatalf("rotate: %v", err)
	}
	// An ordinary node can reserve a slot on it.
	h, err := ip.NewHost(ip.HostOptions{Listen: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := client.Reserve(rctx, h, lpeer.AddrInfo{ID: st.PeerID, Addrs: n.net.node.Host().Addrs()}); err != nil {
		t.Fatalf("reservation on the public node: %v", err)
	}
	n.Close()
	if _, err := os.Stat(filepath.Join(dir, NetworkKeyFile)); err != nil {
		t.Fatal(err)
	}
	n = openPublic()
	defer n.Close()
	if id := n.Network().PeerID; id != st.PeerID {
		t.Fatalf("peer ID %s after a restart, was %s", id, st.PeerID)
	}
}
