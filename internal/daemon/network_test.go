package daemon

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	"github.com/aghman/openaim/internal/daemon/nettest"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/store"
	"github.com/aghman/openaim/internal/transport/ip"
)

// testNetwork is short timings for daemons on loopback that may only reach
// each other through the relay.
func testNetwork(r *nettest.Relay) *NetworkOptions {
	return &NetworkOptions{
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
}

// netDaemon is a daemon on the test network, recording its events.
type netDaemon struct {
	t    *testing.T
	name string
	dir  string
	opts *NetworkOptions
	*Node

	mu     sync.Mutex
	events []Event
	done   chan struct{}
}

// newNetDaemon initializes an identity in a new data dir with the relay in
// its network.json, and starts it.
func newNetDaemon(t *testing.T, name string, r *nettest.Relay) *netDaemon {
	t.Helper()
	dir := tempDir(t)
	c := initCfg(dir)
	c.BackupPath, c.BackupPassphrase = filepath.Join(tempDir(t), "backup"), backupPass
	if _, err := InitIdentity(ctx, c); err != nil {
		t.Fatal(err)
	}
	r.WriteNetworkJSON(t, dir)
	d := &netDaemon{t: t, name: name, dir: dir, opts: testNetwork(r)}
	d.start()
	t.Cleanup(d.stop)
	return d
}

func (d *netDaemon) start() {
	d.t.Helper()
	var log *slog.Logger
	if os.Getenv("OPENAIM_TEST_LOG") != "" {
		log = slog.New(slog.NewTextHandler(testWriter{d.t}, &slog.HandlerOptions{Level: slog.LevelDebug})).With("node", d.name)
	}
	n, err := Open(ctx, Config{DataDir: d.dir, Passphrase: testPass, KeystoreParams: fast, DisplayName: d.name,
		DisableHandleLoop: true, Network: d.opts, Logger: log})
	if err != nil {
		d.t.Fatal(err)
	}
	d.Node, d.done = n, make(chan struct{})
	sub := n.Subscribe()
	go func() {
		defer close(d.done)
		for e := range sub.C {
			d.mu.Lock()
			d.events = append(d.events, e)
			d.mu.Unlock()
		}
	}()
}

// stop closes the daemon (signing off) and waits for its events to end.
func (d *netDaemon) stop() {
	if d.Node == nil {
		return
	}
	d.Node.Close()
	<-d.done
	d.Node = nil
}

// waitEvent waits for an event from index from on that satisfies ok, and
// returns the index after it.
func (d *netDaemon) waitEvent(from int, what string, ok func(Event) bool) int {
	d.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		d.mu.Lock()
		for i := from; i < len(d.events); i++ {
			if ok(d.events[i]) {
				d.mu.Unlock()
				return i + 1
			}
		}
		n := len(d.events)
		d.mu.Unlock()
		if time.Now().After(deadline) {
			d.t.Fatalf("%s: timed out waiting for %s (%d events)", d.name, what, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (d *netDaemon) mark() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.events)
}

func (d *netDaemon) eventsSince(from int) []Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.events[from:])
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// presenceOf matches a presence event for buddy k reaching state st.
func presenceOf(k identity.PublicKey, st PresenceState) func(Event) bool {
	return func(e Event) bool {
		return e.Kind == EventBuddyPresence && e.Buddy.Key == k && e.BuddyPresence.State == st
	}
}

func updateOf(m Message, st DeliveryState) func(Event) bool {
	return func(e Event) bool {
		return e.Kind == EventMessageUpdated && e.Update.MsgID == m.MsgID && e.Update.State == st
	}
}

// befriend makes a and b buddies over the network: b adds a by a's invite
// link (its relay circuit contact hint), a accepts, and both see each other
// online.
func befriend(t *testing.T, a, b *netDaemon) {
	t.Helper()
	var inv CreatedInvite
	waitUntil(t, "a relay circuit contact hint", func() bool {
		var err error
		if inv, err = a.CreateInvite(InviteOptions{}); err != nil {
			t.Fatal(err)
		}
		return inv.Invite.Contact != ""
	})
	ia, ib := a.mark(), b.mark()
	if _, err := b.AddBuddyWith(ctx, AddBuddyOptions{Invite: inv.Link, Petname: a.name, Greeting: "hi from " + b.name}); err != nil {
		t.Fatal(err)
	}
	a.waitEvent(ia, "the buddy request", func(e Event) bool { return e.Kind == EventBuddyRequest && e.Buddy.Key == b.Identity() })
	if _, err := a.SetBuddyLabels(ctx, b.Identity().String(), &b.name, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AcceptBuddy(ctx, b.name); err != nil {
		t.Fatal(err)
	}
	b.waitEvent(ib, "a accepted", func(e Event) bool {
		return e.Kind == EventBuddyChanged && e.Buddy.Key == a.Identity() && e.Buddy.State == store.Accepted
	})
	a.waitEvent(ia, "b online", presenceOf(b.Identity(), Online))
	b.waitEvent(ib, "a online", presenceOf(a.Identity(), Online))
}

// TestNetworkTwoDaemons is the M1 exit scenario on loopback (design §14):
// two daemons that can reach each other only through a relay become
// buddies by invite, see each other online, exchange acked IMs, see away
// and relay resets without flapping, survive a network key rotation, and
// see each other sign off.
func TestNetworkTwoDaemons(t *testing.T) {
	r := nettest.StartRelay(t, &relay.RelayLimit{Duration: 3 * time.Second, Data: 1 << 20})
	a, b := newNetDaemon(t, "alice", r), newNetDaemon(t, "bob", r)
	befriend(t, a, b)

	// IMs both ways, each acked.
	ia, ib := a.mark(), b.mark()
	m1, err := a.SendIM(ctx, "bob", "hey bob")
	if err != nil {
		t.Fatal(err)
	}
	b.waitEvent(ib, "IM from a", func(e Event) bool { return e.Kind == EventMessageReceived && e.Message.Text == "hey bob" })
	a.waitEvent(ia, "IM to b acked", updateOf(m1, DeliveryAcked))
	m2, err := b.SendIM(ctx, "alice", "hey alice")
	if err != nil {
		t.Fatal(err)
	}
	a.waitEvent(ia, "IM from b", func(e Event) bool { return e.Kind == EventMessageReceived && e.Message.Text == "hey alice" })
	b.waitEvent(ib, "IM to a acked", updateOf(m2, DeliveryAcked))
	h, err := a.History(ctx, "bob", 10)
	if err != nil || len(h) != 2 || h[0].Text != "hey bob" || h[0].State != store.Acked || h[1].Text != "hey alice" {
		t.Fatalf("a's history %+v %v", h, err)
	}

	// b goes away; a sees it, and fetches the away message.
	ia = a.mark()
	if _, err := b.SetPresence(ctx, Away, "gone fishing"); err != nil {
		t.Fatal(err)
	}
	a.waitEvent(ia, "b away", presenceOf(b.Identity(), Away))
	a.waitEvent(ia, "b's away message", func(e Event) bool {
		return e.Kind == EventBuddyPresence && e.BuddyPresence.AwayMessage == "gone fishing"
	})
	if p := a.BuddyPresence(b.Identity()); p.State != Away || p.AwayMessage != "gone fishing" {
		t.Fatalf("a shows b as %+v", p)
	}
	if _, err := b.SetPresence(ctx, Online, ""); err != nil {
		t.Fatal(err)
	}
	a.waitEvent(ia, "b back", presenceOf(b.Identity(), Online))

	// The relay cuts circuits every 3 s. Across several resets nobody is
	// shown offline, and IMs still get through.
	ia, ib = a.mark(), b.mark()
	disc := a.net.sess.Stats().Disconnects
	waitUntil(t, "two relay resets", func() bool { return a.net.sess.Stats().Disconnects >= disc+2 })
	m3, err := a.SendIM(ctx, "bob", "still there?")
	if err != nil {
		t.Fatal(err)
	}
	a.waitEvent(ia, "IM across resets acked", updateOf(m3, DeliveryAcked))
	for _, d := range []*netDaemon{a, b} {
		for _, e := range d.eventsSince(map[*netDaemon]int{a: ia, b: ib}[d]) {
			if e.Kind == EventBuddyPresence && e.BuddyPresence.State == Offline {
				t.Fatalf("%s saw %s go offline across a relay reset (%s)", d.name, e.Buddy.Petname, e.BuddyPresence.Reason)
			}
		}
	}

	// a's network key rotates: b moves to the new peer ID without a
	// door close, finds it through the rendezvous record too, and IMs work.
	ia, ib = a.mark(), b.mark()
	old := a.Network().PeerID
	if err := a.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	now := a.Network().PeerID
	if now == old {
		t.Fatal("rotation kept the peer ID")
	}
	waitUntil(t, "b routes to a's new peer ID", func() bool {
		rt, ok := b.net.routeOf(mustBuddy(t, b.Node, a.Identity()).ID)
		return ok && rt.Peer == now
	})
	waitUntil(t, "a's rendezvous record names the new peer ID", func() bool {
		ai, err := b.LookupBuddy(ctx, "alice")
		return err == nil && ai.ID == now
	})
	m4, err := b.SendIM(ctx, "alice", "new phone who dis")
	if err != nil {
		t.Fatal(err)
	}
	b.waitEvent(ib, "IM after rotation acked", updateOf(m4, DeliveryAcked))
	time.Sleep(2 * time.Second) // past the old host's retirement
	for _, e := range b.eventsSince(ib) {
		if e.Kind == EventBuddyPresence && e.BuddyPresence.State == Offline {
			t.Fatalf("b saw a go offline across the rotation (%s)", e.BuddyPresence.Reason)
		}
	}
	_ = ia

	// b signs off: a sees the door close.
	ia = a.mark()
	bKey := b.Identity()
	b.stop()
	i := a.waitEvent(ia, "b offline", presenceOf(bKey, Offline))
	e := a.eventsSince(i - 1)[0]
	if !e.BuddyPresence.DoorClose() || e.BuddyPresence.Reason != "signed-off" {
		t.Fatalf("b went offline with %+v", e.BuddyPresence)
	}
	if st := a.Network(); st.Online != 0 {
		t.Fatalf("a still shows %d buddies online", st.Online)
	}
	fmt.Fprintln(testWriter{t}, "a's network:", a.Network().PeerID, a.Network().Generation)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

// TestNetworkRestart: daemons restarted mid-conversation come back with new
// peer IDs and stale addresses for each other. They find each other again
// through rendezvous records, the IM queued before the restart is
// delivered and acked by the resumed router, and presence resumes.
func TestNetworkRestart(t *testing.T) {
	r := nettest.StartRelay(t, nil)
	a, b := newNetDaemon(t, "alice", r), newNetDaemon(t, "bob", r)
	befriend(t, a, b)
	aKey, bKey := a.Identity(), b.Identity()

	// a signs off; b queues an IM it can't deliver.
	ib := b.mark()
	a.stop()
	b.waitEvent(ib, "a offline", presenceOf(aKey, Offline))
	m, err := b.SendIM(ctx, "alice", "you there?")
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := b.History(ctx, "alice", 1); h[0].State != store.Queued {
		t.Fatalf("IM to a stopped daemon is %s", h[0].State)
	}

	// Both restart, b first, each with a new peer ID: neither has a
	// current address for the other.
	bPeer := b.Network().PeerID
	b.stop()
	b.start()
	if b.Network().PeerID == bPeer {
		t.Fatal("restart kept the peer ID")
	}
	a.start()

	a.waitEvent(0, "the queued IM", func(e Event) bool { return e.Kind == EventMessageReceived && e.Message.MsgID == m.MsgID })
	b.waitEvent(0, "the queued IM acked", updateOf(m, DeliveryAcked))
	a.waitEvent(0, "b online", presenceOf(bKey, Online))
	b.waitEvent(0, "a online", presenceOf(aKey, Online))
	if h, err := b.History(ctx, "alice", 1); err != nil || h[0].State != store.Acked {
		t.Fatalf("after the restart: %+v %v", h, err)
	}
}

// TestNetworkDoorClose: a buddy whose network vanishes without signing off
// (a crash, a pulled cable) is shown offline once the grace period passes
// without a session coming back.
func TestNetworkDoorClose(t *testing.T) {
	r := nettest.StartRelay(t, nil)
	a, b := newNetDaemon(t, "alice", r), newNetDaemon(t, "bob", r)
	befriend(t, a, b)
	ia := a.mark()
	start := time.Now()
	b.net.sess.Close() // no OFFLINE presence goes out
	b.net.node.Close()
	i := a.waitEvent(ia, "bob offline", presenceOf(b.Identity(), Offline))
	e := a.eventsSince(i - 1)[0]
	if !e.BuddyPresence.DoorClose() || e.BuddyPresence.Reason != "door-close" {
		t.Fatalf("bob went offline with %+v", e.BuddyPresence)
	}
	if d := time.Since(start); d < a.opts.PresenceGrace {
		t.Fatalf("offline after %v, before the %v grace", d, a.opts.PresenceGrace)
	}
}
