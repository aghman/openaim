package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	lpeer "github.com/libp2p/go-libp2p/core/peer"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/invite"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// wire connects in-process nodes: each node's FrameSink hands frames to the
// recipient's HandleFrameFrom, synchronously, unless held.
type wire struct {
	t     *testing.T
	mu    sync.Mutex
	nodes map[identity.PublicKey]*Node
	log   []delivery
	held  []delivery
	hold  bool
}

type delivery struct {
	from   identity.PublicKey
	to     DeliveryTarget
	frames [][]byte
	errs   []error // the recipient's HandleFrame results
}

func newWire(t *testing.T) *wire { return &wire{t: t, nodes: map[identity.PublicKey]*Node{}} }

type wireSink struct {
	w    *wire
	from identity.PublicKey
}

func (s wireSink) Deliver(ctx context.Context, to DeliveryTarget, frames [][]byte) error {
	w := s.w
	w.mu.Lock()
	d := delivery{from: s.from, to: to, frames: frames}
	if w.hold {
		w.held = append(w.held, d)
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()
	return w.send(ctx, d)
}

func (w *wire) send(ctx context.Context, d delivery) error {
	w.mu.Lock()
	dst := w.nodes[d.to.Key]
	w.mu.Unlock()
	if dst == nil {
		return fmt.Errorf("no node for %s", d.to.Key.KeyID())
	}
	for _, f := range d.frames {
		_, err := dst.HandleFrameFrom(ctx, "mem", f)
		d.errs = append(d.errs, err)
	}
	w.mu.Lock()
	w.log = append(w.log, d)
	w.mu.Unlock()
	return nil
}

// flush delivers held frames (and stops holding).
func (w *wire) flush(ctx context.Context) {
	w.mu.Lock()
	held := w.held
	w.held, w.hold = nil, false
	w.mu.Unlock()
	for _, d := range held {
		if err := w.send(ctx, d); err != nil {
			w.t.Fatal(err)
		}
	}
}

func (w *wire) deliveries() []delivery {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]delivery(nil), w.log...)
}

// testPeerID is a libp2p peer ID for a contact hint.
func testPeerID(t *testing.T, b byte) string {
	t.Helper()
	k, err := crypto.UnmarshalEd25519PrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	id, err := lpeer.IDFromPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

type nodeOpts struct {
	name    string
	contact string
	burst   int
}

// add starts a node with a recovery key on the wire.
func (w *wire) add(o nodeOpts) *Node {
	t := w.t
	t.Helper()
	dir := tempDir(t)
	c := initCfg(dir)
	c.BackupPath, c.BackupPassphrase = filepath.Join(tempDir(t), "backup"), backupPass
	if _, err := InitIdentity(ctx, c); err != nil {
		t.Fatal(err)
	}
	cfg := Config{DataDir: dir, Passphrase: testPass, KeystoreParams: fast, DisplayName: o.name,
		FirstContactBurst: o.burst, FirstContactRate: 1e-9, DisableHandleLoop: true}
	if o.contact != "" {
		hint := o.contact
		cfg.ContactHint = func() string { return hint }
	}
	n, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	n.SetFrameSink(wireSink{w: w, from: n.Identity()})
	w.mu.Lock()
	w.nodes[n.Identity()] = n
	w.mu.Unlock()
	return n
}

func mustBuddy(t *testing.T, n *Node, k identity.PublicKey) store.Buddy {
	t.Helper()
	b, err := n.store.BuddyByKey(ctx, k)
	if err != nil {
		t.Fatalf("%s has no buddy %s: %v", n.cfg.DisplayName, k.KeyID(), err)
	}
	return b
}

// openRequest opens first-contact frames as their recipient would.
func openRequest(t *testing.T, to *Node, frames [][]byte) (*frame.FirstContact, *pb.BuddyRequest) {
	t.Helper()
	r := &frame.FirstContactReceiver{Me: to.id, Dedup: &frame.MemDedup{}}
	var res frame.FirstContactResult
	var err error
	for _, f := range frames {
		if res, err = r.Accept(f); err != nil {
			t.Fatal(err)
		}
	}
	if res.Status != frame.Delivered {
		t.Fatalf("request not complete: %v", res.Status)
	}
	m, err := body.Unmarshal(frame.BuddyRequest, res.Message.Inner.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.Message, m.(*pb.BuddyRequest)
}

// sealIMFrom seals a DATA frame of content type ct from one node to another.
func sealFrom(t *testing.T, from *Node, to identity.PublicKey, ct frame.ContentType, b []byte) [][]byte {
	t.Helper()
	p, err := from.id.Pair(to)
	if err != nil {
		t.Fatal(err)
	}
	k := frame.NewConvKey(p.Send)
	now := time.Now()
	in := frame.Inner{Type: ct, Time: frame.Timestamp(now), Seq: 99, Body: b}
	s, err := frame.Seal(k, k.Tag(frame.Day(now)), frame.LayoutMesh, in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return s.Frames
}

func TestInviteRequestAccept(t *testing.T) {
	w := newWire(t)
	contact := "/dns4/relay.example.net/tcp/4001/p2p/" + testPeerID(t, 1) + "/p2p-circuit/p2p/" + testPeerID(t, 2)
	alice := w.add(nodeOpts{name: "Alice", contact: contact})
	bob := w.add(nodeOpts{name: "Bob"})
	asub := alice.Subscribe()
	defer asub.Close()

	inv, err := alice.CreateInvite(InviteOptions{})
	if err != nil || inv.Invite.Contact != contact || inv.Note != "" || !strings.HasPrefix(inv.Link, invite.Prefix) {
		t.Fatalf("invite %+v %v", inv, err)
	}
	if _, err := alice.CreateInvite(InviteOptions{ContactHint: "/ip4/192.168.1.5/tcp/4001"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invite with a home IP: %v", err)
	}
	if ni, err := bob.CreateInvite(InviteOptions{Handle: "Bob.Example.com"}); err != nil || ni.Note == "" || ni.Invite.Handle != "bob.example.com" {
		t.Fatalf("invite without a hint %+v %v", ni, err)
	}

	// Bob adds Alice by her invite.
	added, err := bob.AddBuddyWith(ctx, AddBuddyOptions{Invite: inv.Link, Petname: "Al", Greeting: "hey it's bob from class"})
	if err != nil || added.RequestErr != nil || added.Request == nil || added.Accepted {
		t.Fatalf("add by invite: %+v %v", added, err)
	}
	if added.Buddy.State != store.PendingOut || added.Buddy.Key != alice.Identity() || added.Request.State != store.RequestSent {
		t.Fatalf("bob's view: %+v %+v", added.Buddy, added.Request)
	}

	// Exactly one delivery: the request, to the invite's contact hint.
	ds := w.deliveries()
	if len(ds) != 1 || ds[0].to.Kind != TargetFirstContact || ds[0].to.ContactHint != contact || ds[0].to.Key != alice.Identity() ||
		ds[0].errs[len(ds[0].errs)-1] != nil {
		t.Fatalf("deliveries %+v", ds)
	}
	for _, f := range ds[0].frames {
		if k := frame.Kind(f[0] & 0x1F); k != frame.KindFirstContact {
			t.Fatalf("request frame kind %d", k)
		}
	}
	// What the request carries: name, greeting, Bob's recovery public key.
	fc, req := openRequest(t, alice, ds[0].frames)
	if fc.Sender != bob.Identity() || req.GetDisplayName() != "Bob" || req.GetGreeting() != "hey it's bob from class" ||
		!bytes.Equal(req.GetRecoveryKey(), bob.RecoveryKey()[:]) || req.GetCaps().GetWireVersion() != 1 {
		t.Fatalf("request %v from %s", req, fc.Sender.KeyID())
	}

	// Alice sees a pending_in Bob with his name and greeting.
	ab := mustBuddy(t, alice, bob.Identity())
	det, err := alice.Details(ctx, ab)
	if err != nil || ab.State != store.PendingIn || det.Request == nil || det.Request.DisplayName != "Bob" ||
		det.Request.Greeting != "hey it's bob from class" || det.Request.Count != 1 || det.Request.Transport != "mem" {
		t.Fatalf("alice's view %+v %+v %v", ab, det, err)
	}
	if ab.RecoveryKey == nil || *ab.RecoveryKey != *bob.RecoveryKey() {
		t.Fatal("Bob's recovery key not pinned")
	}
	var kinds []EventKind
	for len(asub.C) > 0 {
		kinds = append(kinds, (<-asub.C).Kind)
	}
	if fmt.Sprint(kinds) != fmt.Sprint([]EventKind{EventBuddyAdded, EventBuddyRequest}) {
		t.Fatalf("alice's events %v", kinds)
	}

	// Nothing about Alice reached Bob before she accepts, and nothing of
	// Bob's beyond the request reaches her: no presence keys either way, no
	// frames from her, and his DATA frames aren't even recognized.
	if _, err := bob.Peer(ctx, mustBuddy(t, bob, alice.Identity())); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob knows something about alice: %v", err)
	}
	if p, _ := alice.Peer(ctx, ab); p.PresenceKey != nil {
		t.Fatal("alice has bob's presence key before accepting")
	}
	if _, err := alice.store.Meta(ctx, metaPresenceKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("alice made a presence key before accepting: %v", err)
	}
	early := sealFrom(t, bob, alice.Identity(), frame.IM, []byte("you there?"))
	if _, err := alice.HandleFrame(ctx, early[0]); !errors.Is(err, frame.ErrUnknownTag) {
		t.Fatalf("IM before accept: %v", err)
	}
	if len(w.deliveries()) != 1 {
		t.Fatal("something was sent before accepting")
	}

	// Alice accepts: her BUDDY_ACCEPT goes to Bob, and his comes back.
	if _, err := bob.AcceptBuddy(ctx, alice.Identity().String()); !errors.Is(err, ErrNotPending) {
		t.Fatalf("bob accepting his own request: %v", err)
	}
	acc, err := alice.AcceptBuddy(ctx, "~"+strings.TrimPrefix(bob.Identity().KeyID(), "~"))
	if err != nil || acc.State != store.Accepted {
		t.Fatalf("accept: %+v %v", acc, err)
	}
	ds = w.deliveries()
	if len(ds) != 3 {
		t.Fatalf("%d deliveries after accept", len(ds))
	}
	// Synchronous delivery nests Bob's reply inside Alice's send, so it
	// is logged first.
	reply, accept := ds[1], ds[2]
	if accept.from != alice.Identity() || accept.to.Kind != TargetBuddy || accept.to.Key != bob.Identity() || accept.errs[0] != nil {
		t.Fatalf("alice's accept %+v", accept)
	}
	if reply.from != bob.Identity() || reply.to.Kind != TargetBuddy || reply.to.Key != alice.Identity() || reply.errs[0] != nil {
		t.Fatalf("bob's reply %+v", reply)
	}
	// Bob learnt Alice's REACH from her accept, so his reply is routed by it.
	if reply.to.Reach == nil || len(reply.to.Reach.GetIp()) != 1 {
		t.Fatalf("bob's reply has no reach: %+v", reply.to)
	}
	ab, ba := mustBuddy(t, alice, bob.Identity()), mustBuddy(t, bob, alice.Identity())
	if ab.State != store.Accepted || ba.State != store.Accepted {
		t.Fatalf("states %s / %s", ab.State, ba.State)
	}
	if ba.RecoveryKey == nil || *ba.RecoveryKey != *alice.RecoveryKey() {
		t.Fatal("alice's recovery key not pinned by bob")
	}
	alicePK, _ := alice.store.Meta(ctx, metaPresenceKey)
	bobPK, _ := bob.store.Meta(ctx, metaPresenceKey)
	if p, err := bob.Peer(ctx, ba); err != nil || !bytes.Equal(p.PresenceKey, alicePK) || p.DisplayName != "Alice" || p.Reach == nil {
		t.Fatalf("bob's peer record of alice %+v %v", p, err)
	}
	if p, err := alice.Peer(ctx, ab); err != nil || !bytes.Equal(p.PresenceKey, bobPK) || p.DisplayName != "Bob" {
		t.Fatalf("alice's peer record of bob %+v %v", p, err)
	}
	if bytes.Equal(alicePK, bobPK) {
		t.Fatal("presence keys collide")
	}
	if rs, _ := bob.store.Requests(ctx, ba.ID); len(rs) != 1 || rs[0].State != store.RequestAnswered {
		t.Fatalf("bob's request %+v", rs)
	}
	if alice.keyring.Len() != 1 || bob.keyring.Len() != 1 {
		t.Fatalf("keyrings %d / %d", alice.keyring.Len(), bob.keyring.Len())
	}

	// An IM from Bob now reaches Alice.
	m, err := bob.SendIM(ctx, "Al", "made it!")
	if err != nil {
		t.Fatal(err)
	}
	out, err := bob.Pending(ctx, "Al")
	if err != nil {
		t.Fatal(err)
	}
	var got bool
	for _, o := range out {
		if o.MsgID != m.MsgID {
			continue
		}
		for _, f := range o.Frames {
			res, err := alice.HandleFrame(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			got = res.Status == frame.Delivered
		}
	}
	h, err := alice.History(ctx, bob.Identity().String(), 10)
	if !got || err != nil || len(h) != 1 || h[0].Text != "made it!" {
		t.Fatalf("history %+v %v", h, err)
	}

	// A BUDDY_REQUEST inside a DATA frame is dropped, even from a buddy.
	_, rb, _ := body.Marshal(&pb.BuddyRequest{DisplayName: "Bob"})
	if _, err := alice.HandleFrame(ctx, sealFrom(t, bob, alice.Identity(), frame.BuddyRequest, rb)[0]); !errors.Is(err, ErrRequestInData) {
		t.Fatalf("request in DATA: %v", err)
	}
	if alice.FirstContactStats().DataRequests != 1 {
		t.Fatalf("stats %+v", alice.FirstContactStats())
	}

	// Adding Bob again is a duplicate; accepting again re-sends.
	if _, err := alice.AddBuddy(ctx, bob.Identity().String(), "", ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("re-add: %v", err)
	}
	if _, err := alice.AcceptBuddy(ctx, bob.Identity().String()); err != nil || len(w.deliveries()) != 4 {
		t.Fatalf("re-accept: %v, %d deliveries", err, len(w.deliveries()))
	}
	if mustBuddy(t, bob, alice.Identity()).State != store.Accepted {
		t.Fatal("bob changed state on a repeated accept")
	}
}

func TestDuplicateRequestsMerge(t *testing.T) {
	w := newWire(t)
	alice := w.add(nodeOpts{name: "Alice"})
	carol := w.add(nodeOpts{name: "Carol"})
	k := alice.Identity()

	r1, err := carol.sealRequest(k, "hi", "")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // a later inner timestamp
	carol.cfg.DisplayName = "Carol B."
	r2, err := carol.sealRequest(k, "hi again", "")
	if err != nil {
		t.Fatal(err)
	}
	if r1.E == r2.E || r1.MsgID == r2.MsgID {
		t.Fatal("two sealings aren't distinct messages")
	}
	feed := func(r *store.OutRequest) frame.Result {
		t.Helper()
		var res frame.Result
		for _, f := range r.Frames {
			var err error
			if res, err = alice.HandleFrame(ctx, f); err != nil {
				t.Fatal(err)
			}
		}
		return res
	}
	if res := feed(r1); res.Status != frame.Delivered || res.Conv != carol.Identity() {
		t.Fatalf("first: %+v", res)
	}
	if res := feed(r2); res.Status != frame.Delivered {
		t.Fatalf("second: %+v", res)
	}
	// A replay of the first is a duplicate and changes nothing.
	if res := feed(r1); res.Status != frame.Duplicate {
		t.Fatalf("replay: %+v", res)
	}
	all, _ := alice.Buddies(ctx)
	if len(all) != 1 {
		t.Fatalf("%d buddies", len(all))
	}
	d, err := alice.Details(ctx, all[0])
	if err != nil || d.Request.Count != 2 || d.Request.Greeting != "hi again" || d.Request.DisplayName != "Carol B." {
		t.Fatalf("merged request %+v %v", d.Request, err)
	}
	st := alice.FirstContactStats()
	if st.Requests != 1 || st.Merged != 1 || st.Duplicates != 1 {
		t.Fatalf("stats %+v", st)
	}
	// An older request arriving late doesn't overwrite the newer text.
	r0, err := alice.store.Request(ctx, all[0].ID)
	if err != nil || r0.SentTS != r2.SentTS {
		t.Fatalf("sent_ts %+v %v", r0, err)
	}
	// Nothing was ever sent to Carol.
	if len(w.deliveries()) != 0 {
		t.Fatalf("deliveries %+v", w.deliveries())
	}
}

func TestDeclineAndBlock(t *testing.T) {
	w := newWire(t)
	alice := w.add(nodeOpts{name: "Alice"})
	dave := w.add(nodeOpts{name: "Dave"})
	erin := w.add(nodeOpts{name: "Erin"})

	if _, err := dave.AddBuddy(ctx, alice.Identity().String(), "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := erin.AddBuddy(ctx, alice.Identity().String(), "", ""); err != nil {
		t.Fatal(err)
	}
	before := len(w.deliveries())

	// Decline deletes the request and sends nothing.
	if _, err := alice.DeclineBuddy(ctx, dave.Identity().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.store.BuddyByKey(ctx, dave.Identity()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("declined buddy kept: %v", err)
	}
	if len(w.deliveries()) != before {
		t.Fatal("decline sent something")
	}
	if _, err := alice.DeclineBuddy(ctx, erin.Identity().String()); err != nil {
		t.Fatal(err)
	}
	// A new request from Dave shows up afresh.
	r, err := dave.sealRequest(alice.Identity(), "pls", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Frames {
		if _, err := alice.HandleFrame(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	db := mustBuddy(t, alice, dave.Identity())
	if db.State != store.PendingIn {
		t.Fatalf("dave %+v", db)
	}
	if _, err := alice.DeclineBuddy(ctx, alice.Identity().String()); err == nil {
		t.Fatal("declined ourselves")
	}

	// Block: further requests are dropped.
	if b, err := alice.BlockBuddy(ctx, dave.Identity().String()); err != nil || b.State != store.Blocked {
		t.Fatalf("block %+v %v", b, err)
	}
	r, _ = dave.sealRequest(alice.Identity(), "let me in", "")
	if _, err := alice.HandleFrame(ctx, r.Frames[0]); !errors.Is(err, ErrBlocked) {
		t.Fatalf("request from blocked: %v", err)
	}
	if d, _ := alice.Details(ctx, mustBuddy(t, alice, dave.Identity())); d.Request.Greeting != "pls" || d.Request.Count != 1 {
		t.Fatalf("blocked request recorded: %+v", d.Request)
	}
	if _, err := alice.AcceptBuddy(ctx, dave.Identity().String()); !errors.Is(err, ErrBlocked) {
		t.Fatalf("accept blocked: %v", err)
	}
	if alice.FirstContactStats().Blocked != 1 {
		t.Fatalf("stats %+v", alice.FirstContactStats())
	}

	// Blocking an accepted buddy drops its DATA frames before processing.
	frank := w.add(nodeOpts{name: "Frank"})
	if _, err := frank.AddBuddy(ctx, alice.Identity().String(), "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.AcceptBuddy(ctx, frank.Identity().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.BlockBuddy(ctx, frank.Identity().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.HandleFrame(ctx, sealFrom(t, frank, alice.Identity(), frame.IM, []byte("hi"))[0]); !errors.Is(err, frame.ErrUnknownTag) {
		t.Fatalf("IM from blocked: %v", err)
	}
	// Adding Erin, who asked us earlier (we declined, but she still has us
	// as pending_out), crosses her request: both sides end up accepted.
	if _, err := alice.AddBuddy(ctx, erin.Identity().String(), "", ""); err != nil {
		t.Fatal(err)
	}
	eb := mustBuddy(t, alice, erin.Identity())
	if eb.State != store.Accepted || mustBuddy(t, erin, alice.Identity()).State != store.Accepted {
		t.Fatalf("crossed add: %s", eb.State)
	}
	// Blocking a buddy we asked, who never answered, abandons our request.
	nobody := peer(t, 9).Public()
	if _, err := alice.AddBuddy(ctx, nobody.String(), "", ""); err != nil {
		t.Fatal(err)
	}
	nb := mustBuddy(t, alice, nobody)
	if rs, _ := alice.store.Requests(ctx, nb.ID); len(rs) != 1 || rs[0].State != store.RequestQueued || rs[0].LastError == "" {
		t.Fatalf("undeliverable request %+v", rs[0])
	}
	if _, err := alice.BlockBuddy(ctx, nobody.String()); err != nil {
		t.Fatal(err)
	}
	if rs, _ := alice.store.Requests(ctx, nb.ID); len(rs) != 1 || rs[0].State != store.RequestFailed {
		t.Fatalf("requests to blocked %+v", rs)
	}
	if n, _ := alice.RedeliverRequests(ctx); n != 0 {
		t.Fatal("redelivered a request to a blocked buddy")
	}
}

func TestCrossedRequestsAccept(t *testing.T) {
	w := newWire(t)
	gus := w.add(nodeOpts{name: "Gus"})
	hal := w.add(nodeOpts{name: "Hal"})
	w.mu.Lock()
	w.hold = true
	w.mu.Unlock()
	if _, err := gus.AddBuddy(ctx, hal.Identity().String(), "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := hal.AddBuddy(ctx, gus.Identity().String(), "", ""); err != nil {
		t.Fatal(err)
	}
	w.flush(ctx)
	gh, hg := mustBuddy(t, gus, hal.Identity()), mustBuddy(t, hal, gus.Identity())
	if gh.State != store.Accepted || hg.State != store.Accepted {
		t.Fatalf("states %s / %s", gh.State, hg.State)
	}
	if p, err := gus.Peer(ctx, gh); err != nil || p.PresenceKey == nil {
		t.Fatalf("gus has no presence key for hal: %+v %v", p, err)
	}
	if p, err := hal.Peer(ctx, hg); err != nil || p.PresenceKey == nil {
		t.Fatalf("hal has no presence key for gus: %+v %v", p, err)
	}
	// Two requests and two accepts; no accept ping-pong.
	if n := len(w.deliveries()); n != 4 {
		t.Fatalf("%d deliveries", n)
	}
}

func TestAddPendingInAccepts(t *testing.T) {
	w := newWire(t)
	ivy := w.add(nodeOpts{name: "Ivy"})
	jo := w.add(nodeOpts{name: "Jo"})
	if _, err := jo.AddBuddy(ctx, ivy.Identity().String(), "", ""); err != nil {
		t.Fatal(err)
	}
	a, err := ivy.AddBuddyWith(ctx, AddBuddyOptions{Key: jo.Identity().String(), Petname: "Jo", Group: "Class"})
	if err != nil || !a.Accepted || a.Buddy.State != store.Accepted || a.Buddy.Petname != "Jo" || a.Buddy.Group != "Class" {
		t.Fatalf("add of a pending_in key %+v %v", a, err)
	}
	if mustBuddy(t, jo, ivy.Identity()).State != store.Accepted {
		t.Fatal("jo not accepted")
	}
	// Labels can be changed later.
	name, grp := "Joanna", ""
	b, err := ivy.SetBuddyLabels(ctx, "Jo", &name, nil)
	if err != nil || b.Petname != "Joanna" || b.Group != "Class" {
		t.Fatalf("rename %+v %v", b, err)
	}
	if b, err = ivy.SetBuddyLabels(ctx, "Joanna", nil, &grp); err != nil || b.Group != "Buddies" {
		t.Fatalf("regroup %+v %v", b, err)
	}
	bad := "evil\x1b[2J"
	if _, err := ivy.SetBuddyLabels(ctx, "Joanna", &bad, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad petname: %v", err)
	}
}

func TestFirstContactRateLimit(t *testing.T) {
	w := newWire(t)
	kim := w.add(nodeOpts{name: "Kim", burst: 3})
	lee := w.add(nodeOpts{name: "Lee"})
	var frames [][]byte
	for i := range 5 {
		r, err := lee.sealRequest(kim.Identity(), fmt.Sprint("try ", i), "")
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, r.Frames...)
	}
	var limited int
	for _, f := range frames {
		if _, err := kim.HandleFrameFrom(ctx, "mesh", f); errors.Is(err, ErrRateLimited) {
			limited++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if limited != len(frames)-3 {
		t.Fatalf("%d of %d frames limited", limited, len(frames))
	}
	// Another transport has its own bucket.
	r, _ := lee.sealRequest(kim.Identity(), "via ip", "")
	if _, err := kim.HandleFrameFrom(ctx, "ip", r.Frames[0]); err != nil {
		t.Fatal(err)
	}
	st := kim.FirstContactStats()
	if st.RateLimited != uint64(limited) || st.Frames != uint64(len(frames)+1) {
		t.Fatalf("stats %+v", st)
	}
	// Too many requests waiting: a new key is dropped, a known one merged.
	kim.cfg.MaxPendingRequests = 1
	pat := w.add(nodeOpts{name: "Pat"})
	r, _ = pat.sealRequest(kim.Identity(), "me too", "")
	if _, err := kim.HandleFrameFrom(ctx, "ip", r.Frames[0]); !errors.Is(err, ErrTooManyRequests) {
		t.Fatalf("request over the cap: %v", err)
	}
	r, _ = lee.sealRequest(kim.Identity(), "again", "")
	if _, err := kim.HandleFrameFrom(ctx, "ip2", r.Frames[0]); err != nil {
		t.Fatalf("repeat request over the cap: %v", err)
	}
	if st := kim.FirstContactStats(); st.Overflow != 1 || st.Requests != 1 {
		t.Fatalf("stats %+v", st)
	}
	// Junk counts as dropped, and costs a token.
	if _, err := kim.HandleFrameFrom(ctx, "ip3", append([]byte{frame.VerKind(frame.KindFirstContact)}, make([]byte, 150)...)); err == nil {
		t.Fatal("junk accepted")
	}
	if kim.FirstContactStats().Dropped != 1 {
		t.Fatalf("stats %+v", kim.FirstContactStats())
	}
}

func TestRequestsQueueWithoutSink(t *testing.T) {
	dir := tempDir(t)
	if _, err := Init(ctx, initCfg(dir)); err != nil {
		t.Fatal(err)
	}
	n := open(t, dir)
	mia := peer(t, 3)
	a, err := n.AddBuddyWith(ctx, AddBuddyOptions{Key: mia.Public().String()})
	if err != nil || !errors.Is(a.RequestErr, ErrNoSink) || a.Request.State != store.RequestQueued {
		t.Fatalf("add without a sink %+v %v", a, err)
	}
	// No recovery key here: the request carries none.
	rs, _ := n.store.Requests(ctx, a.Buddy.ID)
	id, _ := identity.FromSeed(bytes.Repeat([]byte{3}, 32))
	r := &frame.FirstContactReceiver{Me: id, Dedup: &frame.MemDedup{}}
	res, err := r.Accept(rs[0].Frames[0])
	if err != nil || res.Status != frame.Delivered {
		t.Fatalf("open: %v %v", res.Status, err)
	}
	m, _ := body.Unmarshal(frame.BuddyRequest, res.Message.Inner.Body)
	if len(m.(*pb.BuddyRequest).GetRecoveryKey()) != 0 {
		t.Fatal("request has a recovery key")
	}
	// Attaching a sink and redelivering sends it, the same bytes.
	var got [][]byte
	n.SetFrameSink(sinkFunc(func(_ context.Context, to DeliveryTarget, frames [][]byte) error {
		got = frames
		return nil
	}))
	if sent, err := n.RedeliverRequests(ctx); err != nil || sent != 1 || !bytes.Equal(got[0], rs[0].Frames[0]) {
		t.Fatalf("redeliver %d %v", sent, err)
	}
	// A failing sink leaves it queued with the error recorded.
	n.SetFrameSink(sinkFunc(func(context.Context, DeliveryTarget, [][]byte) error { return errors.New("radio unplugged") }))
	if sent, _ := n.RedeliverRequests(ctx); sent != 0 {
		t.Fatal("failed delivery counted")
	}
	rs, _ = n.store.Requests(ctx, a.Buddy.ID)
	if rs[0].Attempts != 2 || rs[0].LastError != "radio unplugged" || rs[0].State != store.RequestSent {
		t.Fatalf("request after failure %+v", rs[0])
	}
}

type sinkFunc func(context.Context, DeliveryTarget, [][]byte) error

func (f sinkFunc) Deliver(ctx context.Context, to DeliveryTarget, frames [][]byte) error {
	return f(ctx, to, frames)
}
