package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/aghman/openaim/internal/handle"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/invite"
	"github.com/aghman/openaim/internal/store"
)

// fakeDNS plays the _openaim TXT zone for two DoH resolvers on loopback.
type fakeDNS struct {
	t       *testing.T
	a, b    *httptest.Server
	mu      sync.Mutex
	records map[string]*handle.Record // by handle
	failB   bool                      // resolver b answers SERVFAIL
	delay   time.Duration
	hold    chan struct{} // if set, requests wait for it (or cancellation)

	requests, inflight, maxInflight atomic.Int64
}

func newFakeDNS(t *testing.T) *fakeDNS {
	f := &fakeDNS{t: t, records: map[string]*handle.Record{}}
	f.a = httptest.NewTLSServer(f.handler(false))
	f.b = httptest.NewTLSServer(f.handler(true))
	t.Cleanup(f.a.Close)
	t.Cleanup(f.b.Close)
	return f
}

// verifier verifies against the fake zone only; HTTPS proofs never find an
// address.
func (f *fakeDNS) verifier() *handle.Verifier {
	return &handle.Verifier{
		Resolvers: []string{f.a.URL, f.b.URL},
		Client:    f.a.Client(), // httptest TLS servers share one certificate
		Proof: handle.ProofConfig{LookupIP: func(context.Context, string) ([]netip.Addr, error) {
			return nil, handle.ErrNotFound
		}},
	}
}

// publish points h at signer's key (nil removes the record).
func (f *fakeDNS) publish(h string, signer *identity.Identity, inbox string) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if signer == nil {
		delete(f.records, h)
		return
	}
	r, err := handle.NewRecord(signer, h, time.Unix(1767225600, 0), inbox)
	if err != nil {
		f.t.Fatal(err)
	}
	f.records[h] = r
}

func (f *fakeDNS) setFailB(v bool) {
	f.mu.Lock()
	f.failB = v
	f.mu.Unlock()
}

func (f *fakeDNS) handler(isB bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		cur := f.inflight.Add(1)
		defer f.inflight.Add(-1)
		for {
			m := f.maxInflight.Load()
			if cur <= m || f.maxInflight.CompareAndSwap(m, cur) {
				break
			}
		}
		f.mu.Lock()
		delay, hold, failB := f.delay, f.hold, f.failB
		f.mu.Unlock()
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		time.Sleep(delay)
		body, _ := io.ReadAll(r.Body)
		var q dnsmessage.Message
		if err := q.Unpack(body); err != nil || len(q.Questions) != 1 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		qq := q.Questions[0]
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: dnsmessage.RCodeNameError},
			Questions: q.Questions,
		}
		name := strings.ToLower(qq.Name.String())
		f.mu.Lock()
		rec, ok := f.records[strings.TrimSuffix(strings.TrimPrefix(name, "_openaim."), ".")]
		f.mu.Unlock()
		switch {
		case isB && failB:
			resp.RCode = dnsmessage.RCodeServerFailure
		case ok && strings.HasPrefix(name, "_openaim.") && qq.Type == dnsmessage.TypeTXT:
			resp.RCode = dnsmessage.RCodeSuccess
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.TXTResource{TXT: rec.TXTStrings()},
			}}
		}
		b, err := resp.Pack()
		if err != nil {
			f.t.Errorf("pack: %v", err)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(b)
	}
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var t0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// handleNode is an initialized node wired to a fake zone and clock.
type handleNode struct {
	*Node
	dir   string
	dns   *fakeDNS
	clock *fakeClock
	loop  bool
}

// newHandleNode opens a node with the re-check loop off, so tests drive
// RecheckDueHandles themselves; loopNode leaves the loop on.
func newHandleNode(t *testing.T) *handleNode { return openHandleNode(t, false) }

func loopNode(t *testing.T) *handleNode { return openHandleNode(t, true) }

func openHandleNode(t *testing.T, loop bool) *handleNode {
	t.Helper()
	dir := tempDir(t)
	if _, err := Init(ctx, initCfg(dir)); err != nil {
		t.Fatal(err)
	}
	h := &handleNode{dir: dir, dns: newFakeDNS(t), clock: &fakeClock{t: t0}, loop: loop}
	h.Node = h.reopen(t)
	return h
}

// reopen opens the data dir again with the same zone and clock. The caller
// closes the previous node first.
func (h *handleNode) reopen(t *testing.T) *Node {
	t.Helper()
	n, err := Open(ctx, Config{
		DataDir: h.dir, Passphrase: testPass, KeystoreParams: fast, Now: h.clock.Now,
		HandleVerifier: h.dns.verifier(), HandleRegistry: "Example.com", HandleCheckConcurrency: 2,
		DisableHandleLoop: !h.loop,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func (h *handleNode) check(t *testing.T, id int64) store.HandleCheck {
	t.Helper()
	c, err := h.store.HandleCheck(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func within(t *testing.T, what string, got, from time.Time, lo, hi time.Duration) {
	t.Helper()
	if got.Before(from.Add(lo)) || got.After(from.Add(hi)) {
		t.Fatalf("%s %v: want %v + [%v, %v]", what, got, from, lo, hi)
	}
}

// nextEvent waits for an event.
func nextEvent(t *testing.T, sub *Subscription) Event {
	t.Helper()
	select {
	case e, ok := <-sub.C:
		if !ok {
			t.Fatalf("subscription ended: %v", sub.Err())
		}
		return e
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

func noEvent(t *testing.T, sub *Subscription) {
	t.Helper()
	select {
	case e := <-sub.C:
		t.Fatalf("unexpected event %v %+v", e.Kind, e.HandleCheck)
	default:
	}
}

const alice = "alice.example.com"

func TestAddBuddyByHandlePins(t *testing.T) {
	h := newHandleNode(t)
	bob := peer(t, 2)
	h.dns.publish(alice, bob, "/dns/inbox.example.com/tcp/4001")
	sub := h.Subscribe()
	defer sub.Close()

	a, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: " @Alice.Example.COM. ", Group: "Friends"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Buddy.Key != bob.Public() || a.Buddy.Handle != alice || a.Buddy.Group != "Friends" || a.Buddy.State != store.PendingOut || a.HandleDropped != nil {
		t.Fatalf("added %+v", a)
	}
	c := h.check(t, a.Buddy.ID)
	if c.Status != store.HandleVerified || c.LastResult != store.HandleVerified || !c.CheckedAt.Equal(t0) || !c.VerifiedAt.Equal(t0) ||
		c.InboxHint != "/dns/inbox.example.com/tcp/4001" || c.MovedKey != nil || c.Error != "" {
		t.Fatalf("check %+v", c)
	}
	within(t, "next check", c.NextCheck, t0, 26*day, 34*day)
	// The request goes to the verified record's inbox hint.
	if a.Request == nil || a.Request.ContactHint != "/dns/inbox.example.com/tcp/4001" || !errors.Is(a.RequestErr, ErrNoSink) {
		t.Fatalf("request %+v %v", a.Request, a.RequestErr)
	}
	if e := nextEvent(t, sub); e.Kind != EventBuddyAdded || e.Buddy.Handle != alice || e.HandleCheck == nil || e.HandleCheck.Status != store.HandleVerified {
		t.Fatalf("event %+v", e)
	}

	// Short display under the configured registry, and lookup by it.
	if got := h.DisplayName(a.Buddy); got != "alice" {
		t.Fatalf("display name %q", got)
	}
	if got := h.ShortHandle("bob.sub.example.com"); got != "bob.sub.example.com" {
		t.Fatalf("deep handle shortened to %q", got)
	}
	if b, err := h.FindBuddy(ctx, "Alice"); err != nil || b.ID != a.Buddy.ID {
		t.Fatalf("find by short handle: %v %v", b.ID, err)
	}

	// Adding the same key again, by handle or by key, is a duplicate.
	if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: alice}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate by handle: %v", err)
	}
	if _, err := h.AddBuddy(ctx, bob.Public().String(), "", ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate by key: %v", err)
	}

	// Handles that don't verify add nothing.
	if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: "nobody.example.com"}); !errors.Is(err, ErrHandleUnverified) {
		t.Fatalf("no record: %v", err)
	}
	h.dns.publish("carol.example.com", peer(t, 3), "")
	h.dns.setFailB(true)
	if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: "carol.example.com"}); !errors.Is(err, ErrHandleUnreachable) {
		t.Fatalf("resolver failure: %v", err)
	}
	h.dns.setFailB(false)
	for _, bad := range []string{"not a handle", "10.0.0.1", "xn--80ak6aa92e.com"} {
		if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: bad}); !errors.Is(err, ErrInvalid) {
			t.Errorf("handle %q: %v", bad, err)
		}
	}
	if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("neither key nor handle: %v", err)
	}
	// A handle pointing at our own key is refused like our own key.
	h.dns.publish("me.example.com", h.id, "")
	if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: "me.example.com"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("own key by handle: %v", err)
	}
	if all, _ := h.Buddies(ctx); len(all) != 1 {
		t.Fatalf("%d buddies, want 1", len(all))
	}
}

func TestAddByKeyWithClaimedHandle(t *testing.T) {
	h := newHandleNode(t)
	bob, carol := peer(t, 2), peer(t, 3)
	h.dns.publish(alice, bob, "")

	// Carol claims alice's handle: carol is added, the handle isn't.
	a, err := h.AddBuddyWith(ctx, AddBuddyOptions{Key: carol.Public().String(), Handle: alice, Petname: "Carol"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Buddy.Key != carol.Public() || a.Buddy.Handle != "" || a.Check != nil || !errors.Is(a.HandleDropped, ErrHandleUnverified) {
		t.Fatalf("mismatch: %+v", a)
	}
	if !strings.Contains(a.HandleDropped.Error(), "different key") {
		t.Fatalf("reason: %v", a.HandleDropped)
	}
	if _, err := h.store.HandleCheck(ctx, a.Buddy.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("check stored for dropped handle: %v", err)
	}

	// An unreachable lookup drops the handle too, but still adds the key.
	h.dns.publish("dave.example.com", peer(t, 4), "")
	h.dns.setFailB(true)
	a, err = h.AddBuddyWith(ctx, AddBuddyOptions{Key: peer(t, 4).Public().String(), Handle: "dave.example.com"})
	if err != nil || a.Buddy.Handle != "" || !errors.Is(a.HandleDropped, ErrHandleUnreachable) {
		t.Fatalf("unreachable claim: %+v %v", a, err)
	}
	h.dns.setFailB(false)

	// Bob with his own handle keeps it.
	a, err = h.AddBuddyWith(ctx, AddBuddyOptions{Key: bob.Public().String(), Handle: "ALICE.example.com"})
	if err != nil || a.Buddy.Handle != alice || a.HandleDropped != nil || a.Check == nil || a.Check.Status != store.HandleVerified {
		t.Fatalf("matching claim: %+v %v", a, err)
	}
	// A malformed claimed handle is a bad request, not a silent drop.
	if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{Key: peer(t, 5).Public().String(), Handle: "bad handle"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed claim: %v", err)
	}
}

func TestAddByInviteWithHandle(t *testing.T) {
	h := newHandleNode(t)
	erin := peer(t, 6)
	h.dns.publish("erin.example.com", erin, "/dns/inbox.example.com/tcp/4001/p2p/"+testPeerID(t, 9))
	circuit := "/dns4/relay.example.net/tcp/4001/p2p/" + testPeerID(t, 1) + "/p2p-circuit"
	link := invite.Invite{Key: erin.Public(), Handle: "erin.example.com", Contact: circuit}.String()
	// The handle and key must agree with the link.
	if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{Invite: link, Handle: "other.example.com"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("conflicting handle: %v", err)
	}
	a, err := h.AddBuddyWith(ctx, AddBuddyOptions{Invite: link})
	if err != nil || a.Buddy.Key != erin.Public() || a.Buddy.Handle != "erin.example.com" || a.Check == nil {
		t.Fatalf("add by invite with handle %+v %v", a, err)
	}
	// The invite's contact hint wins over the record's inbox hint.
	if a.Request.ContactHint != circuit {
		t.Fatalf("contact hint %q", a.Request.ContactHint)
	}
	// A claimed handle that proves another key is dropped, as for a key.
	frank := peer(t, 7)
	link = invite.Invite{Key: frank.Public(), Handle: "erin.example.com"}.String()
	if a, err = h.AddBuddyWith(ctx, AddBuddyOptions{Invite: link}); err != nil || a.Buddy.Handle != "" || !errors.Is(a.HandleDropped, ErrHandleUnverified) {
		t.Fatalf("invite claiming someone's handle %+v %v", a, err)
	}
}

func TestRecheckMovedWarnsAndKeepsPin(t *testing.T) {
	h := newHandleNode(t)
	bob, carol := peer(t, 2), peer(t, 3)
	h.dns.publish(alice, bob, "/ip4/192.0.2.1/tcp/4001")
	a, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: alice})
	if err != nil {
		t.Fatal(err)
	}
	sub := h.Subscribe()
	defer sub.Close()

	// Not due yet: nothing is checked.
	before := h.dns.requests.Load()
	h.clock.Add(20 * day)
	if n, err := h.RecheckDueHandles(ctx); err != nil || n != 0 || h.dns.requests.Load() != before {
		t.Fatalf("early sweep: %d %v", n, err)
	}

	// The handle moves to carol's key.
	h.dns.publish(alice, carol, "/ip4/198.51.100.1/tcp/4001")
	h.clock.Add(15 * day)
	now := h.clock.Now()
	if n, err := h.RecheckDueHandles(ctx); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if e := nextEvent(t, sub); e.Kind != EventBuddyChanged || e.HandleCheck.Status != store.HandleMoved {
		t.Fatalf("first event %v %+v", e.Kind, e.HandleCheck)
	}
	e := nextEvent(t, sub)
	if e.Kind != EventBuddyHandleWarning || e.Buddy.Key != bob.Public() || *e.HandleCheck.MovedKey != carol.Public() {
		t.Fatalf("warning %v %+v", e.Kind, e.HandleCheck)
	}
	c := h.check(t, a.Buddy.ID)
	if c.Status != store.HandleMoved || c.LastResult != store.HandleMoved || *c.MovedKey != carol.Public() ||
		!c.VerifiedAt.Equal(t0) || c.InboxHint != "/ip4/192.0.2.1/tcp/4001" || !strings.Contains(c.Error, "different key") {
		t.Fatalf("check %+v", c)
	}
	within(t, "retry", c.NextCheck, now, 20*time.Hour, 28*time.Hour)
	// The pin never changes, and frames still go to bob's key.
	if b, err := h.store.Buddy(ctx, a.Buddy.ID); err != nil || b.Key != bob.Public() || b.Handle != alice {
		t.Fatalf("buddy after move %+v %v", b, err)
	}
	if b, err := h.FindBuddy(ctx, alice); err != nil || b.Key != bob.Public() {
		t.Fatalf("find after move %+v %v", b, err)
	}

	// Still moved the next day: the state is refreshed, but no new warning.
	h.clock.Add(2 * day)
	if r, err := h.CheckHandle(ctx, alice); err != nil || r.Result != store.HandleMoved || r.Buddy.Key != bob.Public() {
		t.Fatalf("check now: %+v %v", r, err)
	}
	if e := nextEvent(t, sub); e.Kind != EventBuddyChanged {
		t.Fatalf("event %v", e.Kind)
	}
	noEvent(t, sub)

	// The record is gone: unverified, which warns (a different warning).
	h.dns.publish(alice, nil, "")
	if r, err := h.CheckHandle(ctx, alice); err != nil || r.Result != store.HandleUnverified || r.Check.MovedKey != nil {
		t.Fatalf("unverified: %+v %v", r, err)
	}
	nextEvent(t, sub)
	if e := nextEvent(t, sub); e.Kind != EventBuddyHandleWarning || e.HandleCheck.Status != store.HandleUnverified {
		t.Fatalf("warning %v %+v", e.Kind, e.HandleCheck)
	}

	// Fixed: back to verified, warning cleared, a month until the next.
	h.dns.publish(alice, bob, "/ip4/192.0.2.9/tcp/4001")
	now = h.clock.Now()
	r, err := h.CheckHandle(ctx, alice)
	if err != nil || r.Result != store.HandleVerified || r.Check.Status != store.HandleVerified || r.Check.Error != "" ||
		r.Check.MovedKey != nil || !r.Check.VerifiedAt.Equal(now) || r.Check.InboxHint != "/ip4/192.0.2.9/tcp/4001" {
		t.Fatalf("verified again: %+v %v", r, err)
	}
	within(t, "recheck", r.Check.NextCheck, now, 26*day, 34*day)
	if e := nextEvent(t, sub); e.Kind != EventBuddyChanged {
		t.Fatalf("event %v", e.Kind)
	}
	noEvent(t, sub)
}

func TestRecheckUnreachableKeepsStatus(t *testing.T) {
	h := newHandleNode(t)
	bob := peer(t, 2)
	h.dns.publish(alice, bob, "")
	a, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: alice})
	if err != nil {
		t.Fatal(err)
	}
	sub := h.Subscribe()
	defer sub.Close()

	// Even with a moved record, a failing resolver means "can't tell".
	h.dns.publish(alice, peer(t, 3), "")
	h.dns.setFailB(true)
	h.clock.Add(40 * day)
	now := h.clock.Now()
	if n, err := h.RecheckDueHandles(ctx); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	c := h.check(t, a.Buddy.ID)
	if c.Status != store.HandleVerified || c.LastResult != store.HandleUnreachable || c.MovedKey != nil || c.Error == "" || !c.CheckedAt.Equal(now) {
		t.Fatalf("check %+v", c)
	}
	within(t, "retry", c.NextCheck, now, 20*time.Hour, 28*time.Hour)
	if e := nextEvent(t, sub); e.Kind != EventBuddyChanged {
		t.Fatalf("event %v", e.Kind)
	}
	noEvent(t, sub)
}

func TestCheckHandleErrors(t *testing.T) {
	h := newHandleNode(t)
	bob := peer(t, 2)
	if _, err := h.AddBuddy(ctx, bob.Public().String(), "Bob", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CheckHandle(ctx, "Bob"); !errors.Is(err, ErrNoHandle) {
		t.Fatalf("no handle: %v", err)
	}
	if _, err := h.CheckHandle(ctx, "nobody"); !errors.Is(err, ErrUnknownBuddy) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestHandleCheckStateSurvivesRestart(t *testing.T) {
	h := loopNode(t)
	h.dns.publish(alice, peer(t, 2), "/dns/x.example/tcp/1")
	a, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: alice})
	if err != nil {
		t.Fatal(err)
	}
	want := h.check(t, a.Buddy.ID)
	h.Close()

	// Reopened before the check is due: the state and schedule are kept
	// and the loop checks nothing.
	before := h.dns.requests.Load()
	h.clock.Add(10 * day)
	h.Node = h.reopen(t)
	h.WakeHandleChecks()
	got := h.check(t, a.Buddy.ID)
	if got.Status != want.Status || !got.NextCheck.Equal(want.NextCheck) || !got.CheckedAt.Equal(want.CheckedAt) || got.InboxHint != want.InboxHint {
		t.Fatalf("after restart %+v, want %+v", got, want)
	}
	if n, ok, err := h.store.NextHandleCheck(ctx); err != nil || !ok || !n.Equal(want.NextCheck) {
		t.Fatalf("schedule %v %v %v", n, ok, err)
	}
	time.Sleep(50 * time.Millisecond)
	if h.dns.requests.Load() != before {
		t.Fatal("restart re-checked a handle that wasn't due")
	}
	h.Close()

	// Reopened after it is due: the background loop checks it on its own.
	h.dns.publish(alice, peer(t, 3), "")
	h.clock.Add(30 * day)
	h.Node = h.reopen(t)
	sub := h.Subscribe()
	defer sub.Close()
	h.WakeHandleChecks()
	for {
		e := nextEvent(t, sub)
		if e.Kind == EventBuddyHandleWarning {
			if *e.HandleCheck.MovedKey != peer(t, 3).Public() || e.Buddy.Key != peer(t, 2).Public() {
				t.Fatalf("warning %+v", e.HandleCheck)
			}
			break
		}
	}
}

func TestRecheckConcurrencyBounded(t *testing.T) {
	h := newHandleNode(t) // HandleCheckConcurrency: 2
	const buddies = 6
	for i := range buddies {
		hn := fmt.Sprintf("b%d.example.com", i)
		h.dns.publish(hn, peer(t, byte(10+i)), "")
		if _, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: hn}); err != nil {
			t.Fatal(err)
		}
	}
	h.dns.mu.Lock()
	h.dns.delay = 20 * time.Millisecond
	h.dns.mu.Unlock()
	h.dns.maxInflight.Store(0)
	h.clock.Add(40 * day)
	if n, err := h.RecheckDueHandles(ctx); err != nil || n != buddies {
		t.Fatalf("sweep: %d %v", n, err)
	}
	// Each check asks both resolvers at once, so two checks at a time is
	// at most four requests in flight across the two servers.
	if m := h.dns.maxInflight.Load(); m > 4 || m < 2 {
		t.Fatalf("max in-flight requests %d", m)
	}
	if due, _ := h.store.DueHandleChecks(ctx, h.clock.Now(), 100); len(due) != 0 {
		t.Fatalf("%d still due", len(due))
	}
}

func TestCloseStopsInFlightChecks(t *testing.T) {
	h := loopNode(t)
	h.dns.publish(alice, peer(t, 2), "")
	a, err := h.AddBuddyWith(ctx, AddBuddyOptions{Handle: alice})
	if err != nil {
		t.Fatal(err)
	}
	want := h.check(t, a.Buddy.ID)
	hold := make(chan struct{})
	defer close(hold)
	h.dns.mu.Lock()
	h.dns.hold = hold
	h.dns.mu.Unlock()
	h.clock.Add(40 * day)
	before := h.dns.requests.Load()
	h.WakeHandleChecks()
	for deadline := time.Now().Add(5 * time.Second); h.dns.requests.Load() == before; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("loop never started the check")
		}
	}
	done := make(chan error, 1)
	go func() { done <- h.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung on an in-flight check")
	}
	// The cancelled check stored nothing.
	h.dns.mu.Lock()
	h.dns.hold = nil
	h.dns.mu.Unlock()
	h.Node = h.reopen(t)
	if got := h.check(t, a.Buddy.ID); !got.CheckedAt.Equal(want.CheckedAt) || got.LastResult != store.HandleVerified {
		t.Fatalf("after cancelled check %+v", got)
	}
}

func TestHandleConfig(t *testing.T) {
	dir := tempDir(t)
	if _, err := Init(ctx, initCfg(dir)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{DoHResolvers: []string{"https://1.1.1.1/dns-query"}},
		{DoHResolvers: []string{"https://1.1.1.1/dns-query", "http://9.9.9.9/dns-query"}},
		{DoHResolvers: []string{"https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"}},
		{HandleRegistry: "not a domain"},
	} {
		c.DataDir, c.Passphrase, c.KeystoreParams = dir, testPass, fast
		if n, err := Open(ctx, c); !errors.Is(err, ErrInvalid) {
			if n != nil {
				n.Close()
			}
			t.Errorf("Open(%v %q) = %v", c.DoHResolvers, c.HandleRegistry, err)
		}
	}
	n, err := Open(ctx, Config{DataDir: dir, Passphrase: testPass, KeystoreParams: fast,
		DoHResolvers: []string{"https://a.example/dns-query", "https://b.example/dns-query"}})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if n.Registry() != "" || n.ShortHandle(alice) != alice {
		t.Fatal("shortened without a registry")
	}
	if got := n.verifier.Resolvers; len(got) != 2 || got[0] != "https://a.example/dns-query" {
		t.Fatalf("resolvers %v", got)
	}
}
