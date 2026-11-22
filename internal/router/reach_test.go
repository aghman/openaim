package router

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/frame"
	pb "github.com/aghman/openaim/internal/wirepb"
)

type changeLog struct {
	mu  sync.Mutex
	ids []int64
}

func (c *changeLog) add(id int64) { c.mu.Lock(); c.ids = append(c.ids, id); c.mu.Unlock() }

func (c *changeLog) take() []int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := c.ids
	c.ids = nil
	return ids
}

func TestReachTableOrdering(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var ch changeLog
	tb := NewReachTable()
	tb.OnChange = ch.add
	hint := func(p string, seq uint64, issued, ttl time.Duration) IPHint {
		return IPHint{Peer: peer.ID(p), Seq: seq, IssuedAt: now.Add(issued), ExpiresAt: now.Add(issued + ttl)}
	}

	if _, ok := tb.IPRoute(1, now); ok {
		t.Fatal("route for an unknown buddy")
	}
	if err := tb.Update(1, FromReach, hint("p5", 5, -time.Minute, time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if r, ok := tb.IPRoute(1, now); !ok || r.Peer != "p5" || r.Live {
		t.Fatalf("route %+v %v", r, ok)
	}
	if got := ch.take(); !slices.Equal(got, []int64{1}) {
		t.Fatalf("OnChange %v", got)
	}

	// Lower and equal seq are ignored, even if issued later.
	for _, seq := range []uint64{4, 5} {
		if err := tb.Update(1, FromReach, hint("evil", seq, 0, time.Hour), now); !errors.Is(err, ErrStaleHint) {
			t.Fatalf("seq %d: %v", seq, err)
		}
	}
	// Already expired, or malformed.
	if err := tb.Update(1, FromReach, hint("old", 9, -2*time.Hour, time.Hour), now); !errors.Is(err, ErrExpiredHint) {
		t.Fatalf("expired: %v", err)
	}
	for _, h := range []IPHint{hint("", 9, 0, time.Hour), hint("x", 9, 0, 0)} {
		if err := tb.Update(1, FromReach, h, now); !errors.Is(err, ErrBadHint) {
			t.Fatalf("bad hint %+v: %v", h, err)
		}
	}
	if err := tb.Update(1, FromSession, hint("x", 9, 0, time.Hour), now); !errors.Is(err, ErrBadHint) {
		t.Fatalf("Update with FromSession: %v", err)
	}
	if r, _ := tb.IPRoute(1, now); r.Peer != "p5" {
		t.Fatalf("ignored records changed the route to %s", r.Peer)
	}
	if got := ch.take(); len(got) != 0 {
		t.Fatalf("OnChange for ignored records: %v", got)
	}

	// Sources have their own seq spaces; the record issued last wins.
	if err := tb.Update(1, FromRendezvous, hint("rdv", 1_700_000_000_000, 0, 30*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if r, _ := tb.IPRoute(1, now); r.Peer != "rdv" {
		t.Fatalf("route %s, want the newer rendezvous record", r.Peer)
	}
	if err := tb.Update(1, FromReach, hint("p6", 6, time.Second, time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if r, _ := tb.IPRoute(1, now); r.Peer != "p6" {
		t.Fatalf("route %s, want the newer REACH", r.Peer)
	}

	// Once everything expires there is no route, and the expired records'
	// seqs still block replays.
	later := now.Add(2 * time.Hour)
	if _, ok := tb.IPRoute(1, later); ok {
		t.Fatal("route after every record expired")
	}
	if err := tb.Update(1, FromReach, IPHint{Peer: "p5", Seq: 5, IssuedAt: later, ExpiresAt: later.Add(time.Hour)}, later); !errors.Is(err, ErrStaleHint) {
		t.Fatalf("replay after expiry: %v", err)
	}

	tb.Forget(1)
	if _, ok := tb.IPRoute(1, now); ok {
		t.Fatal("route after Forget")
	}
}

func TestReachTableSessions(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var ch changeLog
	tb := NewReachTable()
	tb.OnChange = ch.add
	addr := ma.StringCast("/ip4/192.0.2.1/udp/4001/quic-v1")
	if err := tb.Update(1, FromReach, IPHint{Peer: "a", Addrs: []ma.Multiaddr{addr}, Seq: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	ch.take()

	tb.Heard(1, "a", now) // the advertised peer: the route stays on it
	r, ok := tb.IPRoute(1, now)
	if !ok || r.Peer != "a" || !r.Live || len(r.Addrs) != 1 || !r.Addrs[0].Equal(addr) {
		t.Fatalf("session route %+v", r)
	}
	tb.Heard(1, "a", now.Add(time.Second))
	if got := ch.take(); len(got) != 0 {
		t.Fatalf("OnChange %v for the peer already routed to", got)
	}
	tb.Heard(1, "b", now.Add(2*time.Second)) // the buddy moved
	if r, _ := tb.IPRoute(1, now); r.Peer != "b" || !r.Live || len(r.Addrs) != 0 {
		t.Fatalf("route %+v", r)
	}
	if got := ch.take(); !slices.Equal(got, []int64{1}) {
		t.Fatalf("OnChange %v", got)
	}

	if ids := tb.SessionUp("a"); !slices.Equal(ids, []int64{1}) {
		t.Fatalf("SessionUp(a) = %v", ids)
	}
	ch.take()
	tb.SessionDown("b")
	if r, _ := tb.IPRoute(1, now); r.Peer != "a" || r.Live {
		t.Fatalf("after the session went down: %+v", r)
	}
	if got := ch.take(); !slices.Equal(got, []int64{1}) {
		t.Fatalf("OnChange on fallback %v", got)
	}

	// A session record expires if not refreshed. Hearing an unknown buddy
	// is a change.
	tb.Heard(2, "c", now)
	if got := ch.take(); !slices.Equal(got, []int64{2}) {
		t.Fatalf("OnChange %v", got)
	}
	if _, ok := tb.IPRoute(2, now.Add(DefaultSessionHintTTL)); ok {
		t.Fatal("session record outlived its TTL")
	}
}

func TestHintFromReach(t *testing.T) {
	_, pub, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	addr := ma.StringCast("/ip6/2001:db8::1/udp/4001/quic-v1")
	r := &pb.Reach{Seq: 7, IssuedAt: 1000, ExpiresAt: 5000, Ip: []*pb.IPHint{
		{PeerId: []byte("not a peer id")},
		{PeerId: []byte(p), Addrs: [][]byte{{0xff, 0xff}, addr.Bytes()}},
	}}
	h, ok := HintFromReach(r)
	if !ok || h.Peer != p || h.Seq != 7 || len(h.Addrs) != 1 || !h.Addrs[0].Equal(addr) {
		t.Fatalf("hint %+v %v", h, ok)
	}
	if !h.IssuedAt.Equal(frame.TimeOf(1000)) || !h.ExpiresAt.Equal(frame.TimeOf(5000)) {
		t.Fatalf("times %v %v", h.IssuedAt, h.ExpiresAt)
	}
	if _, ok := HintFromReach(&pb.Reach{Seq: 1, IssuedAt: 1, ExpiresAt: 2}); ok {
		t.Fatal("hint from a REACH without IP hints")
	}
}
