package router

import (
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/frame"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Source is where an IP reachability record came from (design §7.1).
type Source uint8

const (
	// FromSession: a fresh, authenticated frame from the buddy arrived over
	// a live /openaim/msg/1 session from this peer (not a duplicate).
	FromSession Source = iota + 1
	// FromReach: an IP hint in a REACH (or BUDDY_ACCEPT) body from the buddy.
	FromReach
	// FromRendezvous: a decrypted, verified rendezvous record.
	FromRendezvous
)

func (s Source) String() string {
	switch s {
	case FromSession:
		return "session"
	case FromReach:
		return "reach"
	case FromRendezvous:
		return "rendezvous"
	}
	return "unknown"
}

// IPHint is one IP reachability record for a buddy. Records from one source
// are ordered by Seq, which is that source's own counter (a REACH seq, a
// rendezvous record's signing time).
type IPHint struct {
	Peer      peer.ID
	Addrs     []ma.Multiaddr
	Seq       uint64
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// HintFromReach converts the first usable IP hint of a validated REACH body.
// It reports false if the body has none.
func HintFromReach(r *pb.Reach) (IPHint, bool) {
	for _, h := range r.GetIp() {
		p, err := peer.IDFromBytes(h.GetPeerId())
		if err != nil {
			continue
		}
		hint := IPHint{Peer: p, Seq: r.GetSeq(),
			IssuedAt: frame.TimeOf(r.GetIssuedAt()), ExpiresAt: frame.TimeOf(r.GetExpiresAt())}
		for _, a := range h.GetAddrs() {
			if m, err := ma.NewMultiaddrBytes(a); err == nil {
				hint.Addrs = append(hint.Addrs, m)
			}
		}
		return hint, true
	}
	return IPHint{}, false
}

// Reasons Update ignores a record.
var (
	ErrStaleHint   = errors.New("router: reachability record not newer than one held")
	ErrExpiredHint = errors.New("router: reachability record expired")
	ErrBadHint     = errors.New("router: malformed reachability record")
)

// DefaultSessionHintTTL is how long a FromSession record lasts without
// hearing the buddy again, in case a session-down event was missed.
const DefaultSessionHintTTL = 30 * time.Minute

// ReachTable holds buddies' IP reachability (design §7.1) and implements
// Reachability. It must be fed only from authenticated content: Heard for
// fresh frames over a session, Update for REACH bodies and rendezvous
// records. A record with a seq not above the highest already seen from its
// source, or past its expiry, is ignored, so replaying old records is
// useless. It is safe for concurrent use.
type ReachTable struct {
	// OnChange, if set, is called (outside the table's lock) when a buddy's
	// reachability is updated: after every accepted Update, when Heard
	// moves the buddy's route to another peer, and from SessionUp and
	// SessionDown.
	// Wire it to Router.RouteChanged.
	OnChange func(buddyID int64)
	// SessionTTL defaults to DefaultSessionHintTTL.
	SessionTTL time.Duration

	mu      sync.Mutex
	buddies map[int64]*reachEntry
}

type reachEntry struct {
	recs   map[Source]IPHint
	maxSeq map[Source]uint64 // highest seq seen per source, kept after expiry
}

// NewReachTable returns an empty table.
func NewReachTable() *ReachTable { return &ReachTable{buddies: map[int64]*reachEntry{}} }

var _ Reachability = (*ReachTable)(nil)

func (t *ReachTable) entry(id int64) *reachEntry {
	e := t.buddies[id]
	if e == nil {
		e = &reachEntry{recs: map[Source]IPHint{}, maxSeq: map[Source]uint64{}}
		t.buddies[id] = e
	}
	return e
}

func (t *ReachTable) changed(ids ...int64) {
	if t.OnChange == nil {
		return
	}
	for _, id := range ids {
		t.OnChange(id)
	}
}

// Update records an advertised hint (FromReach or FromRendezvous) for the
// buddy at now. It returns nil if the record was accepted.
func (t *ReachTable) Update(buddyID int64, src Source, h IPHint, now time.Time) error {
	if src != FromReach && src != FromRendezvous {
		return ErrBadHint
	}
	if h.Peer == "" || !h.ExpiresAt.After(h.IssuedAt) {
		return ErrBadHint
	}
	if !h.ExpiresAt.After(now) {
		return ErrExpiredHint
	}
	t.mu.Lock()
	e := t.entry(buddyID)
	if max, ok := e.maxSeq[src]; ok && h.Seq <= max {
		t.mu.Unlock()
		return ErrStaleHint
	}
	e.maxSeq[src] = h.Seq
	h.Addrs = slices.Clone(h.Addrs)
	e.recs[src] = h
	t.mu.Unlock()
	t.changed(buddyID)
	return nil
}

// Heard records that a fresh (not duplicate) authenticated frame from the
// buddy arrived over a session with p at now.
func (t *ReachTable) Heard(buddyID int64, p peer.ID, now time.Time) {
	ttl := t.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionHintTTL
	}
	t.mu.Lock()
	e := t.entry(buddyID)
	before, had := e.route(now)
	e.recs[FromSession] = IPHint{Peer: p, IssuedAt: now, ExpiresAt: now.Add(ttl)}
	t.mu.Unlock()
	if !had || before.Peer != p {
		t.changed(buddyID)
	}
}

// SessionUp reports buddies with any record naming p, so their queues can
// be flushed (design §7.2 rule 5), and calls OnChange for each.
func (t *ReachTable) SessionUp(p peer.ID) []int64 {
	t.mu.Lock()
	var ids []int64
	for id, e := range t.buddies {
		for _, r := range e.recs {
			if r.Peer == p {
				ids = append(ids, id)
				break
			}
		}
	}
	t.mu.Unlock()
	slices.Sort(ids)
	t.changed(ids...)
	return ids
}

// SessionDown forgets FromSession records naming p. OnChange is called for
// buddies that still have another record to fall back on.
func (t *ReachTable) SessionDown(p peer.ID) {
	t.mu.Lock()
	var ids []int64
	for id, e := range t.buddies {
		if r, ok := e.recs[FromSession]; ok && r.Peer == p {
			delete(e.recs, FromSession)
			if len(e.recs) > 0 {
				ids = append(ids, id)
			}
		}
	}
	t.mu.Unlock()
	slices.Sort(ids)
	t.changed(ids...)
}

// Forget drops everything known about a buddy (removed or blocked).
func (t *ReachTable) Forget(buddyID int64) {
	t.mu.Lock()
	delete(t.buddies, buddyID)
	t.mu.Unlock()
}

// IPRoute returns the buddy's route at now: the live session if there is
// one, else the unexpired advertised record issued last.
func (t *ReachTable) IPRoute(buddyID int64, now time.Time) (Route, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.buddies[buddyID]
	if e == nil {
		return Route{}, false
	}
	return e.route(now)
}

func (e *reachEntry) route(now time.Time) (Route, bool) {
	for src, r := range e.recs {
		if !r.ExpiresAt.After(now) {
			delete(e.recs, src) // maxSeq stays, so it can't be replayed
		}
	}
	var best IPHint
	found := false
	for _, src := range []Source{FromReach, FromRendezvous} {
		if r, ok := e.recs[src]; ok && (!found || r.IssuedAt.After(best.IssuedAt)) {
			best, found = r, true
		}
	}
	if s, ok := e.recs[FromSession]; ok {
		// The live session wins; borrow advertised addresses for its peer,
		// so the stream can be reopened if the connection drops.
		rt := Route{Peer: s.Peer, Live: true}
		for _, src := range []Source{FromReach, FromRendezvous} {
			if r, ok := e.recs[src]; ok && r.Peer == s.Peer && len(r.Addrs) > 0 {
				rt.Addrs = slices.Clone(r.Addrs)
				break
			}
		}
		return rt, true
	}
	if !found {
		return Route{}, false
	}
	return Route{Peer: best.Peer, Addrs: slices.Clone(best.Addrs)}, true
}
