package daemon

import (
	"context"
	"errors"
	"time"

	lpeer "github.com/libp2p/go-libp2p/core/peer"

	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/rendezvous"
	"github.com/aghman/openaim/internal/router"
)

// Rendezvous lookups (spec/dht-records.md): for each accepted buddy without
// a live session we look up their record on a schedule, backing off from
// LookupMin to LookupMax while they stay unreachable, and at once (spaced
// by lookupSpacing) when a message is queued for them. A record found goes
// to the reach table, and we announce ourselves to the peer it names.

// lookupLoop starts the lookups that are due.
func (s *netState) lookupLoop() {
	defer s.wg.Done()
	for {
		now := s.n.now()
		wake := now.Add(s.o.LookupMax)
		type job struct {
			id int64
			k  identity.PublicKey
		}
		var due []job
		s.mu.Lock()
		for id, l := range s.lookups {
			switch {
			case l.running:
			case !now.Before(l.next):
				l.running, l.last = true, now
				due = append(due, job{id, l.key})
			case l.next.Before(wake):
				wake = l.next
			}
		}
		s.mu.Unlock()
		for _, j := range due {
			if !s.goBackground(func(ctx context.Context) { s.scheduledLookup(ctx, j.id, j.k) }) {
				s.finishLookup(j.id, false)
			}
		}
		t := time.NewTimer(max(wake.Sub(now), 50*time.Millisecond))
		select {
		case <-t.C:
		case <-s.kick:
		case <-s.ctx.Done():
			t.Stop()
			return
		}
		t.Stop()
	}
}

// scheduledLookup looks the buddy up unless a live session makes it moot.
func (s *netState) scheduledLookup(ctx context.Context, id int64, k identity.PublicKey) {
	if s.liveRoute(id) {
		s.finishLookup(id, true)
		return
	}
	_, err := s.lookup(ctx, id, k)
	if err != nil && ctx.Err() == nil {
		s.log.Debug("rendezvous lookup", "buddy", k.KeyID(), "err", err)
	}
	s.finishLookup(id, false)
}

// finishLookup schedules the buddy's next lookup: after LookupMax while a
// session is live, else after the backoff, which doubles.
func (s *netState) finishLookup(id int64, live bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.lookups[id]
	if l == nil {
		return
	}
	l.running = false
	now := s.n.now()
	if live {
		l.backoff = s.o.LookupMin
		l.next = now.Add(s.o.LookupMax)
		return
	}
	l.next = now.Add(l.backoff)
	l.backoff = min(2*l.backoff, s.o.LookupMax)
}

// lookupSoon asks for a lookup of the buddy now, unless one ran in the last
// lookupSpacing.
func (s *netState) lookupSoon(id int64) {
	s.mu.Lock()
	l := s.lookups[id]
	if l != nil && !l.running && s.n.now().Sub(l.last) >= lookupSpacing {
		l.next = s.n.now()
	}
	s.mu.Unlock()
	s.wakeLookups()
}

func (s *netState) wakeLookups() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// lookup finds the buddy's rendezvous record, feeds it to the reach table
// and, unless a session with them is live already, announces us to the peer
// it names.
func (s *netState) lookup(ctx context.Context, id int64, k identity.PublicKey) (rendezvous.Found, error) {
	p, err := s.n.pair(k)
	if err != nil {
		return rendezvous.Found{}, err
	}
	lctx, cancel := context.WithTimeout(ctx, s.o.LookupTimeout)
	f, err := rendezvous.Lookup(lctx, s.dht, p.Recv, s.n.now())
	cancel()
	if err != nil {
		return f, err
	}
	h := router.IPHint{Peer: f.ID, Addrs: f.Addrs, Seq: f.Seq, IssuedAt: f.IssuedAt, ExpiresAt: f.ExpiresAt}
	if err := s.rch.Update(id, router.FromRendezvous, h, s.n.now()); err != nil && !errors.Is(err, router.ErrStaleHint) {
		return f, err
	}
	s.attribute(id, k, f.ID, false)
	if !s.liveRoute(id) {
		ai := f.AddrInfo()
		if err := s.announce(ctx, id, k, &ai); err != nil && ctx.Err() == nil {
			s.log.Debug("announce after lookup", "buddy", k.KeyID(), "peer", f.ID, "err", err)
		}
	}
	return f, nil
}

// LookupBuddy looks an accepted buddy up in the DHT now and returns where
// their rendezvous record says they are. The result also feeds the router,
// and we announce ourselves there unless a session with them is live.
func (n *Node) LookupBuddy(ctx context.Context, sel string) (lpeer.AddrInfo, error) {
	s := n.net
	if s == nil {
		return lpeer.AddrInfo{}, ErrOffline
	}
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return lpeer.AddrInfo{}, err
	}
	f, err := s.lookup(ctx, b.ID, b.Key)
	if err != nil {
		return lpeer.AddrInfo{}, err
	}
	return f.AddrInfo(), nil
}
