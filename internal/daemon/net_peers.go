package daemon

import (
	"context"
	"errors"
	"slices"
	"time"

	lpeer "github.com/libp2p/go-libp2p/core/peer"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/presence"
	"github.com/aghman/openaim/internal/router"
	"github.com/aghman/openaim/internal/store"
	"github.com/aghman/openaim/internal/transport/ip"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Which buddy a libp2p peer belongs to is decided only from authenticated
// frame content (design §7.1): a fresh frame from the buddy over a session
// with the peer, or the buddy's REACH or rendezvous record naming it. The
// sessions themselves know nothing about buddies.
//
// For each accepted buddy we keep (ip.Sessions.Keep) a session with the
// peer we last heard them on, so a relay reset reconnects at once and
// presence doesn't flap; it is dropped when they go offline or move to a
// new peer ID.

// handleFrame is the one inbound path: HandleFrameFrom, and every frame
// from the network (from is the sending peer, or "" when unknown).
func (n *Node) handleFrame(ctx context.Context, transport string, from lpeer.ID, b []byte) (frame.Result, error) {
	if len(b) > 0 && b[0]>>5 == frame.Version {
		switch frame.Kind(b[0] & 0x1F) {
		case frame.KindFirstContact, frame.KindFirstContactIP:
			return n.handleFirstContact(ctx, transport, b)
		}
	}
	res, err := n.recv.Accept(b)
	if err != nil {
		return res, err
	}
	k := res.Conv.(identity.PublicKey)
	s := n.net
	var id int64
	if s != nil {
		if id, err = s.idOf(ctx, k); err != nil {
			return res, err // removed meanwhile
		}
		if from != "" && res.Status != frame.Duplicate {
			s.heard(id, k, from)
		}
	}
	if res.Status != frame.Delivered {
		if s != nil {
			s.rt.Received(ctx, id, res) // ACK what we hold
		}
		return res, nil
	}
	handled, err := n.receiveMessage(ctx, k, id, res.Message)
	if s != nil && handled {
		// After the message is stored: an ACK means "kept", and the router
		// applies ACK bodies itself.
		s.rt.Received(ctx, id, res)
	}
	return res, err
}

// receiveMessage handles a delivered DATA message from buddy k (store ID
// id when the network runs). It reports whether the message was dealt with
// for good, so it may be acked: false means a local failure (the store),
// and the sender's retry gets another chance.
func (n *Node) receiveMessage(ctx context.Context, k identity.PublicKey, id int64, m *frame.Message) (bool, error) {
	switch m.Inner.Type {
	case frame.IM:
		return n.receiveIM(ctx, k, m)
	case frame.BuddyAccept:
		err := n.receiveAccept(ctx, k, m.Inner)
		if s := n.net; s != nil && err == nil {
			if msg, uerr := body.Unmarshal(frame.BuddyAccept, m.Inner.Body); uerr == nil {
				if r := msg.(*pb.BuddyAccept).GetReach(); r != nil {
					s.updateReach(id, k, r)
				}
			}
		}
		return err == nil || errors.Is(err, body.ErrInvalid) || errors.Is(err, ErrNotPending), err
	case frame.BuddyRequest:
		n.fcStats.dataRequests.Add(1)
		n.log.Warn("dropping BUDDY_REQUEST in a DATA frame", "buddy", k.KeyID())
		return true, ErrRequestInData
	}
	if s := n.net; s != nil {
		return s.receiveControl(ctx, k, id, m)
	}
	n.log.Debug("dropping unhandled content type", "buddy", k.KeyID(), "type", m.Inner.Type)
	return true, nil
}

// receiveIM stores a delivered IM and tells clients.
func (n *Node) receiveIM(ctx context.Context, k identity.PublicKey, m *frame.Message) (bool, error) {
	if _, err := body.IMText(m.Inner.Body); err != nil {
		return true, err
	}
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	bd, err := n.store.BuddyByKey(ctx, k)
	if err != nil {
		return false, err
	}
	at := n.now()
	fresh, err := n.store.SaveIncoming(ctx, bd.ID, m, at)
	if err != nil {
		return false, err
	}
	if fresh {
		msg := incomingMessage(k, m.MsgID, m.Inner, time.UnixMilli(at.UnixMilli()))
		n.events.publish(Event{Kind: EventMessageReceived, Message: &msg})
	}
	return true, nil
}

// receiveControl handles the content types that only matter with a
// network: presence, away messages, profile requests and REACH. ACKs are
// applied by the router (Received).
func (s *netState) receiveControl(_ context.Context, k identity.PublicKey, id int64, m *frame.Message) (bool, error) {
	ct := m.Inner.Type
	switch ct {
	case frame.Ack:
		return true, nil
	case frame.Presence, frame.AwayMsg, frame.ProfileReq, frame.Reach:
	default:
		s.log.Debug("dropping unhandled content type", "buddy", k.KeyID(), "type", ct)
		return true, nil
	}
	msg, err := body.Unmarshal(ct, m.Inner.Body)
	if err != nil {
		return true, err
	}
	switch v := msg.(type) {
	case *pb.Presence:
		err = s.pres.Received(k, presence.StampOf(m.Inner), v)
	case *pb.AwayMsg:
		err = s.pres.ReceivedAwayMsg(k, v)
	case *pb.ProfileReq:
		if v.GetAwayMsg() {
			var reply *pb.AwayMsg
			if reply, err = s.pres.AwayReply(k); err == nil {
				s.sendLater(id, k, reply)
			}
		}
	case *pb.Reach:
		s.updateReach(id, k, v)
		s.n.writeMu.Lock()
		if b, berr := s.n.store.Buddy(s.ctx, id); berr == nil {
			err = s.n.updatePeer(s.ctx, b, store.PeerUpdate{}, v, s.n.now())
		}
		s.n.writeMu.Unlock()
	}
	switch {
	case err == nil, errors.Is(err, presence.ErrStale), errors.Is(err, presence.ErrNotAccepted), errors.Is(err, presence.ErrClosed):
		return true, nil
	case errors.Is(err, body.ErrInvalid):
		return true, err
	}
	return false, err
}

// heard records a fresh authenticated frame from buddy (id, k) over a
// session with p.
func (s *netState) heard(id int64, k identity.PublicKey, p lpeer.ID) {
	s.rch.Heard(id, p, s.n.now())
	s.attribute(id, k, p, true)
	s.mu.Lock()
	if l := s.lookups[id]; l != nil {
		l.backoff = s.o.LookupMin // live: no lookups needed now
	}
	s.mu.Unlock()
}

// attribute records that peer p belongs to buddy (id, k). live means we
// just heard them on it: for an accepted buddy it becomes the peer we keep
// a session with. If a session with p is up, presence is told.
func (s *netState) attribute(id int64, k identity.PublicKey, p lpeer.ID, live bool) {
	if p == "" {
		return
	}
	_, accepted := s.pres.Buddy(k)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.peerOf[p] = k
	ps := s.peers[k]
	if i := slices.Index(ps, p); i != 0 {
		if i > 0 {
			ps = slices.Delete(ps, i, i+1)
		}
		ps = slices.Insert(ps, 0, p)
		for len(ps) > maxPeersPerBuddy {
			old := ps[len(ps)-1]
			ps = ps[:len(ps)-1]
			if s.peerOf[old] == k && s.kept[k] != old {
				delete(s.peerOf, old)
			}
		}
		s.peers[k] = ps
	}
	var keep bool
	var drop lpeer.ID
	if live && accepted && s.kept[k] != p {
		drop, keep = s.kept[k], true
		s.kept[k] = p
	}
	s.mu.Unlock()
	if keep {
		ai := lpeer.AddrInfo{ID: p}
		if r, ok := s.rch.IPRoute(id, s.n.now()); ok && r.Peer == p {
			ai.Addrs = r.Addrs
		}
		if err := s.sess.Keep(ai); err != nil && !errors.Is(err, ip.ErrSessionsClosed) {
			s.log.Debug("keeping a session", "buddy", k.KeyID(), "peer", p, "err", err)
		}
		if drop != "" {
			s.sess.Drop(drop)
		}
	}
	if ps, ok := s.sess.Peer(p); ok && ps.Up {
		s.pres.SessionUp(k, string(p))
	}
}

// sessionEventLoop feeds session Up/Down events to the reach table and,
// for attributed peers, to presence.
func (s *netState) sessionEventLoop() {
	defer s.wg.Done()
	for e := range s.sess.Events() {
		s.mu.Lock()
		k, ok := s.peerOf[e.Peer]
		s.mu.Unlock()
		if e.Up {
			s.rch.SessionUp(e.Peer)
			if ok {
				s.pres.SessionUp(k, string(e.Peer))
			}
			continue
		}
		s.rch.SessionDown(e.Peer)
		if ok {
			s.pres.SessionDown(k, string(e.Peer))
		}
	}
}

// ---- buddy list changes

// accepted is called once a buddy is accepted (by us or by them), and on
// every BUDDY_ACCEPT we send: publish for them, track their presence, look
// them up, and send our queued BUDDY_ACCEPT (the router has it in the
// outbox) along r, their REACH, if no better route is known.
func (s *netState) accepted(b store.Buddy, r *pb.Reach) {
	s.remember(b.ID, b.Key)
	if r != nil {
		s.updateReach(b.ID, b.Key, r)
	}
	if p, err := s.n.pair(b.Key); err == nil {
		s.pub.SetPair(p)
	}
	if err := s.pres.AddBuddy(b.Key); err != nil && !errors.Is(err, presence.ErrClosed) {
		s.log.Warn("tracking presence", "buddy", b.Key.KeyID(), "err", err)
	}
	now := s.n.now()
	s.mu.Lock()
	if s.lookups[b.ID] == nil {
		s.lookups[b.ID] = &lookupState{key: b.Key, next: now, backoff: s.o.LookupMin}
	}
	peers := slices.Clone(s.peers[b.Key])
	s.mu.Unlock()
	if route, ok := s.rch.IPRoute(b.ID, now); ok && route.Live {
		s.attribute(b.ID, b.Key, route.Peer, true)
	}
	for _, p := range peers {
		if ps, ok := s.sess.Peer(p); ok && ps.Up {
			s.pres.SessionUp(b.Key, string(p))
		}
	}
	s.rt.Kick(b.ID)
	s.wakeLookups()
}

// forget drops everything the network holds about a buddy that was removed,
// declined or blocked: nothing more is sent to them or published for them.
func (s *netState) forget(b store.Buddy) {
	s.rt.Forget(b.ID)
	s.rch.Forget(b.ID)
	s.pub.RemovePair(b.Key)
	if err := s.pres.RemoveBuddy(b.Key); err != nil && !errors.Is(err, presence.ErrClosed) {
		s.log.Warn("untracking presence", "buddy", b.Key.KeyID(), "err", err)
	}
	s.mu.Lock()
	kept := s.kept[b.Key]
	delete(s.kept, b.Key)
	for _, p := range s.peers[b.Key] {
		if s.peerOf[p] == b.Key {
			delete(s.peerOf, p)
		}
	}
	delete(s.peers, b.Key)
	delete(s.lookups, b.ID)
	delete(s.ids, b.Key)
	delete(s.keys, b.ID)
	s.mu.Unlock()
	if kept != "" {
		s.sess.Drop(kept)
	}
}

// wentOffline is called when a buddy is shown offline: stop keeping a
// session with them, and look for them again soon.
func (s *netState) wentOffline(k identity.PublicKey) {
	s.mu.Lock()
	kept := s.kept[k]
	delete(s.kept, k)
	for _, l := range s.lookups {
		if l.key == k {
			l.backoff = s.o.LookupMin
			l.next = s.n.now().Add(s.o.LookupMin)
		}
	}
	s.mu.Unlock()
	if kept != "" {
		s.sess.Drop(kept)
	}
	s.wakeLookups()
}

// liveRoute reports whether the buddy has a route from a live session.
func (s *netState) liveRoute(id int64) bool {
	r, ok := s.rch.IPRoute(id, s.n.now())
	return ok && r.Live
}

// queued tells the router about a newly queued message, and looks the buddy
// up first if we have no live session with them (design §7.2).
func (s *netState) queued(id int64) {
	s.rt.Kick(id)
	if !s.liveRoute(id) {
		s.lookupSoon(id)
	}
}

// routeOf is the buddy's current route, for tests and status.
func (s *netState) routeOf(id int64) (router.Route, bool) { return s.rch.IPRoute(id, s.n.now()) }
