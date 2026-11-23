package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/presence"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Presence over the network (docs/presence.md): the tracker decides; the
// daemon seals and sends its PRESENCE bodies, feeds it sessions and
// authenticated bodies, and turns its events into API events.

// BuddyPresence is what we show for a buddy.
type BuddyPresence struct {
	State PresenceState
	Since time.Time // when State last changed (zero: never seen)
	// IdleMinutes is their idle time as last reported; 0 = not idle.
	IdleMinutes uint32
	// AwayMessage is their away message, once fetched.
	AwayMessage string
	Connected   bool // a session with them is up
	// From and Reason are set in EventBuddyPresence: the state before, and
	// why it changed (presence.Reason, or "away-message").
	From   PresenceState
	Reason string
}

// DoorOpen reports whether the buddy just came online.
func (p BuddyPresence) DoorOpen() bool { return p.From == Offline && p.State != Offline }

// DoorClose reports whether the buddy just went offline.
func (p BuddyPresence) DoorClose() bool {
	return p.From != Offline && p.From != 0 && p.State == Offline
}

// ReasonAwayMessage is BuddyPresence.Reason when a buddy's away message
// arrived.
const ReasonAwayMessage = "away-message"

// BuddyPresence is buddy k's presence as last heard: Offline for buddies
// that aren't accepted and when there is no network.
func (n *Node) BuddyPresence(k identity.PublicKey) BuddyPresence {
	if n.net == nil {
		return BuddyPresence{State: Offline}
	}
	st, ok := n.net.pres.Buddy(k)
	if !ok {
		return BuddyPresence{State: Offline}
	}
	return buddyPresenceOf(st)
}

func buddyPresenceOf(st presence.BuddyStatus) BuddyPresence {
	p := BuddyPresence{State: PresenceState(st.State), Since: st.Since, IdleMinutes: st.IdleMinutes, Connected: st.Connected}
	if st.AwayKnown && st.State == presence.Away {
		p.AwayMessage = st.AwayText
	}
	return p
}

// Activity reports the user's last activity, for idle detection (design
// §11.1). Without a network it does nothing.
func (n *Node) Activity(at time.Time) error {
	if n.net == nil {
		return nil
	}
	if err := n.net.pres.Activity(at); err != nil && !errors.Is(err, presence.ErrClosed) {
		return err
	}
	return nil
}

// sendPresence is the tracker's Sender: PRESENCE, no ACK requested, never
// persisted, along the buddy's route.
func (s *netState) sendPresence(ctx context.Context, to presence.Recipient, p *pb.Presence) error {
	k := to.Key()
	id, err := s.idOf(ctx, k)
	if err != nil {
		return err
	}
	return s.sendOneOff(ctx, id, k, p)
}

// presenceEventLoop handles the tracker's events until it closes.
func (s *netState) presenceEventLoop() {
	defer s.wg.Done()
	for e := range s.pres.Events() {
		switch {
		case e.Transition != nil:
			t := e.Transition
			if t.To == presence.Offline {
				s.wentOffline(t.Buddy)
			}
			st, _ := s.pres.Buddy(t.Buddy)
			if st.Buddy != t.Buddy { // removed meanwhile
				st = presence.BuddyStatus{Buddy: t.Buddy, State: t.To, Since: t.At, IdleMinutes: t.IdleMinutes}
			}
			bp := buddyPresenceOf(st)
			bp.State, bp.From, bp.Reason = PresenceState(t.To), PresenceState(t.From), string(t.Reason)
			s.publishPresence(t.Buddy, bp)
		case e.AwayMessage != nil:
			st, ok := s.pres.Buddy(e.AwayMessage.Buddy)
			if !ok {
				continue
			}
			bp := buddyPresenceOf(st)
			bp.From, bp.Reason = bp.State, ReasonAwayMessage
			s.publishPresence(e.AwayMessage.Buddy, bp)
		case e.FetchAway != nil:
			k := e.FetchAway.Buddy
			if id, err := s.idOf(s.ctx, k); err == nil {
				s.sendLater(id, k, &pb.ProfileReq{AwayMsg: true})
			}
		case e.Own != nil:
			s.ownChanged(*e.Own)
		}
	}
}

func (s *netState) publishPresence(k identity.PublicKey, bp BuddyPresence) {
	b, err := s.n.store.BuddyByKey(context.WithoutCancel(s.ctx), k)
	if err != nil {
		return
	}
	s.n.events.publish(Event{Kind: EventBuddyPresence, Buddy: &b, BuddyPresence: &bp})
}

// ownChanged persists and announces a change the tracker made on its own
// (auto-away and back). Changes we asked for (SetPresence, sign-off) are
// handled where they're made.
func (s *netState) ownChanged(c presence.OwnChange) {
	if c.Reason == presence.ReasonUser {
		return
	}
	n := s.n
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	n.mu.Lock()
	p := n.presence
	if p.State == PresenceState(c.To.State) && p.Away == c.To.AwayText {
		n.mu.Unlock()
		return // only idleness changed
	}
	if p.State != PresenceState(c.To.State) {
		p.Since = c.At
	}
	p.State, p.Away = PresenceState(c.To.State), c.To.AwayText
	n.presence = p
	n.mu.Unlock()
	if b, err := json.Marshal(p); err == nil {
		if err := n.store.SetMeta(context.WithoutCancel(s.ctx), metaPresence, b); err != nil {
			s.log.Warn("saving presence", "err", err)
		}
	}
	n.events.publish(Event{Kind: EventPresenceChanged, Presence: &p})
}
