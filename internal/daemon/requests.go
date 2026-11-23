package daemon

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/invite"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Buddy requests and acceptance (design §5.4, spec/wire.md §11).
//
//   - AddBuddy seals a BUDDY_REQUEST once as a FIRST_CONTACT, persists it
//     with the new pending_out buddy, and hands it to the FrameSink.
//   - An incoming request makes the sender a pending_in buddy (repeat
//     requests merge). Nothing is sent back: approval is required, and
//     strangers are never answered automatically.
//   - AcceptBuddy derives the pairwise keys, starts recognizing the buddy's
//     frames and sends BUDDY_ACCEPT (our presence key, recovery key and
//     reachability) as a DATA frame.
//   - A BUDDY_ACCEPT from a pending_out buddy makes them accepted; we answer
//     it once with our own BUDDY_ACCEPT, so they get our presence key too.
//     That reply goes only to a key we chose to add.
//   - Two requests that cross (each side added the other) count as
//     acceptance on both sides, for the same reason.
//
// TODO(M3): issue the buddy a delivery token for our gateways and mailboxes
// on accept (design §5.4, §7.3, §7.4).

// Errors for request handling.
var (
	// ErrNotPending: the call needs a pending request, and the buddy has
	// none in that direction.
	ErrNotPending = errors.New("daemon: no pending request from this buddy")
	// ErrRequestInData: a BUDDY_REQUEST arrived in a DATA frame. It is valid
	// only inside a first contact (spec/wire.md §11.6), so it is dropped.
	ErrRequestInData = errors.New("daemon: BUDDY_REQUEST in a DATA frame dropped")
	// ErrNotRequest: a first contact that wasn't a BUDDY_REQUEST, dropped.
	ErrNotRequest = errors.New("daemon: first contact is not a buddy request")
	// ErrTooManyRequests: a request from a new key was dropped because
	// Config.MaxPendingRequests are already waiting.
	ErrTooManyRequests = errors.New("daemon: too many buddy requests waiting")
)

// DefaultMaxPendingRequests bounds pending_in buddies (requests waiting for
// an answer) when Config.MaxPendingRequests is zero.
const DefaultMaxPendingRequests = 256

func (n *Node) maxPendingIn() int {
	if n.cfg.MaxPendingRequests > 0 {
		return n.cfg.MaxPendingRequests
	}
	return DefaultMaxPendingRequests
}

// metaPresenceKey holds our 32-byte presence key (design §5.1), made on the
// first accept. It is a symmetric secret shared with every buddy, so unlike
// the identity seed it lives in the database.
const metaPresenceKey = "presence_key"

// presenceKey returns our presence key, making and saving it if needed.
// Caller holds writeMu.
func (n *Node) presenceKey(ctx context.Context) ([]byte, error) {
	v, err := n.store.Meta(ctx, metaPresenceKey)
	if err == nil && len(v) == 32 {
		return v, nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := n.store.SetMeta(ctx, metaPresenceKey, k); err != nil {
		return nil, err
	}
	n.log.Info("presence key created")
	return k, nil
}

// contactHint is our contact hint for invites and REACH, or "": the
// configured one, else the network's relay circuit.
func (n *Node) contactHint() string {
	var h string
	switch {
	case n.cfg.ContactHint != nil:
		h = n.cfg.ContactHint()
	case n.net != nil:
		h = n.net.contactHint()
	}
	if h == "" {
		return ""
	}
	a, err := invite.CheckContactHint(h)
	if err != nil {
		n.log.Warn("ignoring unusable contact hint", "err", err)
		return ""
	}
	return a.String()
}

// recoveryKeyBytes is our recovery public key for a body, or nil.
func (n *Node) recoveryKeyBytes() []byte {
	if k := n.RecoveryKey(); k != nil {
		return k[:]
	}
	return nil
}

// sealRequest builds and seals our BUDDY_REQUEST to k: once, in the mesh
// layout if it fits (so it can take any route), else the IP layout.
func (n *Node) sealRequest(k identity.PublicKey, greeting, contactHint string) (*store.OutRequest, error) {
	req := &pb.BuddyRequest{
		DisplayName: n.cfg.DisplayName, Greeting: greeting, Reach: n.ourReach(),
		RecoveryKey: n.recoveryKeyBytes(), Caps: caps(),
	}
	_, b, err := body.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	now := n.now()
	in := frame.Inner{Type: frame.BuddyRequest, Time: frame.Timestamp(now), Body: b}
	raw := in.Marshal()
	l := frame.LayoutMesh
	if len(raw) > frame.FirstContactMaxInner(l) {
		l = frame.LayoutIP
	}
	s, err := frame.SealFirstContact(n.id, k, l, raw, nil)
	if errors.Is(err, frame.ErrTooLarge) {
		return nil, fmt.Errorf("%w: the request is too large to send", ErrInvalid)
	} else if err != nil {
		return nil, err
	}
	return &store.OutRequest{E: s.E, MsgID: s.MsgID, Layout: s.Layout, ContactHint: contactHint,
		SentTS: in.Time, Frames: s.Frames}, nil
}

// sendRequest hands a persisted request to the sink and records the
// attempt. Call it without writeMu held.
func (n *Node) sendRequest(ctx context.Context, k identity.PublicKey, r *store.OutRequest) error {
	err := n.deliver(ctx, DeliveryTarget{Kind: TargetFirstContact, Key: k, Layout: r.Layout, ContactHint: r.ContactHint}, r.Frames)
	if errors.Is(err, ErrNoSink) {
		n.log.Debug("request queued; no transport attached", "buddy", k.KeyID())
		return err
	}
	var msg string
	if err != nil {
		msg = err.Error()
		n.log.Warn("sending buddy request", "buddy", k.KeyID(), "err", err)
	}
	if rerr := n.store.RecordRequestAttempt(context.WithoutCancel(ctx), r.ID, n.now(), msg); rerr != nil {
		n.log.Error("recording a request attempt", "err", rerr)
	}
	return err
}

// RedeliverRequests resends every unanswered request still inside the
// acceptance window, and marks older ones failed (their timestamp would be
// rejected: a new request is needed). It returns how many it handed to the
// sink.
func (n *Node) RedeliverRequests(ctx context.Context) (int, error) {
	rs, err := n.store.UnansweredRequests(ctx)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, r := range rs {
		b, err := n.store.Buddy(ctx, r.BuddyID)
		if err != nil {
			continue
		}
		if n.now().Sub(frame.TimeOf(r.SentTS)) > frame.MaxAge-time.Hour {
			if _, err := n.store.SetRequestsState(ctx, r.BuddyID, store.RequestFailed); err != nil {
				return sent, err
			}
			continue
		}
		if b.State != store.PendingOut {
			continue
		}
		if err := n.sendRequest(ctx, b.Key, r); err == nil {
			sent++
		} else if errors.Is(err, ErrNoSink) {
			return sent, nil
		}
	}
	return sent, nil
}

// ---- receiving requests

// handleFirstContact takes one FIRST_CONTACT frame: rate limit, trial
// decryption, dedup and reassembly, then the request itself.
func (n *Node) handleFirstContact(ctx context.Context, transport string, b []byte) (frame.Result, error) {
	c := &n.fcStats
	c.frames.Add(1)
	if !n.limiter.allow(transport, n.now()) {
		c.rateLimited.Add(1)
		return frame.Result{}, ErrRateLimited
	}
	res, err := n.fcRecv.Accept(b)
	out := frame.Result{Status: res.Status, Have: res.Have}
	if err != nil {
		c.dropped.Add(1)
		return out, err
	}
	switch res.Status {
	case frame.Duplicate:
		// Never answered, on any route (spec/wire.md §11.5 step 5).
		c.duplicates.Add(1)
		return out, nil
	case frame.Partial:
		return out, nil
	}
	m := res.Message
	out.Conv = m.Sender
	if m.Inner.Type != frame.BuddyRequest {
		c.wrongType.Add(1)
		return out, fmt.Errorf("%w (%v)", ErrNotRequest, m.Inner.Type)
	}
	msg, err := body.Unmarshal(frame.BuddyRequest, m.Inner.Body)
	if err != nil {
		c.dropped.Add(1)
		return out, err
	}
	return out, n.receiveRequest(ctx, transport, m.Sender, m.Inner, msg.(*pb.BuddyRequest))
}

// receiveRequest records an authenticated BUDDY_REQUEST from k.
func (n *Node) receiveRequest(ctx context.Context, transport string, k identity.PublicKey, in frame.Inner, req *pb.BuddyRequest) error {
	c := &n.fcStats
	if k == n.Identity() {
		return fmt.Errorf("%w: request from ourselves", ErrInvalid)
	}
	var rk *identity.PublicKey
	if raw := req.GetRecoveryKey(); len(raw) != 0 {
		if pk, err := identity.ParsePublicKey(raw); err == nil && identity.CheckRecoveryKey(k, pk) == nil {
			rk = &pk
		} else {
			n.log.Warn("request carries an unpinnable recovery key; ignoring it", "from", k.KeyID())
		}
	}

	n.writeMu.Lock()
	prev, err := n.store.BuddyByKey(ctx, k)
	if err == nil && prev.State == store.Blocked {
		n.writeMu.Unlock()
		c.blocked.Add(1)
		n.log.Debug("dropping request from a blocked key", "from", k.KeyID())
		return fmt.Errorf("%w: %s", ErrBlocked, k.KeyID())
	} else if errors.Is(err, store.ErrNotFound) {
		// A new requester. Keys cost nothing, so bound how many strangers
		// can wait at once; the rate limit alone would let the list grow
		// by tens of thousands a day.
		waiting, err := n.store.CountBuddies(ctx, store.PendingIn)
		if err != nil {
			n.writeMu.Unlock()
			return err
		}
		if waiting >= n.maxPendingIn() {
			n.writeMu.Unlock()
			c.overflow.Add(1)
			n.log.Warn("too many buddy requests waiting; dropping one from a new key", "waiting", waiting)
			return fmt.Errorf("%w: %d requests already waiting", ErrTooManyRequests, waiting)
		}
	} else if err != nil {
		n.writeMu.Unlock()
		return err
	}
	now := n.now()
	b, created, err := n.store.RecordRequest(ctx, k, "", store.ReceivedRequest{
		DisplayName: req.GetDisplayName(), Greeting: req.GetGreeting(), SentTS: in.Time, At: now,
		Transport: transport, RecoveryKey: rk,
	})
	if err != nil {
		n.writeMu.Unlock()
		return err
	}
	if created {
		c.requests.Add(1)
	} else {
		c.merged.Add(1)
	}
	if !created && rk != nil && b.RecoveryKey != nil && *b.RecoveryKey != *rk {
		n.log.Warn("request carries a different recovery key than the pinned one; keeping the pinned one", "from", k.KeyID())
	}
	name := req.GetDisplayName()
	if err := n.updatePeer(ctx, b, store.PeerUpdate{DisplayName: &name}, req.GetReach(), now); err != nil {
		n.writeMu.Unlock()
		return err
	}
	// Crossed requests: we asked them too, so this is their acceptance.
	crossed := b.State == store.PendingOut
	var acc *pendingAccept
	if crossed {
		if acc, err = n.acceptLocked(ctx, b); err != nil {
			n.writeMu.Unlock()
			return err
		}
		b = acc.buddy
	}
	det := n.detailsOrNil(ctx, b)
	kind := EventBuddyChanged
	if created {
		kind = EventBuddyAdded
	}
	n.events.publish(Event{Kind: kind, Buddy: &b, HandleCheck: n.handleCheckOrNil(ctx, b), Details: det})
	n.events.publish(Event{Kind: EventBuddyRequest, Buddy: &b, HandleCheck: n.handleCheckOrNil(ctx, b), Details: det})
	n.writeMu.Unlock()
	n.log.Info("buddy request received", "from", k.KeyID(), "new", created, "crossed", crossed, "transport", transport)
	if acc != nil {
		n.sendAccept(ctx, acc)
	}
	return nil
}

// updatePeer stores what a buddy told us, taking a REACH only if it is
// still valid (design §7.1). Caller holds writeMu.
func (n *Node) updatePeer(ctx context.Context, b store.Buddy, u store.PeerUpdate, r *pb.Reach, now time.Time) error {
	if r != nil && r.GetExpiresAt() > frame.Timestamp(now) {
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(r)
		if err != nil {
			return err
		}
		u.Reach, u.ReachSeq, u.ReachExpires = raw, r.GetSeq(), r.GetExpiresAt()
	}
	_, err := n.store.UpdatePeer(ctx, b.ID, u, now)
	return err
}

// peerReach is a buddy's stored REACH if it is still valid, else nil.
func (n *Node) peerReach(ctx context.Context, id int64) *pb.Reach {
	p, err := n.store.Peer(ctx, id)
	if err != nil || p.Reach == nil || p.ReachExpires <= frame.Timestamp(n.now()) {
		return nil
	}
	var r pb.Reach
	if proto.Unmarshal(p.Reach, &r) != nil {
		return nil
	}
	return &r
}

// ---- accepting

// pendingAccept is a BUDDY_ACCEPT sealed and queued, to hand to the sink
// once the locks are released.
type pendingAccept struct {
	buddy store.Buddy
	out   *store.Outgoing
	reach *pb.Reach
}

// AcceptBuddy accepts a pending_in buddy's request (design §5.4): the
// buddy becomes accepted, its frames are recognized from now on, and a
// BUDDY_ACCEPT with our presence key, recovery key and reachability is
// sealed, queued and handed to the transports. On an accepted buddy it
// sends BUDDY_ACCEPT again (for a buddy who lost it). A pending_out buddy
// fails with ErrNotPending, a blocked one with ErrBlocked.
func (n *Node) AcceptBuddy(ctx context.Context, sel string) (store.Buddy, error) {
	n.writeMu.Lock()
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		n.writeMu.Unlock()
		return b, err
	}
	switch b.State {
	case store.Blocked:
		n.writeMu.Unlock()
		return b, fmt.Errorf("%w: %s", ErrBlocked, b.Key.KeyID())
	case store.PendingOut:
		n.writeMu.Unlock()
		return b, fmt.Errorf("%w: we asked %s; waiting for them to accept", ErrNotPending, b.Key.KeyID())
	}
	acc, err := n.acceptLocked(ctx, b)
	if err != nil {
		n.writeMu.Unlock()
		return b, err
	}
	b = acc.buddy
	n.events.publish(Event{Kind: EventBuddyChanged, Buddy: &b, HandleCheck: n.handleCheckOrNil(ctx, b), Details: n.detailsOrNil(ctx, b)})
	n.writeMu.Unlock()
	n.log.Info("buddy accepted", "buddy", b.Key.KeyID())
	n.sendAccept(ctx, acc)
	return b, nil
}

// acceptLocked makes b accepted, registers its inbound key and seals our
// BUDDY_ACCEPT into the outbox. Caller holds writeMu, publishes events and
// then calls sendAccept.
func (n *Node) acceptLocked(ctx context.Context, b store.Buddy) (*pendingAccept, error) {
	p, err := n.pair(b.Key)
	if err != nil {
		return nil, err
	}
	if b.State != store.Accepted {
		if err := n.store.SetBuddyState(ctx, b.ID, store.Accepted); err != nil {
			return nil, err
		}
		b.State = store.Accepted
		if _, err := n.store.SetRequestsState(ctx, b.ID, store.RequestAnswered); err != nil {
			return nil, err
		}
	}
	if err := n.trackBuddy(b); err != nil {
		return nil, err
	}
	pk, err := n.presenceKey(ctx)
	if err != nil {
		return nil, err
	}
	reach := n.ourReach()
	acc := &pb.BuddyAccept{PresenceKey: pk, RecoveryKey: n.recoveryKeyBytes(), DisplayName: n.cfg.DisplayName,
		Reach: reach, Caps: caps()}
	_, raw, err := body.Marshal(acc)
	if err != nil {
		return nil, err
	}
	k := frame.NewConvKey(p.Send)
	out, err := n.store.Enqueue(ctx, b.ID, func(seq uint64) (*frame.Sealed, frame.ContentType, error) {
		now := n.now()
		in := frame.Inner{Type: frame.BuddyAccept, Flags: frame.FlagAckRequested, Time: frame.Timestamp(now), Seq: seq, Body: raw}
		inner := in.Marshal()
		l := frame.LayoutMesh
		if len(inner) > l.MaxInner() {
			l = frame.LayoutIP
		}
		s, err := frame.Seal(k, k.Tag(frame.Day(now)), l, inner)
		return s, frame.BuddyAccept, err
	})
	if err != nil {
		return nil, err
	}
	return &pendingAccept{buddy: b, out: out, reach: n.peerReach(ctx, b.ID)}, nil
}

// sendAccept hands a queued BUDDY_ACCEPT to the sink, or with a network to
// the router, which retries it until acked. Call it without writeMu held.
func (n *Node) sendAccept(ctx context.Context, a *pendingAccept) {
	if n.net != nil {
		n.net.accepted(a.buddy, a.reach)
		return
	}
	err := n.deliver(ctx, DeliveryTarget{Kind: TargetBuddy, Key: a.buddy.Key, Layout: a.out.Layout, Reach: a.reach}, a.out.Frames)
	switch {
	case errors.Is(err, ErrNoSink):
		n.log.Debug("accept queued; no transport attached", "buddy", a.buddy.Key.KeyID())
	case err != nil:
		n.log.Warn("sending buddy accept", "buddy", a.buddy.Key.KeyID(), "err", err)
	default:
		if err := n.store.RecordAttempt(context.WithoutCancel(ctx), a.out.ID, n.now()); err != nil {
			n.log.Error("recording a send attempt", "err", err)
		}
	}
}

// receiveAccept handles an authenticated BUDDY_ACCEPT from buddy k.
func (n *Node) receiveAccept(ctx context.Context, k identity.PublicKey, in frame.Inner) error {
	msg, err := body.Unmarshal(frame.BuddyAccept, in.Body)
	if err != nil {
		return err
	}
	acc := msg.(*pb.BuddyAccept)
	n.writeMu.Lock()
	b, err := n.store.BuddyByKey(ctx, k)
	if err != nil {
		n.writeMu.Unlock()
		return err
	}
	switch b.State {
	case store.PendingOut, store.Accepted:
	default:
		// Not in the keyring, so this can't happen; be safe anyway.
		n.writeMu.Unlock()
		return fmt.Errorf("%w: BUDDY_ACCEPT from a %s buddy", ErrNotPending, b.State)
	}
	if raw := acc.GetRecoveryKey(); len(raw) != 0 {
		pk, err := identity.ParsePublicKey(raw)
		if err == nil {
			err = identity.CheckRecoveryKey(k, pk)
		}
		switch {
		case err != nil:
			n.log.Warn("accept carries an unpinnable recovery key; ignoring it", "from", k.KeyID(), "err", err)
		case b.RecoveryKey == nil:
			if _, err := n.store.SetBuddyRecoveryKey(ctx, b.ID, pk); err != nil {
				n.writeMu.Unlock()
				return err
			}
			b.RecoveryKey = &pk
		case *b.RecoveryKey != pk:
			n.log.Warn("accept carries a different recovery key than the pinned one; keeping the pinned one", "from", k.KeyID())
		}
	}
	now := n.now()
	name := acc.GetDisplayName()
	var capsRaw []byte
	if acc.Caps != nil {
		capsRaw, _ = proto.MarshalOptions{Deterministic: true}.Marshal(acc.Caps)
	}
	u := store.PeerUpdate{DisplayName: &name, PresenceKey: acc.GetPresenceKey(), Caps: capsRaw, AcceptedAt: now}
	if err := n.updatePeer(ctx, b, u, acc.GetReach(), now); err != nil {
		n.writeMu.Unlock()
		return err
	}
	var reply *pendingAccept
	if b.State == store.PendingOut {
		// They accepted our request. Answer once with our own accept, so
		// they get our presence key and reachability.
		if reply, err = n.acceptLocked(ctx, b); err != nil {
			n.writeMu.Unlock()
			return err
		}
		b = reply.buddy
		n.log.Info("buddy accepted our request", "buddy", k.KeyID())
	}
	n.events.publish(Event{Kind: EventBuddyChanged, Buddy: &b, HandleCheck: n.handleCheckOrNil(ctx, b), Details: n.detailsOrNil(ctx, b)})
	n.writeMu.Unlock()
	if reply != nil {
		n.sendAccept(ctx, reply)
	}
	return nil
}

// ---- declining and blocking

// DeclineBuddy declines a pending_in buddy's request: the record is
// deleted and nothing is sent. A later request shows up afresh; BlockBuddy
// stops that.
func (n *Node) DeclineBuddy(ctx context.Context, sel string) (store.Buddy, error) {
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return b, err
	}
	if b.State != store.PendingIn {
		return b, fmt.Errorf("%w: %s is %s", ErrNotPending, b.Key.KeyID(), b.State)
	}
	det := n.detailsOrNil(ctx, b)
	if err := n.store.DeleteBuddy(ctx, b.ID); err != nil {
		return b, err
	}
	n.untrackBuddy(b.Key)
	if n.net != nil {
		n.net.forget(b)
	}
	n.log.Info("buddy request declined", "buddy", b.Key.KeyID())
	n.events.publish(Event{Kind: EventBuddyRemoved, Buddy: &b, Details: det})
	return b, nil
}

// BlockBuddy blocks a buddy in any state (design §7.5): their DATA frames
// are no longer recognized, so they're dropped before any processing, their
// requests are dropped, nothing more is sent to them, and our unanswered
// requests to them are abandoned. Remove the buddy to unblock.
func (n *Node) BlockBuddy(ctx context.Context, sel string) (store.Buddy, error) {
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return b, err
	}
	if b.State == store.Blocked {
		return b, nil
	}
	if err := n.store.SetBuddyState(ctx, b.ID, store.Blocked); err != nil {
		return b, err
	}
	if _, err := n.store.SetRequestsState(ctx, b.ID, store.RequestFailed); err != nil {
		return b, err
	}
	b.State = store.Blocked
	n.untrackBuddy(b.Key)
	if n.net != nil {
		n.net.forget(b)
	}
	if err := n.failQueued(ctx, b); err != nil {
		return b, err
	}
	n.log.Info("buddy blocked", "buddy", b.Key.KeyID())
	n.events.publish(Event{Kind: EventBuddyChanged, Buddy: &b, HandleCheck: n.handleCheckOrNil(ctx, b), Details: n.detailsOrNil(ctx, b)})
	return b, nil
}

// SetBuddyLabels changes a buddy's petname and/or group; nil leaves one as
// it is, and "" clears a petname or resets the group to "Buddies".
func (n *Node) SetBuddyLabels(ctx context.Context, sel string, petname, group *string) (store.Buddy, error) {
	if petname != nil {
		if err := checkLabel("petname", *petname); err != nil {
			return store.Buddy{}, err
		}
	}
	if group != nil {
		if err := checkLabel("group", *group); err != nil {
			return store.Buddy{}, err
		}
	}
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return b, err
	}
	if petname != nil {
		b.Petname = *petname
	}
	if group != nil {
		b.Group = *group
		if b.Group == "" {
			b.Group = "Buddies"
		}
	}
	if err := n.store.SetBuddyLabels(ctx, b.ID, b.Petname, b.Group); err != nil {
		return b, err
	}
	n.events.publish(Event{Kind: EventBuddyChanged, Buddy: &b, HandleCheck: n.handleCheckOrNil(ctx, b), Details: n.detailsOrNil(ctx, b)})
	return b, nil
}

// ---- details for clients

// BuddyDetails is what the buddy list shows beyond the store.Buddy row.
type BuddyDetails struct {
	// Request is the request they sent us, if any (merged).
	Request *store.InRequest
	// OfferedName is the display name they gave in their latest request or
	// accept: their own claim, unverified.
	OfferedName string
	// OutRequest is our latest request to them (without frames), if any.
	OutRequest *store.OutRequest
	// HasPresenceKey says their BUDDY_ACCEPT gave us their presence key.
	HasPresenceKey bool
}

// Details returns a buddy's details.
func (n *Node) Details(ctx context.Context, b store.Buddy) (*BuddyDetails, error) {
	d := &BuddyDetails{}
	if r, err := n.store.Request(ctx, b.ID); err == nil {
		d.Request = &r
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if p, err := n.store.Peer(ctx, b.ID); err == nil {
		d.OfferedName, d.HasPresenceKey = p.DisplayName, p.PresenceKey != nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	rs, err := n.store.Requests(ctx, b.ID)
	if err != nil {
		return nil, err
	}
	if len(rs) > 0 {
		r := rs[len(rs)-1]
		r.Frames = nil
		d.OutRequest = r
	}
	return d, nil
}

// detailsOrNil is Details for event payloads: failures are logged.
func (n *Node) detailsOrNil(ctx context.Context, b store.Buddy) *BuddyDetails {
	d, err := n.Details(ctx, b)
	if err != nil {
		n.log.Warn("reading buddy details", "buddy", b.Key.KeyID(), "err", err)
	}
	return d
}

// Peer returns what buddy b told us about themselves, or store.ErrNotFound.
func (n *Node) Peer(ctx context.Context, b store.Buddy) (store.Peer, error) {
	return n.store.Peer(ctx, b.ID)
}
