package daemon

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/store"
)

// Direction says which way a message went.
type Direction int

const (
	Incoming Direction = iota + 1
	Outgoing
)

// Message is an IM in a conversation, either way.
type Message struct {
	MsgID      frame.MsgID
	Buddy      identity.PublicKey
	Direction  Direction
	Text       string
	SentAt     time.Time      // the inner timestamp (whole seconds)
	ReceivedAt time.Time      // incoming: when we delivered it
	State      store.OutState // outgoing: delivery state
	Seq        uint64

	local time.Time // when it entered this daemon's store, for ordering
}

// SendLayout is the layout IMs are sealed in. Mesh frames fit every route,
// so a queued IM can go out over IP or radio without being sealed again
// (design §8.3).
const SendLayout = frame.LayoutMesh

// SendIM checks text, seals it once as an IM to the buddy, and queues it
// (design §8.2). The seq is allocated in the same transaction that stores the
// frames. Blocked buddies can't be messaged.
//
// TODO(router): hand the queued frames to the router; with no transports the
// message stays queued.
func (n *Node) SendIM(ctx context.Context, sel, text string) (Message, error) {
	if _, err := body.IMText([]byte(text)); err != nil {
		return Message{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return Message{}, err
	}
	if b.State == store.Blocked {
		return Message{}, fmt.Errorf("%w: %s", ErrBlocked, b.Key.KeyID())
	}
	p, err := n.pair(b.Key)
	if err != nil {
		return Message{}, err
	}
	k := frame.NewConvKey(p.Send)

	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	var sentAt time.Time
	out, err := n.store.Enqueue(ctx, b.ID, func(seq uint64) (*frame.Sealed, frame.ContentType, error) {
		sentAt = n.now()
		in := frame.Inner{Type: frame.IM, Flags: frame.FlagAckRequested, Time: frame.Timestamp(sentAt), Seq: seq, Body: []byte(text)}
		s, err := frame.Seal(k, k.Tag(frame.Day(sentAt)), SendLayout, in.Marshal())
		return s, frame.IM, err
	})
	if errors.Is(err, frame.ErrTooLarge) {
		return Message{}, fmt.Errorf("%w: IM of %d bytes is too long to send (the mesh layout carries about %d)",
			ErrInvalid, len(text), SendLayout.MaxInner()-7)
	} else if errors.Is(err, store.ErrNotFound) {
		return Message{}, fmt.Errorf("%w: %s", ErrUnknownBuddy, b.Key.KeyID()) // removed meanwhile
	} else if err != nil {
		return Message{}, err
	}
	m := Message{MsgID: out.MsgID, Buddy: b.Key, Direction: Outgoing, Text: text,
		SentAt: frame.TimeOf(frame.Timestamp(sentAt)), State: out.State, Seq: out.Seq, local: out.CreatedAt}
	n.log.Debug("IM queued", "buddy", b.Key.KeyID(), "msg_id", out.MsgID, "frames", len(out.Frames))
	n.events.publish(Event{Kind: EventMessageQueued, Message: &m})
	return m, nil
}

// Pending lists a buddy's queued messages, oldest first, with their sealed
// frames: what the router will (re)send.
func (n *Node) Pending(ctx context.Context, sel string) ([]*store.Outgoing, error) {
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return nil, err
	}
	return n.store.Pending(ctx, b.ID)
}

// MaxHistory bounds History's limit.
const MaxHistory = 1000

// History returns up to limit of the most recent IMs with a buddy, both
// directions, oldest first. Outgoing IMs are read back by opening our own
// sealed frames, since only the frames are stored.
func (n *Node) History(ctx context.Context, sel string, limit int) ([]Message, error) {
	if limit <= 0 || limit > MaxHistory {
		return nil, fmt.Errorf("%w: limit %d (1–%d)", ErrInvalid, limit, MaxHistory)
	}
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return nil, err
	}
	in, err := n.store.History(ctx, b.ID, limit)
	if err != nil {
		return nil, err
	}
	out, err := n.store.SentHistory(ctx, b.ID, frame.IM, limit)
	if err != nil {
		return nil, err
	}
	p, err := n.pair(b.Key)
	if err != nil {
		return nil, err
	}
	sendKey := frame.NewConvKey(p.Send)

	msgs := make([]Message, 0, len(in)+len(out))
	for _, m := range in {
		if m.Inner.Type != frame.IM {
			continue
		}
		msgs = append(msgs, incomingMessage(b.Key, m.MsgID, m.Inner, m.ReceivedAt))
	}
	for _, o := range out {
		inner, err := openSealed(sendKey, o.Frames)
		if err != nil {
			// Our own frames failing to open means local corruption.
			n.log.Error("can't read back a sent message", "buddy", b.Key.KeyID(), "msg_id", o.MsgID, "err", err)
			continue
		}
		msgs = append(msgs, Message{MsgID: o.MsgID, Buddy: b.Key, Direction: Outgoing, Text: string(inner.Body),
			SentAt: frame.TimeOf(inner.Time), State: o.State, Seq: inner.Seq, local: o.CreatedAt})
	}
	sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].local.Before(msgs[j].local) })
	if len(msgs) > limit {
		msgs = msgs[len(msgs)-limit:]
	}
	return msgs, nil
}

func incomingMessage(k identity.PublicKey, id frame.MsgID, in frame.Inner, at time.Time) Message {
	return Message{MsgID: id, Buddy: k, Direction: Incoming, Text: string(in.Body),
		SentAt: frame.TimeOf(in.Time), ReceivedAt: at, Seq: in.Seq, local: at}
}

// openSealed decrypts a message we sealed, from its stored frames.
func openSealed(k frame.ConvKey, frames [][]byte) (frame.Inner, error) {
	var inner []byte
	for i, f := range frames {
		h, err := frame.ParseHeader(f)
		if err != nil {
			return frame.Inner{}, err
		}
		if h.Index != i || h.Count != len(frames) {
			return frame.Inner{}, fmt.Errorf("%w: fragment %d/%d stored at %d of %d", frame.ErrMalformed, h.Index, h.Count, i, len(frames))
		}
		pt, err := frame.OpenFragment(k, h, f)
		if err != nil {
			return frame.Inner{}, err
		}
		inner = append(inner, pt...)
	}
	return frame.ParseInner(inner)
}

// HandleFrame is HandleFrameFrom with no transport name: every caller
// without one shares a first-contact rate limit.
func (n *Node) HandleFrame(ctx context.Context, b []byte) (frame.Result, error) {
	return n.HandleFrameFrom(ctx, "", b)
}

// HandleFrameFrom takes one inbound frame from a transport (named for the
// per-transport first-contact rate limit). Errors mean the frame was
// dropped.
//
//   - DATA frames are authenticated, deduplicated and reassembled. Complete
//     IMs go to the history (message_received), BUDDY_ACCEPTs complete a
//     request (requests.go), and BUDDY_REQUESTs are dropped: they are valid
//     only in first contacts. Frames from blocked and pending_in buddies
//     aren't recognized at all.
//   - FIRST_CONTACT frames are rate-limited per transport, then tried,
//     deduplicated and reassembled; a complete BUDDY_REQUEST is recorded
//     (requests.go) and never answered automatically. For these, the
//     Result has Status and Have, and Conv is the sender once delivered.
//
// TODO(router): send ACKs for res.Have, and handle the other content types
// (presence, acks, ...).
func (n *Node) HandleFrameFrom(ctx context.Context, transport string, b []byte) (frame.Result, error) {
	if len(b) > 0 && b[0]>>5 == frame.Version {
		switch frame.Kind(b[0] & 0x1F) {
		case frame.KindFirstContact, frame.KindFirstContactIP:
			return n.handleFirstContact(ctx, transport, b)
		}
	}
	res, err := n.recv.Accept(b)
	if err != nil || res.Status != frame.Delivered {
		return res, err
	}
	m := res.Message
	k := res.Conv.(identity.PublicKey)
	switch m.Inner.Type {
	case frame.IM:
	case frame.BuddyAccept:
		return res, n.receiveAccept(ctx, k, m.Inner)
	case frame.BuddyRequest:
		n.fcStats.dataRequests.Add(1)
		n.log.Warn("dropping BUDDY_REQUEST in a DATA frame", "buddy", k.KeyID())
		return res, ErrRequestInData
	default:
		n.log.Debug("dropping unhandled content type", "buddy", k.KeyID(), "type", m.Inner.Type)
		return res, nil
	}
	if _, err := body.IMText(m.Inner.Body); err != nil {
		return res, err
	}
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	bd, err := n.store.BuddyByKey(ctx, k)
	if err != nil {
		return res, err
	}
	at := n.now()
	fresh, err := n.store.SaveIncoming(ctx, bd.ID, m, at)
	if err != nil || !fresh {
		return res, err
	}
	msg := incomingMessage(k, m.MsgID, m.Inner, time.UnixMilli(at.UnixMilli()))
	n.events.publish(Event{Kind: EventMessageReceived, Message: &msg})
	return res, nil
}
