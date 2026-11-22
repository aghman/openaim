package router

import (
	"container/list"
	"context"
	"errors"
	"sync"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Received handles a DATA frame from the buddy that frame.Receiver.Accept
// accepted. Call it for every Partial, Delivered or Duplicate result, after a
// delivered message has been stored.
//
//   - A delivered ACK message is applied (HandleAck) and never acked.
//   - A delivered message with the ack-requested flag, and any partial or
//     duplicate fragment, schedules an ACK entry {msg_id, have}. Duplicates
//     of messages known not to want an ACK are not acked.
func (r *Router) Received(ctx context.Context, buddyID int64, res frame.Result) {
	id := res.Header.MsgID
	switch res.Status {
	case frame.Delivered:
		if res.Message == nil {
			return
		}
		in := res.Message.Inner
		if in.Type == frame.Ack {
			r.noAck.add(ackKey{buddyID, id})
			m, err := body.Unmarshal(frame.Ack, in.Body)
			if err != nil {
				r.n.badAcks.Add(1)
				r.log.Debug("router: bad ACK body", "buddy", buddyID, "err", err)
				return
			}
			if _, _, err := r.HandleAck(ctx, buddyID, m.(*pb.Ack)); err != nil && ctx.Err() == nil {
				r.log.Error("router: applying an ACK", "buddy", buddyID, "err", err)
			}
			return
		}
		if in.Flags&frame.FlagAckRequested == 0 {
			r.noAck.add(ackKey{buddyID, id})
			return
		}
	case frame.Partial, frame.Duplicate:
		// A partial message's type is unknown until fragment 0 is joined
		// with the rest; acking it costs at most an ignored ACK entry.
		if r.noAck.has(ackKey{buddyID, id}) {
			return
		}
	default:
		return
	}
	r.queueAck(buddyID, id, res.Have)
}

// HandleAck applies an ACK body from the buddy: each entry's bitmap is
// merged into our message with that msg_id. Entries for messages we never
// sent the buddy are ignored and counted. It reports how many entries
// matched and how many didn't.
func (r *Router) HandleAck(ctx context.Context, buddyID int64, ack *pb.Ack) (applied, unknown int, err error) {
	r.ackMu.Lock()
	defer r.ackMu.Unlock()
	kick := false
	defer func() {
		if kick {
			r.Kick(buddyID) // a window slot is free
		}
	}()
	for _, e := range ack.GetEntries() {
		r.n.ackEntriesIn.Add(1)
		var id frame.MsgID
		if len(e.GetMsgId()) != len(id) || e.GetHave() == 0 || e.GetHave() >= 1<<16 {
			r.n.badAcks.Add(1)
			continue
		}
		copy(id[:], e.GetMsgId())
		prev, err := r.cfg.Store.OutgoingByMsgID(ctx, buddyID, id)
		if errors.Is(err, store.ErrNotFound) {
			unknown++
			r.n.unknownAcks.Add(1)
			continue
		} else if err != nil {
			return applied, unknown, err
		}
		o, err := r.cfg.Store.Ack(ctx, buddyID, id, uint16(e.GetHave()))
		if err != nil {
			return applied, unknown, err
		}
		applied++
		if o.AckedMask == prev.AckedMask && o.State == prev.State {
			continue
		}
		if o.State == store.Acked {
			kick = true
		}
		r.emit(Event{BuddyID: buddyID, OutboxID: o.ID, MsgID: o.MsgID, State: stateOf(o),
			AckedMask: o.AckedMask, FragCount: prev.FragCount, Attempts: o.Attempts})
	}
	return applied, unknown, nil
}

// queueAck adds {msg_id, have} to the buddy's next ACK, merging bitmaps for
// the same message. The ACK goes out after AckDelay, or at once when it is
// full.
func (r *Router) queueAck(buddyID int64, id frame.MsgID, have uint16) {
	if have == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	st := r.state(buddyID)
	if i, ok := st.ackIdx[id]; ok {
		st.acks[i].Have |= uint32(have)
		return
	}
	if len(st.acks) >= MaxPendingAcks {
		r.n.ackEntriesDropped.Add(1)
		return
	}
	st.ackIdx[id] = len(st.acks)
	st.acks = append(st.acks, &pb.AckEntry{MsgId: id[:], Have: uint32(have)})
	r.armAcksLocked(buddyID, st)
}

// armAcksLocked schedules the buddy's ACK: at once if a full one is waiting,
// else after AckDelay.
func (r *Router) armAcksLocked(id int64, st *bstate) {
	switch {
	case len(st.acks) >= body.MaxAckEntries:
		if st.ackTimer != nil {
			st.ackTimer.Stop()
			st.ackTimer = nil
		}
		r.enqueueAcksLocked(id, st)
	case len(st.acks) > 0 && st.ackTimer == nil && !st.ackQueued:
		st.ackTimer = r.clock.AfterFunc(r.cfg.AckDelay, func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.closed {
				return
			}
			st := r.state(id)
			st.ackTimer = nil
			r.enqueueAcksLocked(id, st)
		})
	}
}

func (r *Router) enqueueAcksLocked(id int64, st *bstate) {
	if st.ackQueued || len(st.acks) == 0 {
		return
	}
	st.ackQueued = true
	r.cfg.jobs.Add(1)
	r.queue = append(r.queue, job{buddy: id, acks: true})
	r.cond.Signal()
}

// takeAcksLocked removes and returns up to n of the buddy's pending ACK
// entries, oldest first.
func (r *Router) takeAcksLocked(st *bstate, n int) []*pb.AckEntry {
	n = min(n, len(st.acks))
	if n == 0 {
		return nil
	}
	out := st.acks[:n:n]
	st.acks = append([]*pb.AckEntry(nil), st.acks[n:]...)
	clear(st.ackIdx)
	for i, e := range st.acks {
		st.ackIdx[frame.MsgID(e.GetMsgId())] = i
	}
	return out
}

// TakeAcks removes and returns up to max (≤ 32) of the buddy's pending ACK
// entries, for a sender that can carry them in another message (piggyback).
// Entries taken are no longer sent by the router.
func (r *Router) TakeAcks(buddyID int64, max int) []*pb.AckEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.buddies[buddyID]
	if st == nil {
		return nil
	}
	return r.takeAcksLocked(st, min(max, body.MaxAckEntries))
}

// sendAcks seals and sends one ACK message of up to 32 pending entries,
// best effort: on any failure the entries are dropped, and the buddy's
// retry gets a fresh ACK when its duplicate arrives.
func (r *Router) sendAcks(buddyID int64) {
	r.mu.Lock()
	st := r.state(buddyID)
	entries := r.takeAcksLocked(st, body.MaxAckEntries)
	if st.ackTimer != nil { // the entries it was for are going now
		st.ackTimer.Stop()
		st.ackTimer = nil
	}
	if !r.closed {
		r.armAcksLocked(buddyID, st) // entries that came meanwhile
	}
	r.mu.Unlock()
	if len(entries) == 0 {
		return
	}
	drop := func(counter interface{ Add(uint64) uint64 }) {
		counter.Add(1)
		r.n.ackEntriesDropped.Add(uint64(len(entries)))
	}
	ctx := r.ctx
	route, ok := r.cfg.Reach.IPRoute(buddyID, r.clock.Now())
	if !ok {
		drop(&r.n.ackNoRoute)
		return
	}
	ct, b, err := body.Marshal(&pb.Ack{Entries: entries})
	if err != nil {
		r.log.Error("router: encoding an ACK", "err", err)
		drop(&r.n.ackSendFailures)
		return
	}
	frames, err := r.cfg.Seal(ctx, buddyID, ct, b)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("router: sealing an ACK", "buddy", buddyID, "err", err)
		}
		drop(&r.n.ackSendFailures)
		return
	}
	sctx, cancel := context.WithTimeout(ctx, r.cfg.SendTimeout)
	err = r.cfg.Transport.Send(sctx, route, frames)
	cancel()
	if err != nil {
		r.log.Debug("router: ACK send failed", "buddy", buddyID, "err", err)
		drop(&r.n.ackSendFailures)
		return
	}
	r.n.acksSent.Add(1)
	r.n.ackEntriesSent.Add(uint64(len(entries)))
}

type ackKey struct {
	buddy int64
	id    frame.MsgID
}

// lru is a bounded set of ackKeys, evicting the least recently added.
type lru struct {
	mu  sync.Mutex
	max int
	l   *list.List
	m   map[ackKey]*list.Element
}

func newLRU(max int) *lru {
	return &lru{max: max, l: list.New(), m: map[ackKey]*list.Element{}}
}

func (c *lru) add(k ackKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.l.MoveToFront(e)
		return
	}
	c.m[k] = c.l.PushFront(k)
	if c.l.Len() > c.max {
		old := c.l.Back()
		c.l.Remove(old)
		delete(c.m, old.Value.(ackKey))
	}
}

func (c *lru) has(k ackKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.m[k]
	return ok
}
