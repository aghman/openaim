package router

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Defaults for Config's zero values.
const (
	// DefaultAckTimeout is how long a first IP attempt waits for an ACK,
	// and the base of the retry backoff.
	DefaultAckTimeout = 3 * time.Second
	// DefaultMaxRetryDelay caps the retry backoff (before jitter).
	DefaultMaxRetryDelay = 5 * time.Minute
	// DefaultJitter spreads each retry delay by ±20%.
	DefaultJitter = 0.2
	// DefaultHorizon is when the router gives up on a message: the
	// receiver's acceptance window (design §8.9), after which it would
	// reject the frames anyway.
	DefaultHorizon = frame.MaxAge
	// DefaultWindow is how many messages per buddy may be awaiting their
	// ACK at once.
	DefaultWindow = 8
	// DefaultSendTimeout bounds one Transport.Send.
	DefaultSendTimeout = 15 * time.Second
	// DefaultWorkers is how many buddies are flushed concurrently.
	DefaultWorkers = 4
	// DefaultAckDelay is how long ACK entries are collected before they are
	// sent (fewer, fuller ACK messages).
	DefaultAckDelay = 100 * time.Millisecond
	// MaxPendingAcks bounds the ACK entries waiting for one buddy; more
	// are dropped (the sender retries and the duplicate is re-acked).
	MaxPendingAcks = 256
	// noAckMemory is how many received messages that must not be acked
	// (ACKs, messages without the ack-requested flag) are remembered, so
	// their duplicates aren't acked either.
	noAckMemory = 4096
)

// Config configures a Router. Store, Transport, Reach and Seal are
// required; zero values elsewhere mean the defaults.
type Config struct {
	Store     *store.Store
	Transport Transport
	Reach     Reachability
	Seal      Sealer
	Clock     Clock // nil means the real clock
	// OnEvent is called on delivery-state changes, from router goroutines.
	// It must not block.
	OnEvent func(Event)
	Log     *slog.Logger

	AckTimeout    time.Duration
	MaxRetryDelay time.Duration
	// Jitter is the relative spread of retry delays; negative means none.
	Jitter      float64
	Horizon     time.Duration
	Window      int
	SendTimeout time.Duration
	Workers     int
	AckDelay    time.Duration

	// jobs, if set, counts queued and running jobs (tests share one
	// between routers to tell when everything is idle).
	jobs *atomic.Int64
}

func (c Config) withDefaults() (Config, error) {
	if c.Store == nil || c.Transport == nil || c.Reach == nil || c.Seal == nil {
		return c, errors.New("router: Store, Transport, Reach and Seal are required")
	}
	if c.Clock == nil {
		c.Clock = realClock{}
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&c.AckTimeout, DefaultAckTimeout)
	def(&c.MaxRetryDelay, DefaultMaxRetryDelay)
	def(&c.Horizon, DefaultHorizon)
	def(&c.SendTimeout, DefaultSendTimeout)
	def(&c.AckDelay, DefaultAckDelay)
	switch {
	case c.Jitter == 0:
		c.Jitter = DefaultJitter
	case c.Jitter < 0:
		c.Jitter = 0
	case c.Jitter >= 1:
		return c, fmt.Errorf("router: jitter %v must be below 1", c.Jitter)
	}
	if c.Window <= 0 {
		c.Window = DefaultWindow
	}
	if c.Workers <= 0 {
		c.Workers = DefaultWorkers
	}
	if c.jobs == nil {
		c.jobs = new(atomic.Int64)
	}
	return c, nil
}

// DeliveryState is an outgoing message's state as clients see it.
type DeliveryState int

const (
	Queued DeliveryState = iota // sealed, not yet sent
	Sent                        // sent at least once; AckedMask may be partial
	Acked                       // every fragment acked
	Failed                      // given up on
)

func (s DeliveryState) String() string {
	return [...]string{"queued", "sent", "acked", "failed"}[s]
}

func stateOf(o *store.Outgoing) DeliveryState {
	switch {
	case o.State == store.Acked:
		return Acked
	case o.State == store.Failed:
		return Failed
	case o.Attempts > 0:
		return Sent
	}
	return Queued
}

// Event is a delivery-state change of an outgoing message: its first send,
// a change to its ACK bitmap, or giving up.
type Event struct {
	BuddyID   int64
	OutboxID  int64
	MsgID     frame.MsgID
	State     DeliveryState
	AckedMask uint16
	FragCount int
	Attempts  int
}

// Stats are cumulative counters.
type Stats struct {
	Sends, SendFailures, FramesSent, Retries uint64
	Failed                                   uint64 // messages given up on
	AcksSent, AckSendFailures, AckNoRoute    uint64 // ACK messages
	AckEntriesSent, AckEntriesDropped        uint64
	AckEntriesIn, UnknownAcks, BadAcks       uint64 // ACK entries received
}

type counters struct {
	sends, sendFailures, framesSent, retries, failed atomic.Uint64
	acksSent, ackSendFailures, ackNoRoute            atomic.Uint64
	ackEntriesSent, ackEntriesDropped                atomic.Uint64
	ackEntriesIn, unknownAcks, badAcks               atomic.Uint64
}

// Router is the send policy v0 (design §7.2 rules 1 and 5) and the IP ACK
// layer (design §8.8).
//
// Outgoing messages live in the store's outbox, sealed once (design §8.2).
// When a buddy has an IP route, the router sends its queued messages oldest
// first, one Transport.Send per message, with at most Window of them
// awaiting an ACK. A message not fully acked is re-sent after a backoff,
// with only the fragments its ACK bitmap lacks, always the stored bytes; it
// is never sealed again. Without a route messages stay queued until
// RouteChanged. Messages still unacked after Horizon are marked failed. All
// retry state (attempts, last attempt, ACK bitmap) is in the store, so a new
// Router on the same store resumes where the last one stopped.
//
// Inbound, Received schedules ACKs for the buddy's DATA messages, coalesced
// into ACK messages of up to 32 entries, sealed by the caller's Sealer and
// sent once (ACKs are neither acked nor persisted), and applies ACKs the
// buddy sent us.
type Router struct {
	cfg    Config
	clock  Clock
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	cond    *sync.Cond
	closed  bool
	queue   []job
	buddies map[int64]*bstate

	ackMu sync.Mutex // serializes HandleAck's read-then-update
	noAck *lru

	n counters
}

type job struct {
	buddy int64
	acks  bool
}

// bstate is a buddy's in-memory scheduling state. Everything durable is in
// the store.
type bstate struct {
	queued, running, again, force bool
	retry                         Timer // next flush

	routeFails   int
	routeRetryAt time.Time // after a Transport failure, wait until then

	acks      []*pb.AckEntry
	ackIdx    map[frame.MsgID]int
	ackQueued bool
	ackTimer  Timer
}

// New starts a router's workers. Call Start to resume the outbox.
func New(cfg Config) (*Router, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{cfg: cfg, clock: cfg.Clock, log: cfg.Log, ctx: ctx, cancel: cancel,
		buddies: map[int64]*bstate{}, noAck: newLRU(noAckMemory)}
	r.cond = sync.NewCond(&r.mu)
	for range cfg.Workers {
		r.wg.Add(1)
		go r.worker()
	}
	return r, nil
}

// Start schedules a flush of every buddy with queued messages, resuming
// retries after a restart.
func (r *Router) Start(ctx context.Context) error {
	ids, err := r.cfg.Store.PendingBuddies(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		r.Kick(id)
	}
	return nil
}

// Close stops the router: pending timers are cancelled, sends in progress
// are abandoned (their context is cancelled) and workers exit. Queued state
// stays in the store. Close waits for the workers.
func (r *Router) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	for _, st := range r.buddies {
		if st.retry != nil {
			st.retry.Stop()
		}
		if st.ackTimer != nil {
			st.ackTimer.Stop()
		}
	}
	r.cfg.jobs.Add(-int64(len(r.queue)))
	r.queue = nil
	r.cond.Broadcast()
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
	return nil
}

// Stats returns the counters.
func (r *Router) Stats() Stats {
	return Stats{
		Sends: r.n.sends.Load(), SendFailures: r.n.sendFailures.Load(), FramesSent: r.n.framesSent.Load(),
		Retries: r.n.retries.Load(), Failed: r.n.failed.Load(),
		AcksSent: r.n.acksSent.Load(), AckSendFailures: r.n.ackSendFailures.Load(), AckNoRoute: r.n.ackNoRoute.Load(),
		AckEntriesSent: r.n.ackEntriesSent.Load(), AckEntriesDropped: r.n.ackEntriesDropped.Load(),
		AckEntriesIn: r.n.ackEntriesIn.Load(), UnknownAcks: r.n.unknownAcks.Load(), BadAcks: r.n.badAcks.Load(),
	}
}

// Kick asks the router to send the buddy's due messages: call it after
// store.Enqueue. It doesn't block.
func (r *Router) Kick(buddyID int64) { r.schedule(buddyID, false) }

// RouteChanged reports an authenticated reachability update for the buddy
// (a REACH body, a rendezvous record, a session coming up). The buddy's
// unacked messages are sent again now, oldest first up to the window,
// ignoring their backoff: earlier attempts may have gone to a dead route
// (design §7.2 rule 5). It doesn't block.
func (r *Router) RouteChanged(buddyID int64) { r.schedule(buddyID, true) }

// Forget drops the buddy's in-memory state (timers, pending ACK entries),
// for a removed or blocked buddy. Its outbox rows are the store's business.
func (r *Router) Forget(buddyID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.buddies[buddyID]
	if st == nil {
		return
	}
	if st.retry != nil {
		st.retry.Stop()
		st.retry = nil
	}
	if st.ackTimer != nil {
		st.ackTimer.Stop()
		st.ackTimer = nil
	}
	st.acks, st.ackIdx = nil, map[frame.MsgID]int{}
	if !st.queued && !st.running && !st.ackQueued {
		// Otherwise a job still refers to the state; it finds nothing to
		// do once the buddy's outbox rows are gone.
		delete(r.buddies, buddyID)
	}
}

func (r *Router) state(id int64) *bstate {
	st := r.buddies[id]
	if st == nil {
		st = &bstate{ackIdx: map[frame.MsgID]int{}}
		r.buddies[id] = st
	}
	return st
}

func (r *Router) schedule(id int64, force bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	st := r.state(id)
	if force {
		st.force = true
		st.routeFails, st.routeRetryAt = 0, time.Time{}
	}
	if st.running {
		st.again = true
		return
	}
	r.enqueueLocked(id, st)
}

func (r *Router) enqueueLocked(id int64, st *bstate) {
	if st.queued {
		return
	}
	st.queued = true
	r.cfg.jobs.Add(1)
	r.queue = append(r.queue, job{buddy: id})
	r.cond.Signal()
}

func (r *Router) worker() {
	defer r.wg.Done()
	for {
		r.mu.Lock()
		for len(r.queue) == 0 && !r.closed {
			r.cond.Wait()
		}
		if r.closed {
			r.mu.Unlock()
			return
		}
		j := r.queue[0]
		r.queue[0] = job{}
		r.queue = r.queue[1:]
		st := r.buddies[j.buddy]
		if j.acks {
			st.ackQueued = false
			r.mu.Unlock()
			r.sendAcks(j.buddy)
			r.cfg.jobs.Add(-1)
			continue
		}
		st.queued, st.running = false, true
		force := st.force
		st.force = false
		r.mu.Unlock()

		wake := r.flush(j.buddy, force)

		r.mu.Lock()
		st.running = false
		if !r.closed {
			r.setRetryLocked(j.buddy, st, wake)
			if st.again {
				st.again = false
				r.enqueueLocked(j.buddy, st)
			}
		}
		r.mu.Unlock()
		r.cfg.jobs.Add(-1)
	}
}

// setRetryLocked arms the buddy's flush timer for wake (zero: none).
func (r *Router) setRetryLocked(id int64, st *bstate, wake time.Time) {
	if st.retry != nil {
		st.retry.Stop()
		st.retry = nil
	}
	if wake.IsZero() {
		return
	}
	st.retry = r.clock.AfterFunc(max(wake.Sub(r.clock.Now()), 0), func() { r.Kick(id) })
}

// RetryDelay is how long after attempt n (1-based) of outbox entry id the
// message is re-sent if not fully acked: AckTimeout·2^(n−1), capped at
// MaxRetryDelay, times a jitter factor in [1−Jitter, 1+Jitter). The jitter
// is a hash of (id, n), so the schedule is the same after a restart.
func (r *Router) RetryDelay(id int64, n int) time.Duration {
	d := r.cfg.MaxRetryDelay
	if n < 1 {
		n = 1
	}
	if n <= 32 {
		if b := r.cfg.AckTimeout << (n - 1); b > 0 && b < d {
			d = b
		}
	}
	if r.cfg.Jitter == 0 {
		return d
	}
	h := fnv.New64a()
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(id))
	binary.BigEndian.PutUint64(buf[8:], uint64(n))
	h.Write(buf[:])
	u := float64(h.Sum64()>>11) / (1 << 53) // [0, 1)
	return time.Duration(float64(d) * (1 + r.cfg.Jitter*(2*u-1)))
}

// flush sends the buddy's due messages and returns when it next needs to
// run (zero: only when kicked).
func (r *Router) flush(id int64, force bool) time.Time {
	ctx := r.ctx
	now := time.UnixMilli(r.clock.Now().UnixMilli()) // the store keeps milliseconds
	var wake time.Time
	at := func(t time.Time) {
		if t.After(now) && (wake.IsZero() || t.Before(wake)) {
			wake = t
		}
	}

	msgs, err := r.cfg.Store.PendingMeta(ctx, id)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("router: reading the outbox", "buddy", id, "err", err)
			at(now.Add(r.cfg.AckTimeout))
		}
		return wake
	}
	if len(msgs) == 0 {
		return wake
	}

	r.mu.Lock()
	st := r.state(id)
	routeRetryAt := st.routeRetryAt
	r.mu.Unlock()
	route, canSend := r.cfg.Reach.IPRoute(id, now)
	if canSend && now.Before(routeRetryAt) {
		canSend = false
		at(routeRetryAt)
	}

	inflight := 0
	for _, m := range msgs {
		giveUp := m.CreatedAt.Add(r.cfg.Horizon)
		if !now.Before(giveUp) {
			r.fail(ctx, m)
			continue
		}
		at(giveUp)
		if m.Attempts > 0 && !force {
			d := r.RetryDelay(m.ID, m.Attempts)
			flightEnd := m.LastAttempt.Add(min(d, r.cfg.AckTimeout))
			if now.Before(flightEnd) { // awaiting its ACK
				inflight++
				at(flightEnd)
				at(m.LastAttempt.Add(d))
				continue
			}
			if now.Before(m.LastAttempt.Add(d)) { // backing off
				at(m.LastAttempt.Add(d))
				continue
			}
		}
		if !canSend || inflight >= r.cfg.Window {
			continue // a flight ending, an ACK or a route change wakes us
		}
		ok, terr := r.send(ctx, route, m, now)
		if ctx.Err() != nil {
			return time.Time{}
		}
		if terr != nil {
			r.log.Debug("router: send failed", "buddy", id, "peer", route.Peer, "err", terr)
			r.mu.Lock()
			st.routeFails++
			// Same backoff as messages; the negated buddy ID keeps its
			// jitter apart from outbox entries'.
			st.routeRetryAt = now.Add(r.RetryDelay(-id, st.routeFails))
			at(st.routeRetryAt)
			r.mu.Unlock()
			canSend = false
			continue
		}
		if !ok { // store trouble; try again later
			at(now.Add(r.cfg.AckTimeout))
			continue
		}
		r.mu.Lock()
		st.routeFails, st.routeRetryAt = 0, time.Time{}
		r.mu.Unlock()
		inflight++
		d := r.RetryDelay(m.ID, m.Attempts+1)
		at(now.Add(min(d, r.cfg.AckTimeout)))
		at(now.Add(d))
	}
	return wake
}

// send sends m's unacked fragments, exactly as stored, and records the
// attempt. It reports whether it sent, and the Transport's error.
func (r *Router) send(ctx context.Context, route Route, m *store.OutgoingMeta, now time.Time) (bool, error) {
	o, err := r.cfg.Store.Outgoing(ctx, m.ID)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("router: loading frames", "outbox_id", m.ID, "err", err)
		}
		return false, nil
	}
	if o.State != store.Queued {
		return false, nil // acked or failed meanwhile
	}
	frames := make([][]byte, 0, len(o.Frames))
	for i, f := range o.Frames {
		if o.AckedMask&(1<<i) == 0 {
			frames = append(frames, f)
		}
	}
	if len(frames) == 0 {
		return false, nil
	}
	sctx, cancel := context.WithTimeout(ctx, r.cfg.SendTimeout)
	err = r.cfg.Transport.Send(sctx, route, frames)
	cancel()
	if err != nil {
		r.n.sendFailures.Add(1)
		return false, err
	}
	r.n.sends.Add(1)
	r.n.framesSent.Add(uint64(len(frames)))
	if o.Attempts > 0 {
		r.n.retries.Add(1)
	}
	if err := r.cfg.Store.RecordAttempt(ctx, m.ID, now); err != nil {
		// The frames went out; without the record they'll be re-sent
		// sooner than planned, which receivers tolerate.
		if ctx.Err() == nil {
			r.log.Error("router: recording an attempt", "outbox_id", m.ID, "err", err)
		}
		return false, nil
	}
	if o.Attempts == 0 {
		r.emit(Event{BuddyID: o.BuddyID, OutboxID: o.ID, MsgID: o.MsgID, State: Sent,
			AckedMask: o.AckedMask, FragCount: len(o.Frames), Attempts: 1})
	}
	return true, nil
}

func (r *Router) fail(ctx context.Context, m *store.OutgoingMeta) {
	if err := r.cfg.Store.MarkFailed(ctx, m.ID); err != nil {
		if !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
			r.log.Error("router: marking a message failed", "outbox_id", m.ID, "err", err)
		}
		return
	}
	r.n.failed.Add(1)
	r.log.Info("router: gave up on a message", "buddy", m.BuddyID, "msg_id", m.MsgID, "attempts", m.Attempts)
	r.emit(Event{BuddyID: m.BuddyID, OutboxID: m.ID, MsgID: m.MsgID, State: Failed,
		AckedMask: m.AckedMask, FragCount: m.FragCount, Attempts: m.Attempts})
}

func (r *Router) emit(e Event) {
	if r.cfg.OnEvent != nil {
		r.cfg.OnEvent(e)
	}
}
