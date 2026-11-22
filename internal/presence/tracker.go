package presence

import (
	"bytes"
	"context"
	"hash/fnv"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/identity"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Tracker is the presence state machine. Its methods are safe for concurrent
// use. It runs 1 + Config.SendWorkers goroutines until Close.
type Tracker struct {
	cfg Config
	clk Clock

	mu      sync.Mutex
	closed  bool
	own     ownState
	buddies map[identity.PublicKey]*buddy
	queue   []*buddy // buddies with a send pending, FIFO
	waiters []chan struct{}
	stats   Stats

	events chan Event
	kick   chan struct{}
	flushq chan chan struct{}
	notify chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type ownState struct {
	state        State
	awayText     string
	awayRev      uint32
	meshNode     uint32
	lastActivity time.Time // zero: none reported, idle detection off
	idle         bool
	autoAway     bool
	autoArmed    bool // auto-away may fire (re-armed by activity)
}

type buddy struct {
	key   identity.PublicKey
	state State
	since time.Time

	idleMinutes uint32
	idleSince   time.Time
	awayRev     uint32
	meshNode    uint32

	stamp     Stamp
	haveStamp bool
	lastHeard time.Time

	peers      map[string]struct{}
	graceUntil time.Time // zero: no grace running

	// Sending.
	hbDue                   time.Time // next heartbeat; zero: none scheduled
	queued, inflight, again bool

	// Away messages, newest last.
	away     []AwayMessage
	fetchRev uint32
	fetchAt  time.Time
}

// New starts a Tracker. Call Close to stop it.
func New(cfg Config) (*Tracker, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &Tracker{
		cfg:     cfg,
		clk:     cfg.Clock,
		buddies: map[identity.PublicKey]*buddy{},
		events:  make(chan Event, cfg.EventBuffer),
		kick:    make(chan struct{}, 1),
		flushq:  make(chan chan struct{}),
		notify:  make(chan struct{}, cfg.SendWorkers),
		ctx:     ctx,
		cancel:  cancel,
	}
	t.own = ownState{
		state:        cfg.State,
		awayText:     cfg.AwayText,
		awayRev:      awayRev(cfg.AwayText),
		meshNode:     cfg.MeshNode,
		lastActivity: cfg.LastActivity,
		autoArmed:    !cfg.LastActivity.IsZero(),
	}
	t.wg.Add(1 + cfg.SendWorkers)
	go t.loop()
	for range cfg.SendWorkers {
		go t.worker()
	}
	return t, nil
}

// Events delivers transitions, fetch requests, away messages and own
// changes, in order. It is closed by Close. If the consumer falls more than
// Config.EventBuffer behind, events are dropped and counted in
// Stats.EventsDropped; Buddies and Own give the current state to resync.
func (t *Tracker) Events() <-chan Event { return t.events }

// Close stops the Tracker without sending anything; call SignOff first for
// a clean sign-off. In-flight sends are cancelled. Close is idempotent.
func (t *Tracker) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	for _, w := range t.waiters {
		close(w)
	}
	t.waiters = nil
	t.mu.Unlock()
	t.cancel()
	t.wg.Wait()
	close(t.events)
	return nil
}

// SignOff sets our state to OFFLINE, sends that to every accepted buddy with
// a session up, and waits until those sends finish or ctx ends. Heartbeats
// stop. The Tracker keeps running (a later Set can sign back on); call Close
// afterwards to shut down.
func (t *Tracker) SignOff(ctx context.Context) error {
	if err := t.SetState(Offline); err != nil {
		return err
	}
	return t.drain(ctx)
}

// drain waits until no send is queued or in flight.
func (t *Tracker) drain(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	if t.sendsIdleLocked() {
		t.mu.Unlock()
		return nil
	}
	w := make(chan struct{})
	t.waiters = append(t.waiters, w)
	t.mu.Unlock()
	select {
	case <-w:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *Tracker) sendsIdleLocked() bool {
	if len(t.queue) > 0 {
		return false
	}
	for _, b := range t.buddies {
		if b.inflight {
			return false
		}
	}
	return true
}

// lock locks t unless it is closed.
func (t *Tracker) lock() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	return nil
}

// unlock unlocks t and wakes the loop to reschedule.
func (t *Tracker) unlock() {
	t.mu.Unlock()
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

func (t *Tracker) emitLocked(e Event) {
	select {
	case t.events <- e:
	default:
		t.stats.EventsDropped++
	}
}

// Stats returns the counters.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats
}

// ---- Accepted set ----

// SetBuddies replaces the accepted buddy set. Buddies that leave it are
// forgotten (a transition to Offline with ReasonRemoved is emitted if they
// were shown online), along with their sessions and away messages.
func (t *Tracker) SetBuddies(keys []identity.PublicKey) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	keep := make(map[identity.PublicKey]bool, len(keys))
	for _, k := range keys {
		keep[k] = true
	}
	now := t.clk.Now()
	for k, b := range t.buddies {
		if !keep[k] {
			t.removeLocked(b, now)
		}
	}
	for k := range keep {
		t.addLocked(k)
	}
	return nil
}

// AddBuddy adds an accepted buddy. If a session with them is already up,
// report it with SessionUp afterwards.
func (t *Tracker) AddBuddy(k identity.PublicKey) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	t.addLocked(k)
	return nil
}

// RemoveBuddy removes a buddy from the accepted set (see SetBuddies).
func (t *Tracker) RemoveBuddy(k identity.PublicKey) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	if b := t.buddies[k]; b != nil {
		t.removeLocked(b, t.clk.Now())
	}
	return nil
}

func (t *Tracker) addLocked(k identity.PublicKey) {
	if t.buddies[k] == nil {
		t.buddies[k] = &buddy{key: k, state: Offline, peers: map[string]struct{}{}}
	}
}

func (t *Tracker) removeLocked(b *buddy, now time.Time) {
	delete(t.buddies, b.key)
	if i := slices.Index(t.queue, b); i >= 0 {
		t.queue = slices.Delete(t.queue, i, i+1)
	}
	if b.state != Offline {
		t.goOfflineLocked(b, now, ReasonRemoved)
	}
	t.wakeWaitersLocked()
}

// ---- Sessions ----

// SessionUp reports that a /openaim/msg/1 session with peer (string(peer.ID))
// is up and belongs to buddy k. Call it once the peer is attributed to the
// buddy: dialled from their rendezvous record, or on the first authenticated
// frame from it. When the buddy's first session comes up we send them our
// presence ("door open") and cancel any door-close grace. A session alone
// never shows the buddy online: only their PRESENCE does (design §7.1).
func (t *Tracker) SessionUp(k identity.PublicKey, peer string) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	b := t.buddies[k]
	if b == nil {
		t.stats.NotAccepted++
		return ErrNotAccepted
	}
	if _, ok := b.peers[peer]; ok {
		return nil
	}
	b.peers[peer] = struct{}{}
	if len(b.peers) == 1 {
		b.graceUntil = time.Time{}
		t.markPendingLocked(b)
	}
	return nil
}

// SessionDown reports that the session with peer went down (an ip.Sessions
// Down event). When the buddy's last session goes down, heartbeats to them
// stop and, if they are shown online, the door-close grace starts. Unknown
// buddies and peers are ignored.
func (t *Tracker) SessionDown(k identity.PublicKey, peer string) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	b := t.buddies[k]
	if b == nil {
		return nil
	}
	if _, ok := b.peers[peer]; !ok {
		return nil
	}
	delete(b.peers, peer)
	if len(b.peers) == 0 {
		b.hbDue = time.Time{}
		if b.state != Offline {
			b.graceUntil = t.clk.Now().Add(t.cfg.Grace)
		}
	}
	return nil
}

// ---- Inbound ----

// Received applies a PRESENCE body from buddy k. The caller guarantees it
// came from k: it was opened under k's pairwise keys and passed the
// receiver's window and dedup checks. sent is its inner payload's stamp;
// bodies not newer than the last applied one are ignored (ErrStale), except
// that once a buddy has been shown OFFLINE for longer than the grace period
// any body is accepted again, so a buddy whose clock stepped back recovers.
func (t *Tracker) Received(k identity.PublicKey, sent Stamp, p *pb.Presence) error {
	if err := body.Validate(p); err != nil {
		return err
	}
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	b := t.buddies[k]
	if b == nil {
		t.stats.NotAccepted++
		return ErrNotAccepted
	}
	now := t.clk.Now()
	if b.haveStamp && !sent.after(b.stamp) && (b.state != Offline || now.Sub(b.since) < t.cfg.Grace) {
		t.stats.Stale++
		return ErrStale
	}
	t.stats.Received++
	b.stamp, b.haveStamp = sent, true
	b.graceUntil = time.Time{}
	to := State(p.GetState())
	if to == Offline {
		if b.state != Offline {
			t.goOfflineLocked(b, now, ReasonSignedOff)
		}
		return nil
	}
	before := b.shown()
	from := b.state
	b.lastHeard = now
	if b.state != to {
		b.state, b.since = to, now
	}
	b.awayRev, b.meshNode = p.GetAwayRev(), p.GetMyMeshNode()
	b.setIdle(p.GetIdleMinutes(), now)
	if b.shown() != before {
		t.transitionLocked(b, from, now, ReasonPresence)
	}
	// A buddy we had as offline may not have our presence either (they
	// just accepted us, or missed our door open): answer.
	if from == Offline && len(b.peers) > 0 {
		t.markPendingLocked(b)
	}
	t.maybeFetchLocked(b, now)
	return nil
}

// ReceivedAwayMsg stores an authenticated AWAY_MSG from buddy k (the reply
// to a FetchAway). Up to a few revs are cached per buddy.
func (t *Tracker) ReceivedAwayMsg(k identity.PublicKey, m *pb.AwayMsg) error {
	if err := body.Validate(m); err != nil {
		return err
	}
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	b := t.buddies[k]
	if b == nil {
		t.stats.NotAccepted++
		return ErrNotAccepted
	}
	am := AwayMessage{Buddy: k, Text: m.GetText(), Rev: m.GetRev()}
	b.away = slices.DeleteFunc(b.away, func(a AwayMessage) bool { return a.Rev == am.Rev })
	b.away = append(b.away, am)
	if len(b.away) > maxAwayCache {
		b.away = slices.Delete(b.away, 0, len(b.away)-maxAwayCache)
	}
	if am.Rev == b.fetchRev {
		b.fetchRev, b.fetchAt = 0, time.Time{}
	}
	if am.Rev == b.awayRev {
		t.emitLocked(Event{AwayMessage: &am})
	}
	return nil
}

// AwayMessage returns buddy k's cached away message for their current rev.
func (t *Tracker) AwayMessage(k identity.PublicKey) (text string, rev uint32, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buddies[k]
	if b == nil {
		return "", 0, false
	}
	if a, ok := b.cachedAway(b.awayRev); ok {
		return a.Text, a.Rev, true
	}
	return "", b.awayRev, false
}

// AwayReply is our AWAY_MSG for a ProfileReq{away_msg: true} from buddy k.
// Strangers get ErrNotAccepted (design §5.4).
func (t *Tracker) AwayReply(k identity.PublicKey) (*pb.AwayMsg, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.buddies[k] == nil {
		t.stats.NotAccepted++
		return nil, ErrNotAccepted
	}
	return &pb.AwayMsg{Text: t.own.awayText, Rev: t.own.awayRev}, nil
}

// Buddy is a snapshot of buddy k.
func (t *Tracker) Buddy(k identity.PublicKey) (BuddyStatus, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buddies[k]
	if b == nil {
		return BuddyStatus{}, false
	}
	return b.status(), true
}

// Buddies are snapshots of every accepted buddy, ordered by key.
func (t *Tracker) Buddies() []BuddyStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]BuddyStatus, 0, len(t.buddies))
	for _, b := range t.buddies {
		out = append(out, b.status())
	}
	slices.SortFunc(out, func(a, b BuddyStatus) int { return bytes.Compare(a.Buddy[:], b.Buddy[:]) })
	return out
}

// ---- Own presence ----

// Own is our current presence.
func (t *Tracker) Own() Own {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.own.snapshot()
}

// Set sets our state and away message together. An explicit state cancels
// auto-away until the next activity.
func (t *Tracker) Set(s State, away string) error {
	return t.setOwn(&s, &away, nil)
}

// SetState sets our state, keeping the away message.
func (t *Tracker) SetState(s State) error { return t.setOwn(&s, nil, nil) }

// SetAwayMessage sets the away message; its rev changes with the text.
func (t *Tracker) SetAwayMessage(text string) error { return t.setOwn(nil, &text, nil) }

// SetMeshNode sets the Meshtastic node number we advertise (0 = none).
func (t *Tracker) SetMeshNode(n uint32) error { return t.setOwn(nil, nil, &n) }

func (t *Tracker) setOwn(s *State, away *string, mesh *uint32) error {
	if s != nil && !s.valid() {
		return ErrInvalid
	}
	if away != nil {
		if err := checkAway(*away); err != nil {
			return err
		}
	}
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	before := t.own.snapshot()
	if s != nil {
		t.own.state = *s
		t.own.autoAway, t.own.autoArmed = false, false
	}
	if away != nil {
		t.own.awayText, t.own.awayRev = *away, awayRev(*away)
	}
	if mesh != nil {
		t.own.meshNode = *mesh
	}
	t.ownChangedLocked(before, t.clk.Now(), ReasonUser)
	return nil
}

// Activity reports the user's last activity (keyboard, mouse, a sent IM),
// from the UI or the OS. It ends idleness and auto-away, and re-arms
// auto-away. Times in the future count as now; older reports are ignored.
func (t *Tracker) Activity(at time.Time) error {
	if err := t.lock(); err != nil {
		return err
	}
	defer t.unlock()
	now := t.clk.Now()
	if at.After(now) {
		at = now
	}
	if !at.After(t.own.lastActivity) {
		return nil
	}
	before := t.own.snapshot()
	t.own.lastActivity = at
	t.own.autoArmed = true
	t.evalIdleLocked(now)
	t.ownChangedLocked(before, now, ReasonActive)
	return nil
}

// evalIdleLocked recomputes idleness and auto-away at now and returns the
// earliest future time either could change (zero: none).
func (t *Tracker) evalIdleLocked(now time.Time) (next time.Time) {
	o := &t.own
	if o.lastActivity.IsZero() {
		return time.Time{}
	}
	inactive := now.Sub(o.lastActivity)
	if t.cfg.IdleAfter > 0 {
		o.idle = inactive >= t.cfg.IdleAfter
		if !o.idle {
			next = o.lastActivity.Add(t.cfg.IdleAfter)
		}
	}
	if aa := t.cfg.AutoAwayAfter; aa > 0 {
		switch {
		case o.autoAway && inactive < aa:
			o.state, o.autoAway = Online, false
		case o.autoArmed && o.state == Online:
			if inactive >= aa {
				o.state, o.autoAway, o.autoArmed = Away, true, false
			} else {
				next = earliest(next, o.lastActivity.Add(aa))
			}
		}
	}
	return next
}

// ownChangedLocked emits an OwnChange and broadcasts if what buddies see
// changed.
func (t *Tracker) ownChangedLocked(before Own, now time.Time, reason Reason) {
	after := t.own.snapshot()
	if after == before {
		return
	}
	if after.AutoAway && !before.AutoAway {
		reason = ReasonAutoAway
	} else if after.Idle && !before.Idle && reason != ReasonUser {
		reason = ReasonIdle
	}
	t.emitLocked(Event{Own: &OwnChange{From: before, To: after, At: now, Reason: reason}})
	idleSeen := before.Idle != after.Idle && after.State != Offline // OFFLINE carries no idle time
	if before.State != after.State || idleSeen || before.AwayRev != after.AwayRev || before.MeshNode != after.MeshNode {
		t.stats.Broadcasts++
		for _, b := range t.buddies {
			if len(b.peers) > 0 {
				t.markPendingLocked(b)
			}
		}
	}
}

func (o *ownState) snapshot() Own {
	s := Own{State: o.state, AwayText: o.awayText, AwayRev: o.awayRev, Idle: o.idle, AutoAway: o.autoAway, MeshNode: o.meshNode}
	if o.idle {
		s.IdleSince = o.lastActivity
	}
	return s
}

// bodyLocked is the PRESENCE we send now.
func (t *Tracker) bodyLocked(now time.Time) *pb.Presence {
	o := &t.own
	p := &pb.Presence{State: o.state.Proto(), AwayRev: o.awayRev, MyMeshNode: o.meshNode}
	if o.idle && o.state != Offline {
		m := now.Sub(o.lastActivity) / time.Minute
		p.IdleMinutes = uint32(min(max(m, 1), body.MaxIdleMinutes))
	}
	return p
}

// ---- Buddy state ----

// shownState is what the UI shows for a buddy; a change emits a Transition.
type shownState struct {
	state             State
	idle              bool
	awayRev, meshNode uint32
}

func (b *buddy) shown() shownState {
	return shownState{state: b.state, idle: b.idleMinutes > 0, awayRev: b.awayRev, meshNode: b.meshNode}
}

func (b *buddy) setIdle(minutes uint32, now time.Time) {
	b.idleMinutes = minutes
	if minutes == 0 {
		b.idleSince = time.Time{}
		return
	}
	since := now.Add(-time.Duration(minutes) * time.Minute)
	// Minute granularity: keep the earlier estimate unless it drifted.
	if d := since.Sub(b.idleSince); b.idleSince.IsZero() || d < -time.Minute || d > time.Minute {
		b.idleSince = since
	}
}

func (b *buddy) cachedAway(rev uint32) (AwayMessage, bool) {
	for _, a := range b.away {
		if a.Rev == rev {
			return a, true
		}
	}
	return AwayMessage{}, false
}

func (b *buddy) status() BuddyStatus {
	s := BuddyStatus{
		Buddy: b.key, State: b.state, Since: b.since, IdleMinutes: b.idleMinutes, IdleSince: b.idleSince,
		AwayRev: b.awayRev, MeshNode: b.meshNode, LastHeard: b.lastHeard,
		Connected: len(b.peers) > 0, InGrace: !b.graceUntil.IsZero(),
	}
	if a, ok := b.cachedAway(b.awayRev); ok {
		s.AwayText, s.AwayKnown = a.Text, true
	}
	return s
}

func (t *Tracker) goOfflineLocked(b *buddy, now time.Time, reason Reason) {
	from := b.state
	b.state, b.since = Offline, now
	b.idleMinutes, b.idleSince = 0, time.Time{}
	b.graceUntil = time.Time{}
	t.transitionLocked(b, from, now, reason)
}

func (t *Tracker) transitionLocked(b *buddy, from State, now time.Time, reason Reason) {
	t.emitLocked(Event{Transition: &Transition{
		Buddy: b.key, From: from, To: b.state, IdleMinutes: b.idleMinutes, IdleSince: b.idleSince,
		AwayRev: b.awayRev, MeshNode: b.meshNode, At: now, Reason: reason,
	}})
}

// maybeFetchLocked signals FetchAway when an away buddy's away rev is not
// cached. Away messages are fetched on demand, never broadcast, so only
// while the buddy is away; a pending fetch is repeated after FetchRetry.
func (t *Tracker) maybeFetchLocked(b *buddy, now time.Time) {
	if b.state != Away || b.awayRev == 0 {
		return
	}
	if _, ok := b.cachedAway(b.awayRev); ok {
		return
	}
	if b.fetchRev == b.awayRev && now.Sub(b.fetchAt) < t.cfg.FetchRetry {
		return
	}
	b.fetchRev, b.fetchAt = b.awayRev, now
	t.emitLocked(Event{FetchAway: &FetchAway{Buddy: b.key, Rev: b.awayRev, At: now}})
}

// ---- Scheduling ----

// tickLocked handles everything due at now and returns the next deadline
// (zero: none).
func (t *Tracker) tickLocked(now time.Time) time.Time {
	before := t.own.snapshot()
	next := t.evalIdleLocked(now)
	t.ownChangedLocked(before, now, ReasonIdle)
	for _, b := range t.buddies {
		if !b.graceUntil.IsZero() {
			if !now.Before(b.graceUntil) {
				t.goOfflineLocked(b, now, ReasonDoorClose)
			} else {
				next = earliest(next, b.graceUntil)
			}
		}
		if b.state != Offline {
			if due := b.lastHeard.Add(t.cfg.BuddyTimeout); !now.Before(due) {
				t.goOfflineLocked(b, now, ReasonTimeout)
			} else {
				next = earliest(next, due)
			}
		}
		if len(b.peers) > 0 && t.own.state != Offline && !b.hbDue.IsZero() {
			if !now.Before(b.hbDue) {
				b.hbDue = time.Time{}
				t.stats.Heartbeats++
				t.markPendingLocked(b)
			} else {
				next = earliest(next, b.hbDue)
			}
		}
	}
	return next
}

func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// loop fires deadlines: own idleness, door-close grace, buddy timeouts and
// heartbeats.
func (t *Tracker) loop() {
	defer t.wg.Done()
	var flushed []chan struct{}
	for {
		t.mu.Lock()
		now := t.clk.Now()
		next := t.tickLocked(now)
		t.mu.Unlock()
		for _, f := range flushed {
			close(f)
		}
		flushed = flushed[:0]
		var timer Timer
		var fire <-chan time.Time
		if !next.IsZero() {
			timer = t.clk.NewTimer(next.Sub(now))
			fire = timer.C()
		}
		select {
		case <-fire:
		case <-t.kick:
		case f := <-t.flushq:
			flushed = append(flushed, f)
		case <-t.ctx.Done():
		}
		if timer != nil {
			timer.Stop()
		}
		if t.ctx.Err() != nil {
			for _, f := range flushed {
				close(f)
			}
			return
		}
	}
}

// flush waits until the loop has handled everything due now (for tests).
func (t *Tracker) flush() {
	f := make(chan struct{})
	select {
	case t.flushq <- f:
		<-f
	case <-t.ctx.Done():
	}
}

// ---- Sending ----

// markPendingLocked queues a send of our current presence to b. Sends are
// coalesced: the body is built when a worker picks b up, so a burst of
// changes costs one send.
func (t *Tracker) markPendingLocked(b *buddy) {
	switch {
	case b.inflight:
		b.again = true
	case b.queued:
	default:
		b.queued = true
		t.queue = append(t.queue, b)
		select {
		case t.notify <- struct{}{}:
		default: // enough wakeups pending; workers drain the queue
		}
	}
}

func (t *Tracker) wakeWaitersLocked() {
	if len(t.waiters) == 0 || !t.sendsIdleLocked() {
		return
	}
	for _, w := range t.waiters {
		close(w)
	}
	t.waiters = nil
}

func (t *Tracker) worker() {
	defer t.wg.Done()
	for {
		t.mu.Lock()
		for len(t.queue) == 0 {
			t.mu.Unlock()
			select {
			case <-t.notify:
			case <-t.ctx.Done():
				return
			}
			t.mu.Lock()
		}
		b := t.queue[0]
		t.queue = slices.Delete(t.queue, 0, 1)
		b.queued = false
		// Accepted and connected right now: removal and session Down win
		// over a queued send.
		if t.buddies[b.key] != b || len(b.peers) == 0 {
			t.wakeWaitersLocked()
			t.mu.Unlock()
			continue
		}
		now := t.clk.Now()
		p := t.bodyLocked(now)
		b.inflight = true
		b.hbDue = time.Time{}
		if t.own.state != Offline {
			b.hbDue = now.Add(t.jitteredLocked())
		}
		t.mu.Unlock()

		ctx, cancel := context.WithTimeout(t.ctx, t.cfg.SendTimeout)
		err := t.cfg.Sender.SendPresence(ctx, Recipient{key: b.key}, p)
		cancel()

		t.mu.Lock()
		b.inflight = false
		live := t.buddies[b.key] == b
		if err != nil {
			t.stats.SendFailures++
			t.cfg.Log.Debug("presence send failed", "buddy", b.key.KeyID(), "err", err)
			if live && len(b.peers) > 0 && t.own.state != Offline {
				b.hbDue = t.clk.Now().Add(t.cfg.RetryDelay)
			}
		} else {
			t.stats.Sent++
		}
		if b.again {
			b.again = false
			if live {
				t.markPendingLocked(b)
			}
		}
		t.wakeWaitersLocked()
		t.unlock()
	}
}

func (t *Tracker) jitteredLocked() time.Duration {
	j := t.cfg.HeartbeatJitter
	return t.cfg.HeartbeatInterval + time.Duration((2*t.cfg.Rand()-1)*float64(j))
}

// ---- Away messages ----

// awayRev is the rev advertised for an away message: a hash of its text, so
// it changes with the text without being persisted, and returns to an old
// value (still cached by buddies) when an old text comes back. 0 means none.
func awayRev(text string) uint32 {
	if text == "" {
		return 0
	}
	h := fnv.New32a()
	h.Write([]byte(text))
	if r := h.Sum32(); r != 0 {
		return r
	}
	return 1
}

func checkAway(text string) error {
	return body.Validate(&pb.AwayMsg{Text: text})
}
