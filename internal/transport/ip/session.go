package ip

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/time/rate"
)

// Session defaults (see docs/ip-rotation-and-dht.md, "Sessions").
const (
	// DefaultSessionQueueLen is the capacity of the inbound frame queue
	// shared by all peers. Frames arriving while it is full are dropped and
	// counted.
	DefaultSessionQueueLen = 1024
	// DefaultSessionEventQueueLen is the capacity of the Up/Down event queue.
	DefaultSessionEventQueueLen = 256
	// DefaultMaxStreamsPerPeer bounds the inbound /openaim/msg/1 streams one
	// peer may hold open at once. A rotation or a relay→direct migration
	// briefly needs two.
	DefaultMaxStreamsPerPeer = 4
	// DefaultSessionIdleTimeout closes a stream with no frames in either
	// direction for this long. Kept peers' outbound streams are exempt.
	DefaultSessionIdleTimeout = 10 * time.Minute
	// DefaultSendTimeout bounds a Send whose context has no earlier
	// deadline, including the reconnect attempts it makes.
	DefaultSendTimeout = 30 * time.Second
	// DefaultOpenTimeout bounds one stream open (dial included).
	DefaultOpenTimeout = 10 * time.Second
	// Per-peer inbound rate limits: sustained rate and burst, in frames and
	// in bytes. A peer over its limit is throttled (its stream is read more
	// slowly, which pushes back on the sender through flow control), not
	// disconnected.
	DefaultPeerFrameRate  = 200
	DefaultPeerFrameBurst = 1000
	DefaultPeerByteRate   = 1 << 20
	DefaultPeerByteBurst  = 4 << 20
	// Reconnect backoff: first retry after DefaultReconnectMin, doubling to
	// DefaultReconnectMax.
	DefaultReconnectMin = 250 * time.Millisecond
	DefaultReconnectMax = 30 * time.Second
)

// sessionAddrTTL is how long addresses given to Send or Keep stay in a host's
// peerstore. They are added again before every stream open.
const sessionAddrTTL = 10 * time.Minute

// ErrSessionsClosed is returned by operations on a closed Sessions.
var ErrSessionsClosed = errors.New("ip: sessions closed")

// SessionOptions configures NewSessions. Zero values mean the defaults above.
type SessionOptions struct {
	// QueueLen is the inbound frame queue capacity.
	QueueLen int
	// EventQueueLen is the event queue capacity.
	EventQueueLen int
	// MaxFrameLen is the largest inbound frame accepted, at most (and by
	// default) MaxFrameLen. A larger frame resets its stream.
	MaxFrameLen int
	// MaxStreamsPerPeer bounds concurrent inbound streams per peer; a new
	// stream beyond it evicts (resets) that peer's oldest inbound stream.
	// Negative means no limit.
	MaxStreamsPerPeer int
	// IdleTimeout closes streams without traffic; negative disables it.
	IdleTimeout time.Duration
	// SendTimeout is the default upper bound on a Send.
	SendTimeout time.Duration
	// OpenTimeout bounds one stream open.
	OpenTimeout time.Duration
	// FrameRate (frames/s) and FrameBurst limit each peer's inbound frames;
	// ByteRate (bytes/s) and ByteBurst its inbound bytes. A negative rate
	// disables that limit. ByteBurst is raised to MaxFrameLen if smaller.
	FrameRate  float64
	FrameBurst int
	ByteRate   float64
	ByteBurst  int
	// ReconnectMin and ReconnectMax bound the reconnect backoff.
	ReconnectMin, ReconnectMax time.Duration
}

func (o SessionOptions) withDefaults() (SessionOptions, error) {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	defD := func(v *time.Duration, d time.Duration) {
		if *v == 0 {
			*v = d
		}
	}
	defF := func(v *float64, d float64) {
		if *v == 0 {
			*v = d
		}
	}
	def(&o.QueueLen, DefaultSessionQueueLen)
	def(&o.EventQueueLen, DefaultSessionEventQueueLen)
	def(&o.MaxFrameLen, MaxFrameLen)
	def(&o.MaxStreamsPerPeer, DefaultMaxStreamsPerPeer)
	def(&o.FrameBurst, DefaultPeerFrameBurst)
	def(&o.ByteBurst, DefaultPeerByteBurst)
	defD(&o.IdleTimeout, DefaultSessionIdleTimeout)
	defD(&o.SendTimeout, DefaultSendTimeout)
	defD(&o.OpenTimeout, DefaultOpenTimeout)
	defD(&o.ReconnectMin, DefaultReconnectMin)
	defD(&o.ReconnectMax, DefaultReconnectMax)
	defF(&o.FrameRate, DefaultPeerFrameRate)
	defF(&o.ByteRate, DefaultPeerByteRate)
	switch {
	case o.QueueLen < 0, o.EventQueueLen < 0:
		return o, errors.New("ip: session queue lengths must not be negative")
	case o.MaxFrameLen < 0 || o.MaxFrameLen > MaxFrameLen:
		return o, fmt.Errorf("ip: session MaxFrameLen %d out of range 1–%d", o.MaxFrameLen, MaxFrameLen)
	case o.SendTimeout < 0, o.OpenTimeout < 0:
		return o, errors.New("ip: session timeouts must not be negative")
	case o.ReconnectMin < 0 || o.ReconnectMax < o.ReconnectMin:
		return o, errors.New("ip: session reconnect backoff must satisfy 0 ≤ min ≤ max")
	case o.FrameBurst < 0, o.ByteBurst < 0:
		return o, errors.New("ip: session rate-limit bursts must not be negative")
	}
	o.ByteBurst = max(o.ByteBurst, o.MaxFrameLen)
	return o, nil
}

// InboundFrame is one frame received on /openaim/msg/1. The peer ID comes
// from the libp2p connection; who the buddy is, is for the router to decide
// from the authenticated frame contents (design §7.1).
type InboundFrame struct {
	Peer  peer.ID
	Frame []byte
	// Path is PathOf the stream's connection, e.g. "direct/tcp" or
	// "relay (limited)"; Relayed is true for the relay paths.
	Path    string
	Relayed bool
	// Local is our peer ID that received it: the current host or one still
	// draining after a rotation.
	Local peer.ID
	At    time.Time
}

// SessionEvent reports a session coming up, going down, or changing path.
type SessionEvent struct {
	Peer peer.ID
	// Up is true while at least one /openaim/msg/1 stream with the peer is
	// open, in either direction.
	Up bool
	// Path, Relayed and Local describe the stream sends would use (or, with
	// no outbound stream, the best inbound one). Empty when down.
	Path    string
	Relayed bool
	Local   peer.ID
	Reason  string
	At      time.Time
}

// PeerSession is a snapshot of one session.
type PeerSession struct {
	Peer              peer.ID
	Up                bool
	Path              string
	Relayed           bool
	Kept              bool
	Inbound, Outbound int // open streams
	// Counters since the session was created (a session with no streams,
	// no Keep and no Send in progress is forgotten).
	InFrames, InBytes, QueueDrops, BadFrames, Evicted, RateLimited uint64
}

// SessionStats are counters across all sessions, for metrics.
type SessionStats struct {
	InFrames, InBytes uint64
	// QueueDrops are frames dropped because the inbound queue was full.
	QueueDrops uint64
	// BadFrames are oversize or zero-length frames; each reset its stream.
	BadFrames uint64
	// StreamsEvicted are inbound streams reset by MaxStreamsPerPeer.
	StreamsEvicted uint64
	// IdleCloses are streams closed by IdleTimeout.
	IdleCloses uint64
	// RateLimited counts frames after which a peer's stream was throttled.
	RateLimited uint64

	OutFrames, OutBytes uint64
	// Sends are Send calls; SendFailures those that returned an error.
	Sends, SendFailures uint64
	// WriteErrors are failed stream writes (Send retries them).
	WriteErrors uint64
	// StreamsOpened and OpenFailures count outbound stream opens.
	StreamsOpened, OpenFailures uint64
	// Migrations are relayed outbound streams replaced by direct ones.
	Migrations uint64
	// Disconnects are connection-closed events for peers with a session.
	Disconnects uint64
	// EventDrops are SessionEvents dropped because Events was full.
	EventDrops uint64
}

type sessionCounters struct {
	inFrames, inBytes, queueDrops, badFrames, evicted, idleCloses, rateLimited  atomic.Uint64
	outFrames, outBytes, sends, sendFailures, writeErrors, opened, openFailures atomic.Uint64
	migrations, disconnects, eventDrops                                         atomic.Uint64
}

// SendError reports a failed Send. Some of its frames may still have
// arrived (a failed write can deliver a prefix of the batch), and an earlier
// attempt may have delivered them all; receivers deduplicate (design §7.2).
type SendError struct {
	Peer     peer.ID
	Attempts int // stream writes or opens tried
	Err      error
}

func (e *SendError) Error() string {
	return fmt.Sprintf("ip: send to %s failed after %d attempt(s): %v", e.Peer, e.Attempts, e.Err)
}

func (e *SendError) Unwrap() error { return e.Err }

// Sessions runs /openaim/msg/1 (design §6.1) on a Node: one logical session
// per remote peer ID, carrying opaque frames both ways, over a relay or
// directly, across connection resets and host rotations.
//
// Each side writes only on streams it opened and reads every stream. A
// session's outbound stream is opened on demand by Send (or kept open by
// Keep), reopened with backoff after a loss, moved to a direct connection
// when one appears, and moved to the current host after a rotation. Inbound
// streams are accepted on every live host.
//
// Delivery is best effort: a successful Send means its frames were written,
// in order and contiguously, to one stream. Acks and retries belong to the
// router (design §8.8). Frames of different Sends may be reordered when the
// session switches streams.
//
// Sessions sets the Node's MsgProtocol handler; use one per Node.
type Sessions struct {
	node *Node
	o    SessionOptions

	ctx    context.Context // cancelled by Close
	cancel context.CancelFunc
	wg     sync.WaitGroup // stream readers, keepers, helpers

	mu     sync.Mutex
	closed bool
	peers  map[peer.ID]*session

	unsub   func()
	detach  func()
	unnotif []func() // for hosts already draining at start

	chMu     sync.RWMutex
	chClosed bool
	in       chan InboundFrame
	ev       chan SessionEvent

	st sessionCounters
}

type session struct {
	id      peer.ID
	sendSem chan struct{} // serializes Sends (and retirements)
	wake    chan struct{} // nudges the keeper
	frames  *rate.Limiter // nil: unlimited
	bytes   *rate.Limiter
	kept    atomic.Bool // mirrors keep, for readers

	mu           sync.Mutex
	addrs        []ma.Multiaddr
	keep         bool
	keepCancel   context.CancelFunc
	sending      int
	streams      []*sstream
	active       *sstream // outbound stream Sends write to
	upgradeAfter time.Time
	up           bool
	path         string
	relayed      bool
	local        peer.ID

	inFrames, inBytes, queueDrops, badFrames, evicted, rateLimited atomic.Uint64
}

type sstream struct {
	sess     *session
	s        network.Stream
	outbound bool
	path     string
	relayed  bool
	local    peer.ID
	last     atomic.Int64 // unix nanos of the last frame read or written
	done     chan struct{}
	once     sync.Once
}

// NewSessions starts /openaim/msg/1 on n.
func NewSessions(n *Node, o SessionOptions) (*Sessions, error) {
	o, err := o.withDefaults()
	if err != nil {
		return nil, err
	}
	s := &Sessions{
		node:  n,
		o:     o,
		peers: map[peer.ID]*session{},
		in:    make(chan InboundFrame, o.QueueLen),
		ev:    make(chan SessionEvent, o.EventQueueLen),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.detach, err = n.Attach(context.Background(), func(_ context.Context, h host.Host) (func(), error) {
		nb := s.notifiee(h)
		h.Network().Notify(nb)
		return func() { h.Network().StopNotify(nb) }, nil
	})
	if err != nil {
		s.cancel()
		return nil, err
	}
	cur := n.Host()
	for _, h := range n.LiveHosts() {
		if h != cur {
			nb := s.notifiee(h)
			h.Network().Notify(nb)
			s.unnotif = append(s.unnotif, func() { h.Network().StopNotify(nb) })
		}
	}
	s.unsub = n.Subscribe(s.onRotate)
	n.SetStreamHandler(MsgProtocol, s.handle)
	return s, nil
}

// Inbound delivers received frames. It is closed by Close.
func (s *Sessions) Inbound() <-chan InboundFrame { return s.in }

// Events delivers session state changes, in order per peer. It is closed by
// Close. If the consumer falls behind, events are dropped (and counted);
// Peers gives the current state.
func (s *Sessions) Events() <-chan SessionEvent { return s.ev }

// Send writes frames to the peer in one stream write, opening or reusing a
// stream (limited relayed connections allowed). ai.Addrs, if any, replace
// the addresses remembered for the peer; with none, an existing connection
// (from either side) or earlier addresses are used. On a stream or
// connection failure Send reconnects with backoff and writes the whole batch
// again, until ctx ends or SendTimeout passes; it then returns a *SendError.
func (s *Sessions) Send(ctx context.Context, ai peer.AddrInfo, frames [][]byte) error {
	if ai.ID == "" {
		return errors.New("ip: send: no peer ID")
	}
	if len(frames) == 0 {
		return nil
	}
	buf, err := encodeBatch(frames)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.o.SendTimeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()

	sess, err := s.pin(ai, func(sess *session) { sess.sending++ })
	if err != nil {
		return err
	}
	defer s.unpin(sess)
	s.st.sends.Add(1)
	fail := func(attempts int, err error) error {
		s.st.sendFailures.Add(1)
		if s.ctx.Err() != nil {
			return ErrSessionsClosed
		}
		if ctx.Err() != nil {
			err = errors.Join(err, ctx.Err())
		}
		return &SendError{Peer: ai.ID, Attempts: attempts, Err: err}
	}
	select {
	case sess.sendSem <- struct{}{}:
	case <-ctx.Done():
		return fail(0, errors.New("waiting for an earlier send"))
	}
	defer func() { <-sess.sendSem }()

	backoff := s.o.ReconnectMin
	for attempt := 1; ; attempt++ {
		st, err := s.writable(ctx, sess)
		if err == nil {
			if err = st.write(ctx, buf); err == nil {
				s.st.outFrames.Add(uint64(len(frames)))
				s.st.outBytes.Add(uint64(len(buf)))
				return nil
			}
			s.st.writeErrors.Add(1)
			s.removeStream(st, "write failed", true)
		}
		if ctx.Err() != nil {
			return fail(attempt, err)
		}
		t := time.NewTimer(backoff)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return fail(attempt, err)
		}
		backoff = min(2*backoff, s.o.ReconnectMax)
	}
}

// Keep holds a stream open to the peer until Drop or Close: it opens one
// now, reopens it with backoff whenever it is lost, and moves it to the new
// host after a rotation. ai.Addrs, if any, replace the remembered addresses.
func (s *Sessions) Keep(ai peer.AddrInfo) error {
	if ai.ID == "" {
		return errors.New("ip: keep: no peer ID")
	}
	var kctx context.Context
	sess, err := s.pin(ai, func(sess *session) {
		if !sess.keep {
			sess.keep = true
			sess.kept.Store(true)
			kctx, sess.keepCancel = context.WithCancel(s.ctx)
		}
	})
	if err != nil {
		return err
	}
	if kctx != nil {
		s.goSafe(func() { s.keeper(kctx, sess) })
	} else {
		notify(sess.wake)
	}
	return nil
}

// Drop stops keeping the peer connected and closes our outbound streams to
// it. Inbound streams from it stay open; the peer decides about those.
func (s *Sessions) Drop(p peer.ID) {
	s.mu.Lock()
	sess := s.peers[p]
	s.mu.Unlock()
	if sess == nil {
		return
	}
	sess.mu.Lock()
	sess.keep = false
	sess.kept.Store(false)
	if sess.keepCancel != nil {
		sess.keepCancel()
		sess.keepCancel = nil
	}
	var out []*sstream
	for _, st := range sess.streams {
		if st.outbound {
			out = append(out, st)
		}
	}
	sess.mu.Unlock()
	for _, st := range out {
		s.removeStream(st, "dropped", false)
	}
	s.maybeRemove(sess)
}

// Peer returns a snapshot of the session with p, if there is one.
func (s *Sessions) Peer(p peer.ID) (PeerSession, bool) {
	s.mu.Lock()
	sess := s.peers[p]
	s.mu.Unlock()
	if sess == nil {
		return PeerSession{}, false
	}
	return sess.snapshot(), true
}

// Peers returns snapshots of all sessions.
func (s *Sessions) Peers() []PeerSession {
	s.mu.Lock()
	sessions := make([]*session, 0, len(s.peers))
	for _, sess := range s.peers {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	out := make([]PeerSession, len(sessions))
	for i, sess := range sessions {
		out[i] = sess.snapshot()
	}
	return out
}

// Stats returns the counters.
func (s *Sessions) Stats() SessionStats {
	c := &s.st
	return SessionStats{
		InFrames: c.inFrames.Load(), InBytes: c.inBytes.Load(),
		QueueDrops: c.queueDrops.Load(), BadFrames: c.badFrames.Load(),
		StreamsEvicted: c.evicted.Load(), IdleCloses: c.idleCloses.Load(),
		RateLimited: c.rateLimited.Load(),
		OutFrames:   c.outFrames.Load(), OutBytes: c.outBytes.Load(),
		Sends: c.sends.Load(), SendFailures: c.sendFailures.Load(),
		WriteErrors:   c.writeErrors.Load(),
		StreamsOpened: c.opened.Load(), OpenFailures: c.openFailures.Load(),
		Migrations: c.migrations.Load(), Disconnects: c.disconnects.Load(),
		EventDrops: c.eventDrops.Load(),
	}
}

// Close removes the stream handler, closes every stream and stops all
// goroutines, then closes Inbound and Events. It does not close the Node.
func (s *Sessions) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var streams []*sstream
	for _, sess := range s.peers {
		sess.mu.Lock()
		if sess.keepCancel != nil {
			sess.keepCancel()
		}
		streams = append(streams, sess.streams...)
		sess.mu.Unlock()
	}
	s.mu.Unlock()

	s.node.RemoveStreamHandler(MsgProtocol)
	s.unsub()
	s.detach()
	for _, f := range s.unnotif {
		f()
	}
	s.cancel()
	for _, st := range streams {
		s.removeStream(st, "closed", false)
	}
	s.wg.Wait()
	s.chMu.Lock()
	s.chClosed = true
	close(s.in)
	close(s.ev)
	s.chMu.Unlock()
	return nil
}

// goSafe runs f in a tracked goroutine unless Sessions is closed.
func (s *Sessions) goSafe(f func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		f()
	}()
	return true
}

// getLocked returns p's session, creating it. Called with s.mu held.
func (s *Sessions) getLocked(p peer.ID) *session {
	if sess := s.peers[p]; sess != nil {
		return sess
	}
	sess := &session{id: p, sendSem: make(chan struct{}, 1), wake: make(chan struct{}, 1)}
	if s.o.FrameRate > 0 {
		sess.frames = rate.NewLimiter(rate.Limit(s.o.FrameRate), max(s.o.FrameBurst, 1))
	}
	if s.o.ByteRate > 0 {
		sess.bytes = rate.NewLimiter(rate.Limit(s.o.ByteRate), s.o.ByteBurst)
	}
	s.peers[p] = sess
	return sess
}

// pin finds or creates the session for ai, updates its addresses and runs f
// on it, all while it cannot be forgotten. f must leave it pinned (sending
// or keep).
func (s *Sessions) pin(ai peer.AddrInfo, f func(*session)) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrSessionsClosed
	}
	sess := s.getLocked(ai.ID)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(ai.Addrs) > 0 {
		sess.addrs = slices.Clone(ai.Addrs)
	}
	f(sess)
	return sess, nil
}

func (s *Sessions) unpin(sess *session) {
	sess.mu.Lock()
	sess.sending--
	sess.mu.Unlock()
	s.maybeRemove(sess)
}

// maybeRemove forgets a session with no streams, no Keep and no Send.
func (s *Sessions) maybeRemove(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if !sess.keep && sess.sending == 0 && len(sess.streams) == 0 && s.peers[sess.id] == sess {
		delete(s.peers, sess.id)
	}
}

// writable returns the stream a Send should write to, opening one if there
// is none or the current one is on a draining host.
func (s *Sessions) writable(ctx context.Context, sess *session) (*sstream, error) {
	cur := s.node.ID()
	sess.mu.Lock()
	act := sess.active
	upgrade := act != nil && act.local != cur && !time.Now().Before(sess.upgradeAfter)
	sess.mu.Unlock()
	if act != nil && !upgrade {
		return act, nil
	}
	st, err := s.open(ctx, sess, act == nil, "send")
	if err != nil {
		if act != nil {
			s.noteUpgradeFailure(sess)
			return act, nil
		}
		return nil, err
	}
	return st, nil
}

func (s *Sessions) noteUpgradeFailure(sess *session) {
	sess.mu.Lock()
	sess.upgradeAfter = time.Now().Add(s.o.ReconnectMax)
	sess.mu.Unlock()
}

// open opens an outbound stream from the current host, dialing if needed.
// With fallback, if that fails it tries the draining hosts that are still
// connected to the peer (e.g. a peer that only dialed us). It returns the
// session's active stream afterwards, which is normally the new one.
func (s *Sessions) open(ctx context.Context, sess *session, fallback bool, reason string) (*sstream, error) {
	octx, cancel := context.WithTimeout(ctx, s.o.OpenTimeout)
	defer cancel()
	octx = network.WithAllowLimitedConn(octx, "openaim msg")
	hosts := s.node.LiveHosts()
	if len(hosts) == 0 {
		return nil, ErrNodeClosed
	}
	cur := hosts[len(hosts)-1]
	sess.mu.Lock()
	addrs := sess.addrs
	sess.mu.Unlock()
	if len(addrs) > 0 {
		cur.Peerstore().AddAddrs(sess.id, addrs, sessionAddrTTL)
	}
	ns, err := cur.NewStream(octx, sess.id, MsgProtocol)
	if err != nil && fallback {
		for _, h := range slices.Backward(hosts[:len(hosts)-1]) {
			if h.Network().Connectedness(sess.id) != network.Connected {
				continue
			}
			ns2, err2 := h.NewStream(network.WithNoDial(octx, "openaim msg on draining host"), sess.id, MsgProtocol)
			if err2 == nil {
				ns, err = ns2, nil
				break
			}
		}
	}
	if err != nil {
		s.st.openFailures.Add(1)
		return nil, err
	}
	s.st.opened.Add(1)
	st, _, err := s.install(sess, ns, reason)
	return st, err
}

// install adds an opened outbound stream to the session and makes it the
// active one if it is better than the current one; the loser is retired
// (closed once in-flight writes finish). It returns the active stream and
// whether the new one became it.
func (s *Sessions) install(sess *session, ns network.Stream, reason string) (*sstream, bool, error) {
	st := newSStream(sess, ns, true)
	cur := s.node.ID()
	s.mu.Lock()
	if s.closed || s.peers[sess.id] != sess {
		s.mu.Unlock()
		ns.Reset()
		return nil, false, ErrSessionsClosed
	}
	sess.mu.Lock()
	sess.streams = append(sess.streams, st)
	var retire *sstream
	won := sess.active == nil || better(st, sess.active, cur)
	if won {
		retire, sess.active = sess.active, st
	} else {
		retire = st
	}
	active := sess.active
	sess.updateLocked(s, reason)
	sess.mu.Unlock()
	s.wg.Add(1)
	s.mu.Unlock()
	go s.readLoop(st)
	if retire != nil {
		s.retire(retire)
	}
	return active, won, nil
}

// better reports whether a should replace b as the active stream: streams
// on the current host beat those on draining hosts, then direct beats
// relayed, then newer beats older.
func better(a, b *sstream, cur peer.ID) bool {
	if ac, bc := a.local == cur, b.local == cur; ac != bc {
		return ac
	}
	if a.relayed != b.relayed {
		return !a.relayed
	}
	return true
}

// retire closes st gracefully once no Send is writing.
func (s *Sessions) retire(st *sstream) {
	if !s.goSafe(func() {
		select {
		case st.sess.sendSem <- struct{}{}:
			defer func() { <-st.sess.sendSem }()
		case <-st.done:
			return
		case <-s.ctx.Done():
		}
		s.removeStream(st, "replaced", false)
	}) {
		s.removeStream(st, "closed", false)
	}
}

// removeStream takes st out of its session and closes (or resets) it. It is
// idempotent.
func (s *Sessions) removeStream(st *sstream, reason string, reset bool) {
	st.once.Do(func() {
		close(st.done)
		sess := st.sess
		sess.mu.Lock()
		if i := slices.Index(sess.streams, st); i >= 0 {
			sess.streams = slices.Delete(sess.streams, i, i+1)
		}
		if sess.active == st {
			sess.active = nil
		}
		sess.updateLocked(s, reason)
		keep := sess.keep
		sess.mu.Unlock()
		if reset {
			st.s.Reset()
		} else {
			st.s.Close()
		}
		if keep {
			notify(sess.wake)
		}
		s.maybeRemove(sess)
	})
}

// updateLocked recomputes the session state and emits an event if it
// changed. Called with sess.mu held.
func (sess *session) updateLocked(s *Sessions, reason string) {
	best := sess.active
	if best == nil {
		for _, st := range sess.streams {
			if best == nil || best.relayed && !st.relayed || best.relayed == st.relayed {
				best = st
			}
		}
	}
	up, path, relayed, local := best != nil, "", false, peer.ID("")
	if up {
		path, relayed, local = best.path, best.relayed, best.local
	}
	if up == sess.up && path == sess.path && relayed == sess.relayed && local == sess.local {
		return
	}
	sess.up, sess.path, sess.relayed, sess.local = up, path, relayed, local
	s.emit(SessionEvent{Peer: sess.id, Up: up, Path: path, Relayed: relayed, Local: local, Reason: reason, At: time.Now()})
}

func (s *Sessions) emit(e SessionEvent) {
	s.chMu.RLock()
	defer s.chMu.RUnlock()
	if s.chClosed {
		return
	}
	select {
	case s.ev <- e:
	default:
		s.st.eventDrops.Add(1)
	}
}

func (sess *session) snapshot() PeerSession {
	sess.mu.Lock()
	ps := PeerSession{Peer: sess.id, Up: sess.up, Path: sess.path, Relayed: sess.relayed, Kept: sess.keep}
	for _, st := range sess.streams {
		if st.outbound {
			ps.Outbound++
		} else {
			ps.Inbound++
		}
	}
	sess.mu.Unlock()
	ps.InFrames, ps.InBytes = sess.inFrames.Load(), sess.inBytes.Load()
	ps.QueueDrops, ps.BadFrames = sess.queueDrops.Load(), sess.badFrames.Load()
	ps.Evicted, ps.RateLimited = sess.evicted.Load(), sess.rateLimited.Load()
	return ps
}

// keeper keeps a kept session's outbound stream open on the current host.
func (s *Sessions) keeper(ctx context.Context, sess *session) {
	backoff := s.o.ReconnectMin
	for {
		cur := s.node.ID()
		sess.mu.Lock()
		act := sess.active
		var wait time.Duration
		need := act == nil
		if act != nil && act.local != cur {
			if wait = time.Until(sess.upgradeAfter); wait <= 0 {
				need = true
			}
		}
		sess.mu.Unlock()
		if need {
			if _, err := s.open(ctx, sess, act == nil, "keep"); err != nil {
				if ctx.Err() != nil {
					return
				}
				if act != nil {
					s.noteUpgradeFailure(sess)
				}
				if !sleepOrWake(ctx, sess.wake, backoff) {
					return
				}
				backoff = min(2*backoff, s.o.ReconnectMax)
			} else {
				backoff = s.o.ReconnectMin
			}
			continue
		}
		if !sleepOrWake(ctx, sess.wake, wait) {
			return
		}
	}
}

// sleepOrWake waits for d (forever if d ≤ 0) or a wake-up. It returns false
// if ctx ended.
func sleepOrWake(ctx context.Context, wake <-chan struct{}, d time.Duration) bool {
	var tc <-chan time.Time
	if d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		tc = t.C
	}
	select {
	case <-tc:
	case <-wake:
	case <-ctx.Done():
		return false
	}
	return true
}

func (s *Sessions) onRotate(HostChange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.peers {
		if sess.kept.Load() {
			notify(sess.wake)
		}
	}
}

// notifiee reacts to h's connection events: a closed connection ends its
// streams at once (so kept sessions reconnect without waiting for a write to
// fail), and a new direct connection migrates a relayed outbound stream.
func (s *Sessions) notifiee(h host.Host) *network.NotifyBundle {
	return &network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			if IsRelayed(c) || !s.hasRelayedActive(c.RemotePeer(), h.ID()) {
				return
			}
			s.goSafe(func() { s.migrate(h, c.RemotePeer()) })
		},
		DisconnectedF: func(_ network.Network, c network.Conn) {
			s.mu.Lock()
			sess := s.peers[c.RemotePeer()]
			s.mu.Unlock()
			if sess != nil {
				s.st.disconnects.Add(1)
				s.goSafe(func() { s.connClosed(sess, c) })
			}
		},
	}
}

func (s *Sessions) hasRelayedActive(p, local peer.ID) bool {
	s.mu.Lock()
	sess := s.peers[p]
	s.mu.Unlock()
	if sess == nil {
		return false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.active != nil && sess.active.relayed && sess.active.local == local
}

func (s *Sessions) connClosed(sess *session, c network.Conn) {
	sess.mu.Lock()
	var dead []*sstream
	for _, st := range sess.streams {
		if sc := st.s.Conn(); sc == c || sc.IsClosed() {
			dead = append(dead, st)
		}
	}
	sess.mu.Unlock()
	for _, st := range dead {
		s.removeStream(st, "connection closed", true)
	}
}

// migrate replaces a relayed outbound stream on h with one on a direct
// connection.
func (s *Sessions) migrate(h host.Host, p peer.ID) {
	if !s.hasRelayedActive(p, h.ID()) {
		return
	}
	s.mu.Lock()
	sess := s.peers[p]
	s.mu.Unlock()
	if sess == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.o.OpenTimeout)
	defer cancel()
	ctx = network.WithAllowLimitedConn(network.WithNoDial(ctx, "openaim msg migration"), "openaim msg")
	ns, err := h.NewStream(ctx, p, MsgProtocol)
	if err != nil {
		return
	}
	if IsRelayed(ns.Conn()) {
		ns.Reset()
		return
	}
	s.st.opened.Add(1)
	if _, won, err := s.install(sess, ns, "migrated to direct"); err == nil && won {
		s.st.migrations.Add(1)
	}
}

// handle accepts an inbound stream. It runs in libp2p's per-stream
// goroutine and reads there; nothing in it waits for the consumer.
func (s *Sessions) handle(ns network.Stream) {
	st := newSStream(nil, ns, false)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ns.Reset()
		return
	}
	sess := s.getLocked(ns.Conn().RemotePeer())
	st.sess = sess
	sess.mu.Lock()
	var evict *sstream
	if s.o.MaxStreamsPerPeer > 0 {
		n := 0
		for _, o := range sess.streams {
			if !o.outbound {
				if evict == nil {
					evict = o
				}
				n++
			}
		}
		if n < s.o.MaxStreamsPerPeer {
			evict = nil
		}
	}
	sess.streams = append(sess.streams, st)
	sess.updateLocked(s, "inbound stream")
	sess.mu.Unlock()
	s.wg.Add(1)
	s.mu.Unlock()
	if evict != nil {
		s.st.evicted.Add(1)
		sess.evicted.Add(1)
		s.removeStream(evict, "stream limit", true)
	}
	s.readLoop(st)
}

// readLoop reads frames from st until it ends. Every stream is read, so a
// peer that writes back on our outbound stream is heard too.
func (s *Sessions) readLoop(st *sstream) {
	defer s.wg.Done()
	sess := st.sess
	br := bufio.NewReader(st.s)
	var hdr [2]byte
	for {
		s.setIdleDeadline(st)
		n, err := io.ReadFull(br, hdr[:])
		if err != nil {
			if n == 0 && isTimeout(err) && !s.idle(st) {
				continue
			}
			s.endStream(st, err, n)
			return
		}
		size := int(binary.BigEndian.Uint16(hdr[:]))
		if size == 0 || size > s.o.MaxFrameLen {
			s.st.badFrames.Add(1)
			sess.badFrames.Add(1)
			s.removeStream(st, "bad frame length", true)
			return
		}
		if s.o.IdleTimeout > 0 {
			st.s.SetReadDeadline(time.Now().Add(s.o.IdleTimeout))
		}
		frame := make([]byte, size)
		if _, err := io.ReadFull(br, frame); err != nil {
			s.endStream(st, err, 1)
			return
		}
		now := time.Now()
		st.last.Store(now.UnixNano())
		s.st.inFrames.Add(1)
		s.st.inBytes.Add(uint64(size))
		sess.inFrames.Add(1)
		sess.inBytes.Add(uint64(size))
		if !s.throttle(st, size) {
			return
		}
		s.deliver(st, InboundFrame{Peer: sess.id, Frame: frame, Path: st.path, Relayed: st.relayed, Local: st.local, At: now})
	}
}

func (s *Sessions) idleExempt(st *sstream) bool {
	return s.o.IdleTimeout <= 0 || st.outbound && st.sess.kept.Load()
}

func (s *Sessions) idle(st *sstream) bool {
	return !s.idleExempt(st) && time.Since(time.Unix(0, st.last.Load())) >= s.o.IdleTimeout
}

func (s *Sessions) setIdleDeadline(st *sstream) {
	if s.idleExempt(st) {
		st.s.SetReadDeadline(time.Time{})
		return
	}
	st.s.SetReadDeadline(time.Unix(0, st.last.Load()).Add(s.o.IdleTimeout))
}

// endStream classifies a read error; n is how many bytes of the frame had
// arrived.
func (s *Sessions) endStream(st *sstream, err error, n int) {
	select {
	case <-st.done:
		return // closed by us
	default:
	}
	switch {
	case n == 0 && isTimeout(err):
		s.st.idleCloses.Add(1)
		s.removeStream(st, "idle", false)
	case n == 0 && errors.Is(err, io.EOF):
		s.removeStream(st, "closed by peer", false)
	case st.s.Conn().IsClosed():
		s.removeStream(st, "connection closed", true)
	default:
		s.removeStream(st, "stream error", true)
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

// throttle applies the peer's rate limits after a frame of size bytes,
// pausing this stream's reads if the peer is over them. It returns false if
// the stream ended meanwhile.
func (s *Sessions) throttle(st *sstream, size int) bool {
	sess := st.sess
	now := time.Now()
	var d time.Duration
	if sess.frames != nil {
		d = sess.frames.ReserveN(now, 1).DelayFrom(now)
	}
	if sess.bytes != nil {
		if r := sess.bytes.ReserveN(now, size); r.OK() {
			d = max(d, r.DelayFrom(now))
		}
	}
	if d <= 0 {
		return true
	}
	s.st.rateLimited.Add(1)
	sess.rateLimited.Add(1)
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-st.done:
	case <-s.ctx.Done():
	}
	return false
}

// deliver queues f without blocking; a full queue drops it.
func (s *Sessions) deliver(st *sstream, f InboundFrame) {
	s.chMu.RLock()
	defer s.chMu.RUnlock()
	if s.chClosed {
		return
	}
	select {
	case s.in <- f:
	default:
		s.st.queueDrops.Add(1)
		st.sess.queueDrops.Add(1)
	}
}

func newSStream(sess *session, ns network.Stream, outbound bool) *sstream {
	c := ns.Conn()
	st := &sstream{
		sess:     sess,
		s:        ns,
		outbound: outbound,
		path:     PathOf(c),
		relayed:  IsRelayed(c),
		local:    c.LocalPeer(),
		done:     make(chan struct{}),
	}
	st.last.Store(time.Now().UnixNano())
	return st
}

// write writes buf in one call, bounded by ctx. A failed write may leave a
// partial frame on the stream, so the caller must reset it.
func (st *sstream) write(ctx context.Context, buf []byte) error {
	dl, _ := ctx.Deadline()
	st.s.SetWriteDeadline(dl)
	stop := context.AfterFunc(ctx, func() { st.s.SetWriteDeadline(time.Unix(1, 0)) })
	_, err := st.s.Write(buf)
	stop()
	if err == nil {
		st.last.Store(time.Now().UnixNano())
	}
	return err
}

// encodeBatch frames each element as WriteFrame does, into one buffer.
func encodeBatch(frames [][]byte) ([]byte, error) {
	n := 0
	for i, f := range frames {
		if len(f) == 0 || len(f) > MaxFrameLen {
			return nil, fmt.Errorf("%w: frame %d is %d bytes", ErrFrameTooLarge, i, len(f))
		}
		n += 2 + len(f)
	}
	buf := make([]byte, 0, n)
	for _, f := range frames {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(f)))
		buf = append(buf, f...)
	}
	return buf, nil
}

func notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
