package ip

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
)

// Rotation defaults (design §6.1: the network key is rotated daily and on
// every restart).
const (
	DefaultRotationInterval = 24 * time.Hour
	// DefaultRotationJitter spreads rotations over ±1 h so they don't happen
	// at a predictable time of day, which would make an old and a new peer ID
	// easier to pair up by timing alone.
	DefaultRotationJitter = time.Hour
	// DefaultRotationGrace is how long a retired host stays up after a
	// rotation, so streams on it can drain while buddies learn the new peer
	// ID over encrypted presence and reconnect. It exceeds the 3-minute
	// "door close" grace, so a buddy that only notices the old host closing
	// has already had time to move.
	DefaultRotationGrace = 5 * time.Minute
	// DefaultRotationRetry is the wait before retrying a failed scheduled
	// rotation. The old host stays current meanwhile.
	DefaultRotationRetry = time.Minute
	// DefaultReservationTimeout bounds how long a rotation waits for the new
	// host's first relay reservations before making it current anyway (the
	// reservation keeper goes on retrying).
	DefaultReservationTimeout = 30 * time.Second
)

// Reasons in HostChange.
const (
	RotationStart     = "start"
	RotationScheduled = "scheduled"
	RotationManual    = "manual"
)

var (
	// ErrNodeClosed is returned by operations on a closed Node.
	ErrNodeClosed = errors.New("ip: node closed")
	// ErrFixedKey is returned by Rotate on a node with NodeOptions.FixedKey.
	ErrFixedKey = errors.New("ip: node has a fixed key and does not rotate")
	// ErrPortReuse is returned when a new host would listen on a port that a
	// still-running older host of the same node uses.
	ErrPortReuse = errors.New("ip: listen port reused across rotations")
)

// NodeOptions configures NewNode.
type NodeOptions struct {
	// Host is the template for every host the node builds. Host.Key must be
	// nil: the node makes a fresh Ed25519 key for each host (use FixedKey
	// for relays and bootstrap nodes). Host.Listen empty means
	// DefaultListen(0), i.e. new random ports for every host.
	Host HostOptions
	// Listen, if set, overrides Host.Listen per host generation (1, 2, …).
	// Use it to alternate between two forwarded ports. Consecutive
	// generations overlap during the grace period, so they must not share a
	// port; NewNode/Rotate fail with ErrPortReuse if they do. A fixed port
	// links peer IDs across rotations for anyone who sees both (see
	// docs/ip-rotation-and-dht.md).
	Listen func(generation uint64) []string
	// FixedKey disables rotation and uses this key for the node's only
	// host. It is for publicly reachable relays and bootstrap nodes, whose
	// peer ID has to stay stable and is public anyway.
	FixedKey crypto.PrivKey

	// Interval between scheduled rotations: 0 means
	// DefaultRotationInterval; negative disables scheduled rotation (Rotate
	// still works). Jitter: 0 means DefaultRotationJitter, negative means
	// none; each wait is uniform in [Interval-Jitter, Interval+Jitter] and
	// Jitter must be less than Interval.
	Interval, Jitter time.Duration
	// Grace is how long a retired host keeps running: 0 means
	// DefaultRotationGrace, negative means close it at once.
	Grace time.Duration
	// RetryInterval after a failed scheduled rotation: 0 means
	// DefaultRotationRetry.
	RetryInterval time.Duration

	// Relays to keep a reservation on, from every host. A new host becomes
	// current once each relay's first reservation attempt has finished, or
	// after ReservationTimeout (0 means DefaultReservationTimeout).
	Relays             []peer.AddrInfo
	ReservationTimeout time.Duration
	// OnReservation, if set, sees every reservation attempt of every host.
	OnReservation func(generation uint64, relay peer.ID, e ReservationEvent)
	// OnError, if set, is told about failed scheduled rotations.
	OnError func(error)
	// Clock defaults to the real clock.
	Clock Clock
}

// HostChange describes the host that just became current.
type HostChange struct {
	Generation uint64
	Host       host.Host
	ID         peer.ID
	// Addrs are the host's own addresses plus a circuit address for each
	// relay holding a reservation, at the time of the change.
	Addrs []ma.Multiaddr
	// Previous is the peer ID that stopped being current ("" at start). Its
	// host keeps running for the grace period.
	Previous peer.ID
	Reason   string // RotationStart, RotationScheduled or RotationManual
	At       time.Time
}

// AddrInfo is the new host's peer ID and addresses.
func (c HostChange) AddrInfo() peer.AddrInfo { return peer.AddrInfo{ID: c.ID, Addrs: c.Addrs} }

// AttachFunc starts something on a host, e.g. a DHT instance. ctx bounds the
// start-up only. The returned stop (which may be nil) is called when that
// host retires, before it closes.
type AttachFunc func(ctx context.Context, h host.Host) (stop func(), err error)

// Node owns the current libp2p host and replaces it with one with a fresh
// network key on a schedule (design §5.1, §6.1). Peer IDs of different
// generations are unlinkable by key: each host has its own random key, its
// own peerstore, connections, listen ports and relay reservations.
//
// A rotation brings the new host fully up (listening, stream handlers set,
// relay reservations made, attached services started) before making it
// current, then tells subscribers, then lets the old host run for the grace
// period so existing streams on it keep working, and finally stops its
// attached services and closes it.
//
// Code that keeps a host.Host from Host() keeps using that generation; use
// the Node's methods, or Subscribe, to follow rotations.
type Node struct {
	opts  NodeOptions
	clock Clock

	ctx    context.Context // cancelled by Close
	cancel context.CancelFunc
	wg     sync.WaitGroup // scheduler and retire goroutines
	resch  chan struct{}  // a manual rotation resets the schedule

	// rotMu serializes host lifecycle changes: rotations, retirements,
	// Attach/detach and Close. It is held while a new host comes up.
	rotMu   sync.Mutex
	closed  bool // under rotMu
	seq     uint64
	atts    []*attachment // under rotMu
	nextAtt int

	mu       sync.RWMutex
	cur      *generation
	gens     []*generation // live hosts, oldest first; includes cur
	change   HostChange
	handlers map[protocol.ID]network.StreamHandler
	subs     map[int]func(HostChange)
	nextSub  int
}

type attachment struct {
	id    int
	start AttachFunc
}

type generation struct {
	seq     uint64
	h       host.Host
	ctx     context.Context // ends when the host retires
	cancel  context.CancelFunc
	wg      sync.WaitGroup // reservation keepers
	stops   map[int]func() // attachment id → stop; under Node.rotMu
	order   []int          // attachment ids in start order
	retired bool           // under Node.rotMu

	rmu      sync.Mutex
	circuits map[peer.ID][]ma.Multiaddr // relays with a live reservation
}

// NewNode starts a node with its first host.
func NewNode(o NodeOptions) (*Node, error) {
	if o.Host.Key != nil {
		return nil, errors.New("ip: NodeOptions.Host.Key must be nil; the node makes its own keys (use FixedKey for relays)")
	}
	if o.Interval == 0 {
		o.Interval = DefaultRotationInterval
	}
	if o.Jitter == 0 {
		o.Jitter = DefaultRotationJitter
	}
	if o.Interval > 0 && o.Jitter >= o.Interval {
		return nil, fmt.Errorf("ip: rotation jitter %v must be less than the interval %v", o.Jitter, o.Interval)
	}
	if o.Grace == 0 {
		o.Grace = DefaultRotationGrace
	}
	if o.RetryInterval <= 0 {
		o.RetryInterval = DefaultRotationRetry
	}
	if o.ReservationTimeout <= 0 {
		o.ReservationTimeout = DefaultReservationTimeout
	}
	n := &Node{
		opts:     o,
		clock:    o.Clock,
		resch:    make(chan struct{}, 1),
		handlers: map[protocol.ID]network.StreamHandler{},
		subs:     map[int]func(HostChange){},
	}
	if n.clock == nil {
		n.clock = realClock{}
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	if err := n.rotate(n.ctx, RotationStart); err != nil {
		n.cancel()
		return nil, err
	}
	if o.FixedKey == nil && o.Interval > 0 {
		n.wg.Add(1)
		go n.schedule()
	}
	return n, nil
}

// Host is the current host.
func (n *Node) Host() host.Host {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cur.h
}

// ID is the current host's peer ID.
func (n *Node) ID() peer.ID { return n.Host().ID() }

// Generation is the current host's generation number, starting at 1.
func (n *Node) Generation() uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cur.seq
}

// Current is the most recent HostChange.
func (n *Node) Current() HostChange {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.change
}

// Addrs are the current host's addresses plus a circuit address for every
// relay it holds a reservation on now.
func (n *Node) Addrs() []ma.Multiaddr {
	n.mu.RLock()
	g := n.cur
	n.mu.RUnlock()
	return g.addrs()
}

// LiveHosts are the hosts still running, oldest first; the last is current.
// Older ones are draining.
func (n *Node) LiveHosts() []host.Host {
	n.mu.RLock()
	defer n.mu.RUnlock()
	hs := make([]host.Host, len(n.gens))
	for i, g := range n.gens {
		hs[i] = g.h
	}
	return hs
}

// NewStream opens a stream from the current host.
func (n *Node) NewStream(ctx context.Context, p peer.ID, pids ...protocol.ID) (network.Stream, error) {
	return n.Host().NewStream(ctx, p, pids...)
}

// Connect connects the current host to ai.
func (n *Node) Connect(ctx context.Context, ai peer.AddrInfo) error {
	return n.Host().Connect(ctx, ai)
}

// SetStreamHandler sets a handler on every live host and every future one.
// Draining hosts keep serving it, so a buddy that hasn't learned the new peer
// ID yet can still reach us.
func (n *Node) SetStreamHandler(pid protocol.ID, handler network.StreamHandler) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handlers[pid] = handler
	for _, g := range n.gens {
		g.h.SetStreamHandler(pid, handler)
	}
}

// RemoveStreamHandler removes a handler set with SetStreamHandler.
func (n *Node) RemoveStreamHandler(pid protocol.ID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.handlers, pid)
	for _, g := range n.gens {
		g.h.RemoveStreamHandler(pid)
	}
}

// Subscribe calls fn after every rotation, in order, from the goroutine that
// rotated. fn must not block for long or call Rotate, Attach or Close. Use
// Current for the state at subscription time. cancel stops further calls.
func (n *Node) Subscribe(fn func(HostChange)) (cancel func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	id := n.nextSub
	n.nextSub++
	n.subs[id] = fn
	return func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		delete(n.subs, id)
	}
}

// Attach runs start on the current host now, and on every new host before it
// becomes current. If start fails on a new host, that rotation fails and the
// old host stays current. detach stops it on every live host and future
// ones.
func (n *Node) Attach(ctx context.Context, start AttachFunc) (detach func(), err error) {
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	if n.closed {
		return nil, ErrNodeClosed
	}
	a := &attachment{id: n.nextAtt, start: start}
	n.nextAtt++
	n.mu.RLock()
	cur := n.cur
	n.mu.RUnlock()
	if err := cur.attach(ctx, a); err != nil {
		return nil, err
	}
	n.atts = append(n.atts, a)
	// Draining hosts are about to go; there is nothing to start there.
	return func() { n.detach(a) }, nil
}

func (n *Node) detach(a *attachment) {
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	i := slices.Index(n.atts, a)
	if i < 0 {
		return
	}
	n.atts = slices.Delete(n.atts, i, i+1)
	n.mu.RLock()
	gens := slices.Clone(n.gens)
	n.mu.RUnlock()
	for _, g := range gens {
		if stop := g.stops[a.id]; stop != nil {
			stop()
		}
		delete(g.stops, a.id)
	}
}

// Rotate replaces the current host with one with a fresh key now, and
// restarts the rotation schedule from now.
func (n *Node) Rotate(ctx context.Context) error {
	if n.opts.FixedKey != nil {
		return ErrFixedKey
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(n.ctx, cancel)
	defer stop()
	if err := n.rotate(ctx, RotationManual); err != nil {
		return err
	}
	select {
	case n.resch <- struct{}{}:
	default:
	}
	return nil
}

// Close stops rotating and closes every host at once, without a grace
// period.
func (n *Node) Close() error {
	n.cancel()
	n.rotMu.Lock()
	if n.closed {
		n.rotMu.Unlock()
		return nil
	}
	n.closed = true
	n.mu.RLock()
	gens := slices.Clone(n.gens)
	n.mu.RUnlock()
	var errs []error
	for _, g := range gens {
		errs = append(errs, n.retireLocked(g))
	}
	n.rotMu.Unlock()
	n.wg.Wait()
	return errors.Join(errs...)
}

func (n *Node) schedule() {
	defer n.wg.Done()
	wait := n.nextInterval()
	for {
		t := n.clock.NewTimer(wait)
		select {
		case <-t.C():
		case <-n.resch:
			t.Stop()
			wait = n.nextInterval()
			continue
		case <-n.ctx.Done():
			t.Stop()
			return
		}
		if err := n.rotate(n.ctx, RotationScheduled); err != nil {
			if n.ctx.Err() != nil {
				return
			}
			if n.opts.OnError != nil {
				n.opts.OnError(fmt.Errorf("ip: scheduled rotation: %w", err))
			}
			wait = n.opts.RetryInterval
			continue
		}
		wait = n.nextInterval()
	}
}

func (n *Node) nextInterval() time.Duration {
	return jitter(n.opts.Interval, n.opts.Jitter, rand.Int64N)
}

// jitter returns a wait uniform in [interval-j, interval+j]. rnd(k) returns a
// value in [0, k). Callers ensure j < interval.
func jitter(interval, j time.Duration, rnd func(int64) int64) time.Duration {
	if j <= 0 {
		return interval
	}
	return interval - j + time.Duration(rnd(int64(2*j)+1))
}

func (n *Node) rotate(ctx context.Context, reason string) error {
	n.rotMu.Lock()
	defer n.rotMu.Unlock()
	if n.closed {
		return ErrNodeClosed
	}
	n.mu.RLock()
	old := n.cur
	n.mu.RUnlock()
	if old != nil && n.opts.FixedKey != nil {
		return ErrFixedKey
	}

	g, err := n.startGeneration(ctx)
	if err != nil {
		return err
	}
	change := HostChange{
		Generation: g.seq,
		Host:       g.h,
		ID:         g.h.ID(),
		Addrs:      g.addrs(),
		Reason:     reason,
		At:         n.clock.Now(),
	}
	if old != nil {
		change.Previous = old.h.ID()
	}
	n.mu.Lock()
	n.cur = g
	n.change = change
	subs := make([]func(HostChange), 0, len(n.subs))
	for _, id := range slices.Sorted(maps.Keys(n.subs)) {
		subs = append(subs, n.subs[id])
	}
	n.mu.Unlock()
	for _, fn := range subs {
		fn(change)
	}
	if old != nil {
		n.retireAfterGrace(old)
	}
	return nil
}

// startGeneration builds and starts the next host. It is called with rotMu
// held. On error nothing of the new host is left running.
func (n *Node) startGeneration(ctx context.Context) (_ *generation, err error) {
	key := n.opts.FixedKey
	if key == nil {
		if key, _, err = crypto.GenerateEd25519Key(nil); err != nil {
			return nil, err
		}
	}
	n.seq++
	seq := n.seq
	ho := n.opts.Host
	ho.Key = key
	if n.opts.Listen != nil {
		ho.Listen = n.opts.Listen(seq)
	}
	h, err := NewHost(ho)
	if err != nil {
		return nil, fmt.Errorf("ip: host generation %d: %w", seq, err)
	}
	g := &generation{seq: seq, h: h, stops: map[int]func(){}, circuits: map[peer.ID][]ma.Multiaddr{}}
	g.ctx, g.cancel = context.WithCancel(n.ctx)

	n.mu.Lock()
	for _, other := range n.gens {
		if p := sharedPort(h, other.h); p != "" {
			n.mu.Unlock()
			g.cancel()
			h.Close()
			return nil, fmt.Errorf("%w: generation %d listens on %s like generation %d", ErrPortReuse, seq, p, other.seq)
		}
	}
	n.gens = append(n.gens, g)
	for pid, handler := range n.handlers {
		h.SetStreamHandler(pid, handler)
	}
	n.mu.Unlock()
	defer func() {
		if err != nil {
			n.retireLocked(g)
		}
	}()

	n.startReservations(ctx, g)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, a := range n.atts {
		if err := g.attach(ctx, a); err != nil {
			return nil, fmt.Errorf("ip: host generation %d: %w", seq, err)
		}
	}
	return g, nil
}

// startReservations starts a reservation keeper per relay and waits until
// each has made its first attempt, ReservationTimeout passes or ctx ends.
func (n *Node) startReservations(ctx context.Context, g *generation) {
	if len(n.opts.Relays) == 0 {
		return
	}
	var first sync.WaitGroup
	for _, relay := range n.opts.Relays {
		relayAddrs, err := peer.AddrInfoToP2pAddrs(&relay)
		if err != nil {
			continue
		}
		first.Add(1)
		var once sync.Once
		g.wg.Go(func() {
			defer once.Do(first.Done) // keeper exited without an attempt
			KeepReservation(g.ctx, g.h, relay, func(e ReservationEvent) {
				var circuits []ma.Multiaddr
				if e.Err == nil {
					for _, ra := range relayAddrs {
						if c, err := CircuitAddr(ra, g.h.ID()); err == nil {
							circuits = append(circuits, c)
						}
					}
				}
				g.rmu.Lock()
				if circuits != nil {
					g.circuits[relay.ID] = circuits
				} else {
					delete(g.circuits, relay.ID)
				}
				g.rmu.Unlock()
				if n.opts.OnReservation != nil {
					n.opts.OnReservation(g.seq, relay.ID, e)
				}
				once.Do(first.Done)
			})
		})
	}
	done := make(chan struct{})
	go func() { first.Wait(); close(done) }()
	t := n.clock.NewTimer(n.opts.ReservationTimeout)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C():
	case <-ctx.Done():
	}
}

func (n *Node) retireAfterGrace(g *generation) {
	if n.opts.Grace < 0 {
		n.retireLocked(g)
		return
	}
	t := n.clock.NewTimer(n.opts.Grace)
	n.wg.Go(func() {
		defer t.Stop()
		select {
		case <-t.C():
		case <-n.ctx.Done():
			return // Close retires it
		}
		n.rotMu.Lock()
		defer n.rotMu.Unlock()
		n.retireLocked(g)
	})
}

// retireLocked stops g's attached services and reservation keepers and
// closes its host. It is called with rotMu held and is idempotent.
func (n *Node) retireLocked(g *generation) error {
	if g.retired {
		return nil
	}
	g.retired = true
	for _, id := range slices.Backward(g.order) {
		if stop := g.stops[id]; stop != nil {
			stop()
		}
	}
	g.stops = nil
	g.cancel()
	g.wg.Wait()
	err := g.h.Close()
	// Only now does it leave LiveHosts: everything on it has stopped.
	n.mu.Lock()
	if i := slices.Index(n.gens, g); i >= 0 {
		n.gens = slices.Delete(n.gens, i, i+1)
	}
	n.mu.Unlock()
	return err
}

func (g *generation) attach(ctx context.Context, a *attachment) error {
	stop, err := a.start(ctx, g.h)
	if err != nil {
		return err
	}
	g.stops[a.id] = stop
	g.order = append(g.order, a.id)
	return nil
}

func (g *generation) addrs() []ma.Multiaddr {
	addrs := slices.Clone(g.h.Addrs())
	g.rmu.Lock()
	defer g.rmu.Unlock()
	for _, id := range slices.Sorted(maps.Keys(g.circuits)) {
		addrs = append(addrs, g.circuits[id]...)
	}
	return addrs
}

// sharedPort returns "tcp/<port>" or "udp/<port>" if a and b listen on the
// same port, else "".
func sharedPort(a, b host.Host) string {
	ports := map[string]bool{}
	for _, addr := range b.Network().ListenAddresses() {
		for _, p := range listenPorts(addr) {
			ports[p] = true
		}
	}
	for _, addr := range a.Network().ListenAddresses() {
		for _, p := range listenPorts(addr) {
			if ports[p] {
				return p
			}
		}
	}
	return ""
}

func listenPorts(a ma.Multiaddr) []string {
	var ps []string
	if v, err := a.ValueForProtocol(ma.P_TCP); err == nil && v != "0" {
		ps = append(ps, "tcp/"+v)
	}
	if v, err := a.ValueForProtocol(ma.P_UDP); err == nil && v != "0" {
		ps = append(ps, "udp/"+v)
	}
	return ps
}
