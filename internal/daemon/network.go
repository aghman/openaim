package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	lpeer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"google.golang.org/protobuf/proto"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/presence"
	"github.com/aghman/openaim/internal/rendezvous"
	"github.com/aghman/openaim/internal/router"
	"github.com/aghman/openaim/internal/store"
	"github.com/aghman/openaim/internal/transport/ip"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// The IP transport and everything that runs on it (design §6.1, §7, §8.8,
// §11.1): the rotating libp2p node with its private DHT and /openaim/msg/1
// sessions, rendezvous publishing and lookups, the router (send policy v0
// and ACKs) and the presence tracker.
//
// Start order: store and identity (Open), then node + DHT + sessions, the
// rendezvous publisher, the router, the presence tracker, and the API
// (internal/api). Shutdown runs the other way round: presence signs off,
// then the router, the publisher, the sessions, the DHT and the node stop.
//
// One inbound path: every frame from a session, DATA or FIRST_CONTACT,
// goes through handleFrame, the code behind HandleFrameFrom.

// Network defaults.
const (
	// DefaultSignOffTimeout bounds the OFFLINE presence sent at shutdown.
	DefaultSignOffTimeout = 3 * time.Second
	// DefaultLookupMin and DefaultLookupMax bound the backoff between
	// rendezvous lookups for a buddy with no live session.
	DefaultLookupMin = 30 * time.Second
	DefaultLookupMax = 30 * time.Minute
	// DefaultLookupTimeout bounds one rendezvous lookup.
	DefaultLookupTimeout = 30 * time.Second
	// DefaultRedeliverInterval is how often unanswered buddy requests are
	// sent again.
	DefaultRedeliverInterval = 10 * time.Minute
	// DefaultSweepInterval is how often incomplete messages past
	// frame.PartialTTL are dropped and expired dedup entries deleted.
	DefaultSweepInterval = 10 * time.Minute
	// OurReachTTL is how long a REACH we build stays valid: like a
	// rendezvous record, a day and a half, past the daily rotation.
	OurReachTTL = rendezvous.MaxTTL

	// maxBackground bounds best-effort sends and lookups in flight.
	maxBackground = 32
	// maxPeersPerBuddy bounds the peer IDs remembered for one buddy.
	maxPeersPerBuddy = 4
	// lookupSpacing is the least time between two lookups of one buddy
	// asked for by a send.
	lookupSpacing = 5 * time.Second
	// oneOffTimeout bounds a best-effort send.
	oneOffTimeout = 30 * time.Second
	// signOffFlush is how long shutdown waits after signing off before
	// closing the transports, so the OFFLINE presence gets out.
	signOffFlush = 300 * time.Millisecond
)

// NetworkOptions configures the IP transport. Zero values mean the
// defaults of each package.
type NetworkOptions struct {
	// Config lists bootstrap and relay nodes. Nil reads network.json from
	// the data directory; a missing file means the built-in defaults.
	Config *ip.NetworkConfig
	// Listen are multiaddrs for every host generation; nil means TCP and
	// QUIC on random ports on every interface.
	Listen []string
	// Public runs a publicly reachable node for relay and bootstrap
	// operators: a fixed network key (FixedKey, else network.key in the data
	// dir, created on first use), the DHT in server mode, and a circuit
	// relay service with RelayLimit (nil: ip.OpenAIMLimit). It takes no
	// relay reservations itself.
	Public     bool
	FixedKey   crypto.PrivKey
	RelayLimit *relay.RelayLimit
	// DHTMode for ordinary nodes; ignored when Public (always a server).
	DHTMode ip.DHTMode
	// DisableHolePunching turns DCUtR off. NATPortMap tries UPnP/NAT-PMP.
	DisableHolePunching bool
	NATPortMap          bool
	// Gater, if set, can veto connections (tests force traffic onto a
	// relay with it). Resolver, if set, resolves /dns* addresses (tests
	// give the relay a name with it).
	Gater    connmgr.ConnectionGater
	Resolver network.MultiaddrDNSResolver

	// Rotation of the network key (ip.NodeOptions).
	RotationInterval, RotationJitter, RotationGrace time.Duration
	ReservationTimeout, DHTBootstrapTimeout         time.Duration
	// Sessions are the /openaim/msg/1 limits and timeouts.
	Sessions ip.SessionOptions

	// Router timings (router.Config).
	AckTimeout, MaxRetryDelay, AckDelay time.Duration
	// Presence timings (presence.Config).
	HeartbeatInterval, HeartbeatJitter, BuddyTimeout, PresenceGrace, PresenceRetry time.Duration
	// AutoAwayAfter switches us to Away after this long without Activity;
	// zero disables it.
	AutoAwayAfter time.Duration
	// SignOffTimeout bounds the OFFLINE presence sent at shutdown.
	SignOffTimeout time.Duration
	// Rendezvous publishing (rendezvous.PublisherOptions).
	PublishRefresh, PublishRetry, PublishPutInterval time.Duration
	// LookupMin and LookupMax bound the rendezvous lookup backoff;
	// LookupTimeout bounds one lookup.
	LookupMin, LookupMax, LookupTimeout time.Duration
	// RedeliverInterval: unanswered requests are resent this often.
	// SweepInterval: partial messages and dedup entries are expired this
	// often.
	RedeliverInterval, SweepInterval time.Duration
}

func (o *NetworkOptions) defaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.SignOffTimeout, DefaultSignOffTimeout)
	def(&o.LookupMin, DefaultLookupMin)
	def(&o.LookupMax, DefaultLookupMax)
	def(&o.LookupTimeout, DefaultLookupTimeout)
	def(&o.RedeliverInterval, DefaultRedeliverInterval)
	def(&o.SweepInterval, DefaultSweepInterval)
	if o.LookupMax < o.LookupMin {
		o.LookupMax = o.LookupMin
	}
}

var errNoRoute = errors.New("daemon: no IP route to the buddy")

// netState is the running network. Its methods are safe for concurrent use.
type netState struct {
	n    *Node
	o    NetworkOptions
	cfg  ip.NetworkConfig
	log  *slog.Logger
	node *ip.Node
	dht  *ip.DHT
	sess *ip.Sessions
	rly  *relay.Relay // Public only
	pub  *rendezvous.Publisher
	rch  *router.ReachTable
	rt   *router.Router
	pres *presence.Tracker

	ctx       context.Context // ends at shutdown
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	sem       chan struct{} // background work slots
	unsubHost func()
	rtEvents  chan router.Event
	kick      chan struct{} // wakes the lookup loop

	mu      sync.Mutex
	closed  bool
	seq     uint64                            // last one-off seq handed out
	ids     map[identity.PublicKey]int64      // buddy key → store ID (cache)
	keys    map[int64]identity.PublicKey      // and back
	peerOf  map[lpeer.ID]identity.PublicKey   // peers attributed to a buddy
	peers   map[identity.PublicKey][]lpeer.ID // a buddy's peers, newest first
	kept    map[identity.PublicKey]lpeer.ID   // the peer we keep a session with
	lookups map[int64]*lookupState            // accepted buddies
	resv    map[lpeer.ID]ip.ReservationEvent  // current generation's reservations
	resvGen uint64
}

type lookupState struct {
	key     identity.PublicKey
	next    time.Time
	last    time.Time
	backoff time.Duration
	running bool
}

// startNetwork brings the transports up. On error everything started is
// stopped again.
func (n *Node) startNetwork(ctx context.Context, o NetworkOptions) (err error) {
	o.defaults()
	s := &netState{
		n: n, o: o, log: n.log.With("part", "net"),
		sem: make(chan struct{}, maxBackground), rtEvents: make(chan router.Event, 256), kick: make(chan struct{}, 1),
		ids: map[identity.PublicKey]int64{}, keys: map[int64]identity.PublicKey{},
		peerOf: map[lpeer.ID]identity.PublicKey{}, peers: map[identity.PublicKey][]lpeer.ID{},
		kept: map[identity.PublicKey]lpeer.ID{}, lookups: map[int64]*lookupState{}, resv: map[lpeer.ID]ip.ReservationEvent{},
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			s.close()
		}
	}()

	if o.Config != nil {
		s.cfg = *o.Config
	} else if s.cfg, err = ip.LoadNetworkConfig(n.paths.Network); err != nil {
		return err
	}
	no := ip.NodeOptions{
		Host: ip.HostOptions{Listen: o.Listen, HolePunching: !o.DisableHolePunching, PublicReachability: o.Public,
			NATPortMap: o.NATPortMap, Gater: o.Gater, Resolver: o.Resolver},
		Interval: o.RotationInterval, Jitter: o.RotationJitter, Grace: o.RotationGrace,
		ReservationTimeout: o.ReservationTimeout, OnReservation: s.onReservation,
		OnError: func(err error) { s.log.Warn("network key rotation failed", "err", err) },
	}
	dhtMode := o.DHTMode
	if o.Public {
		dhtMode = ip.DHTServer
		if no.FixedKey = o.FixedKey; no.FixedKey == nil {
			if no.FixedKey, err = ip.LoadOrCreateKey(n.paths.NetKey); err != nil {
				return fmt.Errorf("daemon: network key: %w", err)
			}
		}
	} else {
		no.Relays = s.cfg.Relays
	}
	if s.node, err = ip.NewNode(no); err != nil {
		return err
	}
	if o.Public {
		limit := o.RelayLimit
		if limit == nil {
			limit = ip.OpenAIMLimit
		}
		if s.rly, err = ip.StartRelay(s.node.Host(), ip.RelayOptions{Limit: limit}); err != nil {
			return err
		}
		s.log.Info("relay service started", "limit", ip.DescribeLimit(limit))
	}
	if s.dht, err = ip.NewDHT(ctx, s.node, ip.DHTOptions{Mode: dhtMode, Bootstrap: s.cfg.Bootstrap,
		BootstrapTimeout: o.DHTBootstrapTimeout}); err != nil {
		return err
	}
	if s.sess, err = ip.NewSessions(s.node, o.Sessions); err != nil {
		return err
	}
	if s.pub, err = rendezvous.NewPublisher(rendezvous.PublisherOptions{
		Store: s.dht, Node: s.node, Refresh: o.PublishRefresh, Retry: o.PublishRetry, PutInterval: o.PublishPutInterval,
		OnPublish: func(e rendezvous.PublishEvent) {
			if e.Err != nil {
				s.log.Debug("rendezvous put failed", "buddy", e.Buddy.KeyID(), "err", e.Err)
			}
		},
	}); err != nil {
		return err
	}
	s.rch = router.NewReachTable()
	if s.rt, err = router.New(router.Config{
		Store: n.store, Transport: router.SessionsTransport(s.sess), Reach: s.rch, Seal: s.sealAck,
		OnEvent: s.onRouterEvent, Log: s.log.With("part", "router"),
		AckTimeout: o.AckTimeout, MaxRetryDelay: o.MaxRetryDelay, AckDelay: o.AckDelay,
	}); err != nil {
		return err
	}
	s.rch.OnChange = s.rt.RouteChanged
	own := n.Presence()
	if s.pres, err = presence.New(presence.Config{
		Sender: presence.SenderFunc(s.sendPresence), Log: s.log.With("part", "presence"),
		HeartbeatInterval: o.HeartbeatInterval, HeartbeatJitter: o.HeartbeatJitter, BuddyTimeout: o.BuddyTimeout,
		Grace: o.PresenceGrace, RetryDelay: o.PresenceRetry, AutoAwayAfter: o.AutoAwayAfter,
		State: presence.State(own.State), AwayText: own.Away,
	}); err != nil {
		return err
	}

	// The buddy list: publish for accepted buddies and the ones we asked,
	// track presence and look up the accepted ones, and start from the
	// reachability they last told us.
	buddies, err := n.store.Buddies(ctx)
	if err != nil {
		return err
	}
	var accepted []identity.PublicKey
	now := n.now()
	for _, b := range buddies {
		s.remember(b.ID, b.Key)
		switch b.State {
		case store.Accepted:
			accepted = append(accepted, b.Key)
			s.lookups[b.ID] = &lookupState{key: b.Key, next: now, backoff: o.LookupMin}
		case store.PendingOut:
		default:
			continue
		}
		if p, err := n.pair(b.Key); err == nil {
			s.pub.SetPair(p)
		}
		if r := n.peerReach(ctx, b.ID); r != nil {
			s.updateReach(b.ID, b.Key, r)
		}
	}
	if err := s.pres.SetBuddies(accepted); err != nil {
		return err
	}
	if err := s.rt.Start(ctx); err != nil {
		return err
	}
	n.net = s

	s.unsubHost = s.node.Subscribe(func(c ip.HostChange) {
		s.log.Info("network key rotated", "peer_id", c.ID, "generation", c.Generation, "reason", c.Reason)
		s.goBackground(s.announceAll)
	})
	s.wg.Add(6)
	go s.inboundLoop()
	go s.sessionEventLoop()
	go s.routerEventLoop()
	go s.presenceEventLoop()
	go s.lookupLoop()
	go s.maintenanceLoop()
	s.goBackground(s.announceAll)
	s.log.Info("network up", "peer_id", s.node.ID(), "public", o.Public,
		"bootstrap", len(s.cfg.Bootstrap), "relays", len(s.cfg.Relays), "dht_mode", dhtMode)
	return nil
}

// close stops the network: presence signs off (bounded), then the router,
// the publisher and the sessions stop, the loops end, and the DHT and the
// node close. It is safe on a partly started netState.
func (s *netState) close() {
	if s.pres != nil {
		ctx, cancel := context.WithTimeout(context.Background(), s.o.SignOffTimeout)
		sent := s.pres.Stats().Sent
		if err := s.pres.SignOff(ctx); err != nil && !errors.Is(err, presence.ErrClosed) {
			s.log.Warn("signing off", "err", err)
		}
		if s.pres.Stats().Sent > sent {
			// A Send returns once the frames are in the stream's buffer;
			// closing the host at once can drop them on the way out.
			// Give the OFFLINE presence a moment to leave.
			t := time.NewTimer(signOffFlush)
			select {
			case <-t.C:
			case <-ctx.Done():
			}
			t.Stop()
		}
		cancel()
		s.pres.Close()
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	if s.unsubHost != nil {
		s.unsubHost()
	}
	if s.rt != nil {
		s.rt.Close()
	}
	if s.pub != nil {
		s.pub.Close()
	}
	if s.sess != nil {
		s.sess.Close()
	}
	s.wg.Wait()
	if s.dht != nil {
		s.dht.Close()
	}
	if s.rly != nil {
		s.rly.Close()
	}
	if s.node != nil {
		if err := s.node.Close(); err != nil {
			s.log.Debug("closing the network node", "err", err)
		}
	}
	s.log.Info("network down")
}

// goBackground runs f in the background with a slot of the shared bound,
// unless the network is closing or every slot is taken. It reports whether
// f was started.
func (s *netState) goBackground(f func(ctx context.Context)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.log.Debug("too much background network work; dropping some")
		return false
	}
	s.wg.Go(func() {
		defer func() { <-s.sem }()
		f(s.ctx)
	})
	return true
}

// ---- buddy IDs

func (s *netState) remember(id int64, k identity.PublicKey) {
	s.mu.Lock()
	s.ids[k], s.keys[id] = id, k
	s.mu.Unlock()
}

// idOf is the store ID of buddy k.
func (s *netState) idOf(ctx context.Context, k identity.PublicKey) (int64, error) {
	s.mu.Lock()
	id, ok := s.ids[k]
	s.mu.Unlock()
	if ok {
		return id, nil
	}
	b, err := s.n.store.BuddyByKey(ctx, k)
	if err != nil {
		return 0, err
	}
	s.remember(b.ID, k)
	return b.ID, nil
}

// keyOf is the key of buddy id.
func (s *netState) keyOf(ctx context.Context, id int64) (identity.PublicKey, error) {
	s.mu.Lock()
	k, ok := s.keys[id]
	s.mu.Unlock()
	if ok {
		return k, nil
	}
	b, err := s.n.store.Buddy(ctx, id)
	if err != nil {
		return identity.PublicKey{}, err
	}
	s.remember(id, b.Key)
	return b.Key, nil
}

// ---- sealing and best-effort sends

// nextSeq is the inner seq for a one-off message: above every one this
// daemon handed out before, across restarts (it starts at the clock, in
// milliseconds). PRESENCE bodies are ordered by (timestamp, seq), so two in
// the same second must not tie.
func (s *netState) nextSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq = max(s.seq+1, uint64(max(s.n.now().UnixMilli(), 0)))
	return s.seq
}

// seal seals a one-off message to buddy k in the IP layout. Nothing is
// persisted: these are sent once (or, for ACKs, re-made on demand).
func (s *netState) seal(k identity.PublicKey, ct frame.ContentType, b []byte, seq uint64) ([][]byte, error) {
	p, err := s.n.pair(k)
	if err != nil {
		return nil, err
	}
	key := frame.NewConvKey(p.Send)
	now := s.n.now()
	in := frame.Inner{Type: ct, Time: frame.Timestamp(now), Seq: seq, Body: b}
	sealed, err := frame.Seal(key, key.Tag(frame.Day(now)), frame.LayoutIP, in.Marshal())
	if err != nil {
		return nil, err
	}
	return sealed.Frames, nil
}

// sealAck is the router's Sealer. ACKs are unordered: seq 0.
func (s *netState) sealAck(ctx context.Context, id int64, ct frame.ContentType, b []byte) ([][]byte, error) {
	k, err := s.keyOf(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.seal(k, ct, b, 0)
}

// sendOneOff seals m for buddy (id, k) and sends it once along the buddy's
// current route.
func (s *netState) sendOneOff(ctx context.Context, id int64, k identity.PublicKey, m proto.Message) error {
	return s.sendOneOffTo(ctx, id, k, m, nil)
}

// sendOneOffTo is sendOneOff to a given peer instead of the route (nil:
// the route).
func (s *netState) sendOneOffTo(ctx context.Context, id int64, k identity.PublicKey, m proto.Message, to *lpeer.AddrInfo) error {
	ct, b, err := body.Marshal(m)
	if err != nil {
		return err
	}
	var ai lpeer.AddrInfo
	if to != nil {
		ai = *to
	} else {
		route, ok := s.rch.IPRoute(id, s.n.now())
		if !ok {
			return errNoRoute
		}
		ai = route.AddrInfo()
	}
	frames, err := s.seal(k, ct, b, s.nextSeq())
	if err != nil {
		return err
	}
	s.attribute(id, k, ai.ID, false)
	ctx, cancel := context.WithTimeout(ctx, oneOffTimeout)
	defer cancel()
	return s.sess.Send(ctx, ai, frames)
}

// sendLater is sendOneOff in the background; failures are logged.
func (s *netState) sendLater(id int64, k identity.PublicKey, m proto.Message) {
	s.goBackground(func(ctx context.Context) {
		if err := s.sendOneOff(ctx, id, k, m); err != nil && ctx.Err() == nil {
			s.log.Debug("best-effort send failed", "buddy", k.KeyID(), "type", fmt.Sprintf("%T", m), "err", err)
		}
	})
}

// ---- what we tell others about ourselves

// reachBody is our REACH now: the current peer ID and its addresses, relay
// circuits first.
func (s *netState) reachBody() *pb.Reach {
	c := s.node.Current()
	now := s.n.now()
	ts := frame.Timestamp(now)
	r := &pb.Reach{Seq: s.nextSeq(), IssuedAt: ts, ExpiresAt: frame.Timestamp(now.Add(OurReachTTL)),
		Ip: []*pb.IPHint{{PeerId: []byte(c.ID)}}}
	for _, a := range pickAddrs(c.ID, s.node.Addrs()) {
		r.Ip[0].Addrs = append(r.Ip[0].Addrs, a.Bytes())
	}
	if err := body.Validate(r); err != nil {
		s.log.Warn("our REACH is invalid", "err", err)
		return nil
	}
	return r
}

// pickAddrs chooses what we advertise of our addresses: without a trailing
// /p2p/<self>, deduplicated, at most body.MaxAddrs of body.MaxAddrLen
// bytes, relay circuits first, then public, private and loopback ones.
func pickAddrs(self lpeer.ID, addrs []ma.Multiaddr) []ma.Multiaddr {
	type ranked struct {
		a    ma.Multiaddr
		rank int
	}
	var rs []ranked
	seen := map[string]bool{}
	for _, a := range addrs {
		if rest, last := ma.SplitLast(a); last != nil && last.Code() == ma.P_P2P && last.Value() == self.String() {
			a = rest
		}
		b := a.Bytes()
		if len(b) == 0 || len(b) > body.MaxAddrLen || seen[string(b)] {
			continue
		}
		seen[string(b)] = true
		rank := 3
		switch {
		case isCircuitAddr(a):
			rank = 0
		case manet.IsPublicAddr(a):
			rank = 1
		case manet.IsPrivateAddr(a) && !manet.IsIPLoopback(a):
			rank = 2
		}
		rs = append(rs, ranked{a, rank})
	}
	slices.SortStableFunc(rs, func(x, y ranked) int { return x.rank - y.rank })
	out := make([]ma.Multiaddr, 0, min(len(rs), body.MaxAddrs))
	for _, r := range rs[:min(len(rs), body.MaxAddrs)] {
		out = append(out, r.a)
	}
	return out
}

func isCircuitAddr(a ma.Multiaddr) bool {
	_, err := a.ValueForProtocol(ma.P_CIRCUIT)
	return err == nil
}

// contactHint is our relay circuit address (…/p2p-circuit/p2p/<us>) on the
// first relay holding a reservation, or "".
func (s *netState) contactHint() string {
	for _, a := range s.node.Addrs() {
		if isCircuitAddr(a) {
			return a.String()
		}
	}
	return ""
}

// announce sends our REACH to a buddy along their current route, so a
// session comes up and they learn where we are (design §7.1: they take it
// only because it is authenticated).
//
// to, if set, is where to send it instead of the buddy's route: the peer a
// rendezvous record just named, which may be a newer place than a REACH
// issued in the same second.
func (s *netState) announce(ctx context.Context, id int64, k identity.PublicKey, to *lpeer.AddrInfo) error {
	r := s.reachBody()
	if r == nil {
		return errors.New("daemon: no REACH to announce")
	}
	return s.sendOneOffTo(ctx, id, k, r, to)
}

// announceAll announces us to every accepted buddy we have a route to: at
// start and after a rotation (the new peer ID).
func (s *netState) announceAll(ctx context.Context) {
	now := s.n.now()
	s.mu.Lock()
	type target struct {
		id int64
		k  identity.PublicKey
	}
	var ts []target
	for id, l := range s.lookups {
		ts = append(ts, target{id, l.key})
	}
	s.mu.Unlock()
	for _, t := range ts {
		if _, ok := s.rch.IPRoute(t.id, now); !ok {
			continue
		}
		s.goBackground(func(ctx context.Context) {
			if err := s.announce(ctx, t.id, t.k, nil); err != nil && ctx.Err() == nil {
				s.log.Debug("announce failed", "buddy", t.k.KeyID(), "err", err)
			}
		})
	}
}

// ---- reachability

// updateReach feeds a buddy's authenticated REACH to the reach table.
func (s *netState) updateReach(id int64, k identity.PublicKey, r *pb.Reach) {
	h, ok := router.HintFromReach(r)
	if !ok {
		return
	}
	if err := s.rch.Update(id, router.FromReach, h, s.n.now()); err != nil {
		if !errors.Is(err, router.ErrStaleHint) {
			s.log.Debug("ignoring REACH", "buddy", k.KeyID(), "err", err)
		}
		return
	}
	s.attribute(id, k, h.Peer, false)
}

// ---- the FrameSink

// Deliver implements FrameSink over the network. First contacts go to the
// contact hint (a relay circuit ending in /p2p/<their peer ID>) or the
// target's REACH; buddy frames along the buddy's route. It hands the frames
// to a background send and returns: a failure shows up as no answer, and
// RedeliverRequests (or the router) sends again.
func (s *netState) Deliver(_ context.Context, to DeliveryTarget, frames [][]byte) error {
	var ai lpeer.AddrInfo
	switch to.Kind {
	case TargetFirstContact:
		var err error
		if ai, err = firstContactAddr(to); err != nil {
			return err
		}
		// Publish for the buddy we asked, so they find us once they accept.
		if p, err := s.n.pair(to.Key); err == nil {
			s.pub.SetPair(p)
		}
	case TargetBuddy:
		id, err := s.idOf(s.ctx, to.Key)
		if err != nil {
			return err
		}
		if to.Reach != nil {
			s.updateReach(id, to.Key, to.Reach)
		}
		route, ok := s.rch.IPRoute(id, s.n.now())
		if !ok {
			return errNoRoute
		}
		ai = route.AddrInfo()
	default:
		return fmt.Errorf("daemon: unknown delivery target %v", to.Kind)
	}
	frames = slices.Clone(frames)
	if !s.goBackground(func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(ctx, oneOffTimeout)
		defer cancel()
		if err := s.sess.Send(ctx, ai, frames); err != nil && ctx.Err() == nil {
			s.log.Info("delivery failed; it will be retried", "to", to.Key.KeyID(), "kind", to.Kind, "peer", ai.ID, "err", err)
		}
	}) {
		return errors.New("daemon: network busy or stopping")
	}
	return nil
}

// firstContactAddr is where a first contact goes.
func firstContactAddr(to DeliveryTarget) (lpeer.AddrInfo, error) {
	if to.ContactHint != "" {
		a, err := ma.NewMultiaddr(to.ContactHint)
		if err != nil {
			return lpeer.AddrInfo{}, fmt.Errorf("daemon: contact hint: %w", err)
		}
		ai, err := lpeer.AddrInfoFromP2pAddr(a)
		if err != nil {
			// A mailbox hint (M3) isn't a peer address.
			return lpeer.AddrInfo{}, fmt.Errorf("daemon: contact hint %s can't be dialled yet: %w", to.ContactHint, err)
		}
		return *ai, nil
	}
	if to.Reach != nil {
		if h, ok := router.HintFromReach(to.Reach); ok {
			return lpeer.AddrInfo{ID: h.Peer, Addrs: h.Addrs}, nil
		}
	}
	return lpeer.AddrInfo{}, errors.New("daemon: no contact hint or reachability for this request; it stays queued")
}

// ---- background loops

// inboundLoop is the one inbound path for frames from the network.
func (s *netState) inboundLoop() {
	defer s.wg.Done()
	ctx := context.Background() // finish each frame even while stopping
	for f := range s.sess.Inbound() {
		if _, err := s.n.handleFrame(ctx, "ip", f.Peer, f.Frame); err != nil {
			s.log.Debug("dropped an inbound frame", "peer", f.Peer, "path", f.Path, "err", err)
		}
	}
}

func (s *netState) routerEventLoop() {
	defer s.wg.Done()
	for {
		select {
		case e := <-s.rtEvents:
			s.publishUpdate(e)
		case <-s.ctx.Done():
			return
		}
	}
}

// onRouterEvent is the router's OnEvent: it must not block.
func (s *netState) onRouterEvent(e router.Event) {
	select {
	case s.rtEvents <- e:
	default:
		s.log.Warn("delivery events backed up; dropping one", "msg_id", e.MsgID)
	}
}

// publishUpdate turns a router event about an IM into message_updated.
func (s *netState) publishUpdate(e router.Event) {
	ctx := s.ctx
	o, err := s.n.store.OutgoingByMsgID(ctx, e.BuddyID, e.MsgID)
	if err != nil || o.ContentType != frame.IM {
		return
	}
	if e.State == router.Sent && o.State != store.Queued {
		// The router reports the first send after recording it, and the
		// ACK can win that race: don't report "sent" after "acked".
		return
	}
	k, err := s.keyOf(ctx, e.BuddyID)
	if err != nil {
		return
	}
	s.n.events.publish(Event{Kind: EventMessageUpdated, Update: &MessageUpdate{
		MsgID: e.MsgID, Buddy: k, State: DeliveryState(e.State), AckedMask: e.AckedMask, FragCount: e.FragCount, Attempts: e.Attempts,
	}})
}

// maintenanceLoop expires partial messages and dedup entries, and resends
// unanswered buddy requests.
func (s *netState) maintenanceLoop() {
	defer s.wg.Done()
	if _, err := s.n.RedeliverRequests(s.ctx); err != nil && s.ctx.Err() == nil {
		s.log.Warn("resending requests", "err", err)
	}
	sweep := time.NewTicker(s.o.SweepInterval)
	defer sweep.Stop()
	redeliver := time.NewTicker(s.o.RedeliverInterval)
	defer redeliver.Stop()
	for {
		select {
		case <-sweep.C:
			s.n.recv.Sweep()
			s.n.fcRecv.Sweep()
			if _, err := s.n.store.ExpireDedup(s.ctx, s.n.now()); err != nil && s.ctx.Err() == nil {
				s.log.Warn("expiring dedup entries", "err", err)
			}
		case <-redeliver.C:
			if _, err := s.n.RedeliverRequests(s.ctx); err != nil && s.ctx.Err() == nil {
				s.log.Warn("resending requests", "err", err)
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// ---- status

func (s *netState) onReservation(gen uint64, relayID lpeer.ID, e ip.ReservationEvent) {
	s.mu.Lock()
	if gen > s.resvGen {
		s.resvGen = gen
		clear(s.resv)
	}
	if gen == s.resvGen {
		s.resv[relayID] = e
	}
	s.mu.Unlock()
	if e.Err != nil {
		s.log.Info("relay reservation failed", "relay", relayID, "reason", e.Reason, "err", e.Err)
	} else {
		s.log.Debug("relay reservation", "relay", relayID, "reason", e.Reason, "expires", e.Reservation.Expiration)
	}
}

// NetworkStatus is the IP transport's state.
type NetworkStatus struct {
	PeerID      lpeer.ID
	Generation  uint64
	Listen      []ma.Multiaddr // own addresses
	Circuits    []ma.Multiaddr // relay circuit addresses
	Relays      []RelayStatus
	Bootstrap   int
	DHTPeers    int
	SessionsUp  int
	Public      bool
	ContactHint string
	Online      int // buddies shown online or away
}

// RelayStatus is our reservation on one configured relay.
type RelayStatus struct {
	ID          lpeer.ID
	Reserved    bool
	LastAttempt time.Time
	Expires     time.Time
	LastError   string
}

// Network reports the IP transport's state, or nil when the daemon runs
// without one.
func (n *Node) Network() *NetworkStatus {
	s := n.net
	if s == nil {
		return nil
	}
	c := s.node.Current()
	st := &NetworkStatus{PeerID: c.ID, Generation: c.Generation, Bootstrap: len(s.cfg.Bootstrap), Public: s.o.Public,
		ContactHint: s.contactHint()}
	for _, a := range s.node.Addrs() {
		if isCircuitAddr(a) {
			st.Circuits = append(st.Circuits, a)
		} else {
			st.Listen = append(st.Listen, a)
		}
	}
	s.mu.Lock()
	for _, r := range s.cfg.Relays {
		rs := RelayStatus{ID: r.ID}
		if e, ok := s.resv[r.ID]; ok {
			rs.LastAttempt = e.At
			if e.Err != nil {
				rs.LastError = e.Err.Error()
			} else if e.Reservation != nil {
				rs.Reserved, rs.Expires = true, e.Reservation.Expiration
			}
		}
		st.Relays = append(st.Relays, rs)
	}
	s.mu.Unlock()
	if kd, err := s.dht.Instance(); err == nil {
		st.DHTPeers = kd.RoutingTable().Size()
	}
	for _, p := range s.sess.Peers() {
		if p.Up {
			st.SessionsUp++
		}
	}
	for _, b := range s.pres.Buddies() {
		if b.State != presence.Offline {
			st.Online++
		}
	}
	return st
}

// Rotate replaces the network key now (a new peer ID), as the daily
// rotation does. It fails on a node without a network or with a fixed key.
func (n *Node) Rotate(ctx context.Context) error {
	if n.net == nil {
		return ErrOffline
	}
	return n.net.node.Rotate(ctx)
}

// ErrOffline: the daemon runs without a network.
var ErrOffline = errors.New("daemon: no network (running offline)")
