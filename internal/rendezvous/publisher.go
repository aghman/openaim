package rendezvous

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/transport/ip"
)

// Publisher defaults (spec/dht-records.md, "Publishing").
const (
	// DefaultTTL is expires_at − issued_at.
	DefaultTTL = MaxTTL
	// DefaultRefresh is how long after its last successful put a record is
	// put again. Storers lose records when their hosts rotate (every host
	// generation starts with an empty DHT datastore), so this is well under
	// a day.
	DefaultRefresh = 12 * time.Hour
	// DefaultPrepublish is how long before UTC midnight tomorrow's record is
	// published, so a lookup at the rollover finds one under either day.
	DefaultPrepublish = time.Hour
	// DefaultConcurrency bounds puts in flight.
	DefaultConcurrency = 4
	// DefaultPutInterval is the least time between the starts of two puts:
	// 100 buddies take about 20 seconds.
	DefaultPutInterval = 200 * time.Millisecond
	// DefaultPutTimeout bounds one put.
	DefaultPutTimeout = time.Minute
	// DefaultRetry is the wait after a failed put. It doubles with every
	// further failure of the same record, up to DefaultMaxRetry.
	DefaultRetry    = time.Minute
	DefaultMaxRetry = 30 * time.Minute
)

// Clock is the time source; it is the same interface ip.Node takes, so one
// fake clock can drive both in tests.
type Clock = ip.Clock

type realClock struct{}

func (realClock) Now() time.Time                    { return time.Now() }
func (realClock) NewTimer(d time.Duration) ip.Timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.t.C }
func (t realTimer) Stop() bool          { return t.t.Stop() }

// Putter stores signed rendezvous records. *ip.DHT implements it.
type Putter interface {
	PutRendezvous(ctx context.Context, priv ed25519.PrivateKey, seq uint64, payload []byte) (string, error)
}

// PublishEvent reports one put.
type PublishEvent struct {
	Buddy identity.PublicKey
	Day   uint32
	Key   string
	Seq   uint64
	ID    peer.ID // the peer ID published
	Err   error
}

// PublisherOptions configures NewPublisher. Zero durations mean the defaults;
// a negative PutInterval disables the spacing between puts.
type PublisherOptions struct {
	// Store receives the records, usually the node's *ip.DHT. Required.
	Store Putter
	// Node, if set, is followed: every HostChange and every change of a
	// host's addresses republishes, and Self defaults to the current peer
	// ID and addresses.
	Node *ip.Node
	// Self is where we are now. Required unless Node is set.
	Self func() peer.AddrInfo

	TTL, Refresh, Prepublish time.Duration
	Concurrency              int
	PutInterval, PutTimeout  time.Duration
	Retry, MaxRetry          time.Duration

	Clock Clock     // nil means the real clock
	Rand  io.Reader // nonce source; nil means crypto/rand
	// OnPublish, if set, sees every put attempt. It must not block for long.
	OnPublish func(PublishEvent)
}

// Publisher keeps a rendezvous record per buddy in the DHT: today's, and
// near UTC midnight tomorrow's too. It publishes on start, when the node's
// host rotates or its addresses change, on Republish, and on a refresh
// schedule, and retries failures with backoff. A record is put only when its
// locator changed or it is due, so triggers are cheap. Puts are spaced and
// run with bounded concurrency.
type Publisher struct {
	o     PublisherOptions
	clock Clock

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	kick   chan struct{}
	unsub  func()
	once   sync.Once

	mu      sync.Mutex
	buddies map[identity.PublicKey][32]byte // → K_dir toward them (Pair.Send)
	state   map[entryKey]*entry

	nextPut time.Time // used by the dispatcher only
}

type entryKey struct {
	buddy identity.PublicKey
	day   uint32
}

// entry is what we last did with one (buddy, day) record.
type entry struct {
	kdir    [32]byte  // the key it was published under
	fp      string    // fingerprint of the last locator put successfully; "" if none
	at      time.Time // when that put was made
	seq     uint64    // the highest seq used for this key
	fails   int       // consecutive failures
	failFP  string    // the locator that last failed
	retryAt time.Time
}

// NewPublisher starts a publisher with no buddies; add them with SetPair.
func NewPublisher(o PublisherOptions) (*Publisher, error) {
	if o.Store == nil {
		return nil, errors.New("rendezvous: PublisherOptions.Store is required")
	}
	if o.Self == nil {
		if o.Node == nil {
			return nil, errors.New("rendezvous: PublisherOptions needs Self or Node")
		}
		n := o.Node
		o.Self = func() peer.AddrInfo { return peer.AddrInfo{ID: n.ID(), Addrs: n.Addrs()} }
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&o.TTL, DefaultTTL)
	def(&o.Refresh, DefaultRefresh)
	def(&o.Prepublish, DefaultPrepublish)
	def(&o.PutInterval, DefaultPutInterval)
	def(&o.PutTimeout, DefaultPutTimeout)
	def(&o.Retry, DefaultRetry)
	def(&o.MaxRetry, DefaultMaxRetry)
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultConcurrency
	}
	switch {
	case o.TTL < time.Second || o.TTL > MaxTTL:
		return nil, fmt.Errorf("rendezvous: TTL %v out of range (1s–%v)", o.TTL, MaxTTL)
	case o.Refresh < 0 || o.Refresh >= o.TTL:
		return nil, fmt.Errorf("rendezvous: refresh interval %v must be positive and less than the TTL %v", o.Refresh, o.TTL)
	case o.Prepublish < 0 || o.Prepublish >= 24*time.Hour:
		return nil, fmt.Errorf("rendezvous: prepublish window %v out of range", o.Prepublish)
	case o.PutTimeout < 0 || o.Retry < 0 || o.MaxRetry < o.Retry:
		return nil, errors.New("rendezvous: bad put timeout or retry intervals")
	}
	p := &Publisher{
		o:       o,
		clock:   o.Clock,
		done:    make(chan struct{}),
		kick:    make(chan struct{}, 1),
		buddies: map[identity.PublicKey][32]byte{},
		state:   map[entryKey]*entry{},
	}
	if p.clock == nil {
		p.clock = realClock{}
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	if o.Node != nil {
		unsub := o.Node.Subscribe(func(ip.HostChange) { p.Republish() })
		detach, err := o.Node.Attach(p.ctx, p.watchAddrs)
		if err != nil {
			unsub()
			p.cancel()
			return nil, err
		}
		p.unsub = func() { unsub(); detach() }
	}
	p.Republish()
	go p.run()
	return p, nil
}

// watchAddrs republishes whenever a host's addresses change, e.g. when it
// learns its public address or gains a relay reservation. Only the current
// host's addresses are published; events from the others are harmless.
func (p *Publisher) watchAddrs(_ context.Context, h host.Host) (func(), error) {
	sub, err := h.EventBus().Subscribe(new(event.EvtLocalAddressesUpdated))
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range sub.Out() {
			p.Republish()
		}
	}()
	return func() { sub.Close(); <-done }, nil
}

// SetPair publishes for pair.Them under pair.Send from now on. Setting a pair
// again with a new key (after a key rotation) republishes.
func (p *Publisher) SetPair(pair *identity.Pair) {
	p.mu.Lock()
	old, ok := p.buddies[pair.Them]
	p.buddies[pair.Them] = pair.Send
	p.mu.Unlock()
	if !ok || old != pair.Send {
		p.Republish()
	}
}

// RemovePair stops publishing for buddy. Its records stay in the DHT until
// they expire, but no new ones are written, so an ex-buddy stops finding us.
func (p *Publisher) RemovePair(buddy identity.PublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.buddies, buddy)
	for k := range p.state {
		if k.buddy == buddy {
			delete(p.state, k)
		}
	}
}

// Republish asks the publisher to check now whether any record is out of
// date, e.g. because our addresses changed, and to put those that are. It
// doesn't block.
func (p *Publisher) Republish() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Close stops publishing and waits for puts in flight to end.
func (p *Publisher) Close() error {
	p.once.Do(func() {
		if p.unsub != nil {
			p.unsub()
		}
		p.cancel()
		<-p.done
	})
	return nil
}

func (p *Publisher) run() {
	defer close(p.done)
	for {
		select {
		case <-p.kick:
		default:
		}
		wake := p.round()
		if p.ctx.Err() != nil {
			return
		}
		t := p.clock.NewTimer(max(wake.Sub(p.clock.Now()), 0))
		select {
		case <-t.C():
		case <-p.kick:
			t.Stop()
		case <-p.ctx.Done():
			t.Stop()
			return
		}
	}
}

// job is one record to put.
type job struct {
	key  entryKey
	kdir [32]byte
}

// round puts every record that is due and returns when the next one will be.
func (p *Publisher) round() time.Time {
	now := p.clock.Now()
	self := p.o.Self()
	addrs := selectAddrs(self)
	fp := fingerprint(self.ID, addrs)
	days := p.publishDays(now)

	p.mu.Lock()
	today := frame.Day(now)
	for k := range p.state {
		if k.day < today {
			delete(p.state, k)
		}
	}
	var jobs []job
	if self.ID != "" {
		for buddy, kdir := range p.buddies {
			for _, day := range days {
				k := entryKey{buddy, day}
				e := p.state[k]
				if e != nil && e.kdir != kdir {
					e = nil // the pair was re-keyed
					delete(p.state, k)
				}
				if p.due(e, fp, now, day) {
					jobs = append(jobs, job{k, kdir})
				}
			}
		}
	}
	p.mu.Unlock()
	// A stable order keeps runs reproducible; it says nothing to the DHT.
	slices.SortFunc(jobs, func(a, b job) int {
		if c := bytes.Compare(a.key.buddy[:], b.key.buddy[:]); c != 0 {
			return c
		}
		return int(a.key.day) - int(b.key.day)
	})

	sem := make(chan struct{}, p.o.Concurrency)
	var wg sync.WaitGroup
	for _, j := range jobs {
		if p.waitTurn() != nil {
			break
		}
		// If we moved (a rotation mid-round), stop putting the old locator;
		// the next round puts the new one.
		if s := p.o.Self(); fingerprint(s.ID, selectAddrs(s)) != fp {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-p.ctx.Done():
		}
		if p.ctx.Err() != nil {
			break
		}
		wg.Go(func() {
			defer func() { <-sem }()
			p.publish(j, self.ID, addrs, fp)
		})
	}
	wg.Wait()
	return p.nextWake(fp, self.ID != "")
}

// publishDays are the days a publisher keeps records for at now.
func (p *Publisher) publishDays(now time.Time) []uint32 {
	today := frame.Day(now)
	if dayStart(today+1).Sub(now) <= p.o.Prepublish {
		return []uint32{today, today + 1}
	}
	return []uint32{today}
}

// due says whether the record e describes needs a put now. Called with mu.
func (p *Publisher) due(e *entry, fp string, now time.Time, day uint32) bool {
	switch {
	case e == nil:
		return true
	case e.fails > 0:
		return fp != e.failFP || !now.Before(e.retryAt)
	case fp != e.fp:
		return true
	}
	next, ok := p.refreshAt(e, day)
	return ok && !now.Before(next)
}

// refreshAt is when a successfully published record is put again. In the
// last Prepublish of its day it isn't (tomorrow's record has taken over).
func (p *Publisher) refreshAt(e *entry, day uint32) (time.Time, bool) {
	next := e.at.Add(p.o.Refresh)
	return next, next.Before(dayStart(day + 1).Add(-p.o.Prepublish))
}

// nextWake is the earliest time something will be due: a refresh, a retry,
// the start of the prepublish window or midnight. It is at least a second
// away, so nothing can spin.
func (p *Publisher) nextWake(fp string, haveSelf bool) time.Time {
	now := p.clock.Now()
	today := frame.Day(now)
	wake := now.Add(p.o.Refresh)
	if pre := dayStart(today + 1).Add(-p.o.Prepublish); now.Before(pre) {
		wake = minTime(wake, pre)
	} else {
		wake = minTime(wake, dayStart(today+1))
	}
	if !haveSelf {
		return maxTime(minTime(wake, now.Add(p.o.Retry)), now.Add(time.Second))
	}
	p.mu.Lock()
	for _, day := range p.publishDays(now) {
		for buddy := range p.buddies {
			e := p.state[entryKey{buddy, day}]
			switch {
			case e == nil || p.due(e, fp, now, day):
				wake = now // e.g. added while we were putting
			case e.fails > 0:
				wake = minTime(wake, e.retryAt)
			default:
				if t, ok := p.refreshAt(e, day); ok {
					wake = minTime(wake, t)
				}
			}
		}
	}
	p.mu.Unlock()
	return maxTime(wake, now.Add(time.Second))
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// waitTurn spaces put starts PutInterval apart.
func (p *Publisher) waitTurn() error {
	if p.o.PutInterval <= 0 {
		return p.ctx.Err()
	}
	now := p.clock.Now()
	start := p.nextPut
	if start.Before(now) {
		start = now
	}
	p.nextPut = start.Add(p.o.PutInterval)
	if d := start.Sub(now); d > 0 {
		t := p.clock.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C():
		case <-p.ctx.Done():
		}
	}
	return p.ctx.Err()
}

// publish seals and puts one record and records the outcome.
func (p *Publisher) publish(j job, id peer.ID, addrs []ma.Multiaddr, fp string) {
	now := p.clock.Now()
	k := Derive(j.kdir, j.key.day)

	seq := uint64(max(now.UnixMilli(), 0))
	p.mu.Lock()
	if e := p.state[j.key]; e != nil && e.kdir == j.kdir && seq <= e.seq {
		seq = e.seq + 1
	}
	p.mu.Unlock()

	loc := Locator{ID: id, Addrs: addrs, IssuedAt: now, ExpiresAt: now.Add(p.o.TTL)}
	payload, err := SealPayload(k, seq, loc, p.o.Rand)
	if err == nil {
		ctx, cancel := context.WithTimeout(p.ctx, p.o.PutTimeout)
		_, err = p.o.Store.PutRendezvous(ctx, k.Priv, seq, payload)
		cancel()
	}

	p.mu.Lock()
	if _, ok := p.buddies[j.key.buddy]; ok && p.buddies[j.key.buddy] == j.kdir {
		e := p.state[j.key]
		if e == nil || e.kdir != j.kdir {
			e = &entry{kdir: j.kdir}
			p.state[j.key] = e
		}
		e.seq = max(e.seq, seq)
		if err == nil {
			e.fp, e.at, e.fails, e.failFP = fp, now, 0, ""
		} else {
			e.fails++
			e.failFP = fp
			backoff := p.o.Retry
			for i := 1; i < e.fails && backoff < p.o.MaxRetry; i++ {
				backoff *= 2
			}
			e.retryAt = now.Add(min(backoff, p.o.MaxRetry))
		}
	}
	p.mu.Unlock()

	if p.o.OnPublish != nil {
		p.o.OnPublish(PublishEvent{Buddy: j.key.buddy, Day: j.key.day, Key: k.Key, Seq: seq, ID: id, Err: err})
	}
}

// selectAddrs is what we publish of self's addresses: without a trailing
// /p2p/<self>, at most MaxAddrLen bytes each, deduplicated, relay circuits
// first, then public, private and loopback ones, and as many as fit in
// MaxAddrs and MaxLocator.
func selectAddrs(self peer.AddrInfo) []ma.Multiaddr {
	type ranked struct {
		a    ma.Multiaddr
		rank int
	}
	var rs []ranked
	seen := map[string]bool{}
	for _, a := range self.Addrs {
		if rest, last := ma.SplitLast(a); last != nil && last.Protocol().Code == ma.P_P2P && last.Value() == self.ID.String() {
			a = rest
		}
		b := a.Bytes()
		if len(b) == 0 || len(b) > MaxAddrLen || seen[string(b)] {
			continue
		}
		seen[string(b)] = true
		rank := 3
		switch {
		case isCircuit(a):
			rank = 0
		case manet.IsPublicAddr(a):
			rank = 1
		case manet.IsPrivateAddr(a) && !manet.IsIPLoopback(a):
			rank = 2
		}
		rs = append(rs, ranked{a, rank})
	}
	slices.SortStableFunc(rs, func(x, y ranked) int { return x.rank - y.rank })
	var out []ma.Multiaddr
	for _, r := range rs[:min(len(rs), MaxAddrs)] {
		out = append(out, r.a)
	}
	// Drop the lowest-ranked addresses until the locator fits.
	for len(out) > 0 {
		if _, err := marshalLocator(Locator{ID: self.ID, Addrs: out, IssuedAt: frame.Epoch, ExpiresAt: frame.Epoch.Add(MaxTTL)}); err == nil || self.ID == "" {
			break
		}
		out = out[:len(out)-1]
	}
	return out
}

func isCircuit(a ma.Multiaddr) bool {
	_, err := a.ValueForProtocol(ma.P_CIRCUIT)
	return err == nil
}

// fingerprint identifies a locator's content apart from its times.
func fingerprint(id peer.ID, addrs []ma.Multiaddr) string {
	var b []byte
	b = append(b, byte(len(id)))
	b = append(b, id...)
	for _, a := range addrs {
		ab := a.Bytes()
		b = append(b, byte(len(ab)))
		b = append(b, ab...)
	}
	return string(b)
}
