// Package daemon is the core of openaimd (design §3): it owns a data
// directory, unlocks the identity, and keeps buddies, conversations and
// presence. Frontends reach it through the local gRPC API (internal/api);
// this package knows nothing about gRPC.
//
// At this stage there are no transports: sent messages are sealed and queued
// in the store, and inbound frames enter through HandleFrame, which the
// transports will call.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/handle"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/router"
	"github.com/aghman/openaim/internal/store"
)

// Config says how to open a node.
type Config struct {
	DataDir    string
	Passphrase []byte // unlocks the keystore
	// KeystoreParams are the Argon2id costs for files the daemon writes
	// (backups); zero means keystore.DefaultParams.
	KeystoreParams keystore.Params
	Logger         *slog.Logger // nil discards
	// Now is the node's clock, used for timestamps and the handle re-check
	// schedule; nil means time.Now.
	Now func() time.Time

	// HandleRegistry is the default registry domain: handles one label
	// under it show as just that label (spec/handle.md §8). "" shortens
	// nothing.
	HandleRegistry string
	// DoHResolvers are the DNS-over-HTTPS resolvers for handle lookups (at
	// least two https URLs); nil means handle.DefaultResolvers.
	DoHResolvers []string
	// HandleVerifier, if set, is used instead of one built from
	// DoHResolvers. Tests point it at local servers.
	HandleVerifier *handle.Verifier
	// HandleCheckConcurrency bounds simultaneous handle re-checks; zero
	// means DefaultHandleCheckConcurrency.
	HandleCheckConcurrency int
	// DisableHandleLoop turns off the background re-check loop, for
	// callers (tests) that call RecheckDueHandles themselves.
	DisableHandleLoop bool
}

// Node is a running daemon's state. Its methods are safe for concurrent use.
type Node struct {
	cfg     Config
	paths   Paths
	log     *slog.Logger
	now     func() time.Time
	lock    *Lock
	store   *store.Store
	id      *identity.Identity
	started time.Time
	events  *bus
	keyring *router.Keyring
	recv    *frame.Receiver

	mu       sync.Mutex // guards pairs and presence
	pairs    map[identity.PublicKey]*identity.Pair
	presence Presence

	// writeMu serializes read-modify-write operations on the store and
	// their events, so events go out in the order the changes were made.
	writeMu sync.Mutex

	// Handles (handles.go).
	verifier   *handle.Verifier
	registry   string
	checkSlots int
	sweepMu    sync.Mutex    // one re-check sweep at a time
	wake       chan struct{} // nudges the re-check loop
	stopLoop   context.CancelFunc
	loopDone   chan struct{}
}

// Open takes the data directory's lock, opens the database and unlocks the
// identity. It fails with ErrLocked if another daemon has the directory,
// ErrNotInitialized if there is no identity yet, ErrIdentityMismatch if the
// keystore and the database disagree, and keystore.ErrWrongPassphrase for a
// wrong passphrase.
func Open(ctx context.Context, cfg Config) (_ *Node, err error) {
	p := PathsFor(cfg.DataDir)
	if err := prepareDir(p.Dir); err != nil {
		return nil, err
	}
	n := &Node{cfg: cfg, paths: p, log: cfg.Logger, now: cfg.Now, pairs: map[identity.PublicKey]*identity.Pair{}}
	if n.log == nil {
		n.log = slog.New(slog.DiscardHandler)
	}
	if n.now == nil {
		n.now = time.Now
	}
	if err := n.setupHandles(cfg); err != nil {
		return nil, err
	}
	if n.lock, err = AcquireLock(p.Lock); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			n.Close()
		}
	}()
	if n.store, err = store.Open(ctx, p.DB); err != nil {
		return nil, err
	}
	ks := &keystore.FileKeystore{Path: p.Keystore, Passphrase: cfg.Passphrase}
	seed, err := ks.Load()
	if errors.Is(err, keystore.ErrNoKey) {
		return nil, ErrNotInitialized
	} else if err != nil {
		return nil, err
	}
	if n.id, err = identity.FromSeed(seed); err != nil {
		return nil, err
	}
	pub := n.id.Public()
	switch have, err := n.store.Meta(ctx, metaIdentity); {
	case errors.Is(err, store.ErrNotFound):
		// Init was interrupted after saving the keystore (see Init).
		n.log.Warn("database had no identity; adopting the keystore's", "key_id", pub.KeyID())
		if err := n.store.SetMeta(ctx, metaIdentity, pub[:]); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	case string(have) != string(pub[:]):
		return nil, ErrIdentityMismatch
	}

	n.started = n.now()
	n.events = newBus(n.now)
	n.keyring = router.NewKeyring()
	n.keyring.Now = n.now
	dedup := n.store.Dedup()
	dedup.OnError = func(err error) { n.log.Error("dedup store failed; dropping fragment", "err", err) }
	n.recv = &frame.Receiver{Keys: n.keyring, Dedup: dedup, Now: n.now}
	if err := n.loadPresence(ctx); err != nil {
		return nil, err
	}
	buddies, err := n.store.Buddies(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range buddies {
		if err := n.trackBuddy(b); err != nil {
			n.log.Warn("skipping buddy with unusable key", "buddy", b.Key.KeyID(), "err", err)
		}
	}
	n.log.Info("identity unlocked", "key_id", pub.KeyID(), "buddies", len(buddies), "data_dir", p.Dir)
	if !cfg.DisableHandleLoop {
		n.startHandleLoop()
	}
	return n, nil
}

// Close stops handle re-checks, ends event subscriptions, closes the
// database and releases the data directory.
func (n *Node) Close() error {
	n.stopHandleLoop()
	if n.events != nil {
		n.events.close()
	}
	var err error
	if n.store != nil {
		err = n.store.Close()
	}
	if lerr := n.lock.Release(); err == nil {
		err = lerr
	}
	return err
}

// Paths are the node's data directory files.
func (n *Node) Paths() Paths { return n.paths }

// Identity is our public identity key.
func (n *Node) Identity() identity.PublicKey { return n.id.Public() }

// Started is when the node was opened.
func (n *Node) Started() time.Time { return n.started }

// Now is the node's clock.
func (n *Node) Now() time.Time { return n.now() }

// Subscribe starts receiving events. Close the subscription when done.
func (n *Node) Subscribe() *Subscription { return n.events.subscribe() }

// pair returns (and caches) the pairwise keys with a buddy.
func (n *Node) pair(k identity.PublicKey) (*identity.Pair, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if p, ok := n.pairs[k]; ok {
		return p, nil
	}
	p, err := n.id.Pair(k)
	if err != nil {
		return nil, err
	}
	n.pairs[k] = p
	return p, nil
}

// trackBuddy puts a buddy's inbound key in the keyring, so its frames are
// recognized. Blocked buddies are left out: their frames are dropped as
// unknown.
func (n *Node) trackBuddy(b store.Buddy) error {
	if b.State == store.Blocked {
		n.keyring.Remove(b.Key)
		return nil
	}
	p, err := n.pair(b.Key)
	if err != nil {
		return err
	}
	n.keyring.Set(b.Key, frame.NewConvKey(p.Recv))
	return nil
}

func (n *Node) untrackBuddy(k identity.PublicKey) {
	n.keyring.Remove(k)
	n.mu.Lock()
	delete(n.pairs, k)
	n.mu.Unlock()
}

// Status is a snapshot for GetStatus.
type Status struct {
	Identity       identity.PublicKey
	Started        time.Time
	Buddies        map[store.BuddyState]int
	TotalBuddies   int
	QueuedMessages int
	Presence       Presence
}

// Status reports counts and our presence.
func (n *Node) Status(ctx context.Context) (Status, error) {
	s := Status{Identity: n.Identity(), Started: n.started, Buddies: map[store.BuddyState]int{}, Presence: n.Presence()}
	buddies, err := n.store.Buddies(ctx)
	if err != nil {
		return s, err
	}
	for _, b := range buddies {
		s.Buddies[b.State]++
	}
	s.TotalBuddies = len(buddies)
	s.QueuedMessages, err = n.store.CountOutgoing(ctx, store.Queued)
	return s, err
}

// ExportBackup encrypts the identity and buddy list under pass
// (spec/backup.md).
func (n *Node) ExportBackup(ctx context.Context, pass []byte) ([]byte, error) {
	if len(pass) == 0 {
		return nil, fmt.Errorf("%w: empty passphrase", ErrInvalid)
	}
	buddies, err := n.store.Buddies(ctx)
	if err != nil {
		return nil, err
	}
	// TODO(openaim-nxb): generate the recovery key at init (design §5.5) and
	// include it here; until then backups carry none.
	b := &keystore.Backup{Identity: n.id, Buddies: buddies, CreatedAt: n.now()}
	return keystore.EncodeBackup(b, pass, n.backupParams())
}

func (n *Node) backupParams() keystore.Params {
	if n.cfg.KeystoreParams == (keystore.Params{}) {
		return keystore.DefaultParams
	}
	return n.cfg.KeystoreParams
}

// RecoveryPhrase is the identity's 24-word recovery phrase.
func (n *Node) RecoveryPhrase() string { return n.id.Phrase() }

// PresenceState is our availability.
type PresenceState int

const (
	Online PresenceState = iota + 1
	Away
	Offline // signed off
)

// Presence is our state and away message.
type Presence struct {
	State PresenceState `json:"state"`
	Away  string        `json:"away,omitempty"`
	Since time.Time     `json:"since"`
}

const metaPresence = "presence"

func (n *Node) loadPresence(ctx context.Context) error {
	n.presence = Presence{State: Online, Since: n.now()}
	b, err := n.store.Meta(ctx, metaPresence)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	var p Presence
	if err := json.Unmarshal(b, &p); err != nil || p.State < Online || p.State > Offline {
		n.log.Warn("ignoring unreadable saved presence", "err", err)
		return nil
	}
	n.presence = p
	return nil
}

// Presence is our current presence.
func (n *Node) Presence() Presence {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.presence
}

// SetPresence changes our presence and away message and saves them.
//
// TODO(presence): broadcast PRESENCE to buddies once transports exist.
func (n *Node) SetPresence(ctx context.Context, state PresenceState, away string) (Presence, error) {
	if state < Online || state > Offline {
		return Presence{}, fmt.Errorf("%w: presence state %d", ErrInvalid, state)
	}
	if err := checkAwayMessage(away); err != nil {
		return Presence{}, err
	}
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	n.mu.Lock()
	p := n.presence
	if p.State != state {
		p.Since = n.now()
	}
	p.State, p.Away = state, away
	n.presence = p
	n.mu.Unlock()

	b, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	if err := n.store.SetMeta(ctx, metaPresence, b); err != nil {
		return p, err
	}
	n.events.publish(Event{Kind: EventPresenceChanged, Presence: &p})
	return p, nil
}
