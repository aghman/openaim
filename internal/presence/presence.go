// Package presence is the presence state machine (design §6.1, §11.1): our
// own online/away/idle state and what we tell buddies about it, and what each
// accepted buddy has told us about theirs.
//
// The package is transport-agnostic. The daemon feeds it:
//
//   - the accepted buddy set (SetBuddies, AddBuddy, RemoveBuddy). Nothing is
//     ever sent to, or accepted from, anyone outside it (design §5.4);
//   - session Up/Down events for each buddy's libp2p peers (SessionUp,
//     SessionDown), once the daemon has attributed a peer to a buddy;
//   - authenticated PRESENCE and AWAY_MSG bodies (Received,
//     ReceivedAwayMsg), only after AEAD verification (design §7.1);
//   - our own state, away message and the user's last activity (Set,
//     SetState, SetAwayMessage, Activity).
//
// It answers with PRESENCE bodies through a Sender (door open on session Up,
// own changes, jittered heartbeats, OFFLINE on SignOff) and with Events: buddy
// transitions (the UI plays door open/close sounds from these), requests to
// fetch an away message, and automatic changes to our own state.
//
// Relay resets do not flap: a session Down starts a grace period (default 3
// minutes, longer than a relay reset), and the buddy only goes OFFLINE if no
// session or PRESENCE comes back within it. A buddy that stops sending
// heartbeats for 2.5 heartbeat intervals goes OFFLINE too. See
// docs/presence.md.
package presence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Defaults. The heartbeat interval plus jitter must stay well under the
// /openaim/msg/1 session idle timeout (ip.DefaultSessionIdleTimeout, 10
// minutes) so a live session is never closed for lack of traffic.
const (
	DefaultHeartbeatInterval = 4 * time.Minute
	DefaultHeartbeatJitter   = 30 * time.Second
	// DefaultBuddyTimeout is 2.5 × DefaultHeartbeatInterval: two heartbeats
	// may be lost before a buddy is shown OFFLINE.
	DefaultBuddyTimeout = DefaultHeartbeatInterval * 5 / 2
	// DefaultGrace is the "door close" grace period after a session goes
	// down. It exceeds go-libp2p's 2-minute relay reset (design §6.1).
	DefaultGrace       = 3 * time.Minute
	DefaultIdleAfter   = 10 * time.Minute
	DefaultRetryDelay  = 20 * time.Second
	DefaultFetchRetry  = 2 * time.Minute
	DefaultSendTimeout = 30 * time.Second
	DefaultSendWorkers = 4
	DefaultEventBuffer = 256

	// maxAwayCache is how many away messages are kept per buddy, by rev.
	maxAwayCache = 4
)

// Errors.
var (
	// ErrNotAccepted means the buddy is not in the accepted set.
	ErrNotAccepted = errors.New("presence: not an accepted buddy")
	// ErrStale means a PRESENCE body is older than one already applied.
	ErrStale = errors.New("presence: stale presence")
	// ErrClosed means the Tracker has been closed.
	ErrClosed = errors.New("presence: closed")
	// ErrInvalid wraps invalid arguments.
	ErrInvalid = errors.New("presence: invalid")
)

// State is an availability. The values match pb.PresenceState.
type State uint8

const (
	Online State = iota + 1
	Away
	Offline
)

func (s State) String() string {
	switch s {
	case Online:
		return "online"
	case Away:
		return "away"
	case Offline:
		return "offline"
	}
	return fmt.Sprintf("state(%d)", uint8(s))
}

// Proto is s as a wire enum.
func (s State) Proto() pb.PresenceState { return pb.PresenceState(s) }

func (s State) valid() bool { return s >= Online && s <= Offline }

// Reason says why a transition happened.
type Reason string

const (
	// Buddy transitions.
	ReasonPresence  Reason = "presence"          // an authenticated PRESENCE body
	ReasonSignedOff Reason = "signed-off"        // PRESENCE with state OFFLINE
	ReasonDoorClose Reason = "door-close"        // no session or PRESENCE within the grace period
	ReasonTimeout   Reason = "heartbeat-timeout" // no PRESENCE for BuddyTimeout
	ReasonRemoved   Reason = "removed"           // removed from the accepted set

	// Own changes.
	ReasonUser     Reason = "user"      // Set, SetState, SetAwayMessage, SetMeshNode
	ReasonIdle     Reason = "idle"      // no activity for IdleAfter
	ReasonActive   Reason = "active"    // activity after idle or auto-away
	ReasonAutoAway Reason = "auto-away" // no activity for AutoAwayAfter
)

// Stamp orders PRESENCE bodies from one buddy: the inner payload's timestamp
// and seq (spec/wire.md §6). Later timestamps win; seq breaks ties.
type Stamp struct {
	Time uint32 // seconds since frame.Epoch
	Seq  uint64
}

// StampOf is the stamp of an inner payload.
func StampOf(in frame.Inner) Stamp { return Stamp{Time: in.Time, Seq: in.Seq} }

func (s Stamp) after(o Stamp) bool {
	if s.Time != o.Time {
		return s.Time > o.Time
	}
	return s.Seq > o.Seq
}

// Recipient is an accepted buddy a PRESENCE may be sent to. Only the Tracker
// makes them, after checking the accepted set, so a Sender cannot be handed a
// stranger.
type Recipient struct{ key identity.PublicKey }

// Key is the buddy's identity key.
func (r Recipient) Key() identity.PublicKey { return r.key }

// Sender sends a PRESENCE body to one accepted buddy over IP. The daemon
// implements it: seal the body (content type PRESENCE, no ack requested) for
// to.Key() and send it on the buddy's session. It is called from a small,
// fixed pool of goroutines, never with the Tracker's lock held, and at most
// once at a time per buddy. ctx is cancelled after Config.SendTimeout or on
// Close.
type Sender interface {
	SendPresence(ctx context.Context, to Recipient, p *pb.Presence) error
}

// SenderFunc adapts a function to Sender.
type SenderFunc func(ctx context.Context, to Recipient, p *pb.Presence) error

// SendPresence calls f.
func (f SenderFunc) SendPresence(ctx context.Context, to Recipient, p *pb.Presence) error {
	return f(ctx, to, p)
}

// Config configures a Tracker. Zero durations mean the defaults.
type Config struct {
	Sender Sender // required
	Clock  Clock  // nil means the real clock
	// Rand returns a number in [0, 1) for heartbeat jitter; nil means
	// math/rand/v2. Called with the Tracker's lock held.
	Rand func() float64
	Log  *slog.Logger // nil discards

	// HeartbeatInterval ± HeartbeatJitter is the gap between PRESENCE
	// heartbeats to each buddy with a session up. Jitter must be less than
	// half the interval.
	HeartbeatInterval time.Duration
	HeartbeatJitter   time.Duration
	// BuddyTimeout shows a buddy OFFLINE after this long without a PRESENCE.
	// It must exceed HeartbeatInterval + HeartbeatJitter.
	BuddyTimeout time.Duration
	// Grace is the "door close" grace period after a buddy's last session
	// goes down.
	Grace time.Duration
	// IdleAfter marks us idle after this long without activity; negative
	// disables idle detection. Idle detection starts with the first
	// Activity report (or LastActivity).
	IdleAfter time.Duration
	// AutoAwayAfter switches us from Online to Away after this long without
	// activity, and back on activity. Zero or negative disables it (the
	// default).
	AutoAwayAfter time.Duration
	// RetryDelay is when a failed send is retried (as an early heartbeat).
	RetryDelay time.Duration
	// FetchRetry is how soon a FetchAway signal for the same rev is repeated
	// if the away message still hasn't arrived.
	FetchRetry  time.Duration
	SendTimeout time.Duration
	SendWorkers int
	EventBuffer int // capacity of Events(); events are dropped (and counted) when full

	// Initial own state: State (zero means Online), away message, mesh node
	// and last activity (zero: none reported yet).
	State        State
	AwayText     string
	MeshNode     uint32
	LastActivity time.Time
}

func (c Config) withDefaults() (Config, error) {
	if c.Sender == nil {
		return c, fmt.Errorf("%w: no Sender", ErrInvalid)
	}
	if c.Clock == nil {
		c.Clock = realClock{}
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&c.HeartbeatInterval, DefaultHeartbeatInterval)
	def(&c.HeartbeatJitter, DefaultHeartbeatJitter)
	def(&c.BuddyTimeout, c.HeartbeatInterval*5/2)
	def(&c.Grace, DefaultGrace)
	def(&c.IdleAfter, DefaultIdleAfter)
	def(&c.RetryDelay, DefaultRetryDelay)
	def(&c.FetchRetry, DefaultFetchRetry)
	def(&c.SendTimeout, DefaultSendTimeout)
	if c.SendWorkers <= 0 {
		c.SendWorkers = DefaultSendWorkers
	}
	if c.EventBuffer <= 0 {
		c.EventBuffer = DefaultEventBuffer
	}
	if c.State == 0 {
		c.State = Online
	}
	switch {
	case c.HeartbeatInterval < 0 || c.HeartbeatJitter < 0 || c.BuddyTimeout < 0 || c.Grace < 0 ||
		c.RetryDelay < 0 || c.FetchRetry < 0 || c.SendTimeout < 0:
		return c, fmt.Errorf("%w: negative duration", ErrInvalid)
	case 2*c.HeartbeatJitter >= c.HeartbeatInterval:
		return c, fmt.Errorf("%w: heartbeat jitter %v is not under half the interval %v", ErrInvalid, c.HeartbeatJitter, c.HeartbeatInterval)
	case c.BuddyTimeout <= c.HeartbeatInterval+c.HeartbeatJitter:
		return c, fmt.Errorf("%w: buddy timeout %v does not exceed the longest heartbeat gap", ErrInvalid, c.BuddyTimeout)
	case !c.State.valid():
		return c, fmt.Errorf("%w: state %v", ErrInvalid, c.State)
	}
	if err := checkAway(c.AwayText); err != nil {
		return c, err
	}
	return c, nil
}

// Own is our presence.
type Own struct {
	State    State
	AwayText string
	AwayRev  uint32 // 0 when there is no away message
	Idle     bool
	// IdleSince is the last activity, when Idle.
	IdleSince time.Time
	// AutoAway is true when State is Away because of AutoAwayAfter.
	AutoAway bool
	MeshNode uint32
}

// OwnChange reports a change to our own presence. The daemon persists To
// and shows it; changes it made itself (Reason "user") are reported too.
type OwnChange struct {
	From, To Own
	At       time.Time
	Reason   Reason
}

// Transition reports a change in what we show for a buddy: State, idleness,
// away rev or mesh node. From == To when only idleness, the away rev or the
// mesh node changed.
type Transition struct {
	Buddy       identity.PublicKey
	From, To    State
	IdleMinutes uint32    // as last reported; 0 = not idle
	IdleSince   time.Time // zero when not idle
	AwayRev     uint32
	MeshNode    uint32 // reachability hint (design §7.1); 0 = none
	At          time.Time
	Reason      Reason
}

// DoorOpen reports whether the buddy just came online.
func (t Transition) DoorOpen() bool { return t.From == Offline && t.To != Offline }

// DoorClose reports whether the buddy just went offline.
func (t Transition) DoorClose() bool { return t.From != Offline && t.To == Offline }

// FetchAway asks the daemon to fetch a buddy's away message: send it
// ProfileReq{away_msg: true} and hand the AWAY_MSG reply to ReceivedAwayMsg.
type FetchAway struct {
	Buddy identity.PublicKey
	Rev   uint32
	At    time.Time
}

// AwayMessage reports that a buddy's current away message arrived.
type AwayMessage struct {
	Buddy identity.PublicKey
	Text  string
	Rev   uint32
}

// Event is one of a buddy transition, a fetch request, an away message or
// an own change; exactly one field is set.
type Event struct {
	Transition  *Transition
	FetchAway   *FetchAway
	AwayMessage *AwayMessage
	Own         *OwnChange
}

// BuddyStatus is a snapshot of one buddy.
type BuddyStatus struct {
	Buddy       identity.PublicKey
	State       State
	Since       time.Time // when State last changed (zero: never seen)
	IdleMinutes uint32
	IdleSince   time.Time
	AwayRev     uint32
	// AwayText is the cached away message for AwayRev, if AwayKnown.
	AwayText  string
	AwayKnown bool
	MeshNode  uint32
	LastHeard time.Time // last applied PRESENCE
	Connected bool      // at least one session is up
	InGrace   bool      // sessions down, door-close grace running
}

// Stats are counters since New.
type Stats struct {
	Sent, SendFailures     uint64
	Received, Stale        uint64
	NotAccepted            uint64 // inputs for buddies outside the accepted set
	EventsDropped          uint64
	Heartbeats, Broadcasts uint64
}
