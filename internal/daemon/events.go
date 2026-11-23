package daemon

import (
	"errors"
	"sync"
	"time"

	"github.com/aghman/openaim/internal/store"
)

// EventKind says what changed.
type EventKind int

const (
	EventBuddyAdded EventKind = iota + 1
	EventBuddyChanged
	EventBuddyRemoved // Buddy is the buddy as it was
	EventMessageQueued
	EventMessageReceived
	EventPresenceChanged // ours
	// EventBuddyHandleWarning: a re-check found the buddy's handle moved to
	// another key or no longer verifying. Buddy and HandleCheck are set.
	EventBuddyHandleWarning
	// EventBuddyRequest: a buddy request arrived (new or merged into an
	// earlier one). Buddy and Details are set; Details.Request has it.
	EventBuddyRequest
)

// Event is one change inside the daemon. Exactly one of Buddy, Message and
// Presence is set, according to Kind. Buddy events also carry the buddy's
// handle check state in HandleCheck, when it has one.
type Event struct {
	Seq      uint64 // 1, 2, … within a daemon run
	Time     time.Time
	Kind     EventKind
	Buddy    *store.Buddy
	Message  *Message
	Presence *Presence

	HandleCheck *store.HandleCheck
	// Details is set on buddy events when known.
	Details *BuddyDetails
}

// Subscription errors, reported by Subscription.Err once C is closed.
var (
	// ErrLagged means the subscriber didn't keep up and was cut off. It
	// should resubscribe and reload state.
	ErrLagged = errors.New("daemon: event subscriber fell behind")
	// ErrClosed means the daemon is shutting down.
	ErrClosed = errors.New("daemon: shutting down")
)

// subscriberBuffer is how many events a subscriber may fall behind by before
// it is cut off. Publishing never blocks on a slow client.
const subscriberBuffer = 256

// bus fans events out to subscribers.
type bus struct {
	mu     sync.Mutex
	seq    uint64
	subs   map[*Subscription]struct{}
	closed bool
	now    func() time.Time
}

func newBus(now func() time.Time) *bus {
	return &bus{subs: map[*Subscription]struct{}{}, now: now}
}

// Subscription receives events published after it was made.
type Subscription struct {
	// C delivers events in order. It is closed when the subscription ends;
	// Err then says why.
	C <-chan Event
	// Seq is the sequence number of the last event published before the
	// subscription started: the first event on C has Seq+1.
	Seq uint64

	c   chan Event
	b   *bus
	err error // guarded by b.mu
}

func (b *bus) subscribe() *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := make(chan Event, subscriberBuffer)
	s := &Subscription{C: c, c: c, b: b, Seq: b.seq}
	if b.closed {
		s.err = ErrClosed
		close(c)
		return s
	}
	b.subs[s] = struct{}{}
	return s
}

func (b *bus) publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.seq++
	e.Seq, e.Time = b.seq, b.now()
	for s := range b.subs {
		select {
		case s.c <- e:
		default:
			b.endLocked(s, ErrLagged)
		}
	}
}

func (b *bus) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for s := range b.subs {
		b.endLocked(s, ErrClosed)
	}
}

func (b *bus) endLocked(s *Subscription, err error) {
	if _, ok := b.subs[s]; !ok {
		return
	}
	delete(b.subs, s)
	s.err = err
	close(s.c)
}

// Close ends the subscription. It is safe to call more than once.
func (s *Subscription) Close() {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	s.b.endLocked(s, nil)
}

// Err says why C was closed: ErrLagged, ErrClosed, or nil after Close.
func (s *Subscription) Err() error {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	return s.err
}
