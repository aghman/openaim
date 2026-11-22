// Package router decides where frames go and which conversation incoming
// frames belong to (design §7): the conversation-tag keyring, buddies' IP
// reachability (ReachTable), and the Router, which sends the sealed outbox
// over IP, retries until acked and sends ACKs (send policy v0).
package router

import (
	"sync"
	"time"

	"github.com/aghman/openaim/internal/frame"
)

// Keyring maps incoming conversation tags to conversations (design §8.1).
// For every conversation it holds the tags of each day that a frame passing
// the acceptance window could carry: Day(now − MaxAge) through
// Day(now + MaxFuture). It rebuilds itself when the UTC day changes.
//
// It implements frame.Keyring and is safe for concurrent use.
type Keyring struct {
	// Now defaults to time.Now.
	Now func() time.Time

	mu    sync.RWMutex
	convs map[any]frame.ConvKey // conversation ID → inbound key
	tags  map[frame.ConvTag][]frame.Conv
	from  uint32 // first day in the current window
	to    uint32 // last day in the current window
	built bool
}

var _ frame.Keyring = (*Keyring)(nil)

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{convs: map[any]frame.ConvKey{}, tags: map[frame.ConvTag][]frame.Conv{}}
}

func (k *Keyring) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

// Window returns the first and last day whose tags are accepted at t.
func Window(t time.Time) (from, to uint32) {
	return frame.Day(t.Add(-frame.MaxAge)), frame.Day(t.Add(frame.MaxFuture))
}

// Set adds or replaces the inbound key for conversation id (a buddy's K_dir
// toward us, or a room epoch key). id must be comparable.
func (k *Keyring) Set(id any, key frame.ConvKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ensureWindowLocked()
	if _, ok := k.convs[id]; ok {
		k.removeTagsLocked(id)
	}
	k.convs[id] = key
	for d := k.from; d <= k.to; d++ {
		t := key.Tag(d)
		k.tags[t] = append(k.tags[t], frame.Conv{Key: key, ID: id})
	}
}

// Remove forgets conversation id (a removed or blocked buddy).
func (k *Keyring) Remove(id any) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.convs[id]; ok {
		k.removeTagsLocked(id)
		delete(k.convs, id)
	}
}

// Len is the number of conversations.
func (k *Keyring) Len() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.convs)
}

// Lookup returns the conversations that use tag in the current window.
func (k *Keyring) Lookup(tag frame.ConvTag) []frame.Conv {
	from, to := Window(k.now())
	k.mu.RLock()
	if k.built && from == k.from && to == k.to {
		c := k.tags[tag]
		k.mu.RUnlock()
		return c
	}
	k.mu.RUnlock()

	k.mu.Lock()
	defer k.mu.Unlock()
	k.ensureWindowLocked()
	return k.tags[tag]
}

// ensureWindowLocked rebuilds the tag table if the window has moved. Only
// the days entering the window are computed; days leaving it are dropped.
func (k *Keyring) ensureWindowLocked() {
	from, to := Window(k.now())
	if k.built && from == k.from && to == k.to {
		return
	}
	if !k.built || from > k.to || to < k.from {
		k.tags = map[frame.ConvTag][]frame.Conv{}
		k.from, k.to, k.built = from, to, true
		for id, key := range k.convs {
			for d := from; d <= to; d++ {
				t := key.Tag(d)
				k.tags[t] = append(k.tags[t], frame.Conv{Key: key, ID: id})
			}
		}
		return
	}
	for id, key := range k.convs {
		for d := k.from; d < from; d++ { // days leaving
			k.dropLocked(key.Tag(d), id)
		}
		for d := k.to + 1; d <= to; d++ { // days entering
			t := key.Tag(d)
			k.tags[t] = append(k.tags[t], frame.Conv{Key: key, ID: id})
		}
	}
	k.from, k.to = from, to
}

func (k *Keyring) removeTagsLocked(id any) {
	key := k.convs[id]
	for d := k.from; d <= k.to; d++ {
		k.dropLocked(key.Tag(d), id)
	}
}

// dropLocked removes id's entry under tag. It builds a new slice so that
// slices already returned by Lookup are never modified.
func (k *Keyring) dropLocked(tag frame.ConvTag, id any) {
	old := k.tags[tag]
	var kept []frame.Conv
	for _, c := range old {
		if c.ID != id {
			kept = append(kept, c)
		}
	}
	if len(kept) == 0 {
		delete(k.tags, tag)
	} else {
		k.tags[tag] = kept
	}
}
