package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aghman/openaim/internal/handle"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/store"
)

// Handle errors. The API maps ErrHandleUnverified and ErrNoHandle to
// FAILED_PRECONDITION and ErrHandleUnreachable to UNAVAILABLE.
var (
	// ErrHandleUnverified: the handle answered but doesn't prove a key
	// (no record, bad record, bad signature, ...).
	ErrHandleUnverified = errors.New("daemon: handle does not verify")
	// ErrHandleUnreachable: no trustworthy answer (network, resolver
	// failure or disagreement). Retrying later may work.
	ErrHandleUnreachable = errors.New("daemon: handle lookup failed")
	// ErrNoHandle: the buddy has no handle to check.
	ErrNoHandle = errors.New("daemon: buddy has no handle")
)

// Handle re-check loop settings.
const (
	DefaultHandleCheckConcurrency = 4
	// handleCheckBatch is how many due buddies one sweep takes on.
	handleCheckBatch = 64
	// handleLoopMaxIdle caps how long the loop sleeps, so a clock change
	// (or a test's clock) is noticed eventually.
	handleLoopMaxIdle = time.Hour
	// handleLoopRetry is the pause after a sweep that failed on the store.
	handleLoopRetry = time.Minute
)

// checkResolvers applies spec/handle.md §4.1 to configured resolvers, so a
// bad configuration fails at startup rather than as "unreachable" on every
// check.
func checkResolvers(rs []string) error {
	if len(rs) < 2 {
		return fmt.Errorf("%w: need at least two DoH resolvers, have %d", ErrInvalid, len(rs))
	}
	for i, r := range rs {
		u, err := url.Parse(r)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("%w: DoH resolver %q is not an https URL", ErrInvalid, r)
		}
		if slices.Contains(rs[:i], r) {
			return fmt.Errorf("%w: DoH resolver %q listed twice", ErrInvalid, r)
		}
	}
	return nil
}

// setupHandles prepares the verifier and registry from the config.
func (n *Node) setupHandles(cfg Config) error {
	if cfg.HandleRegistry != "" {
		reg, err := handle.Normalize(cfg.HandleRegistry)
		if err != nil {
			return fmt.Errorf("%w: handle registry: %v", ErrInvalid, err)
		}
		n.registry = reg
	}
	n.verifier = cfg.HandleVerifier
	if n.verifier == nil {
		rs := cfg.DoHResolvers
		if rs == nil {
			rs = handle.DefaultResolvers
		}
		if err := checkResolvers(rs); err != nil {
			return err
		}
		n.verifier = &handle.Verifier{Resolvers: slices.Clone(rs)}
	}
	n.checkSlots = cfg.HandleCheckConcurrency
	if n.checkSlots <= 0 {
		n.checkSlots = DefaultHandleCheckConcurrency
	}
	n.wake = make(chan struct{}, 1)
	return nil
}

// Registry is the configured default registry domain, or "".
func (n *Node) Registry() string { return n.registry }

// ShortHandle is how a handle shows in the buddy list (spec/handle.md §8).
func (n *Node) ShortHandle(h string) string {
	if h == "" {
		return ""
	}
	return handle.Short(h, n.registry)
}

// DisplayName is what to call a buddy in a list: the petname, else the
// short handle, else the key ID.
func (n *Node) DisplayName(b store.Buddy) string {
	switch {
	case b.Petname != "":
		return b.Petname
	case b.Handle != "":
		return n.ShortHandle(b.Handle)
	}
	return b.Key.KeyID()
}

// HandleCheck is a buddy's handle check state, or nil if the buddy has no
// handle or it was never checked.
func (n *Node) HandleCheck(ctx context.Context, b store.Buddy) (*store.HandleCheck, error) {
	if b.Handle == "" {
		return nil, nil
	}
	c, err := n.store.HandleCheck(ctx, b.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// HandleChecks returns every buddy's handle check state, by buddy ID.
func (n *Node) HandleChecks(ctx context.Context) (map[int64]store.HandleCheck, error) {
	return n.store.HandleChecks(ctx)
}

// handleCheckOrNil is HandleCheck for event payloads: failures are logged.
func (n *Node) handleCheckOrNil(ctx context.Context, b store.Buddy) *store.HandleCheck {
	c, err := n.HandleCheck(ctx, b)
	if err != nil {
		n.log.Warn("reading handle check state", "buddy", b.Key.KeyID(), "err", err)
	}
	return c
}

var pinToStore = map[handle.PinStatus]store.HandleStatus{
	handle.PinVerified:    store.HandleVerified,
	handle.PinMoved:       store.HandleMoved,
	handle.PinUnverified:  store.HandleUnverified,
	handle.PinUnreachable: store.HandleUnreachable,
}

// verifyHandle verifies h and maps failures to daemon errors.
func (n *Node) verifyHandle(ctx context.Context, h string) (*handle.Result, error) {
	res, err := n.verifier.Verify(ctx, h)
	if err == nil {
		return res, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// ComparePin owns the "unreachable or unverified" classification.
	if handle.ComparePin(nil, err, identity.PublicKey{}).Status == handle.PinUnreachable {
		return nil, fmt.Errorf("%w: %s: %v", ErrHandleUnreachable, h, err)
	}
	return nil, fmt.Errorf("%w: %s: %v", ErrHandleUnverified, h, err)
}

// verifiedCheck is the check state right after h verified at now.
func verifiedCheck(now time.Time, res *handle.Result) store.HandleCheck {
	return store.HandleCheck{
		Status: store.HandleVerified, LastResult: store.HandleVerified,
		CheckedAt: now, VerifiedAt: now, NextCheck: handle.NextCheckRandom(now, handle.PinVerified),
		InboxHint: res.Inbox,
	}
}

// HandleCheckResult is one handle check.
type HandleCheckResult struct {
	Buddy  store.Buddy
	Check  store.HandleCheck // the stored state after the check
	Result store.HandleStatus
}

// CheckHandle re-checks a buddy's handle now and reschedules it.
func (n *Node) CheckHandle(ctx context.Context, sel string) (HandleCheckResult, error) {
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return HandleCheckResult{Buddy: b}, err
	}
	if b.Handle == "" {
		return HandleCheckResult{Buddy: b}, fmt.Errorf("%w: %s", ErrNoHandle, b.Key.KeyID())
	}
	return n.recheck(ctx, b)
}

// recheck runs CheckPin for b and stores the outcome. It never changes the
// pinned key: a moved handle is recorded and warned about, nothing more.
func (n *Node) recheck(ctx context.Context, b store.Buddy) (HandleCheckResult, error) {
	pr := n.verifier.CheckPin(ctx, b.Handle, b.Key)
	if err := ctx.Err(); err != nil {
		// Shutting down or the caller gave up: the outcome says nothing
		// about the handle, so store nothing.
		return HandleCheckResult{Buddy: b}, err
	}
	now := n.now()
	result := pinToStore[pr.Status]

	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	// The buddy may have been removed, or its handle changed, while the
	// lookup ran.
	cur, err := n.store.Buddy(ctx, b.ID)
	if errors.Is(err, store.ErrNotFound) {
		return HandleCheckResult{Buddy: b}, fmt.Errorf("%w: %s", ErrUnknownBuddy, b.Key.KeyID())
	} else if err != nil {
		return HandleCheckResult{Buddy: b}, err
	}
	if cur.Handle != b.Handle || cur.Key != b.Key {
		return HandleCheckResult{Buddy: cur}, fmt.Errorf("%w: buddy changed during the check", ErrInvalid)
	}
	prev, err := n.store.HandleCheck(ctx, b.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return HandleCheckResult{Buddy: cur}, err
	}
	c := prev
	c.BuddyID, c.LastResult, c.CheckedAt = b.ID, result, now
	c.NextCheck = handle.NextCheckRandom(now, pr.Status)
	switch pr.Status {
	case handle.PinVerified:
		c.Status, c.VerifiedAt, c.MovedKey, c.Error = store.HandleVerified, now, nil, ""
		c.InboxHint = pr.Result.Inbox
	case handle.PinMoved:
		// The inbox hint stays the pinned key's: the new record's hint
		// belongs to someone else.
		k := pr.Result.Key
		c.Status, c.MovedKey = store.HandleMoved, &k
		c.Error = fmt.Sprintf("%s now points to a different key (%s); the pinned key is kept", b.Handle, k.KeyID())
	case handle.PinUnverified:
		c.Status, c.MovedKey, c.Error = store.HandleUnverified, nil, pr.Err.Error()
	default: // unreachable: keep the status, retry soon
		c.Error = pr.Err.Error()
	}
	if err := n.store.SetHandleCheck(ctx, c); err != nil {
		return HandleCheckResult{Buddy: cur}, err
	}
	warn := (c.Status == store.HandleMoved || c.Status == store.HandleUnverified) &&
		(c.Status != prev.Status || !sameKey(c.MovedKey, prev.MovedKey))
	lvl := n.log.Info
	if warn {
		lvl = n.log.Warn
	}
	lvl("handle checked", "buddy", b.Key.KeyID(), "handle", b.Handle, "result", result, "status", c.Status,
		"next", c.NextCheck.Format(time.RFC3339), "err", c.Error)
	check := c
	n.events.publish(Event{Kind: EventBuddyChanged, Buddy: &cur, HandleCheck: &check})
	if warn {
		n.events.publish(Event{Kind: EventBuddyHandleWarning, Buddy: &cur, HandleCheck: &check})
	}
	return HandleCheckResult{Buddy: cur, Check: c, Result: result}, nil
}

func sameKey(a, b *identity.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// RecheckDueHandles checks every buddy whose handle check is due, at most
// the configured number at a time, and returns how many it checked. The
// background loop calls it; sweeps never overlap.
func (n *Node) RecheckDueHandles(ctx context.Context) (int, error) {
	n.sweepMu.Lock()
	defer n.sweepMu.Unlock()
	total := 0
	for {
		due, err := n.store.DueHandleChecks(ctx, n.now(), handleCheckBatch)
		if err != nil {
			return total, err
		}
		if len(due) == 0 {
			return total, nil
		}
		sem := make(chan struct{}, n.checkSlots)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var stored int
		for _, b := range due {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return total + stored, ctx.Err()
			}
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done() }()
				if _, err := n.recheck(ctx, b); err != nil {
					if ctx.Err() == nil {
						n.log.Warn("handle re-check failed", "buddy", b.Key.KeyID(), "err", err)
					}
					return
				}
				mu.Lock()
				stored++
				mu.Unlock()
			}()
		}
		wg.Wait()
		total += stored
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if stored == 0 {
			// Nothing could be stored (each failure was logged); don't
			// spin on the same rows.
			return total, errors.New("daemon: no due handle check could be stored")
		}
		if len(due) < handleCheckBatch {
			return total, nil
		}
	}
}

// WakeHandleChecks makes the re-check loop look for due checks now, for
// example after the clock was moved.
func (n *Node) WakeHandleChecks() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// startHandleLoop runs the re-check loop until Close.
func (n *Node) startHandleLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	n.stopLoop = cancel
	n.loopDone = make(chan struct{})
	go func() {
		defer close(n.loopDone)
		n.handleLoop(ctx)
	}()
}

func (n *Node) handleLoop(ctx context.Context) {
	for {
		wait := handleLoopMaxIdle
		if _, err := n.RecheckDueHandles(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			n.log.Error("handle re-check sweep failed", "err", err)
			wait = handleLoopRetry
		} else if next, ok, err := n.store.NextHandleCheck(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			n.log.Error("scheduling handle re-checks", "err", err)
			wait = handleLoopRetry
		} else if ok {
			wait = min(max(next.Sub(n.now()), 0), handleLoopMaxIdle)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-n.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// stopHandleLoop cancels the loop and waits for in-flight checks.
func (n *Node) stopHandleLoop() {
	if n.stopLoop != nil {
		n.stopLoop()
		<-n.loopDone
	}
}

// AddBuddyOptions says how to add a buddy: by Key, by Handle, or by Key
// with a claimed Handle.
type AddBuddyOptions struct {
	Key     string // base32 identity key
	Handle  string // user input; normalized
	Petname string
	Group   string
}

// AddedBuddy is the result of AddBuddyWith.
type AddedBuddy struct {
	Buddy store.Buddy
	Check *store.HandleCheck // set when the buddy was added with a handle
	// HandleDropped says why a claimed handle wasn't kept, when a buddy
	// added by key came with one that didn't verify for that key.
	HandleDropped error
}

// AddBuddyWith adds a buddy (design §5.3 rule 4: the buddy is the key; a
// handle is a label on it, kept only once verified).
//
//   - By key alone: as AddBuddy.
//   - By handle alone: the handle is verified and the key it proves is
//     pinned. A handle that doesn't verify fails with ErrHandleUnverified or
//     ErrHandleUnreachable.
//   - By key and handle: the key is added; the handle is kept only if it
//     verifies and proves that key. Otherwise HandleDropped says why.
//
// The inbox hint of a verified record is stored for first contact.
//
// TODO(first-contact): use the inbox hint to send FIRST_CONTACT.
func (n *Node) AddBuddyWith(ctx context.Context, o AddBuddyOptions) (AddedBuddy, error) {
	var h string
	if strings.TrimSpace(o.Handle) != "" {
		var err error
		if h, err = handle.Normalize(o.Handle); err != nil {
			return AddedBuddy{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	keyText := strings.TrimSpace(o.Key)
	if keyText == "" && h == "" {
		return AddedBuddy{}, fmt.Errorf("%w: give an identity key or a handle", ErrInvalid)
	}
	if err := checkLabel("petname", o.Petname); err != nil {
		return AddedBuddy{}, err
	}
	if err := checkLabel("group", o.Group); err != nil {
		return AddedBuddy{}, err
	}
	var k identity.PublicKey
	if keyText != "" {
		var err error
		if k, err = n.checkBuddyKey(keyText); err != nil {
			return AddedBuddy{}, err
		}
		if _, err := n.store.BuddyByKey(ctx, k); err == nil {
			return AddedBuddy{}, ErrDuplicate
		}
	}

	var check *store.HandleCheck
	var dropped error
	if h != "" {
		res, err := n.verifyHandle(ctx, h)
		switch {
		case err != nil && keyText == "":
			return AddedBuddy{}, err
		case err != nil:
			if ctx.Err() != nil {
				return AddedBuddy{}, ctx.Err()
			}
			dropped = err
		case keyText == "":
			if k, err = n.checkBuddyKey(res.Key.String()); err != nil {
				return AddedBuddy{}, err
			}
		case res.Key != k:
			dropped = fmt.Errorf("%w: %s points to a different key (%s), not %s", ErrHandleUnverified, h, res.Key.KeyID(), k.KeyID())
		}
		if dropped == nil {
			c := verifiedCheck(n.now(), res)
			check = &c
		}
	}

	b := store.Buddy{Key: k, Petname: o.Petname, Group: o.Group, State: store.PendingOut, AddedAt: n.now()}
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	var id int64
	var err error
	if check != nil {
		b.Handle = h
		id, err = n.store.AddBuddyWithHandleCheck(ctx, b, *check)
	} else {
		id, err = n.store.AddBuddy(ctx, b)
	}
	if err != nil {
		return AddedBuddy{}, err
	}
	if b, err = n.store.Buddy(ctx, id); err != nil {
		return AddedBuddy{}, err
	}
	if check != nil {
		check.BuddyID = id
	}
	if err := n.trackBuddy(b); err != nil {
		return AddedBuddy{Buddy: b, Check: check}, err
	}
	if dropped != nil {
		n.log.Warn("claimed handle dropped", "buddy", b.Key.KeyID(), "handle", h, "err", dropped)
	}
	n.log.Info("buddy added", "buddy", b.Key.KeyID(), "petname", b.Petname, "handle", b.Handle)
	n.events.publish(Event{Kind: EventBuddyAdded, Buddy: &b, HandleCheck: check})
	if check != nil {
		n.WakeHandleChecks() // reschedule the loop around the new check
	}
	return AddedBuddy{Buddy: b, Check: check, HandleDropped: dropped}, nil
}

// checkBuddyKey parses a buddy's key and checks it can be one.
func (n *Node) checkBuddyKey(s string) (identity.PublicKey, error) {
	k, err := identity.ParsePublicKeyString(s)
	if err != nil {
		return k, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if k == n.Identity() {
		return k, fmt.Errorf("%w: that is our own key", ErrInvalid)
	}
	// The key must also pair: Pair rejects keys whose X25519 form is unusable.
	if _, err := n.pair(k); err != nil {
		return k, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return k, nil
}
