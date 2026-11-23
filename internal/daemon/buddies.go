package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Errors for bad requests. The API maps them to gRPC codes.
var (
	ErrInvalid      = errors.New("daemon: invalid argument")
	ErrUnknownBuddy = errors.New("daemon: no such buddy")
	ErrAmbiguous    = errors.New("daemon: name matches more than one buddy; use the identity key")
	ErrBlocked      = errors.New("daemon: buddy is blocked")
	ErrDuplicate    = store.ErrDuplicate
)

// Labels on a buddy are local, but shown in UIs and kept in backups, so keep
// them short and printable.
const maxLabel = 64

func checkLabel(what, s string) error {
	if len(s) > maxLabel {
		return fmt.Errorf("%w: %s longer than %d bytes", ErrInvalid, what, maxLabel)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s is not UTF-8", ErrInvalid, what)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains control characters", ErrInvalid, what)
		}
	}
	return nil
}

// checkAwayMessage applies the wire limits for AWAY_MSG, since that's where
// the text ends up.
func checkAwayMessage(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: away message is not UTF-8", ErrInvalid)
	}
	if err := body.Validate(&pb.AwayMsg{Text: s}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// Buddies lists the buddy list, by group then name.
func (n *Node) Buddies(ctx context.Context) ([]store.Buddy, error) { return n.store.Buddies(ctx) }

// FindBuddy resolves a buddy selector (see the API's BuddySelector): an
// identity key, a key ID ("~k3f9"), a petname, a handle or a short handle,
// tried in that order. Name matches ignore case.
func (n *Node) FindBuddy(ctx context.Context, sel string) (store.Buddy, error) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return store.Buddy{}, fmt.Errorf("%w: no buddy named", ErrInvalid)
	}
	if k, err := identity.ParsePublicKeyString(sel); err == nil {
		b, err := n.store.BuddyByKey(ctx, k)
		if errors.Is(err, store.ErrNotFound) {
			return b, fmt.Errorf("%w: %s", ErrUnknownBuddy, k.KeyID())
		}
		return b, err
	}
	all, err := n.store.Buddies(ctx)
	if err != nil {
		return store.Buddy{}, err
	}
	matchers := []func(store.Buddy) bool{
		func(b store.Buddy) bool { return b.Key.KeyID() == sel },
		func(b store.Buddy) bool { return b.Petname != "" && strings.EqualFold(b.Petname, sel) },
		func(b store.Buddy) bool { return b.Handle != "" && strings.EqualFold(b.Handle, sel) },
		func(b store.Buddy) bool { return b.Handle != "" && strings.EqualFold(n.ShortHandle(b.Handle), sel) },
	}
	for _, m := range matchers {
		var found []store.Buddy
		for _, b := range all {
			if m(b) {
				found = append(found, b)
			}
		}
		switch len(found) {
		case 0:
			continue
		case 1:
			return found[0], nil
		default:
			return store.Buddy{}, fmt.Errorf("%w: %q", ErrAmbiguous, sel)
		}
	}
	return store.Buddy{}, fmt.Errorf("%w: %q", ErrUnknownBuddy, sel)
}

// AddBuddy adds a buddy by identity key (base32) and sends them a request.
// The buddy starts as pending_out: we've asked, they haven't accepted.
// AddBuddyWith also adds by handle or invite link.
func (n *Node) AddBuddy(ctx context.Context, key, petname, group string) (store.Buddy, error) {
	if strings.TrimSpace(key) == "" {
		return store.Buddy{}, fmt.Errorf("%w: no identity key", ErrInvalid)
	}
	a, err := n.AddBuddyWith(ctx, AddBuddyOptions{Key: key, Petname: petname, Group: group})
	return a.Buddy, err
}

// RemoveBuddy deletes a buddy with its queued messages and history.
//
// TODO(presence): rotate our presence key and revoke the buddy's delivery
// tokens (design §5.4) once those exist.
func (n *Node) RemoveBuddy(ctx context.Context, sel string) (store.Buddy, error) {
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return b, err
	}
	check := n.handleCheckOrNil(ctx, b) // deleted with the buddy
	if err := n.store.DeleteBuddy(ctx, b.ID); err != nil {
		return b, err
	}
	n.untrackBuddy(b.Key)
	n.log.Info("buddy removed", "buddy", b.Key.KeyID())
	n.events.publish(Event{Kind: EventBuddyRemoved, Buddy: &b, HandleCheck: check})
	return b, nil
}

// SetBuddyVerified records whether the user checked the buddy's safety
// number.
func (n *Node) SetBuddyVerified(ctx context.Context, sel string, verified bool) (store.Buddy, error) {
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return b, err
	}
	if b.Verified == verified {
		return b, nil
	}
	if err := n.store.SetBuddyVerified(ctx, b.ID, verified); err != nil {
		return b, err
	}
	b.Verified = verified
	n.events.publish(Event{Kind: EventBuddyChanged, Buddy: &b, HandleCheck: n.handleCheckOrNil(ctx, b)})
	return b, nil
}

// SafetyNumber is the out-of-band verification code for us and a buddy.
func (n *Node) SafetyNumber(ctx context.Context, sel string) (string, store.Buddy, error) {
	b, err := n.FindBuddy(ctx, sel)
	if err != nil {
		return "", b, err
	}
	return identity.SafetyNumber(n.Identity(), b.Key), b, nil
}
