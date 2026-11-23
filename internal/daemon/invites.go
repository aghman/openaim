package daemon

import (
	"fmt"
	"strings"

	"github.com/aghman/openaim/internal/handle"
	"github.com/aghman/openaim/internal/invite"
)

// InviteOptions says what goes in an invite link besides our key.
type InviteOptions struct {
	// Handle is our handle to put in the link, or "". It is only a claim:
	// whoever adds us verifies it (design §5.3).
	Handle string
	// ContactHint overrides Config.ContactHint for this link: a
	// relay-circuit or mailbox address, never a direct IP address.
	ContactHint string
}

// CreatedInvite is an invite link and what it holds.
type CreatedInvite struct {
	Link   string
	Invite invite.Invite
	// Note explains a missing part, such as no contact hint.
	Note string
}

// CreateInvite makes an invite link for our identity (design §5.4):
// openaim:add/<key>?h=<handle>&c=<contact hint>. The contact hint is
// o.ContactHint, else Config.ContactHint's (the current relay reservation),
// else left out, with a note saying the adder needs another way to reach us.
func (n *Node) CreateInvite(o InviteOptions) (CreatedInvite, error) {
	in := invite.Invite{Key: n.Identity()}
	if strings.TrimSpace(o.Handle) != "" {
		h, err := handle.Normalize(o.Handle)
		if err != nil {
			return CreatedInvite{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		in.Handle = h
	}
	var note string
	if strings.TrimSpace(o.ContactHint) != "" {
		a, err := invite.CheckContactHint(strings.TrimSpace(o.ContactHint))
		if err != nil {
			return CreatedInvite{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		in.Contact = a.String()
	} else if in.Contact = n.contactHint(); in.Contact == "" {
		note = "no contact hint: no relay reservation or mailbox is known yet, so the link has none. " +
			"Whoever adds you must reach you another way (a handle's inbox, or the network once you're online)."
	}
	link := in.String()
	if len(link) > invite.MaxLen {
		return CreatedInvite{}, fmt.Errorf("%w: invite link of %d bytes is too long", ErrInvalid, len(link))
	}
	return CreatedInvite{Link: link, Invite: in, Note: note}, nil
}
