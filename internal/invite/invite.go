// Package invite reads and writes OpenAIM invite links (design §5.4):
//
//	openaim:add/<b32 identity key>?h=<handle>&c=<contact hint>
//
// The key is the buddy: lowercase unpadded base32 (spec/wire.md §4.4),
// valid per §4.2. The handle (h) is optional and only a claim: the adder
// verifies it like any handle (design §5.3). The contact hint (c) is
// optional and says where to send the first-contact request. It is a
// relay-circuit or mailbox address, never a direct address of the inviter's
// own machine, since an invite link is handed around and must not reveal a
// home IP.
//
// Parsing is strict: one form, bounded sizes, no unknown parameters.
package invite

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	ma "github.com/multiformats/go-multiaddr"

	"github.com/aghman/openaim/internal/handle"
	"github.com/aghman/openaim/internal/identity"
)

// Prefix starts every invite link.
const Prefix = "openaim:add/"

// Size limits.
const (
	// MaxLen bounds a whole link: a key, a maximal handle and a maximal
	// contact hint, percent-encoded, fit with room to spare.
	MaxLen = 1024
	// MaxContactText bounds a contact hint's text form.
	MaxContactText = 384
	// MaxContactBytes bounds its binary form: the most a REACH address may
	// be (spec/wire.md §6.1).
	MaxContactBytes = 128
	keyLen          = 52 // base32 of 32 bytes
)

// ErrInvalid is wrapped by every parse failure.
var ErrInvalid = errors.New("invite: invalid link")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Invite is a parsed invite link.
type Invite struct {
	Key     identity.PublicKey
	Handle  string // canonical handle, or ""
	Contact string // canonical multiaddr text, or ""
}

// String formats the link. Handle and Contact must be valid (Parse, or
// CheckContactHint, makes them so).
func (in Invite) String() string {
	var b strings.Builder
	b.WriteString(Prefix)
	b.WriteString(in.Key.String())
	sep := "?"
	if in.Handle != "" {
		b.WriteString(sep + "h=" + url.QueryEscape(in.Handle))
		sep = "&"
	}
	if in.Contact != "" {
		b.WriteString(sep + "c=" + url.QueryEscape(in.Contact))
	}
	return b.String()
}

// Parse reads an invite link. Surrounding spaces are trimmed; anything else
// out of place is an error.
func Parse(s string) (Invite, error) {
	var in Invite
	s = strings.TrimSpace(s)
	if len(s) > MaxLen {
		return in, invalid("longer than %d bytes", MaxLen)
	}
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return in, invalid("doesn't start with %q", Prefix)
	}
	keyText, query, hasQuery := strings.Cut(rest, "?")
	if len(keyText) != keyLen {
		return in, invalid("identity key of %d characters, want %d", len(keyText), keyLen)
	}
	k, err := identity.ParsePublicKeyString(keyText)
	if err != nil {
		return in, invalid("identity key: %v", err)
	}
	// One spelling per key: lowercase, and no stray bits in the last
	// character (base32 decoding ignores them).
	if k.String() != keyText {
		return in, invalid("identity key is not in canonical form")
	}
	in.Key = k
	if !hasQuery {
		return in, nil
	}
	if query == "" {
		return in, invalid("empty query")
	}
	for _, part := range strings.Split(query, "&") {
		name, raw, ok := strings.Cut(part, "=")
		if !ok || raw == "" {
			return in, invalid("parameter %q has no value", name)
		}
		// '+' would decode to a space, which neither value may contain;
		// refuse it rather than guess.
		if strings.ContainsAny(raw, "+ ") {
			return in, invalid("parameter %q contains a space or '+'", name)
		}
		v, err := url.QueryUnescape(raw)
		if err != nil {
			return in, invalid("parameter %q: %v", name, err)
		}
		switch name {
		case "h":
			if in.Handle != "" {
				return in, invalid("h given twice")
			}
			if err := handle.Validate(v); err != nil {
				return in, invalid("handle: %v", err)
			}
			in.Handle = v
		case "c":
			if in.Contact != "" {
				return in, invalid("c given twice")
			}
			a, err := CheckContactHint(v)
			if err != nil {
				return in, err
			}
			in.Contact = a.String()
		default:
			return in, invalid("unknown parameter %q", name)
		}
	}
	return in, nil
}

// Contact hint shapes.
const (
	ContactRelay   = "relay-circuit"
	ContactMailbox = "mailbox"
)

// allowed are the protocols a contact hint may use. Anything that names a
// local socket, a zone or a range is out.
var allowed = map[int]bool{
	ma.P_IP4: true, ma.P_IP6: true, ma.P_DNS: true, ma.P_DNS4: true, ma.P_DNS6: true,
	ma.P_TCP: true, ma.P_UDP: true, ma.P_QUIC_V1: true, ma.P_WEBTRANSPORT: true, ma.P_CERTHASH: true,
	ma.P_TLS: true, ma.P_SNI: true, ma.P_WS: true, ma.P_WSS: true, ma.P_NOISE: true,
	ma.P_P2P: true, ma.P_CIRCUIT: true,
}

// CheckContactHint parses a contact hint and checks its shape. Two shapes
// are accepted:
//
//   - A relay circuit: <relay address>/p2p/<relay id>/p2p-circuit, optionally
//     followed by /p2p/<id>. The relay's address may be a DNS name or a
//     public IP address: the relay is infrastructure, and the inviter is
//     reached only through it.
//   - A mailbox: a DNS name (/dns, /dns4 or /dns6) and a transport, ending
//     in /p2p/<mailbox id>, with no IP address anywhere.
//
// A plain IP address (anything else with /ip4 or /ip6) is refused: it would
// put the inviter's own address in a link that gets passed around.
func CheckContactHint(s string) (ma.Multiaddr, error) {
	_, a, err := ClassifyContactHint(s)
	return a, err
}

// ClassifyContactHint is CheckContactHint, also returning the shape
// (ContactRelay or ContactMailbox).
func ClassifyContactHint(s string) (string, ma.Multiaddr, error) {
	if len(s) == 0 {
		return "", nil, invalid("empty contact hint")
	}
	if len(s) > MaxContactText {
		return "", nil, invalid("contact hint longer than %d bytes", MaxContactText)
	}
	a, err := ma.NewMultiaddr(s)
	if err != nil {
		return "", nil, invalid("contact hint: %v", err)
	}
	if n := len(a.Bytes()); n > MaxContactBytes {
		return "", nil, invalid("contact hint of %d bytes (max %d)", n, MaxContactBytes)
	}
	cs := []ma.Component(a)
	if len(cs) == 0 {
		return "", nil, invalid("empty contact hint")
	}
	circuit := -1
	for i := range cs {
		c := &cs[i]
		if !allowed[c.Code()] {
			return "", nil, invalid("contact hint uses /%s", c.Protocol().Name)
		}
		if c.Code() == ma.P_CIRCUIT {
			if circuit >= 0 {
				return "", nil, invalid("contact hint has more than one relay hop")
			}
			circuit = i
		}
	}
	if circuit >= 0 {
		relay, after := cs[:circuit], cs[circuit+1:]
		if len(relay) < 2 || relay[len(relay)-1].Code() != ma.P_P2P {
			return "", nil, invalid("relay circuit must name the relay: <addr>/p2p/<relay id>/p2p-circuit")
		}
		if err := checkHost(&relay[0], true); err != nil {
			return "", nil, err
		}
		for i := 1; i < len(relay); i++ {
			if isHost(relay[i].Code()) {
				return "", nil, invalid("relay address has more than one host")
			}
		}
		switch {
		case len(after) == 0:
		case len(after) == 1 && after[0].Code() == ma.P_P2P:
		default:
			return "", nil, invalid("a relay circuit may be followed only by /p2p/<id>")
		}
		return ContactRelay, a, nil
	}
	first := &cs[0]
	switch first.Code() {
	case ma.P_IP4, ma.P_IP6:
		return "", nil, invalid("contact hint %s is a plain IP address; use a relay-circuit or mailbox address", s)
	}
	if err := checkHost(first, false); err != nil {
		return "", nil, err
	}
	if len(cs) < 3 || cs[len(cs)-1].Code() != ma.P_P2P {
		return "", nil, invalid("mailbox address must be <dns name>/<transport>/p2p/<mailbox id>")
	}
	for i := 1; i < len(cs); i++ {
		if isHost(cs[i].Code()) {
			return "", nil, invalid("mailbox address has more than one host")
		}
	}
	return ContactMailbox, a, nil
}

func isHost(code int) bool {
	switch code {
	case ma.P_IP4, ma.P_IP6, ma.P_DNS, ma.P_DNS4, ma.P_DNS6:
		return true
	}
	return false
}

// checkHost checks an address's first component: a DNS name, or (when ipOK)
// a public unicast IP address.
func checkHost(c *ma.Component, ipOK bool) error {
	switch c.Code() {
	case ma.P_DNS, ma.P_DNS4, ma.P_DNS6:
		name := c.Value()
		if err := handle.Validate(strings.ToLower(name)); err != nil {
			return invalid("host name %q: %v", name, err)
		}
		return nil
	case ma.P_IP4, ma.P_IP6:
		if !ipOK {
			return invalid("contact hint has an IP address")
		}
		ip, err := netip.ParseAddr(c.Value())
		if err != nil {
			return invalid("address %q: %v", c.Value(), err)
		}
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
			return invalid("relay address %s is not a public address", ip)
		}
		return nil
	}
	return invalid("contact hint must start with a host (/dns, /dns4, /dns6, or a relay's /ip4 or /ip6)")
}

// cgnat is the shared address space (RFC 6598): carrier-grade NAT, never a
// reachable relay.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")
