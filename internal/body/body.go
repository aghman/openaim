// Package body encodes and decodes the bodies of inner payloads (spec/wire.md
// §6.1): plain UTF-8 for IM, protobuf (internal/wirepb) for everything else.
//
// Every decoded body is validated against the limits in the spec before the
// caller sees it, so code above this layer can trust lengths and ranges.
package body

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Limits (spec/wire.md §6.1).
const (
	MaxAckEntries   = 32
	MaxDisplayName  = 64
	MaxText         = 1024
	MaxGreeting     = 256
	MaxUserAgent    = 64
	MaxIPHints      = 4
	MaxAddrs        = 8
	MaxAddrLen      = 128
	MaxPeerIDLen    = 64
	MaxServiceHints = 4
	MaxIdleMinutes  = 60 * 24 * 365
)

// ErrInvalid is wrapped by every validation failure.
var ErrInvalid = errors.New("body: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// contentTypes maps each protobuf body to its content type.
var contentTypes = map[frame.ContentType]func() proto.Message{
	frame.Ack:          func() proto.Message { return &pb.Ack{} },
	frame.Presence:     func() proto.Message { return &pb.Presence{} },
	frame.ProfileReq:   func() proto.Message { return &pb.ProfileReq{} },
	frame.Profile:      func() proto.Message { return &pb.Profile{} },
	frame.AwayMsg:      func() proto.Message { return &pb.AwayMsg{} },
	frame.Typing:       func() proto.Message { return &pb.Typing{} },
	frame.BuddyAccept:  func() proto.Message { return &pb.BuddyAccept{} },
	frame.Reach:        func() proto.Message { return &pb.Reach{} },
	frame.Caps:         func() proto.Message { return &pb.Caps{} },
	frame.Rotate:       func() proto.Message { return &pb.Rotate{} },
	frame.BuddyRequest: func() proto.Message { return &pb.BuddyRequest{} },
}

// ContentTypeOf returns the content type a body message travels as.
func ContentTypeOf(m proto.Message) (frame.ContentType, error) {
	switch m.(type) {
	case *pb.Ack:
		return frame.Ack, nil
	case *pb.Presence:
		return frame.Presence, nil
	case *pb.ProfileReq:
		return frame.ProfileReq, nil
	case *pb.Profile:
		return frame.Profile, nil
	case *pb.AwayMsg:
		return frame.AwayMsg, nil
	case *pb.Typing:
		return frame.Typing, nil
	case *pb.BuddyAccept:
		return frame.BuddyAccept, nil
	case *pb.Reach:
		return frame.Reach, nil
	case *pb.Caps:
		return frame.Caps, nil
	case *pb.Rotate:
		return frame.Rotate, nil
	case *pb.BuddyRequest:
		return frame.BuddyRequest, nil
	}
	return 0, fmt.Errorf("body: %T is not a body message", m)
}

var marshal = proto.MarshalOptions{Deterministic: true}

// Marshal validates m and encodes it, returning its content type.
func Marshal(m proto.Message) (frame.ContentType, []byte, error) {
	ct, err := ContentTypeOf(m)
	if err != nil {
		return 0, nil, err
	}
	if err := Validate(m); err != nil {
		return 0, nil, err
	}
	b, err := marshal.Marshal(m)
	return ct, b, err
}

// Unmarshal decodes and validates the body of an inner payload with content
// type ct. Content types without a protobuf body (IM, rooms) are an error;
// use IM for IM bodies.
func Unmarshal(ct frame.ContentType, b []byte) (proto.Message, error) {
	mk, ok := contentTypes[ct]
	if !ok {
		return nil, fmt.Errorf("body: no protobuf body for %v", ct)
	}
	m := mk()
	if err := proto.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := Validate(m); err != nil {
		return nil, err
	}
	return m, nil
}

// IMText checks and returns an IM body: valid UTF-8, not empty, and no
// control characters other than newline and tab.
func IMText(b []byte) (string, error) {
	if len(b) == 0 {
		return "", invalid("empty IM")
	}
	if !utf8.Valid(b) {
		return "", invalid("IM is not UTF-8")
	}
	if err := text("IM", string(b), len(b)); err != nil {
		return "", err
	}
	return string(b), nil
}

// Validate checks a body message against the spec's limits.
func Validate(m proto.Message) error {
	switch v := m.(type) {
	case *pb.Ack:
		n := len(v.GetEntries())
		if n == 0 || n > MaxAckEntries {
			return invalid("ack with %d entries", n)
		}
		for _, e := range v.GetEntries() {
			if len(e.GetMsgId()) != 8 {
				return invalid("ack msg_id of %d bytes", len(e.GetMsgId()))
			}
			if e.GetHave() == 0 || e.GetHave() >= 1<<16 {
				return invalid("ack bitmap %#x", e.GetHave())
			}
		}
	case *pb.Presence:
		if v.GetState() < pb.PresenceState_PRESENCE_STATE_ONLINE || v.GetState() > pb.PresenceState_PRESENCE_STATE_OFFLINE {
			return invalid("presence state %d", v.GetState())
		}
		if v.GetIdleMinutes() > MaxIdleMinutes {
			return invalid("idle for %d minutes", v.GetIdleMinutes())
		}
	case *pb.ProfileReq:
		if !v.GetProfile() && !v.GetAwayMsg() {
			return invalid("profile request asks for nothing")
		}
	case *pb.Profile:
		if err := text("display name", v.GetDisplayName(), MaxDisplayName); err != nil {
			return err
		}
		return text("profile text", v.GetText(), MaxText)
	case *pb.AwayMsg:
		return text("away message", v.GetText(), MaxText)
	case *pb.Typing:
		if v.GetState() < pb.TypingState_TYPING_STATE_TYPING || v.GetState() > pb.TypingState_TYPING_STATE_IDLE {
			return invalid("typing state %d", v.GetState())
		}
	case *pb.BuddyAccept:
		if len(v.GetPresenceKey()) != 32 {
			return invalid("presence key of %d bytes", len(v.GetPresenceKey()))
		}
		if err := recoveryKey(v.GetRecoveryKey()); err != nil {
			return err
		}
		if err := text("display name", v.GetDisplayName(), MaxDisplayName); err != nil {
			return err
		}
		return reachAndCaps(v.Reach, v.Caps)
	case *pb.BuddyRequest:
		if err := text("display name", v.GetDisplayName(), MaxDisplayName); err != nil {
			return err
		}
		if err := text("greeting", v.GetGreeting(), MaxGreeting); err != nil {
			return err
		}
		if err := recoveryKey(v.GetRecoveryKey()); err != nil {
			return err
		}
		return reachAndCaps(v.Reach, v.Caps)
	case *pb.Reach:
		return validateReach(v)
	case *pb.Caps:
		if v.GetWireVersion() == 0 {
			return invalid("caps without a wire version")
		}
		return text("user agent", v.GetUserAgent(), MaxUserAgent)
	case *pb.Rotate:
		for name, k := range map[string][]byte{"old": v.GetOldKey(), "new": v.GetNewKey()} {
			if _, err := identity.ParsePublicKey(k); err != nil {
				return invalid("rotate %s key: %v", name, err)
			}
		}
		if string(v.GetOldKey()) == string(v.GetNewKey()) {
			return invalid("rotate to the same key")
		}
		if len(v.GetSignature()) != 64 {
			return invalid("rotate signature of %d bytes", len(v.GetSignature()))
		}
	default:
		return fmt.Errorf("body: %T is not a body message", m)
	}
	return nil
}

// recoveryKey checks an optional recovery key: empty, or a valid identity
// key (spec/wire.md §4.2).
func recoveryKey(rk []byte) error {
	if len(rk) == 0 {
		return nil
	}
	if _, err := identity.ParsePublicKey(rk); err != nil {
		return invalid("recovery key: %v", err)
	}
	return nil
}

// reachAndCaps checks the optional REACH and CAPS a request or accept
// carries.
func reachAndCaps(r *pb.Reach, c *pb.Caps) error {
	if r != nil {
		if err := Validate(r); err != nil {
			return err
		}
	}
	if c != nil {
		return Validate(c)
	}
	return nil
}

func validateReach(r *pb.Reach) error {
	if r.GetExpiresAt() <= r.GetIssuedAt() {
		return invalid("reach expires at %d, issued at %d", r.GetExpiresAt(), r.GetIssuedAt())
	}
	if n := len(r.GetIp()); n > MaxIPHints {
		return invalid("%d IP hints", n)
	}
	for _, h := range r.GetIp() {
		if n := len(h.GetPeerId()); n == 0 || n > MaxPeerIDLen {
			return invalid("peer ID of %d bytes", n)
		}
		if n := len(h.GetAddrs()); n > MaxAddrs {
			return invalid("%d addresses", n)
		}
		for _, a := range h.GetAddrs() {
			if err := addr(a); err != nil {
				return err
			}
		}
	}
	if n := len(r.GetGateway()); n > MaxServiceHints {
		return invalid("%d gateway hints", n)
	}
	for _, g := range r.GetGateway() {
		if len(g.GetGatewayKey()) != 32 || len(g.GetToken()) != 32 {
			return invalid("gateway hint key/token lengths %d/%d", len(g.GetGatewayKey()), len(g.GetToken()))
		}
		if err := addr(g.GetContact()); err != nil {
			return err
		}
	}
	if n := len(r.GetMailbox()); n > MaxServiceHints {
		return invalid("%d mailbox hints", n)
	}
	for _, m := range r.GetMailbox() {
		if len(m.GetMailboxKey()) != 32 || len(m.GetDepositToken()) != 32 {
			return invalid("mailbox hint key/token lengths %d/%d", len(m.GetMailboxKey()), len(m.GetDepositToken()))
		}
		if err := addr(m.GetContact()); err != nil {
			return err
		}
	}
	return nil
}

func addr(a []byte) error {
	if len(a) == 0 || len(a) > MaxAddrLen {
		return invalid("address of %d bytes", len(a))
	}
	return nil
}

// text checks a string field: at most max bytes, and no C0 or C1 control
// characters except newline and tab. Text from buddies ends up in terminals,
// where ESC and C1 controls could rewrite the screen. (protobuf already
// guarantees valid UTF-8.) Bidi and other display tricks are the UI's job.
func text(what, s string, max int) error {
	if len(s) > max {
		return invalid("%s of %d bytes (max %d)", what, len(s), max)
	}
	for _, r := range s {
		if (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7F && r <= 0x9F) {
			return invalid("%s contains control character %U", what, r)
		}
	}
	return nil
}
