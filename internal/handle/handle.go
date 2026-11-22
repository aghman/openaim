// Package handle verifies Bluesky-style DNS screen names (design §5.3).
// spec/handle.md is normative for the record format, the signed message and
// the verification rules implemented here.
//
// A handle is a DNS name that points at an identity key through a signed TXT
// record at _openaim.<handle>, or through the same record served at
// https://<handle>/.well-known/openaim. The record is self-contained: the
// domain points to the key, and the key's signature claims the handle.
//
// Lookups never use the system resolver. TXT records come from two
// independent DNS-over-HTTPS resolvers that must agree, and HTTPS proofs are
// fetched behind an SSRF guard that checks every dialed address.
//
// Nothing here persists state. Verify and CheckPin return plain values, and
// NextCheck is a pure function, so the daemon decides what to store.
package handle

import (
	"errors"
	"fmt"
	"strings"
)

// Length limits (spec/handle.md §1). MaxLen is below DNS's 253 so that the
// record name "_openaim." + handle still fits in a DNS name.
const (
	MaxLen      = 253 - len(recordPrefix)
	MaxLabelLen = 63
)

// recordPrefix is prepended to a handle to name its TXT record.
const recordPrefix = "_openaim."

// ErrSyntax is wrapped by every handle syntax failure.
var ErrSyntax = errors.New("handle: invalid syntax")

func syntaxErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSyntax, fmt.Sprintf(format, args...))
}

// Validate reports whether h is a handle in canonical form: lowercase LDH
// labels, at least two of them, no punycode, no trailing dot. It is strict on
// purpose; use Normalize for user input.
func Validate(h string) error {
	if h == "" {
		return syntaxErr("empty")
	}
	if len(h) > MaxLen {
		return syntaxErr("longer than %d bytes", MaxLen)
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return syntaxErr("needs at least two labels")
	}
	for i, l := range labels {
		if err := validateLabel(l); err != nil {
			return syntaxErr("label %d: %v", i+1, err)
		}
	}
	// An all-numeric last label would let "10.0.0.1" pass as a handle. No
	// real TLD is numeric (RFC 3696 §2).
	if allDigits(labels[len(labels)-1]) {
		return syntaxErr("numeric top-level label")
	}
	return nil
}

func validateLabel(l string) error {
	switch {
	case l == "":
		return errors.New("empty")
	case len(l) > MaxLabelLen:
		return fmt.Errorf("longer than %d bytes", MaxLabelLen)
	case l[0] == '-' || l[len(l)-1] == '-':
		return errors.New("leading or trailing hyphen")
	case strings.HasPrefix(l, "xn--"):
		// Punycode labels can render as look-alikes of other names. v1
		// rejects them outright rather than trying to judge confusability.
		return errors.New("punycode (xn--) labels are not allowed")
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			if c >= 'A' && c <= 'Z' {
				return errors.New("uppercase letter")
			}
			return fmt.Errorf("byte %#02x is not a lowercase letter, digit or hyphen", c)
		}
	}
	return nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// Normalize turns user input into a canonical handle: it trims surrounding
// spaces, a leading "@" and one trailing dot, and lowercases ASCII letters,
// then applies Validate. Non-ASCII input is rejected, not folded: a handle
// someone typed with a Cyrillic "а" must not quietly become a Latin one.
func Normalize(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "@")
	s = strings.TrimSuffix(s, ".")
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	h := string(b)
	if err := Validate(h); err != nil {
		return "", err
	}
	return h, nil
}

// Short is how a handle is shown in the buddy list (design §5.3 rule 6). A
// handle that is one label directly under the user's configured default
// registry shows as just that label; any other handle shows in full. The
// buddy info panel should always show the full handle.
//
// registry is the user's configured registry domain, e.g. "example.com". An
// empty or invalid registry turns shortening off.
func Short(h, registry string) string {
	if registry == "" || Validate(registry) != nil {
		return h
	}
	name, ok := strings.CutSuffix(h, "."+registry)
	if !ok || name == "" || strings.Contains(name, ".") {
		return h
	}
	return name
}
