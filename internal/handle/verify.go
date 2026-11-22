package handle

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/aghman/openaim/internal/identity"
)

// Verifier resolves and verifies handles. The zero value uses
// DefaultResolvers and production proof settings.
type Verifier struct {
	// Resolvers are DoH endpoint URLs (https only, at least two). Nil means
	// DefaultResolvers. Every one must give the same answer.
	Resolvers []string
	// Client sends DoH queries. Nil uses a client with no proxy and no
	// redirects.
	Client *http.Client
	// DoHTimeout bounds each DoH query. Zero is DefaultDoHTimeout.
	DoHTimeout time.Duration
	// Proof controls the HTTPS proof fallback.
	Proof ProofConfig
}

// Source says where a verified record came from.
type Source int

const (
	SourceDNS   Source = iota + 1 // TXT at _openaim.<handle>, via DoH
	SourceHTTPS                   // https://<handle>/.well-known/openaim
)

func (s Source) String() string {
	switch s {
	case SourceDNS:
		return "dns"
	case SourceHTTPS:
		return "https"
	}
	return fmt.Sprintf("Source(%d)", int(s))
}

// Result is a verified handle binding.
type Result struct {
	Handle string
	Key    identity.PublicKey
	Issued time.Time
	Inbox  string
	Source Source
	Record Record
}

// Verify resolves handle h and checks its record (spec/handle.md §6).
//
// The DNS record is tried first. The HTTPS proof is tried only when every
// resolver agrees there is no DNS record: a resolver that fails or disagrees
// fails the whole check, so blocking a resolver can't push verification onto
// a weaker or different proof.
func (v *Verifier) Verify(ctx context.Context, h string) (*Result, error) {
	if err := Validate(h); err != nil {
		return nil, err
	}
	src := SourceDNS
	var rec *Record
	text, err := v.lookupTXT(ctx, h)
	switch {
	case err == nil:
		if rec, err = ParseRecord(text); err != nil {
			return nil, err
		}
	case errors.Is(err, ErrNotFound):
		src = SourceHTTPS
		if rec, err = v.FetchProof(ctx, h); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("%w: no DNS record and no HTTPS proof for %s: %w", ErrNotFound, h, err)
			}
			return nil, err
		}
	default:
		return nil, err
	}
	if err := rec.Verify(h); err != nil {
		return nil, err
	}
	return &Result{Handle: h, Key: rec.Key, Issued: rec.IssuedAt(), Inbox: rec.Inbox, Source: src, Record: *rec}, nil
}

// PinStatus is the outcome of re-checking a pinned handle (design §5.3
// rules 4 and 5).
type PinStatus int

const (
	// PinVerified: the handle still proves the pinned key.
	PinVerified PinStatus = iota + 1
	// PinMoved: the handle now proves a different key. Never swap the
	// pinned key; show "⚠ moved/unverified". Real key changes arrive as
	// signed rotations (design §5.5).
	PinMoved
	// PinUnverified: the handle answered, but proves nothing: no record, a
	// malformed record, a bad signature, or a forbidden or redirecting
	// HTTPS proof. Shown like PinMoved.
	PinUnverified
	// PinUnreachable: no trustworthy answer (network failure, timeout,
	// resolver error or disagreement). Keep the previous status and retry.
	PinUnreachable
)

func (s PinStatus) String() string {
	switch s {
	case PinVerified:
		return "verified"
	case PinMoved:
		return "moved"
	case PinUnverified:
		return "unverified"
	case PinUnreachable:
		return "unreachable"
	}
	return fmt.Sprintf("PinStatus(%d)", int(s))
}

// PinResult is a pin check. Result is set for PinVerified and PinMoved; Err
// is set for PinUnverified and PinUnreachable.
type PinResult struct {
	Status PinStatus
	Result *Result
	Err    error
}

// ComparePin classifies a Verify outcome against the pinned key. It is pure,
// so a caller can verify once and compare against several pins.
func ComparePin(res *Result, err error, pinned identity.PublicKey) PinResult {
	if err == nil && res == nil {
		err = fmt.Errorf("%w: no result", ErrNotFound)
	}
	switch {
	case err == nil && res.Key == pinned:
		return PinResult{Status: PinVerified, Result: res}
	case err == nil:
		return PinResult{Status: PinMoved, Result: res}
	case errors.Is(err, ErrUnreachable), errors.Is(err, ErrDisagree), errors.Is(err, ErrConfig),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return PinResult{Status: PinUnreachable, Err: err}
	}
	return PinResult{Status: PinUnverified, Err: err}
}

// CheckPin verifies h and compares it with the pinned key.
func (v *Verifier) CheckPin(ctx context.Context, h string, pinned identity.PublicKey) PinResult {
	res, err := v.Verify(ctx, h)
	return ComparePin(res, err, pinned)
}

// Re-check schedule (design §5.3 rule 5).
const (
	RecheckInterval = 30 * 24 * time.Hour
	RecheckJitter   = 4 * 24 * time.Hour // ± around RecheckInterval
	RetryInterval   = 24 * time.Hour
	RetryJitter     = 4 * time.Hour // ± around RetryInterval
)

// NextCheck is when to re-check a handle last checked at last with outcome
// s. u is a uniform random number in [0, 1) that spreads checks out, so
// buddies added together aren't re-checked together; values outside the
// range are clamped.
//
// A verified handle is re-checked about monthly. Anything else is re-checked
// about daily, so a warning clears soon after the record is fixed and a
// transient failure doesn't leave the handle unchecked for a month.
func NextCheck(last time.Time, s PinStatus, u float64) time.Time {
	u = min(max(u, 0), 1)
	base, jitter := RetryInterval, RetryJitter
	if s == PinVerified {
		base, jitter = RecheckInterval, RecheckJitter
	}
	return last.Add(base + time.Duration((2*u-1)*float64(jitter)))
}

// NextCheckRandom is NextCheck with a fresh random u.
func NextCheckRandom(last time.Time, s PinStatus) time.Time {
	return NextCheck(last, s, rand.Float64())
}
