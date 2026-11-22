package rendezvous

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/transport/ip"
)

// MaxSkew is the clock difference a lookup tolerates: a locator may be issued
// up to this far in our future, and within this of the next UTC midnight
// tomorrow's record is tried too.
const MaxSkew = 10 * time.Minute

// ErrNotFound is returned when no valid, unexpired record is found for any of
// the days tried.
var ErrNotFound = errors.New("rendezvous: no record found")

// Getter fetches verified rendezvous records. *ip.DHT implements it.
type Getter interface {
	GetRendezvous(ctx context.Context, key string) (ip.RendezvousRecord, error)
}

// Found is a buddy's locator from the DHT.
type Found struct {
	Locator
	Day uint32 // the record's day
	Seq uint64
}

// LookupDays are the days a lookup at now tries: today and yesterday, and
// tomorrow within MaxSkew of the next UTC midnight.
func LookupDays(now time.Time) []uint32 {
	today := frame.Day(now)
	days := []uint32{today}
	if today > 0 {
		days = append(days, today-1)
	}
	if dayStart(today+1).Sub(now) <= MaxSkew {
		days = append(days, today+1)
	}
	return days
}

// dayStart is the first instant of day.
func dayStart(day uint32) time.Time {
	return frame.Epoch.Add(time.Duration(day) * 24 * time.Hour)
}

// Lookup finds where a buddy is now. kdir is the buddy's directional key
// toward us (Pair.Recv). It tries the days of LookupDays in parallel and
// returns the valid, unexpired locator with the highest seq. Records that
// fail any check are skipped; if none is left the error wraps ErrNotFound
// and says why each day failed.
func Lookup(ctx context.Context, g Getter, kdir [32]byte, now time.Time) (Found, error) {
	days := LookupDays(now)
	found := make([]Found, len(days))
	errs := make([]error, len(days))
	var wg sync.WaitGroup
	for i, day := range days {
		wg.Go(func() { found[i], errs[i] = lookupDay(ctx, g, Derive(kdir, day), now) })
	}
	wg.Wait()

	best := -1
	for i := range days {
		if errs[i] == nil && (best < 0 || found[i].Seq > found[best].Seq) {
			best = i
		}
	}
	if best < 0 {
		var all []error
		for i, day := range days {
			all = append(all, fmt.Errorf("day %d: %w", day, errs[i]))
		}
		return Found{}, fmt.Errorf("%w: %w", ErrNotFound, errors.Join(all...))
	}
	return found[best], nil
}

func lookupDay(ctx context.Context, g Getter, k Keys, now time.Time) (Found, error) {
	r, err := g.GetRendezvous(ctx, k.Key)
	if err != nil {
		return Found{}, err
	}
	l, err := Open(k, r)
	if err != nil {
		return Found{}, err
	}
	if err := checkFresh(l, now); err != nil {
		return Found{}, err
	}
	return Found{Locator: l, Day: k.Day, Seq: r.Seq}, nil
}

// checkFresh rejects a locator that has expired or was issued too far in the
// future.
func checkFresh(l Locator, now time.Time) error {
	if !now.Before(l.ExpiresAt) {
		return bad("expired at %s", l.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if l.IssuedAt.After(now.Add(MaxSkew)) {
		return bad("issued in the future, at %s", l.IssuedAt.UTC().Format(time.RFC3339))
	}
	return nil
}
