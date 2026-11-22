package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aghman/openaim/internal/identity"
)

// HandleStatus is the outcome of checking a buddy's handle against its
// pinned key (spec/handle.md §7).
type HandleStatus string

const (
	HandleVerified    HandleStatus = "verified"    // the handle proves the pinned key
	HandleMoved       HandleStatus = "moved"       // the handle proves a different key
	HandleUnverified  HandleStatus = "unverified"  // the handle answered but proves nothing
	HandleUnreachable HandleStatus = "unreachable" // no trustworthy answer
)

// HandleCheck is the re-check state of one buddy's handle (migration 0002).
// It never holds the pinned key: that is Buddy.Key, and checks never change
// it.
type HandleCheck struct {
	BuddyID int64
	// Status is what the buddy list shows: the last conclusive outcome
	// (verified, moved or unverified). An unreachable check leaves it as it
	// was; "" means no check was ever conclusive.
	Status HandleStatus
	// LastResult is the outcome of the most recent check, which may be
	// HandleUnreachable.
	LastResult HandleStatus
	CheckedAt  time.Time // most recent check
	VerifiedAt time.Time // most recent verified check; zero if never
	NextCheck  time.Time
	// MovedKey is the key the handle points to now, while Status is
	// HandleMoved. It is for display; the pin stays Buddy.Key.
	MovedKey *identity.PublicKey
	// InboxHint is the inbox hint from the last verified record, kept for
	// first contact.
	InboxHint string
	// Error says why the most recent check didn't verify, or "".
	Error string
}

const handleCols = "buddy_id, status, last_result, checked_at, verified_at, next_check, moved_key, inbox_hint, error"

func scanHandleCheck(row interface{ Scan(...any) error }) (HandleCheck, error) {
	var c HandleCheck
	var status, hint, errText sql.NullString
	var verified sql.NullInt64
	var checked, next int64
	var moved []byte
	if err := row.Scan(&c.BuddyID, &status, &c.LastResult, &checked, &verified, &next, &moved, &hint, &errText); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c, ErrNotFound
		}
		return c, err
	}
	c.Status = HandleStatus(status.String)
	c.CheckedAt, c.NextCheck = time.UnixMilli(checked), time.UnixMilli(next)
	if verified.Valid {
		c.VerifiedAt = time.UnixMilli(verified.Int64)
	}
	if len(moved) == 32 {
		var k identity.PublicKey
		copy(k[:], moved)
		c.MovedKey = &k
	}
	c.InboxHint, c.Error = hint.String, errText.String
	return c, nil
}

func (c *HandleCheck) check() error {
	switch c.Status {
	case "", HandleVerified, HandleMoved, HandleUnverified:
	default:
		return fmt.Errorf("store: handle status %q", c.Status)
	}
	switch c.LastResult {
	case HandleVerified, HandleMoved, HandleUnverified, HandleUnreachable:
	default:
		return fmt.Errorf("store: handle check result %q", c.LastResult)
	}
	if c.CheckedAt.IsZero() || c.NextCheck.IsZero() {
		return errors.New("store: handle check needs CheckedAt and NextCheck")
	}
	return nil
}

func (c *HandleCheck) args() []any {
	var moved []byte
	if c.MovedKey != nil {
		moved = c.MovedKey[:]
	}
	var verified sql.NullInt64
	if !c.VerifiedAt.IsZero() {
		verified = sql.NullInt64{Int64: c.VerifiedAt.UnixMilli(), Valid: true}
	}
	return []any{c.BuddyID, nullString(string(c.Status)), string(c.LastResult), c.CheckedAt.UnixMilli(), verified,
		c.NextCheck.UnixMilli(), moved, nullString(c.InboxHint), nullString(c.Error)}
}

const upsertHandleCheck = `INSERT INTO handle_checks (` + handleCols + `) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT (buddy_id) DO UPDATE SET status = excluded.status, last_result = excluded.last_result,
	checked_at = excluded.checked_at, verified_at = excluded.verified_at, next_check = excluded.next_check,
	moved_key = excluded.moved_key, inbox_hint = excluded.inbox_hint, error = excluded.error`

// AddBuddyWithHandleCheck stores a new buddy together with the state of the
// handle check that vouched for it, in one transaction. c.BuddyID is ignored.
func (s *Store) AddBuddyWithHandleCheck(ctx context.Context, b Buddy, c HandleCheck) (int64, error) {
	if b.Handle == "" {
		return 0, errors.New("store: a handle check needs a buddy with a handle")
	}
	if err := c.check(); err != nil {
		return 0, err
	}
	if b.Group == "" {
		b.Group = "Buddies"
	}
	if b.AddedAt.IsZero() {
		b.AddedAt = time.Now()
	}
	var rk []byte
	if b.RecoveryKey != nil {
		rk = b.RecoveryKey[:]
	}
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO buddies (ed_key, handle, petname, group_name, state, verified, recovery_key, added_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ed_key) DO NOTHING`,
			b.Key[:], nullString(b.Handle), nullString(b.Petname), b.Group, string(b.State), b.Verified, rk, b.AddedAt.UnixMilli())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrDuplicate
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
		c.BuddyID = id
		_, err = tx.ExecContext(ctx, upsertHandleCheck, c.args()...)
		return err
	})
	return id, err
}

// SetHandleCheck stores (replacing) the handle check state of buddy
// c.BuddyID. The buddy must exist and have a handle.
func (s *Store) SetHandleCheck(ctx context.Context, c HandleCheck) error {
	if err := c.check(); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var handle sql.NullString
		err := tx.QueryRowContext(ctx, "SELECT handle FROM buddies WHERE id = ?", c.BuddyID).Scan(&handle)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if !handle.Valid {
			return fmt.Errorf("store: buddy %d has no handle", c.BuddyID)
		}
		_, err = tx.ExecContext(ctx, upsertHandleCheck, c.args()...)
		return err
	})
}

// HandleCheck returns buddy id's handle check state, or ErrNotFound if its
// handle was never checked.
func (s *Store) HandleCheck(ctx context.Context, id int64) (HandleCheck, error) {
	return scanHandleCheck(s.db.QueryRowContext(ctx, "SELECT "+handleCols+" FROM handle_checks WHERE buddy_id = ?", id))
}

// HandleChecks returns every stored handle check state, by buddy ID.
func (s *Store) HandleChecks(ctx context.Context) (map[int64]HandleCheck, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+handleCols+" FROM handle_checks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HandleCheck{}
	for rows.Next() {
		c, err := scanHandleCheck(rows)
		if err != nil {
			return nil, err
		}
		out[c.BuddyID] = c
	}
	return out, rows.Err()
}

// dueFrom selects buddies with a handle, with their check state if any.
const dueFrom = ` FROM buddies b LEFT JOIN handle_checks hc ON hc.buddy_id = b.id WHERE b.handle IS NOT NULL`

// DueHandleChecks lists up to limit buddies with a handle whose next check
// is at or before now, most overdue first. Buddies whose handle was never
// checked are due at once.
func (s *Store) DueHandleChecks(ctx context.Context, now time.Time, limit int) ([]Buddy, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT b.id, b.ed_key, b.handle, b.petname, b.group_name, b.state, b.verified, b.recovery_key, b.added_at"+
			dueFrom+" AND coalesce(hc.next_check, 0) <= ? ORDER BY coalesce(hc.next_check, 0), b.id LIMIT ?",
		now.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Buddy
	for rows.Next() {
		b, err := scanBuddy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// NextHandleCheck is the earliest next check among buddies with a handle
// (the zero time for one never checked). ok is false if no buddy has a
// handle.
func (s *Store) NextHandleCheck(ctx context.Context) (next time.Time, ok bool, err error) {
	var ms sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT min(coalesce(hc.next_check, 0))"+dueFrom).Scan(&ms); err != nil {
		return time.Time{}, false, err
	}
	if !ms.Valid {
		return time.Time{}, false, nil
	}
	if ms.Int64 == 0 {
		return time.Time{}, true, nil
	}
	return time.UnixMilli(ms.Int64), true, nil
}
