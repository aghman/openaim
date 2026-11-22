package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aghman/openaim/internal/identity"
)

// BuddyState is where a buddy relationship stands (design §5.4).
type BuddyState string

const (
	PendingOut BuddyState = "pending_out" // we sent a request
	PendingIn  BuddyState = "pending_in"  // they sent us a request
	Accepted   BuddyState = "accepted"
	Blocked    BuddyState = "blocked"
)

// Buddy is a contact. The identity key is the buddy; everything else is a
// label on it (design §5.3 rule 4).
type Buddy struct {
	ID          int64
	Key         identity.PublicKey
	Handle      string // verified handle, or ""
	Petname     string
	Group       string
	State       BuddyState
	Verified    bool
	RecoveryKey *identity.PublicKey // pinned when they were added, if known
	AddedAt     time.Time
}

// ErrDuplicate is returned when adding a buddy whose key is already stored.
var ErrDuplicate = errors.New("store: buddy already exists")

// AddBuddy stores a new buddy and returns its ID.
func (s *Store) AddBuddy(ctx context.Context, b Buddy) (int64, error) {
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
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO buddies (ed_key, handle, petname, group_name, state, verified, recovery_key, added_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ed_key) DO NOTHING`,
		b.Key[:], nullString(b.Handle), nullString(b.Petname), b.Group, string(b.State), b.Verified, rk, b.AddedAt.UnixMilli())
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrDuplicate
	}
	return res.LastInsertId()
}

const buddyCols = "id, ed_key, handle, petname, group_name, state, verified, recovery_key, added_at"

func scanBuddy(row interface{ Scan(...any) error }) (Buddy, error) {
	var b Buddy
	var key, rk []byte
	var handle, petname sql.NullString
	var added int64
	if err := row.Scan(&b.ID, &key, &handle, &petname, &b.Group, &b.State, &b.Verified, &rk, &added); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return b, ErrNotFound
		}
		return b, err
	}
	copy(b.Key[:], key)
	b.Handle, b.Petname = handle.String, petname.String
	if len(rk) == 32 {
		var k identity.PublicKey
		copy(k[:], rk)
		b.RecoveryKey = &k
	}
	b.AddedAt = time.UnixMilli(added)
	return b, nil
}

// Buddy returns the buddy with id.
func (s *Store) Buddy(ctx context.Context, id int64) (Buddy, error) {
	return scanBuddy(s.db.QueryRowContext(ctx, "SELECT "+buddyCols+" FROM buddies WHERE id = ?", id))
}

// BuddyByKey returns the buddy with identity key k.
func (s *Store) BuddyByKey(ctx context.Context, k identity.PublicKey) (Buddy, error) {
	return scanBuddy(s.db.QueryRowContext(ctx, "SELECT "+buddyCols+" FROM buddies WHERE ed_key = ?", k[:]))
}

// Buddies lists every buddy, by group then name.
func (s *Store) Buddies(ctx context.Context) ([]Buddy, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+buddyCols+" FROM buddies ORDER BY group_name, coalesce(petname, handle, ''), id")
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

// SetBuddyState changes a buddy's state.
func (s *Store) SetBuddyState(ctx context.Context, id int64, st BuddyState) error {
	return s.update(ctx, "UPDATE buddies SET state = ? WHERE id = ?", string(st), id)
}

// SetBuddyVerified records that the user checked the buddy's key.
func (s *Store) SetBuddyVerified(ctx context.Context, id int64, verified bool) error {
	return s.update(ctx, "UPDATE buddies SET verified = ? WHERE id = ?", verified, id)
}

// DeleteBuddy removes a buddy with its outbox and history.
func (s *Store) DeleteBuddy(ctx context.Context, id int64) error {
	return s.update(ctx, "DELETE FROM buddies WHERE id = ?", id)
}

// update runs a statement that must change exactly one row.
func (s *Store) update(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	switch n, _ := res.RowsAffected(); n {
	case 0:
		return ErrNotFound
	case 1:
		return nil
	default:
		return fmt.Errorf("store: %d rows changed, want 1", n)
	}
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
