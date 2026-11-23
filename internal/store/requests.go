package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
)

// Buddy requests (migration 0003): sealed first contacts we sent, requests
// we received, and what buddies told us about themselves.

// RequestState is where a request we sent stands.
type RequestState string

const (
	RequestQueued   RequestState = "queued"   // never handed to a transport
	RequestSent     RequestState = "sent"     // handed to a transport at least once
	RequestAnswered RequestState = "answered" // their BUDDY_ACCEPT arrived
	RequestFailed   RequestState = "failed"   // given up on
)

// OutRequest is a sealed FIRST_CONTACT we sent. Frames are exactly the bytes
// produced at seal time.
type OutRequest struct {
	ID          int64
	BuddyID     int64
	E           [32]byte
	MsgID       frame.MsgID
	Layout      frame.Layout
	ContactHint string // where to send it, or ""
	SentTS      uint32 // inner timestamp (OpenAIM-epoch seconds)
	State       RequestState
	Attempts    int
	CreatedAt   time.Time
	LastAttempt time.Time // zero if never sent
	LastError   string
	Frames      [][]byte
}

// insertBuddy inserts b and returns its ID, or ErrDuplicate.
func insertBuddy(ctx context.Context, tx *sql.Tx, b Buddy) (int64, error) {
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
	res, err := tx.ExecContext(ctx,
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

func insertRequest(ctx context.Context, tx *sql.Tx, buddyID int64, r *OutRequest) error {
	if n := len(r.Frames); n == 0 || n > 2 {
		return fmt.Errorf("store: first contact with %d frames", n)
	}
	now := time.Now()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO request_out (buddy_id, e, msg_id, layout, frag_count, contact_hint, sent_ts, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		buddyID, r.E[:], r.MsgID[:], int(r.Layout), len(r.Frames), nullString(r.ContactHint), r.SentTS, now.UnixMilli())
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	for i, f := range r.Frames {
		if _, err := tx.ExecContext(ctx, "INSERT INTO request_out_frames (request_id, idx, frame) VALUES (?, ?, ?)", id, i, f); err != nil {
			return err
		}
	}
	r.ID, r.BuddyID, r.State, r.CreatedAt = id, buddyID, RequestQueued, time.UnixMilli(now.UnixMilli())
	return nil
}

// AddBuddyRequesting stores a new buddy, the handle check that vouched for
// its handle (if check is non-nil), and the sealed request to it (if r is
// non-nil), in one transaction: the frames are persisted before anything can
// send them. It fills in r's ID and state.
func (s *Store) AddBuddyRequesting(ctx context.Context, b Buddy, check *HandleCheck, r *OutRequest) (int64, error) {
	if check != nil {
		if b.Handle == "" {
			return 0, errors.New("store: a handle check needs a buddy with a handle")
		}
		if err := check.check(); err != nil {
			return 0, err
		}
	}
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if id, err = insertBuddy(ctx, tx, b); err != nil {
			return err
		}
		if check != nil {
			c := *check
			c.BuddyID = id
			if _, err := tx.ExecContext(ctx, upsertHandleCheck, c.args()...); err != nil {
				return err
			}
		}
		if r != nil {
			return insertRequest(ctx, tx, id, r)
		}
		return nil
	})
	return id, err
}

// AddRequest stores another sealed request to an existing buddy.
func (s *Store) AddRequest(ctx context.Context, buddyID int64, r *OutRequest) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return insertRequest(ctx, tx, buddyID, r) })
}

const reqCols = "id, buddy_id, e, msg_id, layout, contact_hint, sent_ts, state, attempts, created_at, last_attempt, last_error"

func (s *Store) requests(ctx context.Context, where string, args ...any) ([]*OutRequest, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+reqCols+" FROM request_out WHERE "+where+" ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	var out []*OutRequest
	for rows.Next() {
		var r OutRequest
		var e, id []byte
		var layout int
		var hint, lastErr sql.NullString
		var created int64
		var last sql.NullInt64
		if err := rows.Scan(&r.ID, &r.BuddyID, &e, &id, &layout, &hint, &r.SentTS, &r.State, &r.Attempts, &created, &last, &lastErr); err != nil {
			rows.Close()
			return nil, err
		}
		copy(r.E[:], e)
		copy(r.MsgID[:], id)
		r.Layout, r.ContactHint, r.LastError = frame.Layout(layout), hint.String, lastErr.String
		r.CreatedAt = time.UnixMilli(created)
		if last.Valid {
			r.LastAttempt = time.UnixMilli(last.Int64)
		}
		out = append(out, &r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// One connection: load frames after the first query's rows are closed.
	for _, r := range out {
		fr, err := s.db.QueryContext(ctx, "SELECT frame FROM request_out_frames WHERE request_id = ? ORDER BY idx", r.ID)
		if err != nil {
			return nil, err
		}
		for fr.Next() {
			var f []byte
			if err := fr.Scan(&f); err != nil {
				fr.Close()
				return nil, err
			}
			r.Frames = append(r.Frames, f)
		}
		fr.Close()
		if err := fr.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Requests lists the requests we sent a buddy, oldest first, with frames.
func (s *Store) Requests(ctx context.Context, buddyID int64) ([]*OutRequest, error) {
	return s.requests(ctx, "buddy_id = ?", buddyID)
}

// UnansweredRequests lists every request still queued or sent, oldest
// first, with frames: what to (re)send.
func (s *Store) UnansweredRequests(ctx context.Context) ([]*OutRequest, error) {
	return s.requests(ctx, "state IN ('queued', 'sent')")
}

// RecordRequestAttempt notes an attempt to send a request: errText is ""
// when a transport took it (the request becomes sent), else why not.
func (s *Store) RecordRequestAttempt(ctx context.Context, id int64, at time.Time, errText string) error {
	return s.update(ctx,
		`UPDATE request_out SET attempts = attempts + 1, last_attempt = ?, last_error = ?,
		 state = CASE WHEN ? = '' AND state = 'queued' THEN 'sent' ELSE state END WHERE id = ?`,
		at.UnixMilli(), nullString(errText), errText, id)
}

// SetRequestsState moves a buddy's unanswered requests to st (answered or
// failed) and returns how many changed.
func (s *Store) SetRequestsState(ctx context.Context, buddyID int64, st RequestState) (int64, error) {
	res, err := s.db.ExecContext(ctx, "UPDATE request_out SET state = ? WHERE buddy_id = ? AND state IN ('queued', 'sent')", string(st), buddyID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// InRequest is a merged buddy request we received.
type InRequest struct {
	BuddyID     int64
	DisplayName string
	Greeting    string
	SentTS      uint32 // latest request's inner timestamp
	FirstAt     time.Time
	LastAt      time.Time
	Count       int
	Transport   string
}

// ReceivedRequest is one incoming BUDDY_REQUEST to record.
type ReceivedRequest struct {
	DisplayName string
	Greeting    string
	SentTS      uint32
	At          time.Time
	Transport   string
	// RecoveryKey is pinned if the buddy has none yet (the caller has
	// checked it against the pinning rule). An already pinned one is never
	// replaced.
	RecoveryKey *identity.PublicKey
}

// RecordRequest records a request from key k. A new key becomes a
// pending_in buddy (with group); a known one has the request merged into
// its row: the count goes up, and the name and greeting follow the request
// with the latest inner timestamp. The buddy's state is never changed here.
// It returns the buddy and whether it was created.
func (s *Store) RecordRequest(ctx context.Context, k identity.PublicKey, group string, r ReceivedRequest) (Buddy, bool, error) {
	var b Buddy
	created := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		b, err = scanBuddy(tx.QueryRowContext(ctx, "SELECT "+buddyCols+" FROM buddies WHERE ed_key = ?", k[:]))
		switch {
		case errors.Is(err, ErrNotFound):
			b = Buddy{Key: k, Group: group, State: PendingIn, RecoveryKey: r.RecoveryKey, AddedAt: r.At}
			if b.ID, err = insertBuddy(ctx, tx, b); err != nil {
				return err
			}
			if b, err = scanBuddy(tx.QueryRowContext(ctx, "SELECT "+buddyCols+" FROM buddies WHERE id = ?", b.ID)); err != nil {
				return err
			}
			created = true
		case err != nil:
			return err
		case b.RecoveryKey == nil && r.RecoveryKey != nil:
			if _, err := tx.ExecContext(ctx, "UPDATE buddies SET recovery_key = ? WHERE id = ?", r.RecoveryKey[:], b.ID); err != nil {
				return err
			}
			k := *r.RecoveryKey
			b.RecoveryKey = &k
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO request_in (buddy_id, display_name, greeting, sent_ts, first_at, last_at, count, transport)
			 VALUES (?, ?, ?, ?, ?, ?, 1, ?)
			 ON CONFLICT (buddy_id) DO UPDATE SET
			   count = count + 1, last_at = excluded.last_at, transport = excluded.transport,
			   display_name = CASE WHEN excluded.sent_ts >= sent_ts THEN excluded.display_name ELSE display_name END,
			   greeting = CASE WHEN excluded.sent_ts >= sent_ts THEN excluded.greeting ELSE greeting END,
			   sent_ts = max(sent_ts, excluded.sent_ts)`,
			b.ID, r.DisplayName, r.Greeting, r.SentTS, r.At.UnixMilli(), r.At.UnixMilli(), r.Transport)
		return err
	})
	return b, created, err
}

const inReqCols = "buddy_id, display_name, greeting, sent_ts, first_at, last_at, count, transport"

func scanInRequest(row interface{ Scan(...any) error }) (InRequest, error) {
	var r InRequest
	var first, last int64
	if err := row.Scan(&r.BuddyID, &r.DisplayName, &r.Greeting, &r.SentTS, &first, &last, &r.Count, &r.Transport); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return r, ErrNotFound
		}
		return r, err
	}
	r.FirstAt, r.LastAt = time.UnixMilli(first), time.UnixMilli(last)
	return r, nil
}

// Request returns the merged request we received from buddy id, or
// ErrNotFound.
func (s *Store) Request(ctx context.Context, id int64) (InRequest, error) {
	return scanInRequest(s.db.QueryRowContext(ctx, "SELECT "+inReqCols+" FROM request_in WHERE buddy_id = ?", id))
}

// RequestsIn returns every request we received, by buddy ID.
func (s *Store) RequestsIn(ctx context.Context) (map[int64]InRequest, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+inReqCols+" FROM request_in")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]InRequest{}
	for rows.Next() {
		r, err := scanInRequest(rows)
		if err != nil {
			return nil, err
		}
		out[r.BuddyID] = r
	}
	return out, rows.Err()
}

// Peer is what a buddy told us about themselves (authenticated content
// only).
type Peer struct {
	BuddyID      int64
	DisplayName  string
	PresenceKey  []byte // 32 bytes, or nil
	Reach        []byte // REACH protobuf, or nil
	ReachSeq     uint64
	ReachExpires uint32 // OpenAIM-epoch seconds
	Caps         []byte // CAPS protobuf, or nil
	AcceptedAt   time.Time
	UpdatedAt    time.Time
}

// PeerUpdate changes parts of a buddy's Peer row. Nil fields are kept.
type PeerUpdate struct {
	DisplayName *string
	PresenceKey []byte
	// Reach replaces the held REACH only if it has a higher seq (or none is
	// held). The caller has checked it hasn't expired.
	Reach        []byte
	ReachSeq     uint64
	ReachExpires uint32
	Caps         []byte
	AcceptedAt   time.Time // zero keeps it
}

const peerCols = "buddy_id, display_name, presence_key, reach, reach_seq, reach_expires, caps, accepted_at, updated_at"

func scanPeer(row interface{ Scan(...any) error }) (Peer, error) {
	var p Peer
	var seq, expires, accepted sql.NullInt64
	var updated int64
	if err := row.Scan(&p.BuddyID, &p.DisplayName, &p.PresenceKey, &p.Reach, &seq, &expires, &p.Caps, &accepted, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return p, ErrNotFound
		}
		return p, err
	}
	p.ReachSeq, p.ReachExpires = uint64(seq.Int64), uint32(expires.Int64)
	if accepted.Valid {
		p.AcceptedAt = time.UnixMilli(accepted.Int64)
	}
	p.UpdatedAt = time.UnixMilli(updated)
	return p, nil
}

// Peer returns what buddy id told us, or ErrNotFound.
func (s *Store) Peer(ctx context.Context, id int64) (Peer, error) {
	return scanPeer(s.db.QueryRowContext(ctx, "SELECT "+peerCols+" FROM buddy_peer WHERE buddy_id = ?", id))
}

// UpdatePeer merges u into buddy id's Peer row at time at, and reports
// whether the REACH was taken.
func (s *Store) UpdatePeer(ctx context.Context, id int64, u PeerUpdate, at time.Time) (reachTaken bool, err error) {
	if u.PresenceKey != nil && len(u.PresenceKey) != 32 {
		return false, fmt.Errorf("store: presence key of %d bytes", len(u.PresenceKey))
	}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		p, err := scanPeer(tx.QueryRowContext(ctx, "SELECT "+peerCols+" FROM buddy_peer WHERE buddy_id = ?", id))
		if errors.Is(err, ErrNotFound) {
			p = Peer{BuddyID: id}
		} else if err != nil {
			return err
		}
		if u.DisplayName != nil {
			p.DisplayName = *u.DisplayName
		}
		if u.PresenceKey != nil {
			p.PresenceKey = u.PresenceKey
		}
		if u.Reach != nil && (p.Reach == nil || u.ReachSeq > p.ReachSeq) {
			p.Reach, p.ReachSeq, p.ReachExpires = u.Reach, u.ReachSeq, u.ReachExpires
			reachTaken = true
		}
		if u.Caps != nil {
			p.Caps = u.Caps
		}
		if !u.AcceptedAt.IsZero() {
			p.AcceptedAt = u.AcceptedAt
		}
		var seq, expires, accepted sql.NullInt64
		if p.Reach != nil {
			seq = sql.NullInt64{Int64: int64(p.ReachSeq), Valid: true}
			expires = sql.NullInt64{Int64: int64(p.ReachExpires), Valid: true}
		}
		if !p.AcceptedAt.IsZero() {
			accepted = sql.NullInt64{Int64: p.AcceptedAt.UnixMilli(), Valid: true}
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO buddy_peer (`+peerCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (buddy_id) DO UPDATE SET display_name = excluded.display_name, presence_key = excluded.presence_key,
			   reach = excluded.reach, reach_seq = excluded.reach_seq, reach_expires = excluded.reach_expires,
			   caps = excluded.caps, accepted_at = excluded.accepted_at, updated_at = excluded.updated_at`,
			id, p.DisplayName, p.PresenceKey, p.Reach, seq, expires, p.Caps, accepted, at.UnixMilli())
		return err
	})
	return reachTaken, err
}

// CountBuddies returns how many buddies are in state st.
func (s *Store) CountBuddies(ctx context.Context, st BuddyState) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM buddies WHERE state = ?", string(st)).Scan(&n)
	return n, err
}

// SetBuddyLabels changes a buddy's petname and group.
func (s *Store) SetBuddyLabels(ctx context.Context, id int64, petname, group string) error {
	if group == "" {
		group = "Buddies"
	}
	return s.update(ctx, "UPDATE buddies SET petname = ?, group_name = ? WHERE id = ?", nullString(petname), group, id)
}

// SetBuddyRecoveryKey pins a buddy's recovery key if none is pinned yet. It
// reports whether it did; an already pinned key is never replaced.
func (s *Store) SetBuddyRecoveryKey(ctx context.Context, id int64, k identity.PublicKey) (bool, error) {
	res, err := s.db.ExecContext(ctx, "UPDATE buddies SET recovery_key = ? WHERE id = ? AND recovery_key IS NULL", k[:], id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
