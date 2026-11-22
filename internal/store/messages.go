package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/aghman/openaim/internal/frame"
)

// OutState is an outgoing message's delivery state.
type OutState string

const (
	Queued OutState = "queued" // not yet fully acked; the router keeps sending
	Acked  OutState = "acked"  // every fragment acked
	Failed OutState = "failed" // given up on
)

// Outgoing is a sealed message in the outbox. Frames are exactly the bytes
// produced at seal time.
type Outgoing struct {
	ID          int64
	BuddyID     int64
	Tag         frame.ConvTag
	MsgID       frame.MsgID
	Layout      frame.Layout
	ContentType frame.ContentType
	Seq         uint64
	State       OutState
	AckedMask   uint16
	Attempts    int
	CreatedAt   time.Time
	LastAttempt time.Time // zero if never sent
	Frames      [][]byte
}

// SealFunc builds and seals a message once it has been given its seq. It
// runs inside the transaction that allocates the seq.
type SealFunc func(seq uint64) (sealed *frame.Sealed, ct frame.ContentType, err error)

// Enqueue allocates the buddy's next send seq, seals the message with it and
// persists the frames, all in one transaction (design §8.2, seal once).
//
// Frames must not leave the process before Enqueue returns: if the process
// dies mid-transaction, nothing was sent, the seq is not consumed and the
// message can be sealed again from scratch.
func (s *Store) Enqueue(ctx context.Context, buddyID int64, seal SealFunc) (*Outgoing, error) {
	var out *Outgoing
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var seq uint64
		err := tx.QueryRowContext(ctx, "UPDATE buddies SET send_seq = send_seq + 1 WHERE id = ? RETURNING send_seq", buddyID).Scan(&seq)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		sealed, ct, err := seal(seq)
		if err != nil {
			return err
		}
		if len(sealed.Frames) == 0 || len(sealed.Frames) > 16 {
			return fmt.Errorf("store: sealed message has %d frames", len(sealed.Frames))
		}
		now := time.Now()
		res, err := tx.ExecContext(ctx,
			`INSERT INTO outbox (buddy_id, conv_tag, msg_id, layout, content_type, seq, frag_count, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			buddyID, sealed.Tag[:], sealed.MsgID[:], int(sealed.Layout), int(ct), seq, len(sealed.Frames), now.UnixMilli())
		if err != nil {
			return err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		for i, f := range sealed.Frames {
			if _, err := tx.ExecContext(ctx, "INSERT INTO outbox_frames (outbox_id, idx, frame) VALUES (?, ?, ?)", id, i, f); err != nil {
				return err
			}
		}
		out = &Outgoing{ID: id, BuddyID: buddyID, Tag: sealed.Tag, MsgID: sealed.MsgID, Layout: sealed.Layout,
			ContentType: ct, Seq: seq, State: Queued, CreatedAt: time.UnixMilli(now.UnixMilli()), Frames: sealed.Frames}
		return nil
	})
	return out, err
}

const outCols = "id, buddy_id, conv_tag, msg_id, layout, content_type, seq, state, acked_mask, attempts, created_at, last_attempt"

func scanOut(row interface{ Scan(...any) error }) (Outgoing, error) {
	var o Outgoing
	var tag, id []byte
	var layout, ct int
	var created int64
	var last sql.NullInt64
	if err := row.Scan(&o.ID, &o.BuddyID, &tag, &id, &layout, &ct, &o.Seq, &o.State, &o.AckedMask, &o.Attempts, &created, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return o, ErrNotFound
		}
		return o, err
	}
	copy(o.Tag[:], tag)
	copy(o.MsgID[:], id)
	o.Layout, o.ContentType = frame.Layout(layout), frame.ContentType(ct)
	o.CreatedAt = time.UnixMilli(created)
	if last.Valid {
		o.LastAttempt = time.UnixMilli(last.Int64)
	}
	return o, nil
}

func (s *Store) loadFrames(ctx context.Context, o *Outgoing) error {
	rows, err := s.db.QueryContext(ctx, "SELECT frame FROM outbox_frames WHERE outbox_id = ? ORDER BY idx", o.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var f []byte
		if err := rows.Scan(&f); err != nil {
			return err
		}
		o.Frames = append(o.Frames, f)
	}
	return rows.Err()
}

// Outgoing returns one outbox entry with its frames.
func (s *Store) Outgoing(ctx context.Context, id int64) (*Outgoing, error) {
	o, err := scanOut(s.db.QueryRowContext(ctx, "SELECT "+outCols+" FROM outbox WHERE id = ?", id))
	if err != nil {
		return nil, err
	}
	return &o, s.loadFrames(ctx, &o)
}

// Pending lists a buddy's queued messages, oldest first, with their frames.
func (s *Store) Pending(ctx context.Context, buddyID int64) ([]*Outgoing, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+outCols+" FROM outbox WHERE buddy_id = ? AND state = 'queued' ORDER BY id", buddyID)
	if err != nil {
		return nil, err
	}
	var out []*Outgoing
	for rows.Next() {
		o, err := scanOut(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, &o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, o := range out {
		if err := s.loadFrames(ctx, o); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RecordAttempt notes that the message's frames were sent (again).
func (s *Store) RecordAttempt(ctx context.Context, id int64, at time.Time) error {
	return s.update(ctx, "UPDATE outbox SET attempts = attempts + 1, last_attempt = ? WHERE id = ?", at.UnixMilli(), id)
}

// Ack merges an ACK's fragment bitmap into the message identified by its tag
// and msg_id, marking it acked once every fragment is. It returns the
// updated entry (without frames), or ErrNotFound for an ack of something we
// never sent.
func (s *Store) Ack(ctx context.Context, tag frame.ConvTag, msgID frame.MsgID, mask uint16) (*Outgoing, error) {
	o, err := scanOut(s.db.QueryRowContext(ctx,
		`UPDATE outbox SET
		   acked_mask = acked_mask | (? & ((1 << frag_count) - 1)),
		   state = CASE WHEN state = 'queued' AND (acked_mask | ?) & ((1 << frag_count) - 1) = (1 << frag_count) - 1
		                THEN 'acked' ELSE state END
		 WHERE conv_tag = ? AND msg_id = ?
		 RETURNING `+outCols, mask, mask, tag[:], msgID[:]))
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// MarkFailed stops the router from sending a message again.
func (s *Store) MarkFailed(ctx context.Context, id int64) error {
	return s.update(ctx, "UPDATE outbox SET state = 'failed' WHERE id = ? AND state = 'queued'", id)
}

// Incoming is a delivered message in the history.
type Incoming struct {
	ID         int64
	BuddyID    int64
	Tag        frame.ConvTag
	MsgID      frame.MsgID
	Inner      frame.Inner
	ReceivedAt time.Time
}

// SaveIncoming records a delivered message. It reports false if the message
// (by tag and msg_id) was already stored.
func (s *Store) SaveIncoming(ctx context.Context, buddyID int64, m *frame.Message, at time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO inbox (buddy_id, conv_tag, msg_id, content_type, flags, sent_ts, seq, body, received_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (conv_tag, msg_id) DO NOTHING`,
		buddyID, m.Tag[:], m.MsgID[:], int(m.Inner.Type), int(m.Inner.Flags), m.Inner.Time, m.Inner.Seq, m.Inner.Body, at.UnixMilli())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// History returns up to limit of a buddy's most recent incoming messages,
// oldest first.
func (s *Store) History(ctx context.Context, buddyID int64, limit int) ([]Incoming, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT * FROM (SELECT id, buddy_id, conv_tag, msg_id, content_type, flags, sent_ts, seq, body, received_at
		 FROM inbox WHERE buddy_id = ? ORDER BY received_at DESC, id DESC LIMIT ?) ORDER BY received_at, id`, buddyID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incoming
	for rows.Next() {
		var m Incoming
		var tag, id []byte
		var ct, flags int
		var at int64
		if err := rows.Scan(&m.ID, &m.BuddyID, &tag, &id, &ct, &flags, &m.Inner.Time, &m.Inner.Seq, &m.Inner.Body, &at); err != nil {
			return nil, err
		}
		copy(m.Tag[:], tag)
		copy(m.MsgID[:], id)
		m.Inner.Type, m.Inner.Flags = frame.ContentType(ct), frame.Flags(flags)
		m.ReceivedAt = time.UnixMilli(at)
		out = append(out, m)
	}
	return out, rows.Err()
}

// Dedup is a persistent frame.Dedup backed by the store.
type Dedup struct {
	s *Store
	// OnError is called if the database fails. The fragment is then treated
	// as a duplicate (dropped): failing closed avoids processing replays.
	OnError func(error)
}

// Dedup returns the store's frame.Dedup.
func (s *Store) Dedup() *Dedup { return &Dedup{s: s} }

var _ frame.Dedup = (*Dedup)(nil)

// Insert records id and reports whether it is new within frame.DedupTTL. A
// single upsert makes it atomic: an existing entry is refreshed only if it
// has expired, and changes() tells the two cases apart.
func (d *Dedup) Insert(id frame.FragmentID, now time.Time) bool {
	res, err := d.s.db.Exec(
		`INSERT INTO dedup (conv_tag, msg_id, frag, seen_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT (conv_tag, msg_id, frag) DO UPDATE SET seen_at = excluded.seen_at WHERE dedup.seen_at <= ?`,
		id.Tag[:], id.MsgID[:], int(id.Frag), now.UnixMilli(), now.Add(-frame.DedupTTL).UnixMilli())
	if err == nil {
		var n int64
		if n, err = res.RowsAffected(); err == nil {
			return n == 1
		}
	}
	if d.OnError != nil {
		d.OnError(err)
	}
	return false
}

// ExpireDedup deletes entries older than frame.DedupTTL and returns how many.
func (s *Store) ExpireDedup(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM dedup WHERE seen_at <= ?", now.Add(-frame.DedupTTL).UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
