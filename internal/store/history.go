package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/aghman/openaim/internal/frame"
)

// HistoryEntry is one message of a conversation: exactly one of In and Out
// is set. Ord is its place in the conversation (migration 0004): a counter
// shared by the inbox and the outbox, taken when the row was inserted, so
// two entries never tie.
type HistoryEntry struct {
	Ord int64
	In  *Incoming // a delivered message
	Out *Outgoing // a message we sealed, with its frames
}

// Conversation returns up to limit of the most recent messages of content
// type ct exchanged with a buddy, both directions, oldest first, in the
// order they entered this store.
func (s *Store) Conversation(ctx context.Context, buddyID int64, ct frame.ContentType, limit int) ([]HistoryEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT * FROM (
		   SELECT 0 AS dir, id, ord FROM outbox WHERE buddy_id = ? AND content_type = ?
		   UNION ALL
		   SELECT 1 AS dir, id, ord FROM inbox WHERE buddy_id = ? AND content_type = ?
		   ORDER BY ord DESC LIMIT ?
		 ) ORDER BY ord`, buddyID, int(ct), buddyID, int(ct), limit)
	if err != nil {
		return nil, err
	}
	type ref struct {
		out bool
		id  int64
		ord int64
	}
	var refs []ref
	for rows.Next() {
		var dir int
		var r ref
		if err := rows.Scan(&dir, &r.id, &r.ord); err != nil {
			rows.Close()
			return nil, err
		}
		r.out = dir == 0
		refs = append(refs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The store has a single connection: load each row once the first
	// query's rows are closed.
	out := make([]HistoryEntry, 0, len(refs))
	for _, r := range refs {
		e := HistoryEntry{Ord: r.ord}
		var err error
		if r.out {
			e.Out, err = s.Outgoing(ctx, r.id)
		} else {
			e.In, err = s.incoming(ctx, r.id)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *Store) incoming(ctx context.Context, id int64) (*Incoming, error) {
	var m Incoming
	var tag, msgID []byte
	var ct, flags int
	var at int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, buddy_id, conv_tag, msg_id, content_type, flags, sent_ts, seq, body, received_at
		 FROM inbox WHERE id = ?`, id).
		Scan(&m.ID, &m.BuddyID, &tag, &msgID, &ct, &flags, &m.Inner.Time, &m.Inner.Seq, &m.Inner.Body, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	copy(m.Tag[:], tag)
	copy(m.MsgID[:], msgID)
	m.Inner.Type, m.Inner.Flags = frame.ContentType(ct), frame.Flags(flags)
	m.ReceivedAt = time.UnixMilli(at)
	return &m, nil
}
