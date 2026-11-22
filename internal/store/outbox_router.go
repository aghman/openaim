package store

import (
	"context"

	"github.com/aghman/openaim/internal/frame"
)

// Outbox queries for the router (internal/router): which buddies have work
// after a restart, the send queue without frame bytes, and ACK matching.

// PendingBuddies returns the IDs of the buddies that have queued messages,
// in ascending order.
func (s *Store) PendingBuddies(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT DISTINCT buddy_id FROM outbox WHERE state = 'queued' ORDER BY buddy_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// PendingMeta lists a buddy's queued messages, oldest first, like Pending
// but without their frames (Frames is nil). FragCount is set.
func (s *Store) PendingMeta(ctx context.Context, buddyID int64) ([]*OutgoingMeta, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+outCols+", frag_count FROM outbox WHERE buddy_id = ? AND state = 'queued' ORDER BY id", buddyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OutgoingMeta
	for rows.Next() {
		var m OutgoingMeta
		o, err := scanOut(scanTail{rows, &m.FragCount})
		if err != nil {
			return nil, err
		}
		m.Outgoing = o
		out = append(out, &m)
	}
	return out, rows.Err()
}

// OutgoingMeta is an outbox entry without its frames, plus its fragment
// count.
type OutgoingMeta struct {
	Outgoing
	FragCount int
}

// OutgoingByMsgID returns the outbox entry (without frames) of the message
// with msgID sent to the buddy, or ErrNotFound. ACKs name messages by msg_id
// only (spec/wire.md §6.1), so the lookup is per buddy.
func (s *Store) OutgoingByMsgID(ctx context.Context, buddyID int64, msgID frame.MsgID) (*OutgoingMeta, error) {
	var m OutgoingMeta
	o, err := scanOut(scanTail{s.db.QueryRowContext(ctx,
		"SELECT "+outCols+", frag_count FROM outbox WHERE buddy_id = ? AND msg_id = ?", buddyID, msgID[:]), &m.FragCount})
	if err != nil {
		return nil, err
	}
	m.Outgoing = o
	return &m, nil
}

// scanTail scans outCols with scanOut plus extra trailing columns.
type scanTail struct {
	row   interface{ Scan(...any) error }
	extra any
}

func (t scanTail) Scan(dest ...any) error { return t.row.Scan(append(dest, t.extra)...) }
