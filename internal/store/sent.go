package store

import (
	"context"

	"github.com/aghman/openaim/internal/frame"
)

// Read-only outbox queries for the client API (chat history, status).

// SentHistory returns up to limit of a buddy's most recent outbox entries of
// content type ct, in any state, oldest first, with their frames.
func (s *Store) SentHistory(ctx context.Context, buddyID int64, ct frame.ContentType, limit int) ([]*Outgoing, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT * FROM (SELECT `+outCols+` FROM outbox WHERE buddy_id = ? AND content_type = ?
		 ORDER BY created_at DESC, id DESC LIMIT ?) ORDER BY created_at, id`, buddyID, int(ct), limit)
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
	// The store has a single connection, so frames are loaded after the
	// first query's rows are closed.
	for _, o := range out {
		if err := s.loadFrames(ctx, o); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CountOutgoing returns how many outbox entries, across all buddies, are in
// state st.
func (s *Store) CountOutgoing(ctx context.Context, st OutState) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM outbox WHERE state = ?", string(st)).Scan(&n)
	return n, err
}
