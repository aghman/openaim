package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/frame"
)

// TestConversationOrder: messages stored within one millisecond, in both
// directions, come back in insertion order, and limit takes the newest.
func TestConversationOrder(t *testing.T) {
	s := open(t, ":memory:")
	bid := addBuddy(t, s, 1)
	other := addBuddy(t, s, 2)
	k := frame.NewConvKey([32]byte{7})
	var want []string
	for i := range 20 {
		if i%3 == 1 {
			// Incoming, all with the same received_at millisecond.
			in := frame.Inner{Type: frame.IM, Time: frame.Timestamp(testNow), Seq: uint64(i), Body: fmt.Appendf(nil, "in %d", i)}
			m := &frame.Message{Tag: frame.ConvTag{byte(i)}, MsgID: frame.MsgID{byte(i)}, Inner: in}
			if ok, err := s.SaveIncoming(ctx, bid, m, testNow); err != nil || !ok {
				t.Fatal(ok, err)
			}
			want = append(want, fmt.Sprintf("in %d", i))
			continue
		}
		if _, err := s.Enqueue(ctx, bid, sealIM(k, fmt.Sprintf("out %d", i))); err != nil {
			t.Fatal(err)
		}
		want = append(want, fmt.Sprintf("out %d", i))
		// Another buddy's messages share the counter but not the history.
		if _, err := s.Enqueue(ctx, other, sealIM(k, "elsewhere")); err != nil {
			t.Fatal(err)
		}
	}
	text := func(e HistoryEntry) string {
		if e.In != nil {
			return string(e.In.Inner.Body)
		}
		in, err := openOne(k, e.Out.Frames)
		if err != nil {
			t.Fatal(err)
		}
		return string(in.Body)
	}
	for _, limit := range []int{100, 7} {
		got, err := s.Conversation(ctx, bid, frame.IM, limit)
		if err != nil {
			t.Fatal(err)
		}
		exp := want[max(0, len(want)-limit):]
		if len(got) != len(exp) {
			t.Fatalf("limit %d: %d entries, want %d", limit, len(got), len(exp))
		}
		for i, e := range got {
			if (e.In == nil) == (e.Out == nil) {
				t.Fatalf("entry %d has In %v and Out %v", i, e.In, e.Out)
			}
			if i > 0 && e.Ord <= got[i-1].Ord {
				t.Fatalf("ord not increasing at %d", i)
			}
			if g := text(e); g != exp[i] {
				t.Fatalf("limit %d, entry %d: %q, want %q", limit, i, g, exp[i])
			}
		}
	}
}

func openOne(k frame.ConvKey, frames [][]byte) (frame.Inner, error) {
	h, err := frame.ParseHeader(frames[0])
	if err != nil {
		return frame.Inner{}, err
	}
	pt, err := frame.OpenFragment(k, h, frames[0])
	if err != nil {
		return frame.Inner{}, err
	}
	return frame.ParseInner(pt)
}

// TestMigration0004Backfill: rows written by schema 3 get an order from
// their store times, and new rows continue after them.
func TestMigration0004Backfill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openaim.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		name, err := fsGlobOne(i)
		if err != nil {
			t.Fatal(err)
		}
		b, err := migrations.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatal(err)
		}
	}
	k1 := key(t, 1)
	stmts := []struct {
		q    string
		args []any
	}{
		{"PRAGMA user_version = 3", nil},
		{"INSERT INTO buddies (id, ed_key, state, added_at) VALUES (1, ?, 'accepted', 1)", []any{k1[:]}},
		// Outgoing at 2000 and 4000, incoming at 3000 and (a tie) 4000.
		{`INSERT INTO outbox (id, buddy_id, conv_tag, msg_id, layout, content_type, seq, frag_count, created_at)
		  VALUES (1, 1, x'0000000000000001', x'0000000000000001', 1, 1, 1, 1, 2000),
		         (2, 1, x'0000000000000002', x'0000000000000002', 1, 1, 2, 1, 4000)`, nil},
		{`INSERT INTO inbox (id, buddy_id, conv_tag, msg_id, content_type, flags, sent_ts, seq, body, received_at)
		  VALUES (1, 1, x'01', x'01', 1, 0, 0, 1, 'a', 4000),
		         (2, 1, x'02', x'02', 1, 0, 0, 2, 'b', 3000)`, nil},
	}
	for _, st := range stmts {
		if _, err := db.Exec(st.q, st.args...); err != nil {
			t.Fatalf("%s: %v", st.q, err)
		}
	}
	db.Close()

	s := open(t, path)
	ords := func(table string) map[int64]int64 {
		rows, err := s.db.Query("SELECT id, ord FROM " + table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		m := map[int64]int64{}
		for rows.Next() {
			var id, ord int64
			if err := rows.Scan(&id, &ord); err != nil {
				t.Fatal(err)
			}
			m[id] = ord
		}
		return m
	}
	out, in := ords("outbox"), ords("inbox")
	// 2000 out#1, 3000 in#2, 4000 out#2 then in#1 (outgoing first on a tie).
	if out[1] != 1 || in[2] != 2 || out[2] != 3 || in[1] != 4 {
		t.Fatalf("backfilled order: outbox %v, inbox %v", out, in)
	}
	m := &frame.Message{Tag: frame.ConvTag{9}, MsgID: frame.MsgID{9}, Inner: frame.Inner{Type: frame.IM, Body: []byte("c")}}
	if _, err := s.SaveIncoming(ctx, 1, m, time.UnixMilli(1)); err != nil {
		t.Fatal(err)
	}
	if in := ords("inbox"); in[3] != 5 {
		t.Fatalf("new row's ord %d, want 5", in[3])
	}
}

// fsGlobOne returns migration n's file name.
func fsGlobOne(n int) (string, error) {
	names, err := migrations.ReadDir("migrations")
	if err != nil {
		return "", err
	}
	for _, e := range names {
		if len(e.Name()) > 4 && e.Name()[:4] == fmt.Sprintf("%04d", n) {
			return "migrations/" + e.Name(), nil
		}
	}
	return "", fmt.Errorf("no migration %d", n)
}
