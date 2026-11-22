package store

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aghman/openaim/internal/frame"
)

func TestRouterQueries(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "db"))
	a, b, c := addBuddy(t, s, 1), addBuddy(t, s, 2), addBuddy(t, s, 3)
	k := frame.NewConvKey([32]byte{7})

	if ids, err := s.PendingBuddies(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("PendingBuddies on an empty outbox: %v %v", ids, err)
	}
	a1, err := s.Enqueue(ctx, a, sealIM(k, "one"))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := s.Enqueue(ctx, a, sealIM(k, strings.Repeat("x", 300))) // 2 fragments
	if err != nil {
		t.Fatal(err)
	}
	c1, err := s.Enqueue(ctx, c, sealIM(k, "three"))
	if err != nil {
		t.Fatal(err)
	}
	b1, err := s.Enqueue(ctx, b, sealIM(k, "two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ack(ctx, b, b1.MsgID, 1); err != nil { // b has nothing queued now
		t.Fatal(err)
	}
	if ids, err := s.PendingBuddies(ctx); err != nil || !slices.Equal(ids, []int64{a, c}) {
		t.Fatalf("PendingBuddies = %v, %v", ids, err)
	}

	if err := s.RecordAttempt(ctx, a1.ID, testNow); err != nil {
		t.Fatal(err)
	}
	meta, err := s.PendingMeta(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != 2 || meta[0].ID != a1.ID || meta[1].ID != a2.ID {
		t.Fatalf("PendingMeta = %+v", meta)
	}
	if meta[0].Frames != nil || meta[0].FragCount != 1 || meta[1].FragCount != 2 {
		t.Fatalf("PendingMeta frames/counts: %v %d %d", meta[0].Frames, meta[0].FragCount, meta[1].FragCount)
	}
	if meta[0].Attempts != 1 || !meta[0].LastAttempt.Equal(testNow) || meta[0].MsgID != a1.MsgID {
		t.Fatalf("PendingMeta[0] = %+v", meta[0])
	}

	m, err := s.OutgoingByMsgID(ctx, a, a2.MsgID)
	if err != nil || m.ID != a2.ID || m.FragCount != 2 || m.State != Queued {
		t.Fatalf("OutgoingByMsgID = %+v, %v", m, err)
	}
	if _, err := s.OutgoingByMsgID(ctx, b, c1.MsgID); !errors.Is(err, ErrNotFound) { // another buddy's
		t.Fatalf("OutgoingByMsgID across buddies: %v", err)
	}
	if _, err := s.OutgoingByMsgID(ctx, a, frame.MsgID{9}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OutgoingByMsgID unknown: %v", err)
	}
}
