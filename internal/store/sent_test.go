package store

import (
	"testing"

	"github.com/aghman/openaim/internal/frame"
)

func TestSentHistoryAndCount(t *testing.T) {
	s := open(t, ":memory:")
	b := addBuddy(t, s, 2)
	other := addBuddy(t, s, 3)
	k := frame.NewConvKey([32]byte{9})
	var ids []frame.MsgID
	for _, body := range []string{"one", "two", "three"} {
		o, err := s.Enqueue(ctx, b, sealIM(k, body))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, o.MsgID)
	}
	if _, err := s.Enqueue(ctx, other, sealIM(k, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ack(ctx, b, ids[0], 1); err != nil {
		t.Fatal(err)
	}

	got, err := s.SentHistory(ctx, b, frame.IM, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].MsgID != ids[1] || got[1].MsgID != ids[2] || len(got[0].Frames) == 0 {
		t.Fatalf("last two: %+v", got)
	}
	all, err := s.SentHistory(ctx, b, frame.IM, 10)
	if err != nil || len(all) != 3 || all[0].State != Acked || all[0].MsgID != ids[0] {
		t.Fatalf("all: %+v %v", all, err)
	}
	if none, err := s.SentHistory(ctx, b, frame.Presence, 10); err != nil || len(none) != 0 {
		t.Fatalf("other content type: %v %v", none, err)
	}

	if n, err := s.CountOutgoing(ctx, Queued); err != nil || n != 3 {
		t.Fatalf("queued count %d %v", n, err)
	}
	if n, err := s.CountOutgoing(ctx, Acked); err != nil || n != 1 {
		t.Fatalf("acked count %d %v", n, err)
	}
}
