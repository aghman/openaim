package store

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/frame"
)

func TestRequestsOut(t *testing.T) {
	s := open(t, ":memory:")
	k := key(t, 1)
	r := &OutRequest{E: [32]byte{1}, MsgID: frame.MsgID{2}, Layout: frame.LayoutMesh, ContactHint: "/dns4/x.example/tcp/1",
		SentTS: 100, Frames: [][]byte{{0x63, 1}, {0x63, 2}}}
	check := HandleCheck{Status: HandleVerified, LastResult: HandleVerified, CheckedAt: testNow, NextCheck: testNow.Add(time.Hour), InboxHint: "/dns4/i.example/tcp/1"}
	id, err := s.AddBuddyRequesting(ctx, Buddy{Key: k, Handle: "a.example.com", State: PendingOut}, &check, r)
	if err != nil || r.ID == 0 || r.State != RequestQueued || r.BuddyID != id {
		t.Fatalf("add: %+v %v", r, err)
	}
	if c, err := s.HandleCheck(ctx, id); err != nil || c.InboxHint != check.InboxHint {
		t.Fatalf("check %+v %v", c, err)
	}
	// A duplicate buddy stores no request either.
	r2 := &OutRequest{E: [32]byte{3}, MsgID: frame.MsgID{4}, Layout: frame.LayoutMesh, SentTS: 1, Frames: [][]byte{{1}}}
	if _, err := s.AddBuddyRequesting(ctx, Buddy{Key: k, State: PendingOut}, nil, r2); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.AddBuddyRequesting(ctx, Buddy{Key: key(t, 2), State: PendingOut}, nil, &OutRequest{Frames: make([][]byte, 3)}); err == nil {
		t.Fatal("three-frame first contact stored")
	}
	if bs, _ := s.Buddies(ctx); len(bs) != 1 {
		t.Fatalf("buddies %+v", bs)
	}
	rs, err := s.Requests(ctx, id)
	if err != nil || len(rs) != 1 || !bytes.Equal(rs[0].Frames[1], []byte{0x63, 2}) || rs[0].E != r.E || rs[0].MsgID != r.MsgID ||
		rs[0].ContactHint != r.ContactHint || rs[0].SentTS != 100 || rs[0].Layout != frame.LayoutMesh {
		t.Fatalf("requests %+v %v", rs, err)
	}
	if err := s.RecordRequestAttempt(ctx, r.ID, testNow, "no route"); err != nil {
		t.Fatal(err)
	}
	if rs, _ := s.Requests(ctx, id); rs[0].State != RequestQueued || rs[0].LastError != "no route" || rs[0].Attempts != 1 {
		t.Fatalf("after failure %+v", rs[0])
	}
	if err := s.RecordRequestAttempt(ctx, r.ID, testNow, ""); err != nil {
		t.Fatal(err)
	}
	if rs, _ := s.UnansweredRequests(ctx); len(rs) != 1 || rs[0].State != RequestSent || rs[0].LastError != "" || !rs[0].LastAttempt.Equal(testNow) {
		t.Fatalf("after send %+v", rs)
	}
	if n, err := s.SetRequestsState(ctx, id, RequestAnswered); err != nil || n != 1 {
		t.Fatalf("answer %d %v", n, err)
	}
	if rs, _ := s.UnansweredRequests(ctx); len(rs) != 0 {
		t.Fatalf("unanswered %+v", rs)
	}
	// Deleting the buddy deletes its requests.
	if err := s.DeleteBuddy(ctx, id); err != nil {
		t.Fatal(err)
	}
	if rs, _ := s.Requests(ctx, id); len(rs) != 0 {
		t.Fatal("requests outlived their buddy")
	}
}

func TestRequestsInMerge(t *testing.T) {
	s := open(t, ":memory:")
	k, rk, rk2 := key(t, 1), key(t, 2), key(t, 3)
	b, created, err := s.RecordRequest(ctx, k, "", ReceivedRequest{DisplayName: "Sam", Greeting: "hi", SentTS: 10, At: testNow, Transport: "mesh", RecoveryKey: &rk})
	if err != nil || !created || b.State != PendingIn || b.Group != "Buddies" || *b.RecoveryKey != rk {
		t.Fatalf("first %+v %v %v", b, created, err)
	}
	// A newer request updates the text; an older one only counts.
	if _, created, err = s.RecordRequest(ctx, k, "", ReceivedRequest{DisplayName: "Sam2", Greeting: "hello?", SentTS: 20, At: testNow.Add(time.Minute), RecoveryKey: &rk2}); err != nil || created {
		t.Fatalf("second %v %v", created, err)
	}
	if _, _, err = s.RecordRequest(ctx, k, "", ReceivedRequest{DisplayName: "Old", Greeting: "stale", SentTS: 5, At: testNow.Add(2 * time.Minute), Transport: "ip"}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Request(ctx, b.ID)
	if err != nil || r.Count != 3 || r.DisplayName != "Sam2" || r.Greeting != "hello?" || r.SentTS != 20 || r.Transport != "ip" ||
		!r.FirstAt.Equal(testNow) || !r.LastAt.Equal(testNow.Add(2*time.Minute)) {
		t.Fatalf("merged %+v %v", r, err)
	}
	// The first pinned recovery key stays.
	if got, _ := s.BuddyByKey(ctx, k); *got.RecoveryKey != rk {
		t.Fatal("recovery key replaced")
	}
	if ok, err := s.SetBuddyRecoveryKey(ctx, b.ID, rk2); err != nil || ok {
		t.Fatalf("SetBuddyRecoveryKey replaced a pin: %v %v", ok, err)
	}
	all, err := s.RequestsIn(ctx)
	if err != nil || len(all) != 1 || all[b.ID].Count != 3 {
		t.Fatalf("all %+v %v", all, err)
	}
	if n, err := s.CountBuddies(ctx, PendingIn); err != nil || n != 1 {
		t.Fatalf("count %d %v", n, err)
	}
	// A known buddy's state is never changed by a request.
	if err := s.SetBuddyState(ctx, b.ID, Accepted); err != nil {
		t.Fatal(err)
	}
	if b, _, _ = s.RecordRequest(ctx, k, "", ReceivedRequest{SentTS: 30, At: testNow}); b.State != Accepted {
		t.Fatalf("state %s", b.State)
	}
}

func TestPeerReachSeq(t *testing.T) {
	s := open(t, ":memory:")
	id, err := s.AddBuddy(ctx, Buddy{Key: key(t, 1), State: Accepted})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Peer(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("peer before any: %v", err)
	}
	name := "Ann"
	pk := bytes.Repeat([]byte{7}, 32)
	if took, err := s.UpdatePeer(ctx, id, PeerUpdate{DisplayName: &name, PresenceKey: pk, Reach: []byte("r5"), ReachSeq: 5, ReachExpires: 99}, testNow); err != nil || !took {
		t.Fatalf("first %v %v", took, err)
	}
	// A lower or equal seq is ignored; a higher one replaces.
	for _, seq := range []uint64{4, 5} {
		if took, err := s.UpdatePeer(ctx, id, PeerUpdate{Reach: []byte("old"), ReachSeq: seq, ReachExpires: 99}, testNow); err != nil || took {
			t.Fatalf("seq %d taken: %v %v", seq, took, err)
		}
	}
	if took, _ := s.UpdatePeer(ctx, id, PeerUpdate{Reach: []byte("r6"), ReachSeq: 6, ReachExpires: 100, AcceptedAt: testNow}, testNow); !took {
		t.Fatal("higher seq ignored")
	}
	p, err := s.Peer(ctx, id)
	if err != nil || p.DisplayName != "Ann" || !bytes.Equal(p.PresenceKey, pk) || string(p.Reach) != "r6" || p.ReachSeq != 6 ||
		p.ReachExpires != 100 || !p.AcceptedAt.Equal(testNow) {
		t.Fatalf("peer %+v %v", p, err)
	}
	if _, err := s.UpdatePeer(ctx, id, PeerUpdate{PresenceKey: []byte{1}}, testNow); err == nil {
		t.Fatal("short presence key stored")
	}
	if err := s.SetBuddyLabels(ctx, id, "Annie", ""); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.Buddy(ctx, id); b.Petname != "Annie" || b.Group != "Buddies" {
		t.Fatalf("labels %+v", b)
	}
	if err := s.SetBuddyLabels(ctx, 999, "x", "y"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("labels on a missing buddy: %v", err)
	}
}
