package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMigration0002KeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openaim.db")

	// Build a schema-1 database by hand, as an older daemon left it.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	init1, err := migrations.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	k1, k2 := key(t, 1), key(t, 2)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{string(init1), nil},
		{"PRAGMA user_version = 1", nil},
		{"INSERT INTO meta (key, value) VALUES ('identity_key', x'0102')", nil},
		{"INSERT INTO buddies (ed_key, handle, petname, state, added_at) VALUES (?, 'alice.example.com', 'Alice', 'accepted', 1000)", []any{k1[:]}},
		{"INSERT INTO buddies (ed_key, petname, state, added_at) VALUES (?, 'Bob', 'pending_out', 2000)", []any{k2[:]}},
	} {
		if _, err := db.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	db.Close()

	s := open(t, path)
	if v, err := s.SchemaVersion(ctx); err != nil || v != 4 {
		t.Fatalf("schema version %d, %v", v, err)
	}
	if v, err := s.Meta(ctx, "identity_key"); err != nil || string(v) != "\x01\x02" {
		t.Fatalf("meta: %x %v", v, err)
	}
	all, err := s.Buddies(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("buddies: %+v %v", all, err)
	}
	alice, err := s.BuddyByKey(ctx, k1)
	if err != nil || alice.Handle != "alice.example.com" || alice.Petname != "Alice" || alice.State != Accepted || alice.AddedAt.UnixMilli() != 1000 {
		t.Fatalf("alice: %+v %v", alice, err)
	}
	// A migrated buddy with a handle has no check yet, so it is due now.
	if _, err := s.HandleCheck(ctx, alice.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("check before any: %v", err)
	}
	due, err := s.DueHandleChecks(ctx, time.UnixMilli(1), 10)
	if err != nil || len(due) != 1 || due[0].ID != alice.ID {
		t.Fatalf("due: %+v %v", due, err)
	}
	if next, ok, err := s.NextHandleCheck(ctx); err != nil || !ok || !next.IsZero() {
		t.Fatalf("next: %v %v %v", next, ok, err)
	}
}

func TestHandleChecks(t *testing.T) {
	s := open(t, ":memory:")
	if _, ok, err := s.NextHandleCheck(ctx); err != nil || ok {
		t.Fatalf("next with no handles: %v %v", ok, err)
	}
	moved := key(t, 9)
	c := HandleCheck{
		Status: HandleVerified, LastResult: HandleVerified,
		CheckedAt: testNow, VerifiedAt: testNow, NextCheck: testNow.Add(30 * 24 * time.Hour),
		InboxHint: "/dns/inbox.example.com/tcp/4001",
	}
	id, err := s.AddBuddyWithHandleCheck(ctx, Buddy{Key: key(t, 1), Handle: "alice.example.com", State: PendingOut, AddedAt: testNow}, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddBuddyWithHandleCheck(ctx, Buddy{Key: key(t, 1), Handle: "x.example.com", State: PendingOut}, c); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.AddBuddyWithHandleCheck(ctx, Buddy{Key: key(t, 3), State: PendingOut}, c); err == nil {
		t.Fatal("check stored for a buddy without a handle")
	}
	got, err := s.HandleCheck(ctx, id)
	c.BuddyID = id
	if err != nil || got.Status != c.Status || got.LastResult != c.LastResult || !got.CheckedAt.Equal(c.CheckedAt) ||
		!got.VerifiedAt.Equal(c.VerifiedAt) || !got.NextCheck.Equal(c.NextCheck) || got.MovedKey != nil || got.InboxHint != c.InboxHint || got.Error != "" {
		t.Fatalf("got %+v, %v; want %+v", got, err, c)
	}

	// A buddy without a handle is never due; one with a handle is due once
	// its time comes.
	plain := addBuddy(t, s, 2)
	if err := s.SetHandleCheck(ctx, HandleCheck{BuddyID: plain, LastResult: HandleVerified, CheckedAt: testNow, NextCheck: testNow}); err == nil {
		t.Fatal("check stored for a buddy without a handle")
	}
	if err := s.SetHandleCheck(ctx, HandleCheck{BuddyID: 999, LastResult: HandleVerified, CheckedAt: testNow, NextCheck: testNow}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing buddy: %v", err)
	}
	if due, err := s.DueHandleChecks(ctx, testNow.Add(29*24*time.Hour), 10); err != nil || len(due) != 0 {
		t.Fatalf("due early: %+v %v", due, err)
	}
	if due, err := s.DueHandleChecks(ctx, c.NextCheck, 10); err != nil || len(due) != 1 || due[0].ID != id || due[0].Handle != "alice.example.com" {
		t.Fatalf("due: %+v %v", due, err)
	}
	if next, ok, err := s.NextHandleCheck(ctx); err != nil || !ok || !next.Equal(c.NextCheck) {
		t.Fatalf("next: %v %v %v", next, ok, err)
	}

	// Moved: the status and moved key change, the verified time stays.
	later := testNow.Add(31 * 24 * time.Hour)
	m := got
	m.Status, m.LastResult, m.CheckedAt, m.NextCheck, m.MovedKey, m.Error = HandleMoved, HandleMoved, later, later.Add(24*time.Hour), &moved, "points elsewhere"
	if err := s.SetHandleCheck(ctx, m); err != nil {
		t.Fatal(err)
	}
	all, err := s.HandleChecks(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("all: %v %v", all, err)
	}
	if g := all[id]; g.Status != HandleMoved || *g.MovedKey != moved || !g.VerifiedAt.Equal(testNow) || g.Error != "points elsewhere" {
		t.Fatalf("after move: %+v", g)
	}
	// The pin is untouched.
	if b, err := s.Buddy(ctx, id); err != nil || b.Key != key(t, 1) {
		t.Fatalf("pin changed: %+v %v", b, err)
	}

	for _, bad := range []HandleCheck{
		{BuddyID: id, Status: HandleUnreachable, LastResult: HandleUnreachable, CheckedAt: later, NextCheck: later},
		{BuddyID: id, LastResult: "", CheckedAt: later, NextCheck: later},
		{BuddyID: id, LastResult: HandleVerified},
	} {
		if err := s.SetHandleCheck(ctx, bad); err == nil {
			t.Errorf("stored %+v", bad)
		}
	}

	// Deleting the buddy deletes its check.
	if err := s.DeleteBuddy(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HandleCheck(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("check after delete: %v", err)
	}
}
