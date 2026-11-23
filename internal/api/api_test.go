package api

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
)

// fast Argon2id costs (the minimum the keystore accepts), so tests don't
// spend a quarter second per unlock.
var fast = keystore.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1}

var testPass = []byte("correct horse battery staple")

// shortTempDir is a data dir with a short path: Unix socket paths are
// limited to about 104 bytes, and t.TempDir() paths on macOS run long.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "oa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// initDir creates an identity in a fresh data dir.
func initDir(t *testing.T) (string, *identity.Identity) {
	t.Helper()
	dir := shortTempDir(t)
	id, err := daemon.Init(context.Background(), daemon.InitConfig{DataDir: dir, Passphrase: testPass, KeystoreParams: fast})
	if err != nil {
		t.Fatal(err)
	}
	return dir, id
}

func cfg(dir string) Config {
	return Config{Config: daemon.Config{DataDir: dir, Passphrase: testPass, KeystoreParams: fast}}
}

// start runs a daemon on dir and returns it with a connected client. The
// daemon is stopped at cleanup if the test didn't stop it.
func start(t *testing.T, dir string) (*Daemon, pb.DaemonClient) {
	t.Helper()
	d, err := Start(context.Background(), cfg(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	conn, err := Dial(d.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return d, pb.NewDaemonClient(conn)
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func peer(t *testing.T, b byte) *identity.Identity {
	t.Helper()
	id, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func wantCode(t *testing.T, err error, c codes.Code) {
	t.Helper()
	if status.Code(err) != c {
		t.Fatalf("got %v, want code %v", err, c)
	}
}

// sealFrom seals an IM from buddy to us, as the buddy's daemon would.
func sealFrom(t *testing.T, buddy *identity.Identity, me identity.PublicKey, seq uint64, text string) [][]byte {
	t.Helper()
	p, err := buddy.Pair(me)
	if err != nil {
		t.Fatal(err)
	}
	k := frame.NewConvKey(p.Send)
	now := time.Now()
	in := frame.Inner{Type: frame.IM, Time: frame.Timestamp(now), Seq: seq, Body: []byte(text)}
	s, err := frame.Seal(k, k.Tag(frame.Day(now)), frame.LayoutMesh, in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return s.Frames
}

func TestEveryRPC(t *testing.T) {
	dir, me := initDir(t)
	d, c := start(t, dir)
	ctx := ctxT(t)
	bob, carol := peer(t, 2), peer(t, 3)

	st, err := c.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetIdentityKey() != me.Public().String() || st.GetKeyId() != me.Public().KeyID() {
		t.Fatalf("status identity %s %s", st.GetIdentityKey(), st.GetKeyId())
	}
	if st.GetVersion() == "" || st.GetUptime() == nil || st.GetBuddies().GetTotal() != 0 || st.GetDataDir() != dir {
		t.Fatalf("status %v", st)
	}
	if st.GetPresence().GetState() != pb.PresenceState_PRESENCE_STATE_ONLINE {
		t.Fatalf("initial presence %v", st.GetPresence())
	}

	// AddBuddy.
	b, err := c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: bob.Public().String(), Petname: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	if b.GetState() != pb.BuddyState_BUDDY_STATE_PENDING_OUT || b.GetPetname() != "Bob" || b.GetGroup() != "Buddies" ||
		b.GetKeyId() != bob.Public().KeyID() || b.GetVerified() || b.GetAddedAt() == nil {
		t.Fatalf("added %v", b)
	}
	if _, err := c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: carol.Public().String(), Group: "Family"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: bob.Public().String()})
	wantCode(t, err, codes.AlreadyExists)
	_, err = c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: me.Public().String()})
	wantCode(t, err, codes.InvalidArgument)
	_, err = c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: "not-a-key"})
	wantCode(t, err, codes.InvalidArgument)
	_, err = c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: peer(t, 4).Public().String(), Petname: "evil\x1b[2J"})
	wantCode(t, err, codes.InvalidArgument)

	// ListBuddies: by group, then name.
	list, err := c.ListBuddies(ctx, &pb.ListBuddiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetBuddies()) != 2 || list.GetBuddies()[0].GetPetname() != "Bob" || list.GetBuddies()[1].GetGroup() != "Family" {
		t.Fatalf("buddies %v", list.GetBuddies())
	}

	// SetBuddyVerified, by petname (any case).
	v, err := c.SetBuddyVerified(ctx, &pb.SetBuddyVerifiedRequest{Buddy: "bob", Verified: true})
	if err != nil || !v.GetVerified() {
		t.Fatalf("verify: %v %v", v, err)
	}
	_, err = c.SetBuddyVerified(ctx, &pb.SetBuddyVerifiedRequest{Buddy: "nobody", Verified: true})
	wantCode(t, err, codes.NotFound)

	// GetSafetyNumber, by key ID.
	sn, err := c.GetSafetyNumber(ctx, &pb.GetSafetyNumberRequest{Buddy: bob.Public().KeyID()})
	if err != nil {
		t.Fatal(err)
	}
	if want := identity.SafetyNumber(me.Public(), bob.Public()); sn.GetSafetyNumber() != want || sn.GetBuddy().GetPetname() != "Bob" {
		t.Fatalf("safety number %q, want %q", sn.GetSafetyNumber(), want)
	}

	// SendIM.
	sent, err := c.SendIM(ctx, &pb.SendIMRequest{Buddy: "Bob", Text: "hey, you going friday?"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sent.GetMsgId()) != 16 || sent.GetMessage().GetDelivery() != pb.DeliveryState_DELIVERY_STATE_QUEUED ||
		sent.GetMessage().GetSeq() != 1 || sent.GetMessage().GetDirection() != pb.Direction_DIRECTION_OUTGOING {
		t.Fatalf("sent %v", sent)
	}
	for _, bad := range []string{"", "clear\x1b[2J", "bell\a", "c1\u0085", strings.Repeat("x", 700)} {
		_, err = c.SendIM(ctx, &pb.SendIMRequest{Buddy: "Bob", Text: bad})
		wantCode(t, err, codes.InvalidArgument)
	}
	_, err = c.SendIM(ctx, &pb.SendIMRequest{Buddy: peer(t, 9).Public().String(), Text: "hi"})
	wantCode(t, err, codes.NotFound)
	_, err = c.SendIM(ctx, &pb.SendIMRequest{Buddy: "Mallory", Text: "hi"})
	wantCode(t, err, codes.NotFound)
	if _, err := c.SendIM(ctx, &pb.SendIMRequest{Buddy: "Bob", Text: strings.Repeat("x", 600) + "\nline two\ttab"}); err != nil {
		t.Fatal(err)
	}

	// An IM arrives from Bob (no transports yet: inject its frames), in the
	// same millisecond as the send, likely as not. History orders both
	// directions by insertion, so it still comes last.
	for _, f := range sealFrom(t, bob, me.Public(), 1, "yeah if my radio reaches lol") {
		if _, err := d.Node().HandleFrame(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	// History: both directions, oldest first.
	h, err := c.History(ctx, &pb.HistoryRequest{Buddy: bob.Public().String()})
	if err != nil {
		t.Fatal(err)
	}
	ms := h.GetMessages()
	if len(ms) != 3 {
		t.Fatalf("history has %d messages: %v", len(ms), ms)
	}
	if ms[0].GetMsgId() != sent.GetMsgId() || ms[0].GetText() != "hey, you going friday?" ||
		ms[0].GetDelivery() != pb.DeliveryState_DELIVERY_STATE_QUEUED || ms[0].GetSentAt() == nil {
		t.Fatalf("first message %v", ms[0])
	}
	if ms[2].GetDirection() != pb.Direction_DIRECTION_INCOMING || ms[2].GetText() != "yeah if my radio reaches lol" ||
		ms[2].GetReceivedAt() == nil || ms[2].GetBuddyKey() != bob.Public().String() {
		t.Fatalf("last message %v", ms[2])
	}
	h, err = c.History(ctx, &pb.HistoryRequest{Buddy: "Bob", Limit: 1})
	if err != nil || len(h.GetMessages()) != 1 || h.GetMessages()[0].GetDirection() != pb.Direction_DIRECTION_INCOMING {
		t.Fatalf("limited history %v %v", h, err)
	}
	_, err = c.History(ctx, &pb.HistoryRequest{Buddy: "Bob", Limit: 5000})
	wantCode(t, err, codes.InvalidArgument)

	// SetPresence.
	p, err := c.SetPresence(ctx, &pb.SetPresenceRequest{State: pb.PresenceState_PRESENCE_STATE_AWAY, AwayMessage: "at class. %n, IM me later"})
	if err != nil || p.GetState() != pb.PresenceState_PRESENCE_STATE_AWAY || p.GetSince() == nil {
		t.Fatalf("presence %v %v", p, err)
	}
	_, err = c.SetPresence(ctx, &pb.SetPresenceRequest{})
	wantCode(t, err, codes.InvalidArgument)
	_, err = c.SetPresence(ctx, &pb.SetPresenceRequest{State: pb.PresenceState_PRESENCE_STATE_AWAY, AwayMessage: "\x1b]0;pwned\a"})
	wantCode(t, err, codes.InvalidArgument)

	st, err = c.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetBuddies().GetTotal() != 2 || st.GetBuddies().GetPendingOut() != 2 || st.GetQueuedMessages() != 2 ||
		st.GetPresence().GetAwayMessage() != "at class. %n, IM me later" {
		t.Fatalf("status %v", st)
	}

	// ExportBackup.
	bk, err := c.ExportBackup(ctx, &pb.ExportBackupRequest{Passphrase: []byte("backup pass"), IncludeRecoveryPhrase: true})
	if err != nil {
		t.Fatal(err)
	}
	if bk.GetRecoveryPhrase() != me.Phrase() {
		t.Fatal("wrong recovery phrase")
	}
	dec, err := keystore.DecodeBackup(bk.GetBackup(), []byte("backup pass"))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Identity.Public() != me.Public() || len(dec.Buddies) != 2 || dec.Recovery != nil {
		t.Fatalf("backup %+v", dec)
	}
	bk, err = c.ExportBackup(ctx, &pb.ExportBackupRequest{Passphrase: []byte("x")})
	if err != nil || bk.GetRecoveryPhrase() != "" {
		t.Fatalf("backup without phrase: %v", err)
	}
	_, err = c.ExportBackup(ctx, &pb.ExportBackupRequest{})
	wantCode(t, err, codes.InvalidArgument)

	// RemoveBuddy takes its history with it.
	if _, err := c.RemoveBuddy(ctx, &pb.RemoveBuddyRequest{Buddy: "Bob"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.RemoveBuddy(ctx, &pb.RemoveBuddyRequest{Buddy: "Bob"})
	wantCode(t, err, codes.NotFound)
	_, err = c.History(ctx, &pb.HistoryRequest{Buddy: bob.Public().String()})
	wantCode(t, err, codes.NotFound)
	if st, _ := c.GetStatus(ctx, &pb.GetStatusRequest{}); st.GetBuddies().GetTotal() != 1 || st.GetQueuedMessages() != 0 {
		t.Fatalf("after remove: %v", st)
	}
	// Bob's frames are no longer recognized.
	_, err = d.Node().HandleFrame(ctx, sealFrom(t, bob, me.Public(), 2, "hello?")[0])
	if !errors.Is(err, frame.ErrUnknownTag) {
		t.Fatalf("frame from removed buddy: %v", err)
	}

	// Shutdown.
	if _, err := c.Shutdown(ctx, &pb.ShutdownRequest{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("daemon didn't stop after Shutdown")
	}
	if err := d.Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(d.SocketPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
}

func TestAmbiguousName(t *testing.T) {
	dir, _ := initDir(t)
	_, c := start(t, dir)
	ctx := ctxT(t)
	for _, b := range []byte{2, 3} {
		if _, err := c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: peer(t, b).Public().String(), Petname: "Sam"}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.SendIM(ctx, &pb.SendIMRequest{Buddy: "sam", Text: "which one?"})
	wantCode(t, err, codes.InvalidArgument)
	if _, err := c.SendIM(ctx, &pb.SendIMRequest{Buddy: peer(t, 3).Public().String(), Text: "you"}); err != nil {
		t.Fatal(err)
	}
}

// recv reads the next event, failing the test after a timeout.
func recv(t *testing.T, s grpc.ServerStreamingClient[pb.Event]) *pb.Event {
	t.Helper()
	type res struct {
		e   *pb.Event
		err error
	}
	ch := make(chan res, 1)
	go func() { e, err := s.Recv(); ch <- res{e, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("event stream: %v", r.err)
		}
		return r.e
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
		return nil
	}
}

func TestEvents(t *testing.T) {
	dir, me := initDir(t)
	d, c := start(t, dir)
	ctx := ctxT(t)
	bob := peer(t, 2)

	s, err := c.SubscribeEvents(ctx, &pb.SubscribeEventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ready := recv(t, s)
	if ready.GetReady() == nil {
		t.Fatalf("first event %v, want ready", ready)
	}

	if _, err := c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: bob.Public().String(), Petname: "Bob"}); err != nil {
		t.Fatal(err)
	}
	e := recv(t, s)
	if e.GetBuddyAdded().GetIdentityKey() != bob.Public().String() || e.GetSeq() != ready.GetSeq()+1 || e.GetTime() == nil {
		t.Fatalf("got %v, want buddy_added", e)
	}

	sent, err := c.SendIM(ctx, &pb.SendIMRequest{Buddy: "Bob", Text: "brb"})
	if err != nil {
		t.Fatal(err)
	}
	if e := recv(t, s); e.GetMessageQueued().GetMsgId() != sent.GetMsgId() || e.GetMessageQueued().GetText() != "brb" {
		t.Fatalf("got %v, want message_queued", e)
	}

	if _, err := c.SetBuddyVerified(ctx, &pb.SetBuddyVerifiedRequest{Buddy: "Bob", Verified: true}); err != nil {
		t.Fatal(err)
	}
	if e := recv(t, s); !e.GetBuddyChanged().GetVerified() {
		t.Fatalf("got %v, want buddy_changed", e)
	}

	for _, f := range sealFrom(t, bob, me.Public(), 1, "back") {
		if _, err := d.Node().HandleFrame(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	if e := recv(t, s); e.GetMessageReceived().GetText() != "back" {
		t.Fatalf("got %v, want message_received", e)
	}

	if _, err := c.SetPresence(ctx, &pb.SetPresenceRequest{State: pb.PresenceState_PRESENCE_STATE_AWAY, AwayMessage: "afk"}); err != nil {
		t.Fatal(err)
	}
	if e := recv(t, s); e.GetPresenceChanged().GetAwayMessage() != "afk" {
		t.Fatalf("got %v, want presence_changed", e)
	}

	if _, err := c.RemoveBuddy(ctx, &pb.RemoveBuddyRequest{Buddy: "Bob"}); err != nil {
		t.Fatal(err)
	}
	if e := recv(t, s); e.GetBuddyRemoved().GetPetname() != "Bob" {
		t.Fatalf("got %v, want buddy_removed", e)
	}

	// Shutdown ends the stream with UNAVAILABLE, and doesn't wait for it.
	if _, err := c.Shutdown(ctx, &pb.ShutdownRequest{}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Recv()
	wantCode(t, err, codes.Unavailable)
	select {
	case <-d.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("daemon didn't stop")
	}
}

func TestRestartKeepsState(t *testing.T) {
	dir, me := initDir(t)
	d, c := start(t, dir)
	ctx := ctxT(t)
	bob := peer(t, 2)
	if _, err := c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: bob.Public().String(), Petname: "Bob"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetBuddyVerified(ctx, &pb.SetBuddyVerifiedRequest{Buddy: "Bob", Verified: true}); err != nil {
		t.Fatal(err)
	}
	sent, err := c.SendIM(ctx, &pb.SendIMRequest{Buddy: "Bob", Text: "first"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetPresence(ctx, &pb.SetPresenceRequest{State: pb.PresenceState_PRESENCE_STATE_AWAY, AwayMessage: "gone fishing"}); err != nil {
		t.Fatal(err)
	}
	d.Stop()

	d, c = start(t, dir)
	st, err := c.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetIdentityKey() != me.Public().String() || st.GetBuddies().GetTotal() != 1 || st.GetQueuedMessages() != 1 {
		t.Fatalf("status after restart %v", st)
	}
	if st.GetPresence().GetState() != pb.PresenceState_PRESENCE_STATE_AWAY || st.GetPresence().GetAwayMessage() != "gone fishing" {
		t.Fatalf("presence after restart %v", st.GetPresence())
	}
	list, err := c.ListBuddies(ctx, &pb.ListBuddiesRequest{})
	if err != nil || len(list.GetBuddies()) != 1 || !list.GetBuddies()[0].GetVerified() || list.GetBuddies()[0].GetPetname() != "Bob" {
		t.Fatalf("buddies after restart %v %v", list, err)
	}
	// The queued IM kept its frames and msg_id; the next one gets seq 2.
	pending, err := d.Node().Pending(ctx, "Bob")
	if err != nil || len(pending) != 1 || pending[0].MsgID.String() != sent.GetMsgId() {
		t.Fatalf("pending after restart %v %v", pending, err)
	}
	second, err := c.SendIM(ctx, &pb.SendIMRequest{Buddy: "Bob", Text: "second"})
	if err != nil || second.GetMessage().GetSeq() != 2 {
		t.Fatalf("second IM %v %v", second, err)
	}
	h, err := c.History(ctx, &pb.HistoryRequest{Buddy: "Bob"})
	if err != nil || len(h.GetMessages()) != 2 || h.GetMessages()[0].GetMsgId() != sent.GetMsgId() || h.GetMessages()[1].GetText() != "second" {
		t.Fatalf("history after restart %v %v", h, err)
	}
	// Bob's frames are recognized after a restart too.
	for _, f := range sealFrom(t, bob, me.Public(), 1, "welcome back") {
		if _, err := d.Node().HandleFrame(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSecondDaemonRefused(t *testing.T) {
	dir, _ := initDir(t)
	d, _ := start(t, dir)
	_, err := Start(context.Background(), cfg(dir))
	if !errors.Is(err, daemon.ErrLocked) {
		t.Fatalf("second daemon: %v, want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), "pid") {
		t.Errorf("error doesn't name the holder: %v", err)
	}
	// Nor can init run under it.
	_, err = daemon.Init(context.Background(), daemon.InitConfig{DataDir: dir, Passphrase: testPass, KeystoreParams: fast})
	if !errors.Is(err, daemon.ErrLocked) {
		t.Fatalf("init under a running daemon: %v", err)
	}
	// The first daemon still works, and once stopped the dir is free.
	if _, err := os.Lstat(d.SocketPath()); err != nil {
		t.Fatal(err)
	}
	d.Stop()
	start(t, dir)
}

func TestSocketPermissions(t *testing.T) {
	dir, _ := initDir(t)
	d, c := start(t, dir)
	fi, err := os.Lstat(d.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want a 0600 socket", fi.Mode())
	}
	if filepath.Dir(d.SocketPath()) != dir {
		t.Fatalf("socket %s not in the data dir", d.SocketPath())
	}
	di, err := os.Stat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("data dir mode %v %v", di.Mode(), err)
	}
	for _, f := range []string{daemon.KeystoreFile, daemon.LockFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v %v", f, fi.Mode(), err)
		}
	}
	if _, err := c.GetStatus(ctxT(t), &pb.GetStatusRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestStaleSocketAfterCrash(t *testing.T) {
	dir, _ := initDir(t)
	p := daemon.PathsFor(dir)
	// A crashed daemon leaves its socket and pidfile behind.
	l, err := net.Listen("unix", p.Socket)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if err := os.WriteFile(p.Lock, []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, c := start(t, dir)
	if _, err := c.GetStatus(ctxT(t), &pb.GetStatusRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestSocketInUseElsewhere(t *testing.T) {
	dir, _ := initDir(t)
	d, _ := start(t, dir)
	// A second identity pointed at the first daemon's live socket.
	dir2, _ := initDir(t)
	c := cfg(dir2)
	c.SocketPath = d.SocketPath()
	if _, err := Start(context.Background(), c); !errors.Is(err, ErrSocketInUse) {
		t.Fatalf("got %v, want ErrSocketInUse", err)
	}
	// It must also have released its own data dir.
	start(t, dir2)
}

func TestStartErrors(t *testing.T) {
	dir, _ := initDir(t)
	c := cfg(dir)
	c.Passphrase = []byte("wrong")
	if _, err := Start(context.Background(), c); !errors.Is(err, keystore.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := Start(context.Background(), cfg(shortTempDir(t))); !errors.Is(err, daemon.ErrNotInitialized) {
		t.Fatalf("empty dir: %v", err)
	}
	// A keystore from another identity next to this database.
	other, _ := initDir(t)
	ks, err := os.ReadFile(filepath.Join(other, daemon.KeystoreFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, daemon.KeystoreFile), ks, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(context.Background(), cfg(dir)); !errors.Is(err, daemon.ErrIdentityMismatch) {
		t.Fatalf("mismatched keystore: %v", err)
	}
	// After every failure the lock was released.
	if l, err := daemon.AcquireLock(daemon.PathsFor(dir).Lock); err != nil {
		t.Fatal(err)
	} else {
		l.Release()
	}
}

func TestRunStopsOnContext(t *testing.T) {
	dir, _ := initDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg(dir)) }()
	sock := daemon.PathsFor(dir).Socket
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Lstat(sock); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
	}
	conn, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := pb.NewDaemonClient(conn)
	if _, err := c.GetStatus(ctxT(t), &pb.GetStatusRequest{}); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return")
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
}
