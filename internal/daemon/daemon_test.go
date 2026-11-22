package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/store"
)

var (
	ctx      = context.Background()
	fast     = keystore.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1}
	testPass = []byte("hunter2 hunter2")
)

// tempDir is a private (0700) temporary directory; t.TempDir's are 0755.
func tempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func initCfg(dir string) InitConfig {
	return InitConfig{DataDir: dir, Passphrase: testPass, KeystoreParams: fast}
}

func open(t *testing.T, dir string) *Node {
	t.Helper()
	n, err := Open(ctx, Config{DataDir: dir, Passphrase: testPass, KeystoreParams: fast})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func peer(t *testing.T, b byte) *identity.Identity {
	t.Helper()
	id, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestInitAndRestoreSameIdentity(t *testing.T) {
	dir := filepath.Join(tempDir(t), "new", "openaim") // parents are created
	id, err := Init(ctx, initCfg(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700) {
		t.Fatalf("data dir: %v %v", fi.Mode(), err)
	}
	n := open(t, dir)
	if n.Identity() != id.Public() {
		t.Fatal("opened a different identity")
	}
	n.Close()

	// A second init on the same dir is refused.
	if _, err := Init(ctx, initCfg(dir)); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second init: %v", err)
	}

	// Restoring the phrase elsewhere gives the same identity.
	dir2 := tempDir(t)
	c := initCfg(dir2)
	c.Phrase = id.Phrase()
	restored, err := Init(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Public() != id.Public() {
		t.Fatal("restore gave a different identity")
	}
	if n := open(t, dir2); n.Identity() != id.Public() {
		t.Fatal("restored dir opens a different identity")
	}

	c.Phrase = "not a phrase"
	if _, err := Init(ctx, c); err == nil {
		t.Fatal("bad phrase accepted")
	}
	if _, err := Init(ctx, InitConfig{DataDir: tempDir(t)}); !errors.Is(err, keystore.ErrEmptyPassphrase) {
		t.Fatalf("empty passphrase: %v", err)
	}
}

func TestRestoreLostKeystore(t *testing.T) {
	dir := tempDir(t)
	id, err := Init(ctx, initCfg(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(PathsFor(dir).Keystore); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, Config{DataDir: dir, Passphrase: testPass}); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("open without keystore: %v", err)
	}
	// A plain init would orphan the database's identity.
	if _, err := Init(ctx, initCfg(dir)); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("init over orphaned db: %v", err)
	}
	// Restoring someone else's phrase is refused.
	c := initCfg(dir)
	c.Phrase = peer(t, 7).Phrase()
	if _, err := Init(ctx, c); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("restore of another identity: %v", err)
	}
	// Restoring the right one recreates the keystore.
	c.Phrase = id.Phrase()
	if _, err := Init(ctx, c); err != nil {
		t.Fatal(err)
	}
	if n := open(t, dir); n.Identity() != id.Public() {
		t.Fatal("wrong identity after restore")
	}
}

func TestOpenAdoptsKeystoreAfterInterruptedInit(t *testing.T) {
	dir := tempDir(t)
	id := peer(t, 5)
	ks := &keystore.FileKeystore{Path: PathsFor(dir).Keystore, Passphrase: testPass, Params: fast}
	if err := ks.Save(id.Seed()); err != nil {
		t.Fatal(err)
	}
	n := open(t, dir)
	if n.Identity() != id.Public() {
		t.Fatal("wrong identity")
	}
	pub := id.Public()
	if v, err := n.store.Meta(ctx, metaIdentity); err != nil || !bytes.Equal(v, pub[:]) {
		t.Fatalf("meta identity %x %v", v, err)
	}
}

func TestDataDirPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits")
	}
	dir := tempDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, initCfg(dir)); err == nil {
		t.Fatal("init accepted a world-readable data dir")
	}
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o600)
	if _, err := Init(ctx, initCfg(f)); err == nil {
		t.Fatal("init accepted a file as data dir")
	}
}

func TestDefaultDataDir(t *testing.T) {
	t.Setenv(EnvDataDir, "/somewhere/else")
	if d, err := DefaultDataDir(); err != nil || d != "/somewhere/else" {
		t.Fatalf("override: %q %v", d, err)
	}
	t.Setenv(EnvDataDir, "")
	d, err := DefaultDataDir()
	if err != nil || filepath.Base(d) != "openaim" {
		t.Fatalf("default: %q %v", d, err)
	}
	if runtime.GOOS == "linux" {
		t.Setenv("XDG_DATA_HOME", "/xdg")
		if d, _ := DefaultDataDir(); d != "/xdg/openaim" {
			t.Fatalf("XDG: %q", d)
		}
	}
}

func TestLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), LockFile)
	l, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	l, err = AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	l.Release() // idempotent
}

func TestFindBuddy(t *testing.T) {
	dir := tempDir(t)
	if _, err := Init(ctx, initCfg(dir)); err != nil {
		t.Fatal(err)
	}
	n := open(t, dir)
	bob := peer(t, 2)
	b, err := n.AddBuddy(ctx, bob.Public().String(), "Bob", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, sel := range []string{bob.Public().String(), bob.Public().KeyID(), "bob", " BOB "} {
		got, err := n.FindBuddy(ctx, sel)
		if err != nil || got.ID != b.ID {
			t.Errorf("FindBuddy(%q) = %v, %v", sel, got.ID, err)
		}
	}
	for _, sel := range []string{"", "alice", peer(t, 3).Public().String()} {
		if _, err := n.FindBuddy(ctx, sel); err == nil {
			t.Errorf("FindBuddy(%q) succeeded", sel)
		}
	}
}

func TestBlockedBuddy(t *testing.T) {
	dir := tempDir(t)
	me, err := Init(ctx, initCfg(dir))
	if err != nil {
		t.Fatal(err)
	}
	n := open(t, dir)
	bob := peer(t, 2)
	b, err := n.AddBuddy(ctx, bob.Public().String(), "Bob", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.store.SetBuddyState(ctx, b.ID, store.Blocked); err != nil {
		t.Fatal(err)
	}
	b.State = store.Blocked
	if err := n.trackBuddy(b); err != nil {
		t.Fatal(err)
	}
	if _, err := n.SendIM(ctx, "Bob", "hi"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("IM to blocked buddy: %v", err)
	}
	// Frames from a blocked buddy aren't recognized.
	p, _ := bob.Pair(me.Public())
	k := frame.NewConvKey(p.Send)
	now := time.Now()
	in := frame.Inner{Type: frame.IM, Time: frame.Timestamp(now), Seq: 1, Body: []byte("let me in")}
	s, err := frame.Seal(k, k.Tag(frame.Day(now)), frame.LayoutMesh, in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.HandleFrame(ctx, s.Frames[0]); !errors.Is(err, frame.ErrUnknownTag) {
		t.Fatalf("frame from blocked buddy: %v", err)
	}
}

func TestIncomingDedupAndValidation(t *testing.T) {
	dir := tempDir(t)
	me, err := Init(ctx, initCfg(dir))
	if err != nil {
		t.Fatal(err)
	}
	n := open(t, dir)
	bob := peer(t, 2)
	if _, err := n.AddBuddy(ctx, bob.Public().String(), "Bob", ""); err != nil {
		t.Fatal(err)
	}
	sub := n.Subscribe()
	defer sub.Close()
	p, _ := bob.Pair(me.Public())
	k := frame.NewConvKey(p.Send)
	seal := func(seq uint64, text string) []byte {
		now := time.Now()
		in := frame.Inner{Type: frame.IM, Time: frame.Timestamp(now), Seq: seq, Body: []byte(text)}
		s, err := frame.Seal(k, k.Tag(frame.Day(now)), frame.LayoutMesh, in.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		return s.Frames[0]
	}
	f := seal(1, "hello")
	if res, err := n.HandleFrame(ctx, f); err != nil || res.Status != frame.Delivered {
		t.Fatalf("first: %v %v", res.Status, err)
	}
	if res, err := n.HandleFrame(ctx, f); err != nil || res.Status != frame.Duplicate {
		t.Fatalf("replay: %v %v", res.Status, err)
	}
	// An authenticated IM with a terminal escape is still dropped.
	if _, err := n.HandleFrame(ctx, seal(2, "\x1b[2J")); err == nil {
		t.Fatal("IM with control characters stored")
	}
	h, err := n.History(ctx, "Bob", 10)
	if err != nil || len(h) != 1 || h[0].Text != "hello" {
		t.Fatalf("history %v %v", h, err)
	}
	if e := <-sub.C; e.Kind != EventMessageReceived || e.Message.Text != "hello" {
		t.Fatalf("event %+v", e)
	}
	select {
	case e := <-sub.C:
		t.Fatalf("unexpected event %+v", e)
	default:
	}
}

func TestBusLaggingSubscriber(t *testing.T) {
	b := newBus(time.Now)
	slow, fast := b.subscribe(), b.subscribe()
	for i := 0; i < subscriberBuffer+1; i++ {
		b.publish(Event{Kind: EventPresenceChanged, Presence: &Presence{}})
		<-fast.C
	}
	got := 0
	for range slow.C {
		got++
	}
	if got != subscriberBuffer || !errors.Is(slow.Err(), ErrLagged) {
		t.Fatalf("slow subscriber got %d events, err %v", got, slow.Err())
	}
	b.close()
	if _, ok := <-fast.C; ok || !errors.Is(fast.Err(), ErrClosed) {
		t.Fatalf("after close: %v", fast.Err())
	}
	if s := b.subscribe(); !errors.Is(s.Err(), ErrClosed) {
		t.Fatal("subscribe after close")
	}
	fast.Close() // no-op after close
}
