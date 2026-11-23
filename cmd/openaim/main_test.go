package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aghman/openaim/internal/api"
	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/body"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/store"
	wpb "github.com/aghman/openaim/internal/wirepb"
)

// fast Argon2id costs (the minimum the keystore accepts).
var fast = keystore.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1}

var testPass = []byte("correct horse battery staple")

// shortDir is a private temp dir with a path short enough for a Unix socket.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "oac")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func initDir(t *testing.T) (string, *identity.Identity) {
	t.Helper()
	dir := shortDir(t)
	id, err := daemon.Init(context.Background(), daemon.InitConfig{DataDir: dir, Passphrase: testPass, KeystoreParams: fast})
	if err != nil {
		t.Fatal(err)
	}
	return dir, id
}

func startDaemon(t *testing.T, dir string) *api.Daemon {
	t.Helper()
	d, err := api.Start(context.Background(), api.Config{Config: daemon.Config{DataDir: dir, Passphrase: testPass, KeystoreParams: fast}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	return d
}

func peer(t *testing.T, b byte) *identity.Identity {
	t.Helper()
	id, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// syncBuffer is a bytes.Buffer safe to read while a command writes it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type result struct {
	code           int
	stdout, stderr string
}

// opts are an invocation's surroundings.
type opts struct {
	stdin  string
	vars   map[string]string
	tty    bool
	secret func(string) ([]byte, error)
}

func runOpts(ctx context.Context, o opts, args ...string) result {
	var out, errb syncBuffer
	e := newEnv(strings.NewReader(o.stdin), &out, &errb)
	e.getenv = func(k string) string { return o.vars[k] }
	e.stdoutTTY = o.tty
	e.readSecret = o.secret
	code := e.run(ctx, args)
	return result{code, out.String(), errb.String()}
}

// h is a daemon on a fresh data dir, and a way to run the CLI against it.
type h struct {
	t   *testing.T
	dir string
	me  *identity.Identity
	d   *api.Daemon
}

func newH(t *testing.T) *h {
	t.Helper()
	dir, me := initDir(t)
	return &h{t: t, dir: dir, me: me, d: startDaemon(t, dir)}
}

func (x *h) cli(o opts, args ...string) result {
	x.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return runOpts(ctx, o, append([]string{"--data-dir", x.dir}, args...)...)
}

// ok runs a command that must succeed.
func (x *h) ok(args ...string) result {
	x.t.Helper()
	r := x.cli(opts{}, args...)
	if r.code != 0 {
		x.t.Fatalf("openaim %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

// code runs a command that must exit with want.
func (x *h) code(want int, args ...string) result {
	x.t.Helper()
	r := x.cli(opts{}, args...)
	if r.code != want {
		x.t.Fatalf("openaim %s: exit %d, want %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.code, want, r.stdout, r.stderr)
	}
	return r
}

// jsonObj parses a --json result: exactly one object on one line.
func jsonObj(t *testing.T, s string) map[string]any {
	t.Helper()
	if strings.Count(s, "\n") != 1 || !strings.HasSuffix(s, "\n") {
		t.Fatalf("want one JSON line, got %q", s)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad JSON %q: %v", s, err)
	}
	return m
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

var msgIDRE = regexp.MustCompile(`^[0-9a-f]{16}\n$`)

func TestStatusAndBuddies(t *testing.T) {
	t.Parallel()
	x := newH(t)
	bob, carol := peer(t, 2), peer(t, 3)

	r := x.ok("status")
	for _, want := range []string{x.me.Public().KeyID(), x.me.Public().String(), "online", "Buddies", "0 message(s)"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("status lacks %q:\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "Data dir") {
		t.Fatalf("terse status shows the data dir:\n%s", r.stdout)
	}
	r = x.ok("status", "--verbose")
	for _, want := range []string{"Data dir", x.dir, "Uptime", "Started", "Version", "0 accepted"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("verbose status lacks %q:\n%s", want, r.stdout)
		}
	}
	// Global flags work before and after the command.
	for _, args := range [][]string{{"--json", "status"}, {"status", "--json"}} {
		m := jsonObj(t, x.ok(args...).stdout)
		if m["identity_key"] != x.me.Public().String() || m["data_dir"] != x.dir || m["version"] == "" {
			t.Fatalf("status json %v", m)
		}
	}

	if r := x.ok("buddies"); !strings.Contains(r.stdout, "No buddies yet") {
		t.Fatalf("empty list: %q", r.stdout)
	}

	r = x.ok("add", bob.Public().String(), "--petname", "Bob")
	if !strings.Contains(r.stdout, "Added Bob ("+bob.Public().KeyID()+") to Buddies; pending-out") {
		t.Fatalf("add: %q", r.stdout)
	}
	m := jsonObj(t, x.ok("--json", "add", "--group", "Family", carol.Public().String()).stdout)
	if m["group"] != "Family" || m["state"] != "BUDDY_STATE_PENDING_OUT" || m["key_id"] != carol.Public().KeyID() {
		t.Fatalf("add json %v", m)
	}
	r = x.code(exitExists, "add", bob.Public().String())
	if !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("dup add: %q", r.stderr)
	}
	m = jsonObj(t, x.code(exitExists, "--json", "add", bob.Public().String()).stderr)
	if m["code"] != "already_exists" || m["exit_code"] != float64(exitExists) {
		t.Fatalf("dup add json error %v", m)
	}
	x.code(exitError, "add", "not-a-key")
	x.code(exitUsage, "add")

	r = x.ok("buddies")
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "GROUP") || !strings.HasPrefix(lines[1], "Buddies  Bob") ||
		!strings.HasPrefix(lines[2], "Family") || !strings.Contains(lines[1], "unverified") ||
		!strings.Contains(lines[1], bob.Public().KeyID()) || !strings.Contains(lines[1], "offline") {
		t.Fatalf("buddies:\n%s", r.stdout)
	}
	// Columns line up: KEY ID starts at the same place in every row.
	col := strings.Index(lines[0], "KEY ID")
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l[col:], "~") {
			t.Fatalf("misaligned buddies:\n%s", r.stdout)
		}
	}
	if strings.Contains(r.stdout, "\x1b") {
		t.Fatal("colors on a non-terminal")
	}
	m = jsonObj(t, x.ok("buddies", "--json").stdout)
	if bs := m["buddies"].([]any); len(bs) != 2 || bs[0].(map[string]any)["petname"] != "Bob" {
		t.Fatalf("buddies json %v", m)
	}

	// Colors only on a terminal, and never with NO_COLOR.
	if r := x.cli(opts{tty: true}, "buddies"); !strings.Contains(r.stdout, "\x1b[33munverified\x1b[0m") {
		t.Fatalf("no colors on a terminal:\n%q", r.stdout)
	}
	if r := x.cli(opts{tty: true, vars: map[string]string{"NO_COLOR": "1"}}, "buddies"); strings.Contains(r.stdout, "\x1b") {
		t.Fatalf("colors despite NO_COLOR:\n%q", r.stdout)
	}

	// verify shows the number in 8 groups of 5; --confirm marks it.
	sn := identity.SafetyNumber(x.me.Public(), bob.Public())
	g := strings.Fields(sn)
	r = x.ok("verify", "bob")
	if !strings.Contains(r.stdout, strings.Join(g[:4], " ")+"\n") || !strings.Contains(r.stdout, strings.Join(g[4:], " ")+"\n") ||
		!strings.Contains(r.stdout, "unverified") || !strings.Contains(r.stdout, "--confirm") {
		t.Fatalf("verify:\n%s", r.stdout)
	}
	r = x.ok("verify", bob.Public().KeyID(), "--confirm")
	if !strings.Contains(r.stdout, "Bob is now verified") {
		t.Fatalf("verify --confirm:\n%s", r.stdout)
	}
	if r := x.ok("buddies"); !strings.Contains(strings.Split(r.stdout, "\n")[1], "✓") {
		t.Fatalf("not marked verified:\n%s", r.stdout)
	}
	m = jsonObj(t, x.ok("--json", "verify", "Bob").stdout)
	if m["safety_number"] != sn || m["buddy"].(map[string]any)["verified"] != true {
		t.Fatalf("verify json %v", m)
	}
	m = jsonObj(t, x.ok("--json", "verify", "Bob", "--unverify").stdout)
	if m["buddy"].(map[string]any)["verified"] != false {
		t.Fatalf("verify --unverify json %v", m)
	}
	x.code(exitUsage, "verify", "Bob", "--confirm", "--unverify")
	x.code(exitNotFound, "verify", "nobody")
}

func TestMessaging(t *testing.T) {
	t.Parallel()
	x := newH(t)
	bob := peer(t, 2)
	x.ok("add", bob.Public().String(), "--petname", "Bob")

	r := x.ok("send", "Bob", "you", "going", "friday?")
	if !msgIDRE.MatchString(r.stdout) {
		t.Fatalf("send printed %q", r.stdout)
	}
	m := jsonObj(t, x.ok("--json", "send", "bob", "-x", "is", "a", "word", "here").stdout)
	if len(m["msg_id"].(string)) != 16 || m["message"].(map[string]any)["text"] != "-x is a word here" {
		t.Fatalf("send json %v", m)
	}
	// Text from stdin, one trailing newline dropped.
	r = x.cli(opts{stdin: "line one\nline two\n"}, "send", "Bob", "-")
	if r.code != 0 || !msgIDRE.MatchString(r.stdout) {
		t.Fatalf("send -: %+v", r)
	}
	x.code(exitUsage, "send", "Bob")
	if r := x.cli(opts{stdin: "\n"}, "send", "Bob", "-"); r.code != exitUsage {
		t.Fatalf("empty stdin: %+v", r)
	}
	x.code(exitNotFound, "send", "Mallory", "hi")
	x.code(exitError, "send", "Bob", "bell\a")

	// An incoming IM, likely in the same millisecond as the last send:
	// history orders by insertion, so it still comes last.
	for _, f := range sealFrom(t, bob, x.me.Public(), 1, "yeah if my radio reaches lol") {
		if _, err := x.d.Node().HandleFrame(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}

	r = x.ok("history", "Bob")
	lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
	if len(lines) != 5 || !strings.Contains(lines[0], "] me: you going friday?  [queued]") ||
		!strings.Contains(lines[2], "] me: line one") || !strings.HasPrefix(strings.TrimLeft(lines[3], " "), "line two") ||
		!strings.Contains(lines[4], "] Bob: yeah if my radio reaches lol") {
		t.Fatalf("history:\n%s", r.stdout)
	}
	// Continuation lines are indented under the text.
	if i := strings.Index(lines[2], "line one"); !strings.HasPrefix(lines[3], strings.Repeat(" ", i)+"line two") {
		t.Fatalf("continuation not indented:\n%s", r.stdout)
	}
	// Flags after the buddy.
	m = jsonObj(t, x.ok("history", "Bob", "--limit", "1", "--json").stdout)
	ms := m["messages"].([]any)
	if len(ms) != 1 || ms[0].(map[string]any)["direction"] != "DIRECTION_INCOMING" {
		t.Fatalf("history json %v", m)
	}
	x.code(exitNotFound, "history", "nobody")
	x.code(exitUsage, "history", "Bob", "--limit", "-1")

	// Presence.
	r = x.ok("away", "at", "class.", "%n,", "IM", "me", "later")
	if !strings.Contains(r.stdout, `away: "at class. %n, IM me later"`) {
		t.Fatalf("away: %q", r.stdout)
	}
	if r := x.ok("status"); !strings.Contains(r.stdout, `away: "at class.`) {
		t.Fatalf("status after away:\n%s", r.stdout)
	}
	m = jsonObj(t, x.ok("--json", "away").stdout)
	if m["state"] != "PRESENCE_STATE_AWAY" || m["away_message"] != "" {
		t.Fatalf("away json %v", m)
	}
	if r := x.ok("back"); r.stdout != "Presence: online\n" {
		t.Fatalf("back: %q", r.stdout)
	}
	m = jsonObj(t, x.ok("back", "--json").stdout)
	if m["state"] != "PRESENCE_STATE_ONLINE" {
		t.Fatalf("back json %v", m)
	}

	// remove.
	if r := x.ok("remove", "bob"); r.stdout != "Removed bob.\n" {
		t.Fatalf("remove: %q", r.stdout)
	}
	x.code(exitNotFound, "remove", "bob")
	x.ok("add", bob.Public().String())
	if m := jsonObj(t, x.ok("--json", "remove", bob.Public().KeyID()).stdout); m["removed"] != bob.Public().KeyID() {
		t.Fatalf("remove json %v", m)
	}
	m = jsonObj(t, x.code(exitNotFound, "--json", "remove", "bob").stderr)
	if m["code"] != "not_found" || m["exit_code"] != float64(exitNotFound) {
		t.Fatalf("not found json %v", m)
	}
}

func TestWatch(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{false, true} {
		x := newH(t)
		bob := peer(t, 2)
		x.ok("add", bob.Public().String(), "--petname", "Bob")

		var out, errb syncBuffer
		e := newEnv(strings.NewReader(""), &out, &errb)
		e.getenv = func(string) string { return "" }
		args := []string{"--data-dir", x.dir, "watch"}
		if jsonMode {
			args = append(args, "--json")
		}
		done := make(chan int, 1)
		go func() { done <- e.run(context.Background(), args) }()
		waitFor(t, func() bool {
			if jsonMode {
				return strings.Contains(out.String(), `"ready":{}`)
			}
			return strings.Contains(errb.String(), "Watching")
		})

		x.ok("send", "Bob", "hello there")
		for _, f := range sealFrom(t, bob, x.me.Public(), 1, "hi back") {
			if _, err := x.d.Node().HandleFrame(context.Background(), f); err != nil {
				t.Fatal(err)
			}
		}
		x.ok("away", "brb")
		waitFor(t, func() bool { return strings.Contains(out.String(), "brb") })

		x.ok("shutdown")
		select {
		case code := <-done:
			if code != 0 {
				t.Fatalf("watch exited %d: %s", code, errb.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatal("watch did not end on shutdown")
		}
		got := out.String()
		if jsonMode {
			lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
			if len(lines) != 4 {
				t.Fatalf("json watch lines:\n%s", got)
			}
			for i, key := range []string{"ready", "message_queued", "message_received", "presence_changed"} {
				m := jsonObj(t, lines[i]+"\n")
				if _, ok := m[key]; !ok {
					t.Fatalf("line %d is not %s: %s", i, key, lines[i])
				}
			}
		} else {
			for _, want := range []string{"IM to Bob queued", "hello there", "Bob: hi back", `presence: away: "brb"`} {
				if !strings.Contains(got, want) {
					t.Fatalf("watch lacks %q:\n%s", want, got)
				}
			}
			if !strings.Contains(errb.String(), "shut down") {
				t.Fatalf("watch stderr: %q", errb.String())
			}
		}
		<-x.d.Done()
		// And now the daemon is gone.
		x.code(exitNotRunning, "status")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
	}
}

func TestWatchInterrupt(t *testing.T) {
	t.Parallel()
	x := newH(t)
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb syncBuffer
	e := newEnv(strings.NewReader(""), &out, &errb)
	e.getenv = func(string) string { return "" }
	done := make(chan int, 1)
	go func() { done <- e.run(ctx, []string{"--data-dir", x.dir, "watch"}) }()
	waitFor(t, func() bool { return strings.Contains(errb.String(), "Watching") })
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("interrupted watch exited %d: %s", code, errb.String())
	}
}

func TestBackupExport(t *testing.T) {
	t.Parallel()
	x := newH(t)
	bob := peer(t, 2)
	x.ok("add", bob.Public().String(), "--petname", "Bob")
	out := filepath.Join(shortDir(t), "oa-backup")
	env := map[string]string{EnvBackupPassphrase: "backup pass"}

	r := x.cli(opts{vars: env}, "backup", "export", "--out", out)
	if r.code != 0 || !strings.Contains(r.stdout, "Wrote encrypted backup to "+out) || strings.Contains(r.stdout, "RECOVERY") {
		t.Fatalf("backup: %+v", r)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %04o", fi.Mode().Perm())
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	b, err := keystore.DecodeBackup(blob, []byte("backup pass"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Identity.Public() != x.me.Public() || len(b.Buddies) != 1 || b.Buddies[0].Petname != "Bob" {
		t.Fatalf("backup holds %v %v", b.Identity.Public(), b.Buddies)
	}

	// No overwriting without --force.
	r = x.cli(opts{vars: env}, "backup", "export", "--out", out)
	if r.code != exitError || !strings.Contains(r.stderr, "--force") {
		t.Fatalf("overwrite: %+v", r)
	}
	if err := writePrivateFile(out, []byte("x"), false); err == nil {
		t.Fatal("writePrivateFile replaced a file without force")
	}

	// --force, passphrase from a file, and the phrase shown.
	passFile := filepath.Join(shortDir(t), "pass")
	if err := os.WriteFile(passFile, []byte("file pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = x.ok("backup", "export", out, "--force", "--show-phrase", "--passphrase-file", passFile)
	if !strings.Contains(r.stdout, "RECOVERY PHRASE") || !strings.Contains(r.stdout, "24. ") {
		t.Fatalf("show phrase:\n%s", r.stdout)
	}
	blob, _ = os.ReadFile(out)
	if _, err := keystore.DecodeBackup(blob, []byte("file pass")); err != nil {
		t.Fatalf("forced backup: %v", err)
	}
	words := strings.Fields(x.me.Phrase())
	if !strings.Contains(r.stdout, "1. "+words[0]) || !strings.Contains(r.stdout, "24. "+words[23]) {
		t.Fatalf("wrong phrase:\n%s", r.stdout)
	}

	// JSON, and a terminal prompt (asked twice).
	out2 := filepath.Join(filepath.Dir(out), "second")
	asked := 0
	secret := func(string) ([]byte, error) { asked++; return []byte("typed pass"), nil }
	r = x.cli(opts{secret: secret}, "--json", "backup", "export", "--out", out2, "--show-phrase")
	if r.code != 0 || asked != 2 {
		t.Fatalf("prompted backup: %+v (asked %d)", r, asked)
	}
	m := jsonObj(t, r.stdout)
	if m["path"] != out2 || m["recovery_phrase"] != x.me.Phrase() || m["bytes"] == float64(0) {
		t.Fatalf("backup json %v", m)
	}
	blob, _ = os.ReadFile(out2)
	if _, err := keystore.DecodeBackup(blob, []byte("typed pass")); err != nil {
		t.Fatal(err)
	}

	// Mismatched prompts, no passphrase source, a passphrase flag.
	n := 0
	mismatch := func(string) ([]byte, error) { n++; return []byte{byte('a' + n)}, nil }
	if r := x.cli(opts{secret: mismatch}, "backup", "export", "--out", out+"3"); r.code != exitError || !strings.Contains(r.stderr, "match") {
		t.Fatalf("mismatch: %+v", r)
	}
	if r := x.cli(opts{}, "backup", "export", "--out", out+"3"); r.code != exitError || !strings.Contains(r.stderr, EnvBackupPassphrase) {
		t.Fatalf("no passphrase: %+v", r)
	}
	if _, err := os.Stat(out + "3"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed export left a file")
	}
	x.code(exitUsage, "backup", "export", "--out", out+"3", "--passphrase", "x")
	x.code(exitUsage, "backup", "export")
	x.code(exitUsage, "backup", "import", out)
	x.code(exitUsage, "backup")
	// Nothing but the backups in the directory: no temp files left.
	ents, _ := os.ReadDir(filepath.Dir(out))
	if len(ents) != 2 {
		t.Fatalf("directory holds %v", ents)
	}
}

func TestBackupExportCarriesRecoveryKey(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)
	first := filepath.Join(shortDir(t), "first")
	res, err := daemon.InitIdentity(context.Background(), daemon.InitConfig{DataDir: dir, Passphrase: testPass, KeystoreParams: fast,
		BackupPath: first, BackupPassphrase: []byte("first pass")})
	if err != nil {
		t.Fatal(err)
	}
	x := &h{t: t, dir: dir, me: res.Identity, d: startDaemon(t, dir)}
	if m := jsonObj(t, x.ok("--json", "status").stdout); m["recovery_key"] != res.RecoveryKey.String() {
		t.Fatalf("status %v", m)
	}
	env := map[string]string{EnvBackupPassphrase: "new pass"}
	out := filepath.Join(shortDir(t), "plain")
	r := x.cli(opts{vars: env}, "backup", "export", "--out", out)
	if r.code != 0 || !strings.Contains(r.stdout, "does NOT hold your recovery key") {
		t.Fatalf("plain export: %+v", r)
	}
	passFile := filepath.Join(shortDir(t), "pass")
	if err := os.WriteFile(passFile, []byte("first pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out2 := filepath.Join(filepath.Dir(out), "carried")
	r = x.cli(opts{vars: env}, "--json", "backup", "export", "--out", out2, "--from", first, "--from-passphrase-file", passFile)
	if r.code != 0 {
		t.Fatalf("carried export: %+v", r)
	}
	if m := jsonObj(t, r.stdout); m["includes_recovery_key"] != true || m["recovery_key"] != res.RecoveryKey.String() {
		t.Fatalf("carried json %v", m)
	}
	blob, _ := os.ReadFile(out2)
	b, err := keystore.DecodeBackup(blob, []byte("new pass"))
	if err != nil || b.Recovery == nil || b.Recovery.Public() != *res.RecoveryKey {
		t.Fatalf("carried backup %+v %v", b, err)
	}
	// The wrong passphrase for --from, and --from-passphrase-file alone.
	if r := x.cli(opts{vars: env}, "backup", "export", "--out", out2+"x", "--from", first); r.code != exitError || !strings.Contains(r.stderr, "passphrase") {
		t.Fatalf("wrong --from passphrase: %+v", r)
	}
	x.code(exitUsage, "backup", "export", "--out", out2+"x", "--from-passphrase-file", passFile)
}

func TestHostileText(t *testing.T) {
	t.Parallel()
	dir, me := initDir(t)
	// A buddy whose labels the daemon would never accept, as if from an
	// older version or a crafted backup: written to the store directly.
	st, err := store.Open(context.Background(), daemon.PathsFor(dir).DB)
	if err != nil {
		t.Fatal(err)
	}
	evilPet := "\x1b[2J\x1b]0;pwned\x07Mallory"
	evilHandle := "csi\u009b31m.example"
	if _, err := st.AddBuddy(context.Background(), store.Buddy{Key: peer(t, 5).Public(), Petname: evilPet, Handle: evilHandle,
		Group: "Evil\r\nGroup", State: store.Accepted}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	x := &h{t: t, dir: dir, me: me, d: startDaemon(t, dir)}
	// The daemon accepts bidi overrides in petnames; they must not reach the
	// terminal raw either.
	bidi := "Bob\u202egnp.exe"
	x.ok("add", peer(t, 6).Public().String(), "--petname", bidi)

	unsafeOut := func(s string) bool {
		for _, r := range s {
			if r != '\n' && unsafeRune(r) {
				return true
			}
		}
		return false
	}
	for _, args := range [][]string{{"buddies"}, {"verify", peer(t, 5).Public().KeyID()}, {"history", bidi}} {
		r := x.ok(args...)
		if unsafeOut(r.stdout) || unsafeOut(r.stderr) {
			t.Fatalf("%v printed unsafe text: %q", args, r.stdout)
		}
	}
	r := x.ok("buddies")
	if !strings.Contains(r.stdout, "\uFFFD[2J\uFFFD]0;pwned\uFFFDMallory") || !strings.Contains(r.stdout, "Bob\uFFFDgnp.exe") {
		t.Fatalf("buddies:\n%q", r.stdout)
	}
	// Even an unknown-buddy error echoes the selector cleaned.
	r = x.code(exitNotFound, "send", "x\x1b[2J", "hi")
	if strings.Contains(r.stderr, "\x1b") {
		t.Fatalf("error echoed raw ESC: %q", r.stderr)
	}

	// JSON keeps the exact text, but escaped.
	r = x.ok("--json", "buddies")
	if unsafeOut(strings.TrimSuffix(r.stdout, "\n")) || strings.Contains(r.stdout, "\x1b") {
		t.Fatalf("json printed unsafe text: %q", r.stdout)
	}
	m := jsonObj(t, r.stdout)
	var pets []any
	for _, b := range m["buddies"].([]any) {
		pets = append(pets, b.(map[string]any)["petname"])
	}
	if !strings.Contains(r.stdout, `\u202e`) || !strings.Contains(r.stdout, `\u009b`) ||
		(pets[0] != evilPet && pets[1] != evilPet) || (pets[0] != bidi && pets[1] != bidi) {
		t.Fatalf("json petnames %q from %q", pets, r.stdout)
	}
}

func TestDaemonNotRunning(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	empty := shortDir(t)
	var out, errb bytes.Buffer
	code := run(ctx, []string{"--data-dir", empty, "status"}, strings.NewReader(""), &out, &errb)
	if code != exitNotRunning || !strings.Contains(errb.String(), "openaimd is not running (no socket at "+filepath.Join(empty, "openaimd.sock")) ||
		!strings.Contains(errb.String(), "openaimd init") {
		t.Fatalf("empty dir: %d %q", code, errb.String())
	}

	dir, _ := initDir(t)
	for _, args := range [][]string{{"status"}, {"buddies"}, {"send", "bob", "hi"}, {"watch"}, {"shutdown"}, {"history", "bob"}} {
		r := runOpts(ctx, opts{}, append([]string{"--data-dir", dir}, args...)...)
		if r.code != exitNotRunning || !strings.Contains(r.stderr, "start it with `openaimd run`") || strings.Contains(r.stderr, "openaimd init") {
			t.Fatalf("%v: %+v", args, r)
		}
	}
	// The data dir also comes from $OPENAIM_DATA_DIR.
	if r := runOpts(ctx, opts{vars: map[string]string{daemon.EnvDataDir: dir}}, "status"); r.code != exitNotRunning ||
		!strings.Contains(r.stderr, dir) {
		t.Fatalf("env data dir: %+v", r)
	}
	r := runOpts(ctx, opts{}, "--json", "--data-dir", dir, "status")
	if m := jsonObj(t, r.stderr); m["code"] != "not_running" || m["exit_code"] != float64(exitNotRunning) || r.stdout != "" {
		t.Fatalf("json not running: %+v", r)
	}

	// A stale socket left by a crash: it exists, but nothing answers.
	sock := daemon.PathsFor(dir).Socket
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if r := runOpts(ctx, opts{}, "--data-dir", dir, "status"); r.code != exitNotRunning || !strings.Contains(r.stderr, "nothing answers") {
		t.Fatalf("stale socket: %+v", r)
	}
	if r := runOpts(ctx, opts{}, "--data-dir", dir, "watch"); r.code != exitNotRunning {
		t.Fatalf("watch on stale socket: %+v", r)
	}

	// version works without a daemon.
	r = runOpts(ctx, opts{}, "--data-dir", dir, "version")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "openaim ") || !strings.Contains(r.stdout, "openaimd not running") {
		t.Fatalf("version: %+v", r)
	}
	m := jsonObj(t, runOpts(ctx, opts{}, "--data-dir", dir, "--json", "version").stdout)
	if _, ok := m["daemon"]; ok || m["client"] == "" {
		t.Fatalf("version json %v", m)
	}
}

func TestVersionShutdownHelp(t *testing.T) {
	t.Parallel()
	x := newH(t)
	r := x.ok("version")
	if !strings.HasPrefix(r.stdout, "openaim "+daemon.BuildVersion()+"\nopenaimd ") {
		t.Fatalf("version: %q", r.stdout)
	}
	if m := jsonObj(t, x.ok("version", "--json").stdout); m["daemon"] != daemon.BuildVersion() {
		t.Fatalf("version json %v", m)
	}

	// Help: top level, per command, and -h; none needs the daemon.
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		r := runOpts(context.Background(), opts{}, args...)
		if r.code != 0 || !strings.Contains(r.stdout, "Commands:") || !strings.Contains(r.stdout, "Exit codes:") {
			t.Fatalf("%v: %+v", args, r)
		}
	}
	for _, c := range commands {
		for _, args := range [][]string{{"help", c.name}, {c.name, "-h"}} {
			r := runOpts(context.Background(), opts{}, args...)
			if r.code != 0 || !strings.HasPrefix(r.stdout, "Usage: openaim "+c.name) || !strings.Contains(r.stdout, "-json") {
				t.Fatalf("%v: %+v", args, r)
			}
		}
	}
	if r := runOpts(context.Background(), opts{}, "help", "backup"); !strings.Contains(r.stdout, "-passphrase-file") {
		t.Fatalf("backup help lacks its flags:\n%s", r.stdout)
	}
	if r := runOpts(context.Background(), opts{}); r.code != exitUsage || !strings.Contains(r.stderr, "Commands:") {
		t.Fatalf("no command: %+v", r)
	}
	if r := runOpts(context.Background(), opts{}, "frobnicate"); r.code != exitUsage || !strings.Contains(r.stderr, `unknown command "frobnicate"`) {
		t.Fatalf("unknown command: %+v", r)
	}
	x.code(exitUsage, "status", "extra")
	x.code(exitUsage, "status", "--bogus")
	x.code(exitUsage, "--timeout", "soon", "status")

	if m := jsonObj(t, x.ok("--json", "shutdown").stdout); m["shutting_down"] != true {
		t.Fatalf("shutdown json %v", m)
	}
	<-x.d.Done()
	x.code(exitNotRunning, "status")
}

func TestShutdownHuman(t *testing.T) {
	t.Parallel()
	x := newH(t)
	if r := x.ok("shutdown"); r.stdout != "openaimd is shutting down.\n" {
		t.Fatalf("shutdown: %q", r.stdout)
	}
	<-x.d.Done()
}

func TestCleaning(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"plain":            "plain",
		"a\x1b[31mb":       "a\uFFFD[31mb",
		"tab\tnl\n":        "tab nl ",
		"c1\u0085\u009b":   "c1\uFFFD\uFFFD",
		"bidi\u202e\u2066": "bidi\uFFFD\uFFFD",
		"ls\u2028":         "ls\uFFFD",
		"bad\xffutf8":      "bad\uFFFDutf8",
		"emoji 👋🏽 ok":      "emoji 👋🏽 ok",
		"del\x7f":          "del\uFFFD",
	}
	for in, want := range cases {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanText("a\nb\tc\x1b", "  "); got != "a\n  b\tc\uFFFD" {
		t.Errorf("cleanText = %q", got)
	}
	b, err := marshalJSON(map[string]string{"k": "x\x1b\u202e\u0085<>&"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"k":"x\u001b\u202e\u0085<>&"}`+"\n" {
		t.Errorf("json %s", b)
	}
	if got := displayWidth("日本ab\u0301"); got != 6 {
		t.Errorf("displayWidth = %d", got)
	}
	if got := safetyGroups("12345 67890 12345 67890 12345 67890 12345 67890"); len(got) != 2 || got[1] != "12345 67890 12345 67890" {
		t.Errorf("safetyGroups = %q", got)
	}
	if got := safetyGroups("odd\x1b"); len(got) != 1 || got[0] != "odd\uFFFD" {
		t.Errorf("safetyGroups odd = %q", got)
	}
}

// requestFrom seals a BUDDY_REQUEST from id to me, as id's daemon would.
func requestFrom(t *testing.T, id *identity.Identity, me identity.PublicKey, name, greeting string) [][]byte {
	t.Helper()
	_, b, err := body.Marshal(&wpb.BuddyRequest{DisplayName: name, Greeting: greeting})
	if err != nil {
		t.Fatal(err)
	}
	in := frame.Inner{Type: frame.BuddyRequest, Time: frame.Timestamp(time.Now()), Body: b}
	s, err := frame.SealFirstContact(id, me, frame.LayoutMesh, in.Marshal(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s.Frames
}

func TestRequestCommands(t *testing.T) {
	t.Parallel()
	x := newH(t)

	r := x.cli(opts{}, "invite")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "openaim:add/"+x.me.Public().String()) || !strings.Contains(r.stderr, "no contact hint") {
		t.Fatalf("invite: %+v", r)
	}
	m := jsonObj(t, x.ok("--json", "invite", "--handle", "me.example.com").stdout)
	if m["handle"] != "me.example.com" || !strings.Contains(m["link"].(string), "?h=me.example.com") {
		t.Fatalf("invite json %v", m)
	}
	x.code(exitError, "invite", "--contact", "/ip4/192.168.1.2/tcp/4001")

	// add takes an invite link.
	bob := peer(t, 2)
	link := "openaim:add/" + bob.Public().String()
	r = x.ok("add", link, "--petname", "Bob", "--greeting", "hey")
	if !strings.Contains(r.stdout, "Added Bob") || !strings.Contains(r.stdout, "pending-out") {
		t.Fatalf("add by link: %q", r.stdout)
	}
	x.code(exitExists, "add", link)
	x.code(exitError, "add", "openaim:add/notakey")

	// A request arrives: buddies shows it; accept, decline, block, rename.
	carol, dave := peer(t, 3), peer(t, 4)
	for _, id := range []*identity.Identity{carol, dave} {
		for _, f := range requestFrom(t, id, x.me.Public(), "Pal "+id.Public().KeyID(), "it's me") {
			if _, err := x.d.Node().HandleFrame(context.Background(), f); err != nil {
				t.Fatal(err)
			}
		}
	}
	r = x.ok("buddies")
	if !strings.Contains(r.stdout, "2 buddy request(s) waiting") || !strings.Contains(r.stdout, `calls themselves "Pal `+carol.Public().KeyID()) ||
		!strings.Contains(r.stdout, `"it's me"`) {
		t.Fatalf("buddies:\n%s", r.stdout)
	}
	x.code(exitError, "accept", "Bob") // pending-out: they haven't asked
	if r := x.ok("accept", carol.Public().KeyID()); !strings.Contains(r.stdout, "Accepted") || !strings.Contains(r.stdout, "accepted") {
		t.Fatalf("accept: %q", r.stdout)
	}
	if r := x.ok("decline", dave.Public().String()); !strings.Contains(r.stdout, "Declined") {
		t.Fatalf("decline: %q", r.stdout)
	}
	x.code(exitNotFound, "decline", dave.Public().String())
	if r := x.ok("rename", carol.Public().KeyID(), "Carol", "--group", "Friends"); !strings.Contains(r.stdout, "Carol") || !strings.Contains(r.stdout, "Friends") {
		t.Fatalf("rename: %q", r.stdout)
	}
	x.code(exitUsage, "rename", "Carol")
	m = jsonObj(t, x.ok("--json", "block", "Carol").stdout)
	if m["state"] != "BUDDY_STATE_BLOCKED" || m["petname"] != "Carol" {
		t.Fatalf("block json %v", m)
	}
	x.code(exitNotFound, "block", "Nobody")
}

func TestFormatNetworkEvents(t *testing.T) {
	names := map[string]string{"kbob": "Bob"}
	bob := &pb.Buddy{IdentityKey: "kbob", Petname: "Bob", KeyId: "~kbob",
		Presence: &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_AWAY, AwayMessage: "lunch"}}
	at := timestamppb.Now()
	for _, c := range []struct {
		ev   *pb.Event
		want string
	}{
		{&pb.Event{Time: at, Kind: &pb.Event_BuddyPresence{BuddyPresence: &pb.BuddyPresence{Buddy: bob,
			From: pb.PresenceState_PRESENCE_STATE_ONLINE, To: pb.PresenceState_PRESENCE_STATE_AWAY}}}, `Bob is away: "lunch"`},
		{&pb.Event{Time: at, Kind: &pb.Event_BuddyPresence{BuddyPresence: &pb.BuddyPresence{
			Buddy: &pb.Buddy{IdentityKey: "kbob", Petname: "Bob", Presence: &pb.Presence{State: pb.PresenceState_PRESENCE_STATE_OFFLINE}},
			To:    pb.PresenceState_PRESENCE_STATE_OFFLINE, DoorClose: true, Reason: "door-close"}}}, "Bob is offline (door-close)"},
		{&pb.Event{Time: at, Kind: &pb.Event_MessageUpdated{MessageUpdated: &pb.MessageUpdate{MsgId: "00ff", BuddyKey: "kbob",
			Delivery: pb.DeliveryState_DELIVERY_STATE_ACKED}}}, "IM to Bob delivered (00ff)"},
		{&pb.Event{Time: at, Kind: &pb.Event_MessageUpdated{MessageUpdated: &pb.MessageUpdate{MsgId: "00fe", BuddyKey: "kbob",
			Delivery: pb.DeliveryState_DELIVERY_STATE_SENT}}}, "IM to Bob sent (00fe)"},
	} {
		if got := formatEvent(style{}, c.ev, names); !strings.HasSuffix(got, c.want) {
			t.Errorf("got %q, want …%q", got, c.want)
		}
	}
}
