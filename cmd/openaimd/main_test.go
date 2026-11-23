package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/aghman/openaim/internal/api"
	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/transport/ip"
)

func init() { keystoreParams = keystore.Params{Time: 1, MemoryKiB: 8 << 10, Threads: 1} }

// shortDir is a private temp dir with a path short enough for a Unix socket.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "oad")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

type result struct {
	code           int
	stdout, stderr string
}

func runCmd(ctx context.Context, stdin string, vars map[string]string, args ...string) result {
	var out, errb bytes.Buffer
	e := env{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, getenv: func(k string) string { return vars[k] }}
	code := run(ctx, args, e)
	return result{code, out.String(), errb.String()}
}

var (
	wordRE = regexp.MustCompile(`\d+\. (\S+)`)
	keyRE  = regexp.MustCompile(`\n  key: (\S+)`)
	recRE  = regexp.MustCompile(`recovery key: ([a-z2-7]{52}) `)
)

func TestInitRestoreRun(t *testing.T) {
	ctx := context.Background()
	passFile := filepath.Join(shortDir(t), "pass")
	if err := os.WriteFile(passFile, []byte("s3cret pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(shortDir(t), "a")
	// A new identity needs somewhere for its recovery key.
	if r := runCmd(ctx, "", nil, "init", "--data-dir", dir, "--passphrase-file", passFile); r.code != 1 || !strings.Contains(r.stderr, "--backup") {
		t.Fatalf("init without --backup: %+v", r)
	}
	backup := filepath.Join(shortDir(t), "first.oaimbak")
	bvars := map[string]string{EnvBackupPassphrase: "backup pass"}
	r := runCmd(ctx, "", bvars, "init", "--data-dir", dir, "--passphrase-file", passFile, "--backup", backup)
	if r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "backup: "+backup) || !strings.Contains(r.stdout, "ONLY copy of the recovery key") {
		t.Fatalf("no backup notice:\n%s", r.stdout)
	}
	rkey := recRE.FindStringSubmatch(r.stdout)[1]
	if !strings.Contains(r.stdout, "RECOVERY PHRASE") {
		t.Fatalf("no phrase warning:\n%s", r.stdout)
	}
	var words []string
	for _, m := range wordRE.FindAllStringSubmatch(r.stdout, -1) {
		words = append(words, m[1])
	}
	if len(words) != 24 {
		t.Fatalf("printed %d words:\n%s", len(words), r.stdout)
	}
	key := keyRE.FindStringSubmatch(r.stdout)[1]

	blob, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	bk, err := keystore.DecodeBackup(blob, []byte("backup pass"))
	if err != nil || bk.Recovery == nil || bk.Recovery.Public().String() != rkey || bk.Identity.Public().String() != key {
		t.Fatalf("backup %+v %v", bk, err)
	}

	// Init again is refused, and an existing backup file is never replaced.
	if r := runCmd(ctx, "", bvars, "init", "--data-dir", dir, "--passphrase-file", passFile, "--no-recovery-key"); r.code != 1 {
		t.Fatalf("second init: %d", r.code)
	}
	if r := runCmd(ctx, "", bvars, "init", "--data-dir", shortDir(t), "--passphrase-file", passFile, "--backup", backup); r.code != 1 || !strings.Contains(r.stderr, "exists") {
		t.Fatalf("init over an existing backup: %+v", r)
	}
	if r := runCmd(ctx, "", bvars, "init", "--restore", "--backup", backup); r.code != 2 {
		t.Fatalf("restore with --backup: %+v", r)
	}

	// Restoring from the backup brings back the recovery key.
	dir3 := filepath.Join(shortDir(t), "c")
	r = runCmd(ctx, "", bvars, "init", "--data-dir", dir3, "--passphrase-file", passFile, "--restore-backup", backup)
	if r.code != 0 || keyRE.FindStringSubmatch(r.stdout)[1] != key || recRE.FindStringSubmatch(r.stdout)[1] != rkey ||
		strings.Contains(r.stdout, "RECOVERY PHRASE") {
		t.Fatalf("restore from backup: %+v", r)
	}
	if r := runCmd(ctx, "", map[string]string{EnvBackupPassphrase: "wrong"}, "init", "--data-dir", shortDir(t), "--passphrase-file", passFile, "--restore-backup", backup); r.code != 1 {
		t.Fatalf("restore with the wrong backup passphrase: %+v", r)
	}

	// Restore from the phrase on stdin, passphrase from the environment.
	dir2 := filepath.Join(shortDir(t), "b")
	vars := map[string]string{EnvPassphrase: "other pass", daemon.EnvDataDir: dir2}
	r = runCmd(ctx, strings.Join(words, " ")+"\n", vars, "init", "--restore")
	if r.code != 0 {
		t.Fatalf("restore: %d %s", r.code, r.stderr)
	}
	if got := keyRE.FindStringSubmatch(r.stdout)[1]; got != key {
		t.Fatalf("restored %s, want %s", got, key)
	}
	if strings.Contains(r.stdout, "RECOVERY PHRASE") {
		t.Fatal("restore printed the phrase again")
	}
	if !strings.Contains(r.stdout, "recovery key: none") {
		t.Fatalf("phrase restore claims a recovery key:\n%s", r.stdout)
	}
	if r := runCmd(ctx, "abandon abandon\n", vars, "init", "--restore", "--data-dir", shortDir(t)); r.code != 1 {
		t.Fatalf("bad phrase: %d", r.code)
	}

	// Run serves until the context ends.
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan result, 1)
	// "run" is the default command. On the network, but only on loopback.
	go func() { done <- runCmd(runCtx, "", vars, "--listen", "/ip4/127.0.0.1/tcp/0") }()
	sock := daemon.PathsFor(dir2).Socket
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Lstat(sock); err == nil {
			break
		} else if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket never appeared: %+v", <-done)
		}
	}
	conn, err := api.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st, err := pb.NewDaemonClient(conn).GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil || st.GetIdentityKey() != key {
		t.Fatalf("status %v %v", st, err)
	}
	if n := st.GetNetwork(); n.GetPeerId() == "" || len(n.GetListenAddrs()) == 0 ||
		!strings.HasPrefix(n.GetListenAddrs()[0], "/ip4/127.0.0.1/tcp/") || n.GetPublic() {
		t.Fatalf("network %v", n)
	}
	cancel()
	if r := <-done; r.code != 0 {
		t.Fatalf("run exited %d: %s", r.code, r.stderr)
	}
}

func TestRunErrors(t *testing.T) {
	ctx := context.Background()
	dir := shortDir(t)
	if r := runCmd(ctx, "", map[string]string{EnvPassphrase: "x"}, "run", "--data-dir", dir); r.code != 1 || !strings.Contains(r.stderr, "openaimd init") {
		t.Fatalf("uninitialized: %+v", r)
	}
	// No passphrase source and no terminal.
	if r := runCmd(ctx, "", nil, "run", "--data-dir", dir); r.code != 1 || !strings.Contains(r.stderr, "passphrase") {
		t.Fatalf("no passphrase: %+v", r)
	}
	// Handle settings are checked at startup.
	if r := runCmd(ctx, "", map[string]string{EnvPassphrase: "x"}, "run", "--data-dir", dir, "--doh-resolver", "https://a.example/dns-query"); r.code != 1 || !strings.Contains(r.stderr, "resolver") {
		t.Fatalf("one resolver: %+v", r)
	}
	if r := runCmd(ctx, "", map[string]string{EnvPassphrase: "x"}, "run", "--data-dir", dir, "--registry", "-bad-"); r.code != 1 || !strings.Contains(r.stderr, "registry") {
		t.Fatalf("bad registry: %+v", r)
	}
	// Invite contact hints never name our own IP address.
	if r := runCmd(ctx, "", map[string]string{EnvPassphrase: "x"}, "run", "--data-dir", dir, "--contact-hint", "/ip4/203.0.113.9/tcp/4001"); r.code != 1 || !strings.Contains(r.stderr, "--contact-hint") {
		t.Fatalf("home IP contact hint: %+v", r)
	}
	if r := runCmd(ctx, "", map[string]string{EnvPassphrase: "x"}, "run", "--data-dir", dir, "--first-contact-burst", "0"); r.code != 1 {
		t.Fatalf("zero burst: %+v", r)
	}
	if r := runCmd(ctx, "", nil, "frobnicate"); r.code != 2 {
		t.Fatalf("unknown command: %+v", r)
	}
	if r := runCmd(ctx, "", nil, "run", "--passphrase", "x"); r.code != 2 {
		t.Fatalf("--passphrase flag accepted: %+v", r)
	}
	if r := runCmd(ctx, "", nil, "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "openaimd ") {
		t.Fatalf("version: %+v", r)
	}
}

func TestKeychainInitRun(t *testing.T) {
	keyring.MockInit() // never the real keychain
	ctx := context.Background()
	dir := filepath.Join(shortDir(t), "k")

	if r := runCmd(ctx, "", nil, "init", "--data-dir", dir, "--keystore", "vault", "--no-recovery-key"); r.code != 1 || !strings.Contains(r.stderr, "--keystore") {
		t.Fatalf("bad mode: %+v", r)
	}
	// No passphrase source at all: the keychain doesn't need one.
	r := runCmd(ctx, "", nil, "init", "--data-dir", dir, "--keystore", "keychain", "--no-recovery-key")
	if r.code != 0 || !strings.Contains(r.stdout, "keystore: OS keychain") {
		t.Fatalf("keychain init: %+v", r)
	}
	key := keyRE.FindStringSubmatch(r.stdout)[1]
	if _, err := os.Stat(daemon.PathsFor(dir).Keystore); !os.IsNotExist(err) {
		t.Fatalf("keystore file written: %v", err)
	}

	// Asking run for the file keystore is refused.
	if r := runCmd(ctx, "", map[string]string{EnvPassphrase: "x"}, "run", "--data-dir", dir, "--keystore", "file"); r.code != 1 || !strings.Contains(r.stderr, "keystore") {
		t.Fatalf("mismatched run: %+v", r)
	}

	// Plain run uses the keychain, with no passphrase.
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan result, 1)
	go func() { done <- runCmd(runCtx, "", nil, "run", "--data-dir", dir, "--offline") }()
	sock := daemon.PathsFor(dir).Socket
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Lstat(sock); err == nil {
			break
		} else if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket never appeared: %+v", <-done)
		}
	}
	conn, err := api.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st, err := pb.NewDaemonClient(conn).GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil || st.GetIdentityKey() != key || st.GetNetwork() != nil {
		t.Fatalf("status %v %v", st, err)
	}
	cancel()
	if r := <-done; r.code != 0 {
		t.Fatalf("run exited %d: %s", r.code, r.stderr)
	}

	// A file-keystore identity refuses --keystore=keychain.
	passFile := filepath.Join(shortDir(t), "pass")
	if err := os.WriteFile(passFile, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir2 := filepath.Join(shortDir(t), "f")
	if r := runCmd(ctx, "", nil, "init", "--data-dir", dir2, "--passphrase-file", passFile, "--no-recovery-key"); r.code != 0 || !strings.Contains(r.stdout, "keystore: passphrase-encrypted file") {
		t.Fatalf("file init: %+v", r)
	}
	if r := runCmd(ctx, "", nil, "run", "--data-dir", dir2, "--keystore", "keychain"); r.code != 1 || !strings.Contains(r.stderr, "keystore") {
		t.Fatalf("mismatched run: %+v", r)
	}
}

func TestNetworkInit(t *testing.T) {
	dir := filepath.Join(shortDir(t), "n")
	r := runCmd(context.Background(), "", nil, "network", "init", "--data-dir", dir)
	path := daemon.PathsFor(dir).Network
	if r.code != 0 || !strings.Contains(r.stdout, path) {
		t.Fatalf("network init: %+v", r)
	}
	b, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(b, ip.DefaultNetworkConfigJSON()) {
		t.Fatalf("wrote %q %v", b, err)
	}
	if _, err := ip.LoadNetworkConfig(path); err != nil {
		t.Fatal(err)
	}
	// It won't overwrite an edited file without --force.
	if err := os.WriteFile(path, []byte(`{"relays": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runCmd(context.Background(), "", nil, "network", "init", "--data-dir", dir); r.code != 1 || !strings.Contains(r.stderr, "--force") {
		t.Fatalf("second init: %+v", r)
	}
	if r := runCmd(context.Background(), "", nil, "network", "init", "--data-dir", dir, "--force"); r.code != 0 {
		t.Fatalf("--force: %+v", r)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, ip.DefaultNetworkConfigJSON()) {
		t.Fatalf("--force left %q", b)
	}
	if r := runCmd(context.Background(), "", nil, "network"); r.code != 2 || !strings.Contains(r.stderr, "network init") {
		t.Fatalf("bare network: %+v", r)
	}
}

func TestRunNetworkFlags(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(shortDir(t), "f")
	vars := map[string]string{EnvPassphrase: "x"}
	if r := runCmd(ctx, "", vars, "init", "--data-dir", dir, "--no-recovery-key"); r.code != 0 {
		t.Fatalf("init: %+v", r)
	}
	if r := runCmd(ctx, "", vars, "run", "--data-dir", dir, "--offline", "--public"); r.code != 2 {
		t.Fatalf("--offline --public: %+v", r)
	}
	if r := runCmd(ctx, "", vars, "run", "--data-dir", dir, "--listen", "not an addr"); r.code != 1 || !strings.Contains(r.stderr, "--listen") {
		t.Fatalf("bad --listen: %+v", r)
	}
	// A broken network.json is reported before anything starts.
	if err := os.WriteFile(daemon.PathsFor(dir).Network, []byte(`{"relay": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runCmd(ctx, "", vars, "run", "--data-dir", dir, "--listen", "/ip4/127.0.0.1/tcp/0"); r.code != 1 || !strings.Contains(r.stderr, "network init --force") {
		t.Fatalf("broken network.json: %+v", r)
	}
}
