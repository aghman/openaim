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

	"github.com/aghman/openaim/internal/api"
	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/keystore"
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
	keyRE  = regexp.MustCompile(`key: (\S+)`)
)

func TestInitRestoreRun(t *testing.T) {
	ctx := context.Background()
	passFile := filepath.Join(shortDir(t), "pass")
	if err := os.WriteFile(passFile, []byte("s3cret pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(shortDir(t), "a")
	r := runCmd(ctx, "", nil, "init", "--data-dir", dir, "--passphrase-file", passFile)
	if r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stderr)
	}
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

	// Init again is refused.
	if r := runCmd(ctx, "", nil, "init", "--data-dir", dir, "--passphrase-file", passFile); r.code != 1 {
		t.Fatalf("second init: %d", r.code)
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
	if r := runCmd(ctx, "abandon abandon\n", vars, "init", "--restore", "--data-dir", shortDir(t)); r.code != 1 {
		t.Fatalf("bad phrase: %d", r.code)
	}

	// Run serves until the context ends.
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan result, 1)
	go func() { done <- runCmd(runCtx, "", vars) }() // "run" is the default command
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
