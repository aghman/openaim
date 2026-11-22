package daemon

import (
	"errors"
	"os"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/aghman/openaim/internal/keystore"
)

// These tests use go-keyring's in-memory mock, never the real keychain.

func noPassphrase(t *testing.T) func() ([]byte, error) {
	return func() ([]byte, error) {
		t.Error("asked for a passphrase")
		return nil, errors.New("no passphrase here")
	}
}

func recorded(t *testing.T, n *Node) string {
	t.Helper()
	v, err := n.store.Meta(ctx, metaKeystore)
	if err != nil {
		t.Fatal(err)
	}
	return string(v)
}

func TestKeychainKeystore(t *testing.T) {
	keyring.MockInit()
	dir := tempDir(t)
	id, err := Init(ctx, InitConfig{DataDir: dir, Keystore: KeystoreModeKeychain, PassphraseFunc: noPassphrase(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PathsFor(dir).Keystore); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("keychain init wrote a keystore file: %v", err)
	}
	ks, _ := keystore.NewKeychainKeystore(dir)
	if seed, err := ks.Load(); err != nil || string(seed) != string(id.Seed()) {
		t.Fatalf("keychain item: %v", err)
	}

	// Default and auto take the recorded keychain; no passphrase is asked.
	for _, m := range []KeystoreMode{KeystoreModeDefault, KeystoreModeAuto, KeystoreModeKeychain} {
		n, err := Open(ctx, Config{DataDir: dir, Keystore: m, PassphraseFunc: noPassphrase(t)})
		if err != nil {
			t.Fatalf("open %q: %v", m, err)
		}
		if n.Identity() != id.Public() || recorded(t, n) != "keychain" {
			t.Fatalf("open %q: wrong identity or record", m)
		}
		n.Close()
	}
	// Asking for the file is refused, whatever the passphrase.
	if _, err := Open(ctx, Config{DataDir: dir, Keystore: KeystoreModeFile, Passphrase: testPass}); !errors.Is(err, ErrKeystoreMismatch) {
		t.Fatalf("open as file: %v", err)
	}
	// A second init doesn't overwrite the seed.
	if _, err := Init(ctx, InitConfig{DataDir: dir, Keystore: KeystoreModeKeychain}); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second init: %v", err)
	}
	if seed, _ := ks.Load(); string(seed) != string(id.Seed()) {
		t.Fatal("seed replaced")
	}
}

// The recovery seed never reaches the keychain either, and the backup uses
// the default costs when none are given.
func TestKeychainInitWithRecoveryKey(t *testing.T) {
	keyring.MockInit()
	dir := tempDir(t)
	path := tempDir(t) + "/first.oaimbak"
	res, err := InitIdentity(ctx, InitConfig{DataDir: dir, Keystore: KeystoreModeKeychain, PassphraseFunc: noPassphrase(t),
		BackupPath: path, BackupPassphrase: backupPass})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bk, err := keystore.DecodeBackup(blob, backupPass)
	if err != nil || bk.Recovery == nil || bk.Recovery.Public() != *res.RecoveryKey {
		t.Fatalf("backup %+v %v", bk, err)
	}
	ks, _ := keystore.NewKeychainKeystore(dir)
	if seed, err := ks.Load(); err != nil || string(seed) != string(res.Identity.Seed()) {
		t.Fatalf("keychain item: %v", err)
	}
	if hits := filesContain(t, dir, bk.Recovery.Seed()); len(hits) != 0 {
		t.Fatalf("recovery seed in %v", hits)
	}
}

func TestKeychainItemNeverOverwritten(t *testing.T) {
	keyring.MockInit()
	dir := tempDir(t)
	// A seed for this data dir is in the keychain, but the database is new
	// (e.g. the directory was wiped).
	ks, _ := keystore.NewKeychainKeystore(dir)
	old := peer(t, 8)
	if err := ks.Save(old.Seed()); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, InitConfig{DataDir: dir, Keystore: KeystoreModeKeychain}); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("init over a keychain item: %v", err)
	}
	if seed, _ := ks.Load(); string(seed) != string(old.Seed()) {
		t.Fatal("keychain seed overwritten")
	}
}

func TestFileKeystoreRecorded(t *testing.T) {
	keyring.MockInit()
	dir := tempDir(t)
	if _, err := Init(ctx, initCfg(dir)); err != nil {
		t.Fatal(err)
	}
	n := open(t, dir)
	if recorded(t, n) != "file" {
		t.Fatalf("recorded %q", recorded(t, n))
	}
	n.Close()
	if _, err := Open(ctx, Config{DataDir: dir, Keystore: KeystoreModeKeychain}); !errors.Is(err, ErrKeystoreMismatch) {
		t.Fatalf("open as keychain: %v", err)
	}
	// The passphrase is asked lazily, and only for the file keystore.
	asked := 0
	n, err := Open(ctx, Config{DataDir: dir, Keystore: KeystoreModeAuto, KeystoreParams: fast,
		PassphraseFunc: func() ([]byte, error) { asked++; return testPass, nil }})
	if err != nil || asked != 1 {
		t.Fatalf("open with passphrase func: %v, asked %d", err, asked)
	}
	n.Close()
	if _, err := Open(ctx, Config{DataDir: dir}); !errors.Is(err, keystore.ErrEmptyPassphrase) {
		t.Fatalf("open without passphrase: %v", err)
	}
	if _, err := Open(ctx, Config{DataDir: dir, Keystore: "vault", Passphrase: testPass}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown mode: %v", err)
	}
}

func TestAutoKeystore(t *testing.T) {
	keyring.MockInit()
	dir := tempDir(t)
	if _, err := Init(ctx, InitConfig{DataDir: dir, Keystore: KeystoreModeAuto, PassphraseFunc: noPassphrase(t)}); err != nil {
		t.Fatal(err)
	}
	if n := open(t, dir); recorded(t, n) != "keychain" {
		t.Fatal("auto with a keychain didn't use it")
	}

	// No keychain answers (say, a server with no D-Bus session).
	keyring.MockInitWithError(errors.New("no D-Bus session"))
	t.Cleanup(keyring.MockInit)
	if m, err := ResolveKeystoreMode(KeystoreModeAuto); err != nil || m != KeystoreModeFile {
		t.Fatalf("auto without keychain: %q %v", m, err)
	}
	if _, err := ResolveKeystoreMode(KeystoreModeKeychain); !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("keychain without keychain: %v", err)
	}
	dir2 := tempDir(t)
	if _, err := Init(ctx, InitConfig{DataDir: dir2, Keystore: KeystoreModeAuto}); !errors.Is(err, keystore.ErrEmptyPassphrase) {
		t.Fatalf("auto falls back to the file, which needs a passphrase: %v", err)
	}
	if _, err := Init(ctx, InitConfig{DataDir: dir2, Keystore: KeystoreModeAuto, Passphrase: testPass, KeystoreParams: fast}); err != nil {
		t.Fatal(err)
	}
	if n := open(t, dir2); recorded(t, n) != "file" {
		t.Fatal("auto without a keychain didn't use the file")
	}
	if _, err := Init(ctx, InitConfig{DataDir: tempDir(t), Keystore: KeystoreModeKeychain}); !errors.Is(err, ErrNoKeychain) {
		t.Fatalf("keychain init without keychain: %v", err)
	}
}

func TestParseKeystoreMode(t *testing.T) {
	for _, s := range []string{"", "auto", "keychain", "file"} {
		if m, err := ParseKeystoreMode(s); err != nil || string(m) != s {
			t.Errorf("%q: %q %v", s, m, err)
		}
	}
	for _, s := range []string{"File", "vault", " file"} {
		if _, err := ParseKeystoreMode(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", s)
		}
	}
}
