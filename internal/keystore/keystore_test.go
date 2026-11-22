package keystore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/store"
)

// fast are the cheapest accepted parameters, to keep tests quick.
var fast = Params{Time: 1, MemoryKiB: minMemoryKiB, Threads: 1}

func id(t *testing.T, b byte) *identity.Identity {
	t.Helper()
	i, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestEnvelope(t *testing.T) {
	blob, err := Seal(MagicKeystore, []byte("hunter2"), []byte("secret"), fast)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(MagicKeystore, []byte("hunter2"), blob); err != nil || string(pt) != "secret" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := Open(MagicKeystore, []byte("hunter3"), blob); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := Open(MagicBackup, []byte("hunter2"), blob); !errors.Is(err, ErrFormat) {
		t.Fatalf("keystore opened as backup: %v", err)
	}
	if _, err := Seal(MagicKeystore, nil, []byte("x"), fast); !errors.Is(err, ErrEmptyPassphrase) {
		t.Fatalf("empty passphrase: %v", err)
	}
	// Sealing twice gives different bytes (fresh salt and nonce).
	again, _ := Seal(MagicKeystore, []byte("hunter2"), []byte("secret"), fast)
	if bytes.Equal(blob, again) {
		t.Fatal("two seals produced identical envelopes")
	}
}

func TestEnvelopeTampering(t *testing.T) {
	blob, _ := Seal(MagicBackup, []byte("pw"), []byte("contents"), fast)
	for i := range blob {
		bad := bytes.Clone(blob)
		bad[i] ^= 1
		if _, err := Open(MagicBackup, []byte("pw"), bad); err == nil {
			t.Fatalf("flipping byte %d went unnoticed", i)
		}
	}
	if _, err := Open(MagicBackup, []byte("pw"), blob[:len(blob)-1]); err == nil {
		t.Fatal("truncated envelope opened")
	}
}

// A crafted file must not make Open spend unbounded memory or time.
func TestEnvelopeParamBounds(t *testing.T) {
	blob, _ := Seal(MagicBackup, []byte("pw"), []byte("x"), fast)
	for name, mod := range map[string]func([]byte){
		"4 GiB memory": func(b []byte) { binary.BigEndian.PutUint32(b[13:], 4<<20) },
		"1 KiB memory": func(b []byte) { binary.BigEndian.PutUint32(b[13:], 1) },
		"1000 passes":  func(b []byte) { binary.BigEndian.PutUint32(b[9:], 1000) },
		"0 passes":     func(b []byte) { binary.BigEndian.PutUint32(b[9:], 0) },
		"255 threads":  func(b []byte) { b[17] = 255 },
		"unknown KDF":  func(b []byte) { b[8] = 2 },
	} {
		bad := bytes.Clone(blob)
		mod(bad)
		start := time.Now()
		_, err := Open(MagicBackup, []byte("pw"), bad)
		if !errors.Is(err, ErrParams) && !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
		if time.Since(start) > 100*time.Millisecond {
			t.Errorf("%s: rejecting took %v", name, time.Since(start))
		}
	}
	if _, err := Seal(MagicBackup, []byte("pw"), nil, Params{Time: 1, MemoryKiB: 1, Threads: 1}); !errors.Is(err, ErrParams) {
		t.Errorf("weak params sealed: %v", err)
	}
}

// Passphrases are NFC-normalized: "é" typed as one code point or as e +
// combining accent opens the same file.
func TestPassphraseNormalization(t *testing.T) {
	blob, _ := Seal(MagicKeystore, []byte("café"), []byte("x"), fast)
	if _, err := Open(MagicKeystore, []byte("café"), blob); err != nil {
		t.Fatalf("decomposed passphrase: %v", err)
	}
}

func TestBackupRoundTrip(t *testing.T) {
	rk := id(t, 9).Public()
	b := &Backup{
		Identity: id(t, 1), Recovery: id(t, 2), CreatedAt: time.Unix(1_790_000_000, 0),
		Buddies: []store.Buddy{
			{Key: id(t, 3).Public(), Handle: "skaterdude99.example", Petname: "Sk8", Group: "Buddies", State: store.Accepted, Verified: true, RecoveryKey: &rk},
			{Key: id(t, 4).Public(), Group: "Family", State: store.PendingOut},
		},
	}
	blob, err := EncodeBackup(b, []byte("correct horse"), fast)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBackup(blob, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity.Public() != b.Identity.Public() || got.Recovery.Public() != b.Recovery.Public() || !got.CreatedAt.Equal(b.CreatedAt) {
		t.Fatal("identity, recovery key or time lost")
	}
	if len(got.Buddies) != 2 || got.Buddies[0].Handle != "skaterdude99.example" || *got.Buddies[0].RecoveryKey != rk ||
		!got.Buddies[0].Verified || got.Buddies[1].State != store.PendingOut || got.Buddies[1].RecoveryKey != nil {
		t.Fatalf("buddies: %+v", got.Buddies)
	}
	if _, err := DecodeBackup(blob, []byte("wrong horse")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// Without a recovery key yet.
	blob, _ = EncodeBackup(&Backup{Identity: id(t, 1)}, []byte("pw"), fast)
	if got, err := DecodeBackup(blob, []byte("pw")); err != nil || got.Recovery != nil {
		t.Fatalf("no recovery key: %v", err)
	}
}

func TestBackupRejectsBadContents(t *testing.T) {
	// A well-formed envelope around contents that fail validation.
	for name, pt := range map[string][]byte{
		"not protobuf": {0xff, 0xff},
		"short seed":   {0x0a, 0x01, 0x00},
	} {
		blob, _ := Seal(MagicBackup, []byte("pw"), pt, fast)
		if _, err := DecodeBackup(blob, []byte("pw")); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := &Backup{Identity: id(t, 1), Buddies: []store.Buddy{{Key: id(t, 3).Public(), State: "friendly"}}}
	blob, _ := EncodeBackup(bad, []byte("pw"), fast)
	if _, err := DecodeBackup(blob, []byte("pw")); !errors.Is(err, ErrFormat) {
		t.Errorf("unknown buddy state: %v", err)
	}
}

func TestFileKeystore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.key")
	ks := &FileKeystore{Path: path, Passphrase: []byte("pw"), Params: fast}
	if _, err := ks.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty keystore: %v", err)
	}
	seed := id(t, 5).Seed()
	if err := ks.Save(seed); err != nil {
		t.Fatal(err)
	}
	if got, err := ks.Load(); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("load: %v", err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("keystore file mode %v, want 0600", fi.Mode().Perm())
		}
	}
	// Replacing the key leaves no temp files behind.
	if err := ks.Save(id(t, 6).Seed()); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 1 {
		t.Fatalf("%d files in the keystore dir, want 1", len(ents))
	}
	wrong := &FileKeystore{Path: path, Passphrase: []byte("nope")}
	if _, err := wrong.Load(); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// A backup file is not a keystore file.
	bk, _ := EncodeBackup(&Backup{Identity: id(t, 1)}, []byte("pw"), fast)
	os.WriteFile(path, bk, 0o600)
	if _, err := ks.Load(); !errors.Is(err, ErrFormat) {
		t.Fatalf("backup loaded as keystore: %v", err)
	}
}

func TestDefaultParamsAccepted(t *testing.T) {
	if err := DefaultParams.check(); err != nil {
		t.Fatal(err)
	}
}

func FuzzOpen(f *testing.F) {
	blob, _ := Seal(MagicBackup, []byte("pw"), []byte("x"), fast)
	f.Add(blob)
	f.Fuzz(func(t *testing.T, b []byte) {
		// Keep the fuzzer from spending its time in Argon2id: only accept
		// headers with the cheapest parameters.
		if len(b) >= headerLen && (binary.BigEndian.Uint32(b[9:]) != fast.Time || binary.BigEndian.Uint32(b[13:]) != fast.MemoryKiB || b[17] != fast.Threads) {
			return
		}
		Open(MagicBackup, []byte("pw"), b)
	})
}
