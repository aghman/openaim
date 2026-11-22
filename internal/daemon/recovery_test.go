package daemon

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/store"
)

var backupPass = []byte("backup pass phrase")

// initWithBackup creates an identity with a recovery key whose first backup
// goes to dir/../backup.oaimbak.
func initWithBackup(t *testing.T, dir string) (*Initialized, string) {
	t.Helper()
	path := filepath.Join(tempDir(t), "first.oaimbak")
	c := initCfg(dir)
	c.BackupPath, c.BackupPassphrase = path, backupPass
	res, err := InitIdentity(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	return res, path
}

// filesContain reports whether any file under dir contains needle.
func filesContain(t *testing.T, dir string, needle []byte) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, needle) {
			hits = append(hits, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

func TestInitGeneratesRecoveryKeyOnlyInBackup(t *testing.T) {
	dir := tempDir(t)
	res, path := initWithBackup(t, dir)
	if res.RecoveryKey == nil || res.BackupPath != path {
		t.Fatalf("init result %+v", res)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if isUnix() && fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v", fi.Mode())
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bk, err := keystore.DecodeBackup(blob, backupPass)
	if err != nil {
		t.Fatal(err)
	}
	if bk.Identity.Public() != res.Identity.Public() || bk.Recovery == nil || bk.Recovery.Public() != *res.RecoveryKey {
		t.Fatalf("backup holds %+v", bk)
	}

	n := open(t, dir)
	if rk := n.RecoveryKey(); rk == nil || *rk != *res.RecoveryKey {
		t.Fatalf("node recovery key %v", rk)
	}
	// The recovery seed is nowhere in the data dir (database, WAL,
	// keystore); its public key is.
	if hits := filesContain(t, dir, bk.Recovery.Seed()); len(hits) != 0 {
		t.Fatalf("recovery seed found in %v", hits)
	}
	if hits := filesContain(t, dir, res.RecoveryKey[:]); len(hits) == 0 {
		t.Fatal("recovery public key not recorded")
	}

	// A later backup carries it only when given one that has it.
	if _, err := n.AddBuddy(ctx, peer(t, 2).Public().String(), "Bob", ""); err != nil {
		t.Fatal(err)
	}
	plain, err := n.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: []byte("new pass")})
	if err != nil || plain.IncludesRecovery || plain.RecoveryKey == nil || *plain.RecoveryKey != *res.RecoveryKey {
		t.Fatalf("plain export %+v %v", plain, err)
	}
	if b, _ := keystore.DecodeBackup(plain.Blob, []byte("new pass")); b.Recovery != nil || len(b.Buddies) != 1 {
		t.Fatalf("plain backup %+v", b)
	}
	carried, err := n.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: []byte("new pass"), Previous: blob, PreviousPassphrase: backupPass})
	if err != nil || !carried.IncludesRecovery {
		t.Fatalf("carried export %+v %v", carried, err)
	}
	b2, err := keystore.DecodeBackup(carried.Blob, []byte("new pass"))
	if err != nil || b2.Recovery == nil || b2.Recovery.Public() != *res.RecoveryKey || len(b2.Buddies) != 1 {
		t.Fatalf("carried backup %+v %v", b2, err)
	}
	// Chaining works: the new file can be the next one's previous.
	if c, err := n.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: []byte("new pass"), Previous: carried.Blob}); err != nil || !c.IncludesRecovery {
		t.Fatalf("chained export %+v %v", c, err)
	}
	// Wrong passphrase for the previous backup.
	if _, err := n.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: []byte("new pass"), Previous: blob}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("previous with wrong passphrase: %v", err)
	}
	// Someone else's backup.
	other, err := keystore.EncodeBackup(&keystore.Backup{Identity: peer(t, 3), Recovery: peer(t, 4)}, backupPass, fast)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: backupPass, Previous: other}); !errors.Is(err, ErrBackupMismatch) {
		t.Fatalf("other identity's backup: %v", err)
	}
	// Our identity with a different recovery key.
	forged, err := keystore.EncodeBackup(&keystore.Backup{Identity: res.Identity, Recovery: peer(t, 4)}, backupPass, fast)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: backupPass, Previous: forged}); !errors.Is(err, ErrBackupMismatch) {
		t.Fatalf("backup with another recovery key: %v", err)
	}
	if rk := n.RecoveryKey(); *rk != *res.RecoveryKey {
		t.Fatal("recovery key changed")
	}
}

func isUnix() bool { return runtime.GOOS != "windows" }

func TestInitBackupRules(t *testing.T) {
	dir := tempDir(t)
	existing := filepath.Join(tempDir(t), "taken")
	if err := os.WriteFile(existing, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := initCfg(dir)
	c.BackupPath, c.BackupPassphrase = existing, backupPass
	if _, err := InitIdentity(ctx, c); err == nil {
		t.Fatal("init overwrote an existing file")
	}
	if b, _ := os.ReadFile(existing); string(b) != "mine" {
		t.Fatal("existing file changed")
	}
	if _, err := os.Stat(PathsFor(dir).Keystore); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("keystore written after the backup failed: %v", err)
	}
	c.BackupPath, c.BackupPassphrase = filepath.Join(tempDir(t), "b"), nil
	if _, err := InitIdentity(ctx, c); !errors.Is(err, keystore.ErrEmptyPassphrase) {
		t.Fatalf("backup without passphrase: %v", err)
	}
	c.BackupPassphrase, c.Phrase = backupPass, peer(t, 1).Phrase()
	if _, err := InitIdentity(ctx, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("restore with a backup path: %v", err)
	}

	// Without a backup there is no recovery key.
	res, err := InitIdentity(ctx, initCfg(tempDir(t)))
	if err != nil || res.RecoveryKey != nil || res.BackupPath != "" {
		t.Fatalf("plain init %+v %v", res, err)
	}
}

func TestRestoreAndRecoveryKey(t *testing.T) {
	dir := tempDir(t)
	res, path := initWithBackup(t, dir)
	n := open(t, dir)
	bob := peer(t, 2)
	if _, err := n.AddBuddy(ctx, bob.Public().String(), "Bob", "Friends"); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	full, err := n.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: backupPass, Previous: first})
	if err != nil {
		t.Fatal(err)
	}
	n.Close()

	// From the phrase: no recovery key.
	pdir := tempDir(t)
	c := initCfg(pdir)
	c.Phrase = res.Identity.Phrase()
	pr, err := InitIdentity(ctx, c)
	if err != nil || pr.RecoveryKey != nil {
		t.Fatalf("phrase restore %+v %v", pr, err)
	}
	pn := open(t, pdir)
	if pn.RecoveryKey() != nil {
		t.Fatal("phrase-restored node has a recovery key")
	}
	// It adopts the recovery key from a backup of the same identity.
	if e, err := pn.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: backupPass, Previous: first}); err != nil || !e.IncludesRecovery {
		t.Fatalf("adopting export %+v %v", e, err)
	}
	if rk := pn.RecoveryKey(); rk == nil || *rk != *res.RecoveryKey {
		t.Fatalf("adopted %v", rk)
	}
	pn.Close()
	if rk := open(t, pdir).RecoveryKey(); rk == nil || *rk != *res.RecoveryKey {
		t.Fatal("adopted key not persisted")
	}

	// From the backup: identity, recovery key and buddies.
	bk, err := keystore.DecodeBackup(full.Blob, backupPass)
	if err != nil {
		t.Fatal(err)
	}
	bdir := tempDir(t)
	c = initCfg(bdir)
	c.FromBackup = bk
	br, err := InitIdentity(ctx, c)
	if err != nil || br.RecoveryKey == nil || *br.RecoveryKey != *res.RecoveryKey || br.Buddies != 1 || br.BackupPath != "" {
		t.Fatalf("backup restore %+v %v", br, err)
	}
	bn := open(t, bdir)
	if bn.Identity() != res.Identity.Public() || *bn.RecoveryKey() != *res.RecoveryKey {
		t.Fatal("backup restore opened the wrong keys")
	}
	got, err := bn.FindBuddy(ctx, "Bob")
	if err != nil || got.Group != "Friends" || got.State != store.PendingOut {
		t.Fatalf("restored buddy %+v %v", got, err)
	}
	if hits := filesContain(t, bdir, bk.Recovery.Seed()); len(hits) != 0 {
		t.Fatalf("restore wrote the recovery seed to %v", hits)
	}
	c.Phrase = res.Identity.Phrase()
	if _, err := InitIdentity(ctx, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("phrase and backup together: %v", err)
	}
}
