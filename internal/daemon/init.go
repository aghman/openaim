package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/store"
)

// metaIdentity is the store meta key holding our 32-byte public identity
// key. It lets the daemon notice a keystore and database that belong to
// different identities.
const metaIdentity = "identity_key"

// metaRecoveryKey holds our recovery key's 32-byte PUBLIC key (design §5.5,
// spec/wire.md §4.6), which BUDDY_REQUEST and BUDDY_ACCEPT carry. Its seed
// is never stored here or in the keystore: only in backup files.
const metaRecoveryKey = "recovery_key"

// Identity lifecycle errors.
var (
	ErrNotInitialized     = errors.New("daemon: no identity in this data dir (run: openaimd init)")
	ErrAlreadyInitialized = errors.New("daemon: data dir already has an identity")
	ErrIdentityMismatch   = errors.New("daemon: keystore and database belong to different identities")
)

// InitConfig says how to create an identity.
type InitConfig struct {
	DataDir string
	// Keystore is where to keep the seed. KeystoreModeDefault is the file;
	// KeystoreModeAuto is the keychain if one answers, else the file. The
	// choice is recorded, and Open insists on the same one.
	Keystore KeystoreMode
	// Passphrase encrypts a file keystore. If it is empty, PassphraseFunc
	// is asked instead, and only when the file keystore is used. A
	// keychain keystore needs neither.
	Passphrase     []byte
	PassphraseFunc func() ([]byte, error)
	// Phrase, if set, restores the identity from its recovery phrase
	// instead of generating a new one. A phrase restores the identity key
	// only: the recovery key isn't in it (spec/wire.md §4.5, §4.6), so a
	// phrase-restored identity has none, unless the database already
	// recorded one. FromBackup brings it back.
	Phrase string
	// FromBackup, if set, restores the identity, the recovery public key
	// and the buddy list from a decoded backup file (keystore.DecodeBackup)
	// instead of generating a new identity. The recovery seed stays in that
	// file: nothing new is written.
	FromBackup *keystore.Backup

	// BackupPath and BackupPassphrase, for a new identity, make Init
	// generate the recovery key (design §5.5) and write the first backup
	// file, holding the identity seed and the recovery seed, to BackupPath
	// before anything else is saved. The file must not exist yet. The
	// recovery seed goes only into that file, never into the keystore or
	// the database, which keep only its public key. Without BackupPath no
	// recovery key is made. Restores (Phrase, FromBackup) refuse BackupPath.
	BackupPath       string
	BackupPassphrase []byte

	// KeystoreParams are the keystore's (and the backup's) Argon2id costs;
	// zero means keystore.DefaultParams. Tests use cheap ones.
	KeystoreParams keystore.Params
}

// Initialized is what InitIdentity made.
type Initialized struct {
	Identity *identity.Identity
	// RecoveryKey is the recovery public key now recorded, or nil if the
	// identity has none.
	RecoveryKey *identity.PublicKey
	// BackupPath is the backup file written (absolute), or "" if none.
	BackupPath string
	// Buddies is how many buddies were restored from FromBackup.
	Buddies int
}

// Init is InitIdentity, returning only the identity.
func Init(ctx context.Context, cfg InitConfig) (*identity.Identity, error) {
	r, err := InitIdentity(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return r.Identity, nil
}

// InitIdentity creates (or restores) the identity in a data directory: it
// saves the seed in the keystore under the passphrase and records the public
// key in the database. It refuses a directory that already has an identity,
// and holds the directory's lock throughout, so it can't race a running
// daemon.
//
// For a new identity with cfg.BackupPath set, it also generates the recovery
// key and writes the first backup file; see InitConfig.
//
// The caller shows the new identity's recovery phrase (id.Phrase()) to the
// user, once.
func InitIdentity(ctx context.Context, cfg InitConfig) (*Initialized, error) {
	kind, err := ResolveKeystoreMode(cfg.Keystore)
	if err != nil {
		return nil, err
	}
	if kind == KeystoreModeFile && len(cfg.Passphrase) == 0 && cfg.PassphraseFunc == nil {
		return nil, keystore.ErrEmptyPassphrase
	}
	restoring := cfg.Phrase != "" || cfg.FromBackup != nil
	switch {
	case cfg.Phrase != "" && cfg.FromBackup != nil:
		return nil, fmt.Errorf("%w: restore from a phrase or from a backup, not both", ErrInvalid)
	case restoring && cfg.BackupPath != "":
		return nil, fmt.Errorf("%w: a restore makes no recovery key, so it writes no backup", ErrInvalid)
	case cfg.BackupPath != "" && len(cfg.BackupPassphrase) == 0:
		return nil, fmt.Errorf("%w (for the backup)", keystore.ErrEmptyPassphrase)
	}
	var id, recovery *identity.Identity
	var recoveryPub *identity.PublicKey
	switch {
	case cfg.FromBackup != nil:
		if id = cfg.FromBackup.Identity; id == nil {
			return nil, fmt.Errorf("%w: backup without an identity", ErrInvalid)
		}
		if r := cfg.FromBackup.Recovery; r != nil {
			pk := r.Public()
			if err := identity.CheckRecoveryKey(id.Public(), pk); err != nil {
				return nil, fmt.Errorf("%w: the backup's recovery key: %v", ErrInvalid, err)
			}
			recoveryPub = &pk
		}
	case cfg.Phrase != "":
		id, err = identity.FromPhrase(cfg.Phrase)
	default:
		id, err = identity.Generate()
		if err == nil && cfg.BackupPath != "" {
			if recovery, err = newRecoveryKey(id.Public()); err == nil {
				pk := recovery.Public()
				recoveryPub = &pk
			}
		}
	}
	if err != nil {
		return nil, err
	}
	var backupPath string
	if cfg.BackupPath != "" {
		if backupPath, err = filepath.Abs(cfg.BackupPath); err != nil {
			return nil, err
		}
	}

	p := PathsFor(cfg.DataDir)
	if err := prepareDir(p.Dir); err != nil {
		return nil, err
	}
	lock, err := AcquireLock(p.Lock)
	if err != nil {
		return nil, err
	}
	defer lock.Release()

	if _, err := os.Stat(p.Keystore); err == nil {
		return nil, fmt.Errorf("%w (%s exists)", ErrAlreadyInitialized, p.Keystore)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	st, err := store.Open(ctx, p.DB)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	pub := id.Public()
	if have, err := st.Meta(ctx, metaIdentity); err == nil {
		// The database names an identity but its keystore is gone. Only
		// restoring that same identity may recreate the keystore.
		switch {
		case !restoring:
			return nil, fmt.Errorf("%w (the database names one but its keystore is missing; restore it with: openaimd init --restore)", ErrAlreadyInitialized)
		case string(have) != string(pub[:]):
			return nil, fmt.Errorf("%w: the phrase or backup is not for the identity this database belongs to", ErrIdentityMismatch)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	ks, err := newKeystore(kind, p, cfg.Passphrase, cfg.PassphraseFunc, cfg.KeystoreParams)
	if err != nil {
		return nil, err
	}
	if kind == KeystoreModeKeychain {
		// Never overwrite a seed: the keychain item outlives the data dir.
		switch _, err := ks.Load(); {
		case err == nil:
			return nil, fmt.Errorf("%w (the OS keychain already holds an identity for %s)", ErrAlreadyInitialized, p.Dir)
		case !errors.Is(err, keystore.ErrNoKey):
			return nil, err
		}
	}

	// The backup goes first: the recovery seed exists nowhere else, so if
	// it can't be written nothing else may be. If a later step fails before
	// the keystore holds the identity seed, the backup names an identity
	// that was never set up, and is removed.
	saved := false
	if backupPath != "" {
		params := cfg.KeystoreParams
		if params == (keystore.Params{}) {
			params = keystore.DefaultParams
		}
		blob, err := keystore.EncodeBackup(&keystore.Backup{Identity: id, Recovery: recovery, CreatedAt: time.Now()},
			cfg.BackupPassphrase, params)
		if err != nil {
			return nil, err
		}
		if err := WriteNewPrivateFile(backupPath, blob); err != nil {
			return nil, fmt.Errorf("daemon: writing the backup: %w", err)
		}
		defer func() {
			if !saved {
				os.Remove(backupPath)
			}
		}()
	}

	// Record the keystore kind, then save the seed, then the identity. If
	// we die before the identity is recorded, Open adopts the keystore's
	// identity (it has the secret), rather than leaving a database that
	// names an identity nobody holds.
	if err := st.SetMeta(ctx, metaKeystore, []byte(kind)); err != nil {
		return nil, err
	}
	if err := ks.Save(id.Seed()); err != nil {
		return nil, err
	}
	saved = true
	if err := st.SetMeta(ctx, metaIdentity, pub[:]); err != nil {
		return nil, err
	}
	res := &Initialized{Identity: id, BackupPath: backupPath}
	if recoveryPub != nil {
		if err := st.SetMeta(ctx, metaRecoveryKey, recoveryPub[:]); err != nil {
			return nil, err
		}
	} else if v, err := st.Meta(ctx, metaRecoveryKey); err == nil {
		// A phrase restore into a database that already recorded one (a
		// lost keystore): keep it; the user's backup still has its seed.
		if pk, err := identity.ParsePublicKey(v); err == nil {
			recoveryPub = &pk
		}
	}
	res.RecoveryKey = recoveryPub
	if cfg.FromBackup != nil {
		n, err := restoreBuddies(ctx, st, pub, cfg.FromBackup.Buddies)
		if err != nil {
			return res, err
		}
		res.Buddies = n
	}
	return res, nil
}

// newRecoveryKey generates a recovery key for identity key k. A fresh random
// key sharing k's X25519 form is astronomically unlikely, but checking the
// pinning rule (spec/wire.md §4.6) costs nothing.
func newRecoveryKey(k identity.PublicKey) (*identity.Identity, error) {
	r, err := identity.GenerateRecovery()
	if err != nil {
		return nil, err
	}
	if err := identity.CheckRecoveryKey(k, r.Public()); err != nil {
		return nil, err
	}
	return r, nil
}

// restoreBuddies adds a backup's buddies that aren't in the store yet, and
// returns how many it added. A pinned recovery key comes back only if it
// still passes the pinning rule; labels that no longer pass are dropped.
func restoreBuddies(ctx context.Context, st *store.Store, me identity.PublicKey, bs []store.Buddy) (int, error) {
	added := 0
	now := time.Now()
	for _, b := range bs {
		if b.Key == me {
			continue
		}
		if b.RecoveryKey != nil && identity.CheckRecoveryKey(b.Key, *b.RecoveryKey) != nil {
			b.RecoveryKey = nil
		}
		if checkLabel("petname", b.Petname) != nil {
			b.Petname = ""
		}
		if checkLabel("group", b.Group) != nil {
			b.Group = ""
		}
		b.ID, b.AddedAt = 0, now
		if _, err := st.AddBuddy(ctx, b); errors.Is(err, store.ErrDuplicate) {
			continue
		} else if err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

// WriteNewPrivateFile writes data to path, which must not exist, with mode
// 0600: a temporary file in the same directory is synced and then linked
// into place, so a crash never leaves half a file and an existing file is
// never replaced.
func WriteNewPrivateFile(path string, data []byte) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // after a link, this drops the temporary name
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		if _, serr := os.Lstat(path); serr == nil {
			return fmt.Errorf("%s already exists", path)
		}
		// No hard links on this filesystem: the check above has to do.
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync() // best effort: make the new name durable
		d.Close()
	}
	return nil
}
