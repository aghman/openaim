package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/store"
)

// metaIdentity is the store meta key holding our 32-byte public identity
// key. It lets the daemon notice a keystore and database that belong to
// different identities.
const metaIdentity = "identity_key"

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
	// instead of generating a new one.
	Phrase string
	// KeystoreParams are the keystore's Argon2id costs; zero means
	// keystore.DefaultParams. Tests use cheap ones.
	KeystoreParams keystore.Params
}

// Init creates (or restores) the identity in a data directory: it saves the
// seed in the keystore under the passphrase and records the public key in the
// database. It refuses a directory that already has an identity, and holds
// the directory's lock throughout, so it can't race a running daemon.
//
// The caller shows the new identity's recovery phrase (id.Phrase()) to the
// user, once.
func Init(ctx context.Context, cfg InitConfig) (*identity.Identity, error) {
	kind, err := ResolveKeystoreMode(cfg.Keystore)
	if err != nil {
		return nil, err
	}
	if kind == KeystoreModeFile && len(cfg.Passphrase) == 0 && cfg.PassphraseFunc == nil {
		return nil, keystore.ErrEmptyPassphrase
	}
	var id *identity.Identity
	if cfg.Phrase != "" {
		id, err = identity.FromPhrase(cfg.Phrase)
	} else {
		id, err = identity.Generate()
	}
	if err != nil {
		return nil, err
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
		case cfg.Phrase == "":
			return nil, fmt.Errorf("%w (the database names one but its keystore is missing; restore it with: openaimd init --restore)", ErrAlreadyInitialized)
		case string(have) != string(pub[:]):
			return nil, fmt.Errorf("%w: the phrase is not for the identity this database belongs to", ErrIdentityMismatch)
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
	if err := st.SetMeta(ctx, metaIdentity, pub[:]); err != nil {
		return nil, err
	}
	return id, nil
}
