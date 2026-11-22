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
	DataDir    string
	Passphrase []byte // encrypts the keystore; must not be empty
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
	if len(cfg.Passphrase) == 0 {
		return nil, keystore.ErrEmptyPassphrase
	}
	var id *identity.Identity
	var err error
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

	// Keystore first: if we die before the meta write, Open adopts the
	// keystore's identity (it has the secret), rather than leaving a
	// database that names an identity nobody holds.
	ks := &keystore.FileKeystore{Path: p.Keystore, Passphrase: cfg.Passphrase, Params: cfg.KeystoreParams}
	if err := ks.Save(id.Seed()); err != nil {
		return nil, err
	}
	if err := st.SetMeta(ctx, metaIdentity, pub[:]); err != nil {
		return nil, err
	}
	return id, nil
}
