package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/store"
)

// KeystoreMode says where the identity seed is kept (spec/backup.md §3,
// §3.1).
type KeystoreMode string

const (
	// KeystoreModeDefault: for Init, the file; for Open, whatever Init recorded.
	KeystoreModeDefault KeystoreMode = ""
	// KeystoreModeFile: the passphrase-encrypted identity.key in the data dir.
	KeystoreModeFile KeystoreMode = "file"
	// KeystoreModeKeychain: the OS keychain. No passphrase, but any program
	// running as the user in an unlocked session can read the seed.
	KeystoreModeKeychain KeystoreMode = "keychain"
	// KeystoreModeAuto: for Init, the keychain if one answers, else the file;
	// for Open, whatever Init recorded.
	KeystoreModeAuto KeystoreMode = "auto"
)

// metaKeystore is the store meta key recording which keystore holds the
// identity ("file" or "keychain"). Identities created before it existed
// have none and use the file.
const metaKeystore = "keystore"

// Keystore errors.
var (
	// ErrKeystoreMismatch: the keystore asked for isn't the one the
	// identity was created with.
	ErrKeystoreMismatch = errors.New("daemon: keystore mode differs from the one this identity uses")
	// ErrNoKeychain: the keychain was asked for but no OS keychain answers.
	ErrNoKeychain = errors.New("daemon: no OS keychain available")
)

// ParseKeystoreMode parses "", "auto", "keychain" or "file".
func ParseKeystoreMode(s string) (KeystoreMode, error) {
	switch m := KeystoreMode(s); m {
	case KeystoreModeDefault, KeystoreModeAuto, KeystoreModeKeychain, KeystoreModeFile:
		return m, nil
	}
	return "", fmt.Errorf("%w: keystore %q (want auto, keychain or file)", ErrInvalid, s)
}

// ResolveKeystoreMode is the keystore Init will use for mode: file or
// keychain. Auto picks the keychain if one answers. It may query the OS
// keychain.
func ResolveKeystoreMode(mode KeystoreMode) (KeystoreMode, error) {
	switch mode {
	case KeystoreModeDefault, KeystoreModeFile:
		return KeystoreModeFile, nil
	case KeystoreModeKeychain:
		if !keystore.KeychainAvailable() {
			return "", ErrNoKeychain
		}
		return KeystoreModeKeychain, nil
	case KeystoreModeAuto:
		if keystore.KeychainAvailable() {
			return KeystoreModeKeychain, nil
		}
		return KeystoreModeFile, nil
	}
	_, err := ParseKeystoreMode(string(mode))
	return "", err
}

// recordedKeystore is the keystore the database says the identity uses.
func recordedKeystore(ctx context.Context, st *store.Store) (KeystoreMode, error) {
	v, err := st.Meta(ctx, metaKeystore)
	if errors.Is(err, store.ErrNotFound) {
		return KeystoreModeFile, nil
	} else if err != nil {
		return "", err
	}
	switch m := KeystoreMode(v); m {
	case KeystoreModeFile, KeystoreModeKeychain:
		return m, nil
	}
	return "", fmt.Errorf("daemon: database records an unknown keystore %q", v)
}

// checkKeystoreMode applies Open's rule: an explicit file or keychain must
// match the recorded one; default and auto accept it.
func checkKeystoreMode(asked, recorded KeystoreMode) error {
	if _, err := ParseKeystoreMode(string(asked)); err != nil {
		return err
	}
	if asked == KeystoreModeDefault || asked == KeystoreModeAuto || asked == recorded {
		return nil
	}
	return fmt.Errorf("%w: this identity's seed is in the %s keystore, not the %s one (drop --keystore, or use --keystore=%s)",
		ErrKeystoreMismatch, recorded, asked, recorded)
}

// passphrase returns the static passphrase, else asks fn.
func passphrase(static []byte, fn func() ([]byte, error)) ([]byte, error) {
	if len(static) > 0 || fn == nil {
		if len(static) == 0 {
			return nil, keystore.ErrEmptyPassphrase
		}
		return static, nil
	}
	p, err := fn()
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, keystore.ErrEmptyPassphrase
	}
	return p, nil
}

// newKeystore builds the keystore of kind for a data dir. The file keystore
// gets its passphrase from pass or passFn (asked only here).
func newKeystore(kind KeystoreMode, p Paths, pass []byte, passFn func() ([]byte, error), params keystore.Params) (keystore.Keystore, error) {
	switch kind {
	case KeystoreModeKeychain:
		return keystore.NewKeychainKeystore(p.Dir)
	case KeystoreModeFile:
		pp, err := passphrase(pass, passFn)
		if err != nil {
			return nil, err
		}
		return &keystore.FileKeystore{Path: p.Keystore, Passphrase: pp, Params: params}, nil
	}
	return nil, fmt.Errorf("daemon: keystore kind %q", kind)
}
