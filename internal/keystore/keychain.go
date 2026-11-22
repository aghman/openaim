package keystore

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zalando/go-keyring"
)

// Keystore holds the identity seed day to day (design §5.5).
type Keystore interface {
	Save(seed []byte) error
	Load() ([]byte, error)
}

var (
	_ Keystore = (*FileKeystore)(nil)
	_ Keystore = (*KeychainKeystore)(nil)
)

// KeychainService is the service name OpenAIM's keychain items use.
const KeychainService = "openaim"

// keychainPrefix versions the stored value: "oa1:" + base64(seed).
const keychainPrefix = "oa1:"

// KeychainKeystore keeps the identity seed in the OS keychain: macOS
// Keychain, the Secret Service (GNOME Keyring, KWallet) on Linux, or the
// Windows Credential Manager.
//
// Protection is the OS account's: any process running as the user in an
// unlocked session can read the item (on macOS the item belongs to
// /usr/bin/security, which go-keyring drives). That's weaker than the
// passphrase-encrypted FileKeystore, and the same trade-off as an SSH agent.
// spec/backup.md §3.1 says so to users.
type KeychainKeystore struct {
	Service string // defaults to KeychainService
	Account string
}

// NewKeychainKeystore returns the keychain keystore for a data directory.
// The account names the directory, so several daemons (or a test daemon)
// on one account keep separate identities.
func NewKeychainKeystore(dataDir string) (*KeychainKeystore, error) {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	return &KeychainKeystore{Service: KeychainService, Account: "identity:" + abs}, nil
}

func (k *KeychainKeystore) service() string {
	if k.Service == "" {
		return KeychainService
	}
	return k.Service
}

// Save stores the seed, replacing any previous one.
func (k *KeychainKeystore) Save(seed []byte) error {
	if len(seed) != 32 {
		return errors.New("keystore: seed must be 32 bytes")
	}
	if err := keyring.Set(k.service(), k.Account, keychainPrefix+base64.StdEncoding.EncodeToString(seed)); err != nil {
		return fmt.Errorf("keystore: keychain: %w", err)
	}
	return nil
}

// Load returns the stored seed, or ErrNoKey.
func (k *KeychainKeystore) Load() ([]byte, error) {
	v, err := keyring.Get(k.service(), k.Account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNoKey
	} else if err != nil {
		return nil, fmt.Errorf("keystore: keychain: %w", err)
	}
	enc, ok := strings.CutPrefix(v, keychainPrefix)
	if !ok {
		return nil, fmt.Errorf("%w: keychain item has no %q prefix", ErrFormat, keychainPrefix)
	}
	seed, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("%w: keychain item is not a 32-byte seed", ErrFormat)
	}
	return seed, nil
}

// Delete removes the item. Deleting a missing item is not an error.
func (k *KeychainKeystore) Delete() error {
	err := keyring.Delete(k.service(), k.Account)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keystore: keychain: %w", err)
	}
	return nil
}

// KeychainAvailable reports whether an OS keychain answers. A lookup of a
// missing item that fails with "not found" means it does; anything else (no
// D-Bus session, no Secret Service, unsupported OS) means it doesn't.
func KeychainAvailable() bool {
	_, err := keyring.Get(KeychainService, "availability-probe")
	return err == nil || errors.Is(err, keyring.ErrNotFound)
}

// Choose picks the keystore for a data directory: the OS keychain if one is
// available and preferKeychain is set, otherwise the passphrase file. The
// passphrase is only used for the file keystore.
func Choose(dataDir string, preferKeychain bool, passphrase []byte) (Keystore, error) {
	if preferKeychain && KeychainAvailable() {
		return NewKeychainKeystore(dataDir)
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("%w: no OS keychain, and the file keystore needs a passphrase", ErrEmptyPassphrase)
	}
	return &FileKeystore{Path: filepath.Join(dataDir, "identity.key"), Passphrase: passphrase}, nil
}
