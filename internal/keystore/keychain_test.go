package keystore

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/zalando/go-keyring"
)

// These tests use go-keyring's in-memory mock, so they never touch the real
// keychain. TestRealKeychain does, and only when asked to.

func TestKeychainKeystore(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	ks, err := NewKeychainKeystore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty keychain: %v", err)
	}
	seed := id(t, 5).Seed()
	if err := ks.Save(seed); err != nil {
		t.Fatal(err)
	}
	if got, err := ks.Load(); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("load: %v", err)
	}
	// Another data directory is another account.
	other, _ := NewKeychainKeystore(t.TempDir())
	if _, err := other.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("other data dir sees our key: %v", err)
	}
	if err := ks.Save(make([]byte, 31)); err == nil {
		t.Fatal("31-byte seed saved")
	}
	if err := ks.Delete(); err != nil {
		t.Fatal(err)
	}
	if err := ks.Delete(); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if _, err := ks.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestKeychainRejectsForeignItems(t *testing.T) {
	keyring.MockInit()
	ks, _ := NewKeychainKeystore(t.TempDir())
	for name, v := range map[string]string{
		"no prefix":   "c2VjcmV0",
		"bad base64":  keychainPrefix + "!!!",
		"short seed":  keychainPrefix + "AAAA",
		"empty value": "",
	} {
		keyring.Set(ks.service(), ks.Account, v)
		if _, err := ks.Load(); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestChoose(t *testing.T) {
	dir := t.TempDir()
	keyring.MockInit()
	if k, err := Choose(dir, true, nil); err != nil {
		t.Fatal(err)
	} else if _, ok := k.(*KeychainKeystore); !ok {
		t.Fatalf("keychain available but got %T", k)
	}
	if k, _ := Choose(dir, false, []byte("pw")); k == nil {
		t.Fatal("no file keystore")
	} else if _, ok := k.(*FileKeystore); !ok {
		t.Fatalf("keychain not preferred but got %T", k)
	}

	keyring.MockInitWithError(errors.New("no D-Bus session"))
	if KeychainAvailable() {
		t.Fatal("broken keychain reported available")
	}
	if k, err := Choose(dir, true, []byte("pw")); err != nil {
		t.Fatal(err)
	} else if _, ok := k.(*FileKeystore); !ok {
		t.Fatalf("fallback: got %T", k)
	}
	if _, err := Choose(dir, true, nil); !errors.Is(err, ErrEmptyPassphrase) {
		t.Fatalf("no keychain and no passphrase: %v", err)
	}
	keyring.MockInit()
}

// TestRealKeychain stores, loads and deletes a throwaway item in the real OS
// keychain. It is skipped unless OPENAIM_TEST_REAL_KEYCHAIN=1, because it
// writes to the user's keychain (and may prompt).
func TestRealKeychain(t *testing.T) {
	if os.Getenv("OPENAIM_TEST_REAL_KEYCHAIN") != "1" {
		t.Skip("set OPENAIM_TEST_REAL_KEYCHAIN=1 to test against the real OS keychain")
	}
	ks := &KeychainKeystore{Service: KeychainService + "-test", Account: "identity:" + t.TempDir()}
	t.Cleanup(func() { ks.Delete() })
	seed := id(t, 7).Seed()
	if err := ks.Save(seed); err != nil {
		t.Fatal(err)
	}
	if got, err := ks.Load(); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("load: %v", err)
	}
}
