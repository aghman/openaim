package keystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/store"
	pb "github.com/aghman/openaim/internal/wirepb"
)

// Backup is what a backup file holds (design §5.5): the identity seed, the
// recovery key (which lives only here), and the buddy list with pinned keys.
type Backup struct {
	Identity  *identity.Identity
	Recovery  *identity.Identity // nil if not set up yet
	Buddies   []store.Buddy      // IDs and AddedAt are not kept
	CreatedAt time.Time
}

// EncodeBackup encrypts a backup under passphrase.
func EncodeBackup(b *Backup, pass []byte, p Params) ([]byte, error) {
	if b.Identity == nil {
		return nil, errors.New("keystore: backup without an identity")
	}
	c := &pb.BackupContents{IdentitySeed: b.Identity.Seed(), CreatedAt: uint64(b.CreatedAt.Unix())}
	if b.Recovery != nil {
		c.RecoverySeed = b.Recovery.Seed()
	}
	for _, bd := range b.Buddies {
		e := &pb.BackupBuddy{Key: bd.Key[:], Handle: bd.Handle, Petname: bd.Petname, Group: bd.Group,
			State: string(bd.State), Verified: bd.Verified}
		if bd.RecoveryKey != nil {
			e.RecoveryKey = bd.RecoveryKey[:]
		}
		c.Buddies = append(c.Buddies, e)
	}
	pt, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		return nil, err
	}
	return Seal(MagicBackup, pass, pt, p)
}

// DecodeBackup opens and checks a backup file.
func DecodeBackup(blob, pass []byte) (*Backup, error) {
	pt, err := Open(MagicBackup, pass, blob)
	if err != nil {
		return nil, err
	}
	var c pb.BackupContents
	if err := proto.Unmarshal(pt, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	b := &Backup{CreatedAt: time.Unix(int64(c.GetCreatedAt()), 0)}
	if b.Identity, err = identity.FromSeed(c.GetIdentitySeed()); err != nil {
		return nil, fmt.Errorf("%w: identity seed: %v", ErrFormat, err)
	}
	if rs := c.GetRecoverySeed(); len(rs) != 0 {
		if b.Recovery, err = identity.FromSeed(rs); err != nil {
			return nil, fmt.Errorf("%w: recovery seed: %v", ErrFormat, err)
		}
	}
	for i, e := range c.GetBuddies() {
		k, err := identity.ParsePublicKey(e.GetKey())
		if err != nil {
			return nil, fmt.Errorf("%w: buddy %d: %v", ErrFormat, i, err)
		}
		bd := store.Buddy{Key: k, Handle: e.GetHandle(), Petname: e.GetPetname(), Group: e.GetGroup(),
			State: store.BuddyState(e.GetState()), Verified: e.GetVerified()}
		switch bd.State {
		case store.PendingOut, store.PendingIn, store.Accepted, store.Blocked:
		default:
			return nil, fmt.Errorf("%w: buddy %d: state %q", ErrFormat, i, e.GetState())
		}
		if rk := e.GetRecoveryKey(); len(rk) != 0 {
			r, err := identity.ParsePublicKey(rk)
			if err != nil {
				return nil, fmt.Errorf("%w: buddy %d recovery key: %v", ErrFormat, i, err)
			}
			bd.RecoveryKey = &r
		}
		b.Buddies = append(b.Buddies, bd)
	}
	return b, nil
}

// FileKeystore keeps the identity seed in a passphrase-encrypted file (the
// fallback when there is no OS keychain).
type FileKeystore struct {
	Path       string
	Passphrase []byte
	Params     Params // zero means DefaultParams
}

// ErrNoKey is returned by Load when no key has been saved yet.
var ErrNoKey = errors.New("keystore: no identity key stored")

// Save stores the seed, replacing any previous file atomically. The file is
// readable only by its owner.
func (k *FileKeystore) Save(seed []byte) error {
	if len(seed) != 32 {
		return errors.New("keystore: seed must be 32 bytes")
	}
	p := k.Params
	if p == (Params{}) {
		p = DefaultParams
	}
	blob, err := Seal(MagicKeystore, k.Passphrase, seed, p)
	if err != nil {
		return err
	}
	return writeFileAtomic(k.Path, blob, 0o600)
}

// Load returns the stored seed.
func (k *FileKeystore) Load() ([]byte, error) {
	blob, err := os.ReadFile(k.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	} else if err != nil {
		return nil, err
	}
	seed, err := Open(MagicKeystore, k.Passphrase, blob)
	if err != nil {
		return nil, err
	}
	if len(seed) != 32 {
		return nil, fmt.Errorf("%w: %d-byte seed", ErrFormat, len(seed))
	}
	return seed, nil
}

// writeFileAtomic writes data to a temporary file in the same directory,
// syncs it and renames it over path, so a crash never leaves half a file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(perm); err != nil {
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
	return os.Rename(tmp, path)
}
