package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/aghman/openaim/internal/identity"
	"github.com/aghman/openaim/internal/keystore"
	"github.com/aghman/openaim/internal/store"
)

// The recovery key (design §5.5, spec/wire.md §4.6, spec/backup.md §5).
//
// Its seed lives only in backup files. The daemon never holds it: Init
// writes it into the first backup and forgets it, and the store keeps only
// the public key (meta recovery_key), which goes into BUDDY_REQUEST and
// BUDDY_ACCEPT. A later backup can carry the seed forward only if it is
// given an earlier backup that has it (ExportBackupOptions.Previous).

// loadRecoveryKey reads our recovery public key, if we have one.
func (n *Node) loadRecoveryKey(ctx context.Context) error {
	v, err := n.store.Meta(ctx, metaRecoveryKey)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	pk, err := identity.ParsePublicKey(v)
	if err == nil {
		err = identity.CheckRecoveryKey(n.id.Public(), pk)
	}
	if err != nil {
		// Never advertise a recovery key that couldn't be pinned.
		n.log.Error("ignoring unusable recorded recovery key", "err", err)
		return nil
	}
	n.recoveryKey = &pk
	return nil
}

// RecoveryKey is our recovery public key, or nil if this identity has none
// (it was restored from its phrase, or made without a backup).
func (n *Node) RecoveryKey() *identity.PublicKey {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.recoveryKey == nil {
		return nil
	}
	k := *n.recoveryKey
	return &k
}

// ExportBackupOptions says how to write a backup.
type ExportBackupOptions struct {
	// Passphrase encrypts the new backup; it must not be empty.
	Passphrase []byte
	// Previous is an earlier backup file of this identity. Its recovery
	// seed, if it has one, is carried into the new backup, since the daemon
	// doesn't keep it. PreviousPassphrase opens it; empty means Passphrase.
	Previous           []byte
	PreviousPassphrase []byte
}

// ExportedBackup is a backup file and what it holds.
type ExportedBackup struct {
	Blob []byte
	// IncludesRecovery says whether the recovery seed is in Blob.
	IncludesRecovery bool
	// RecoveryKey is our recovery public key, or nil if we have none.
	RecoveryKey *identity.PublicKey
}

// ErrBackupMismatch: the previous backup given to ExportBackupWith isn't for
// this identity, or holds a different recovery key than the one recorded.
var ErrBackupMismatch = errors.New("daemon: the previous backup doesn't match this identity")

// ExportBackup encrypts the identity and buddy list under pass
// (spec/backup.md). It can't include the recovery seed, which the daemon
// doesn't hold; ExportBackupWith can, given an earlier backup.
func (n *Node) ExportBackup(ctx context.Context, pass []byte) ([]byte, error) {
	b, err := n.ExportBackupWith(ctx, ExportBackupOptions{Passphrase: pass})
	return b.Blob, err
}

// ExportBackupWith writes a backup of the identity and buddy list, carrying
// the recovery seed over from o.Previous when it is given.
//
// A previous backup must be this identity's. If we have a recorded recovery
// key, its recovery seed must match it. If we have none (a phrase restore)
// and the previous backup has one, it is adopted: recorded and advertised
// from then on.
func (n *Node) ExportBackupWith(ctx context.Context, o ExportBackupOptions) (ExportedBackup, error) {
	if len(o.Passphrase) == 0 {
		return ExportedBackup{}, fmt.Errorf("%w: empty passphrase", ErrInvalid)
	}
	n.writeMu.Lock()
	defer n.writeMu.Unlock()
	var recovery *identity.Identity
	if len(o.Previous) != 0 {
		pp := o.PreviousPassphrase
		if len(pp) == 0 {
			pp = o.Passphrase
		}
		prev, err := keystore.DecodeBackup(o.Previous, pp)
		if err != nil {
			return ExportedBackup{}, fmt.Errorf("%w: previous backup: %v", ErrInvalid, err)
		}
		if prev.Identity.Public() != n.id.Public() {
			return ExportedBackup{}, fmt.Errorf("%w: it is for identity %s", ErrBackupMismatch, prev.Identity.Public().KeyID())
		}
		if prev.Recovery != nil {
			rk := prev.Recovery.Public()
			switch cur := n.RecoveryKey(); {
			case cur != nil && *cur != rk:
				return ExportedBackup{}, fmt.Errorf("%w: its recovery key isn't the one this identity uses", ErrBackupMismatch)
			case cur == nil:
				if err := identity.CheckRecoveryKey(n.id.Public(), rk); err != nil {
					return ExportedBackup{}, fmt.Errorf("%w: its recovery key: %v", ErrBackupMismatch, err)
				}
				if err := n.store.SetMeta(ctx, metaRecoveryKey, rk[:]); err != nil {
					return ExportedBackup{}, err
				}
				n.mu.Lock()
				n.recoveryKey = &rk
				n.mu.Unlock()
				n.log.Info("recovery key adopted from a previous backup", "recovery_key_id", rk.KeyID())
			}
			recovery = prev.Recovery
		}
	}
	buddies, err := n.store.Buddies(ctx)
	if err != nil {
		return ExportedBackup{}, err
	}
	b := &keystore.Backup{Identity: n.id, Recovery: recovery, Buddies: buddies, CreatedAt: n.now()}
	blob, err := keystore.EncodeBackup(b, o.Passphrase, n.backupParams())
	if err != nil {
		return ExportedBackup{}, err
	}
	return ExportedBackup{Blob: blob, IncludesRecovery: recovery != nil, RecoveryKey: n.RecoveryKey()}, nil
}
