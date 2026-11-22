# OpenAIM local secret files, draft v1

**Status: draft.** These are local file formats, not wire formats, but they go to the external review with spec/wire.md.
`internal/keystore` implements them.

There are two kinds of file:

| File | Magic | Holds | Where |
|------|-------|-------|-------|
| **Backup** | `OAIMBAK1` | identity seed, recovery seed, buddy list with pinned keys | wherever the user saves it (design §5.5) |
| **Keystore** | `OAIMKEY1` | identity seed only | the daemon's data directory, unless the OS keychain is used (§3.1) |

The recovery seed is kept **only** in the backup, never in the keystore, so a stolen device can't sign a key rotation (design §5.5).
§5 says how it gets there: `openaimd init` writes the first backup, and the daemon keeps only the public key.

## 1. Envelope

Both files use one envelope. All integers are big-endian.

| Offset | Bytes | Field |
|--------|-------|-------|
| 0 | 8 | magic (`OAIMBAK1` or `OAIMKEY1`) |
| 8 | 1 | KDF: `1` = Argon2id (RFC 9106, version 0x13) |
| 9 | 4 | Argon2id time cost `t` |
| 13 | 4 | Argon2id memory `m`, in KiB |
| 17 | 1 | Argon2id parallelism `p` |
| 18 | 16 | salt, random |
| 34 | 24 | nonce, random |
| 58 | n + 16 | XChaCha20-Poly1305 ciphertext and tag |

- **Key:** `key = Argon2id(password = NFC(passphrase), salt, t, m, p, length = 32)`, where `NFC` is Unicode Normalization Form C. Without it, the same passphrase typed on two systems could produce different bytes.
- **Encryption:** `ciphertext = XChaCha20-Poly1305(key, nonce, plaintext, ad = bytes 0–57)`.
- **The whole header is authenticated,** magic and cost parameters included. A backup can't be passed off as a keystore file, and an attacker can't lower the costs without breaking the tag.
- **Defaults:** `t = 3`, `m = 65536` (64 MiB), `p = 4`. That's RFC 9106's second recommended option, about a quarter second on a laptop.
- **Accepted ranges:** 1 ≤ `t` ≤ 16, 8 MiB ≤ `m` ≤ 1 GiB, 1 ≤ `p` ≤ 16. Readers reject anything else before running Argon2id, so a crafted file can't use up memory or time. The plaintext is at most 16 MiB.
- **Errors:** a wrong passphrase and a modified file look the same (the tag fails).

## 2. Backup contents

The plaintext is a `BackupContents` protobuf, defined in [proto/openaim/v1/backup.proto](../proto/openaim/v1/backup.proto) and encoded deterministically:

- **`identity_seed`:** 32 bytes, the same seed the recovery phrase encodes (wire.md §4.5).
- **`recovery_seed`:** 32 bytes, or empty if no recovery key has been set up yet.
- **`created_at`:** unix seconds.
- **`buddies`:** each entry has:
  - the pinned Ed25519 key (32 bytes, valid per wire.md §4.2)
  - the handle, petname and group
  - the state (`pending_out`, `pending_in`, `accepted` or `blocked`)
  - whether the user verified the buddy
  - the buddy's pinned recovery key, 32 bytes or empty

Readers reject a backup whose seeds aren't 32 bytes, or whose keys or states are invalid.

## 3. Keystore contents

The plaintext is the 32-byte identity seed. The file is written atomically: a temporary file in the same directory is
synced, then renamed over the old one. It's readable only by its owner (mode 0600 on Unix).

### 3.1 OS keychain instead of the file

When an OS keychain answers, the daemon can keep the seed there instead of in the keystore file:
- macOS: the login Keychain
- Linux: the Secret Service, provided by GNOME Keyring or KWallet
- Windows: the Credential Manager

The item is stored as follows:

| | |
|---|---|
| Service | `openaim` |
| Account | `identity:<absolute data directory>`, so separate data directories keep separate identities |
| Value | `oa1:` followed by base64(seed), 32 bytes once decoded |

**This protects less than the passphrase file.** Any process running as the user in an unlocked session can read the
item. On macOS that's because the item belongs to `/usr/bin/security`, which the keychain library drives (secrets go to it
over stdin, never on the command line). It's the same trade-off as an SSH agent. The passphrase file protects the seed
even from the user's other programs, as long as the passphrase isn't cached. Users choose. If no keychain answers (for
example, a Linux server with no D-Bus session), the daemon falls back to the file.

## 4. Open questions

- **Passphrase policy:** minimum length or strength checks are the UI's job. The format accepts any non-empty passphrase.
- **Upgrading the KDF:** when defaults rise, should the daemon re-seal the keystore under new parameters the next time it opens?
- **The recovery key isn't in the phrase.** The 24-word phrase encodes the identity seed only (wire.md §4.5), and the recovery seed
  is only in the backup file. A user who keeps the phrase but loses the file can restore their identity but can't sign a rotation
  (wire.md §4.6), so after a compromise they'd have to re-add every buddy. Options: show a second phrase for the recovery seed at
  setup, or have the daemon warn while no backup has been exported since the recovery key was made. Deriving the recovery seed from
  the identity seed isn't one: anyone who stole the identity key could then rotate.
- **Re-exporting the recovery seed.** The daemon can't put the recovery seed into a new backup by itself (§5), so the user has to
  supply the old file. A daemon that remembered "a backup with the recovery seed exists" could nag when every export since lacks it.

## 5. The recovery key at setup

The recovery key (wire.md §4.6) is made by `openaimd init`, and its seed is never held by the daemon afterwards. This section says
how, and where each half lives.

| | Where | Written by |
|---|---|---|
| recovery **seed** | backup files only | `openaimd init --backup FILE`; `openaim backup export --from OLD` copies it from `OLD` |
| recovery **public key** | the database's `meta` table, key `recovery_key` (32 bytes) | init, or a restore from a backup |

**A new identity** (`openaimd init --backup FILE`):

1. The daemon generates the identity and the recovery key, and checks the pinning rule (wire.md §4.6) on them.
2. Before anything else is saved, it writes the first backup to `FILE`, under a backup passphrase the user gives
   (`--backup-passphrase-file`, `$OPENAIM_BACKUP_PASSPHRASE` or a prompt). It holds both seeds and no buddies. `FILE` must not
   exist, and is written with mode 0600 through a synced temporary file linked into place, so nothing is ever overwritten.
3. Only then are the keystore and the database written. The database gets the recovery **public** key. If init fails before the
   keystore holds the identity seed, it deletes the backup, which would name an identity that was never set up.
4. The seed is dropped from memory. The keystore, the OS keychain and the database never see it.

The user is told the file is the only copy of the recovery key and to move it off the device. A backup that stays on the device
next to the keystore protects less: whoever steals the device and learns the backup passphrase can rotate. init warns when the
backup and keystore passphrases are the same.

**Without a backup.** `--no-recovery-key` creates an identity with none. Library callers of `daemon.Init` that pass no backup path
get the same. Requests and accepts from such an identity carry no recovery key, and it can never sign a rotation.

**Restoring.**
- **From the phrase** (`init --restore`): the phrase encodes the identity seed only, so the restored identity has no recovery key.
  Init doesn't make a new one: buddies who pinned the old key would reject rotations signed by a new one, and the old key may still
  be in a backup file the user finds later. If the database already recorded a recovery public key (the keystore alone was lost),
  it is kept.
- **From a backup file** (`init --restore-backup FILE`): restores the identity seed, records the backup's recovery public key and
  adds its buddies. The seed stays in `FILE`; nothing new is written.
- **Adopting later.** A phrase-restored identity gets its recovery key back when an `ExportBackup` is given an earlier backup of the
  same identity that has one (below): its public key is recorded from then on.

**Later backups.** `ExportBackup` (`openaim backup export`) writes the identity seed and the buddy list. It includes the recovery
seed only when given an earlier backup that has it (`--from OLD`; the API's `previous_backup`). That backup must be the same
identity's, and its recovery key must be the recorded one, or the export fails. The reply says whether the recovery seed is in the
new file, and the CLI warns when it isn't.
