# OpenAIM local secret files, draft v1

**Status: draft.** These are local file formats, not wire formats, but they go to the external review with spec/wire.md.
`internal/keystore` implements them.

There are two kinds of file:

| File | Magic | Holds | Where |
|------|-------|-------|-------|
| **Backup** | `OAIMBAK1` | identity seed, recovery seed, buddy list with pinned keys | wherever the user saves it (design §5.5) |
| **Keystore** | `OAIMKEY1` | identity seed only | the daemon's data directory, used when there's no OS keychain |

The recovery seed is kept **only** in the backup, never in the keystore, so a stolen device can't sign a key rotation (design §5.5).

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

## 4. Open questions

- **OS keychain backend:** openaim-nxb.25.
- **Passphrase policy:** minimum length or strength checks are the UI's job. The format accepts any non-empty passphrase.
- **Upgrading the KDF:** when defaults rise, should the daemon re-seal the keystore under new parameters the next time it opens?
