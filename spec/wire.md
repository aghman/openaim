# OpenAIM wire format, draft v1

**Status: draft, not frozen.** The format changes freely until the external cryptography review at the end of M2
([design.md §10.4](../docs/design.md#104-review-gate)). After that, this document is normative and changes only with a new wire version.

The draft covers identity keys, pairwise keys, the `DATA` frame (sealing, fragmentation and receiving) and inner-payload bodies. First contact, beacons,
adverts and rooms come later in M1 and M2. Where this document and design.md disagree, this document wins. §9 lists every
place where it departs from design.md v0.3, with the reason.

Golden vectors are in [vectors/v1.json](vectors/v1.json). [vectors/verify_v1.py](vectors/verify_v1.py) recomputes the key
schedule using only the Python standard library.

## 1. Notation and primitives

- `‖` is concatenation. All integers are **big-endian** unless noted. `[:n]` takes the first `n` bytes.
- **HKDF:**
  - `HKDF(ikm, salt, info)` is HKDF-SHA256 (RFC 5869) Extract-then-Expand, producing 32 bytes.
  - `Expand(prk, info)` is HKDF-SHA256 Expand only, producing 32 bytes. It's used where the input key is already uniform.
- `HMAC` is HMAC-SHA256.
- AEAD is ChaCha20-Poly1305 (RFC 8439) with a 12-byte nonce and a 16-byte tag.
- X25519 is RFC 7748. Ed25519 is RFC 8032.
- **Info strings** are ASCII labels followed by fixed-length binary fields. No field is variable-length, so concatenation is unambiguous.

## 2. Labels

Every derivation and signature has its own label. No two uses share one.

| Label | Used for | Section |
|-------|----------|---------|
| `openaim/v1` | HKDF salt for `K_pair` | §4.3 |
| `openaim/v1/pair` | `K_pair` info | §4.3 |
| `openaim/v1/dir` | directional key `K_dir` | §4.3 |
| `openaim/v1/siv` | synthetic-ID key `K_siv` | §5.3 |
| `openaim/v1/tag` | conversation tag | §5.2 |
| `openaim/v1/msg` | per-message key `K_msg` | §5.4 |
| `openaim/v1/safety-number` | safety number | §4.4 |
| `openaim/v1/handle-claim`, `/nearby`, `/gateway-ad`, `/rotate`, `/mailbox-delegation`, `/mailbox-fetch`, `/registry-auth` | Ed25519 signatures over `label ‖ message` | design.md §10.2 |
| `openaim/v1/first-contact`, `rdv`, `loc`, `token` | reserved, specified later | — |

## 3. Frames

The first byte of every frame is `ver_kind = version << 5 | kind`. In this draft `version` is **1**.

| Kind | Name | Status |
|------|------|--------|
| 1 | `DATA`: buddy or room message, mesh layout | specified (§5) |
| 2 | `DATA_IP`: buddy or room message, IP-only layout | specified (§5) |
| 3 | `FIRST_CONTACT` | reserved |
| 4 | `BEACON` | reserved |
| 5 | `NEARBY` | reserved |
| 6 | `GATEWAY_AD` | reserved |

Receivers drop frames with another version, or with a kind they don't handle.

## 4. Identity and pairwise keys

### 4.1 Identity key

An identity is a 32-byte Ed25519 seed.

- **Public key:** the RFC 8032 public key `Ed`.
- **X25519 private scalar:** `SHA-512(seed)[:32]`, clamped as RFC 7748 does. That's the same scalar Ed25519 signs with.
- **X25519 public key:** the birational map of `Ed`, `u = (1 + y) / (1 − y) mod p`. It equals the X25519 base-point multiple of the scalar.

### 4.2 Public key validation

A received identity key must meet all of these, or it's rejected:

- 32 bytes long
- a canonical encoding: `y < p`, and re-encoding the decoded point gives the same bytes
- a point on the curve
- not of small order: the point times the cofactor 8 is not the identity

The X25519 output of §4.3 must not be all zero.

### 4.3 Pairwise keys

For identities A and B, let `lo ‖ hi` be their Ed25519 public keys sorted by byte order. Then:

```
shared  = X25519(my_scalar, their_x25519)
K_pair  = HKDF(ikm = shared, salt = "openaim/v1", info = "openaim/v1/pair" ‖ lo ‖ hi)
K_dir_S = Expand(K_pair, "openaim/v1/dir" ‖ Ed_S)      for sender S ∈ {A, B}
```

`K_dir_A` protects frames A sends to B, and `K_dir_B` frames B sends to A. Derivations bind the Ed25519 keys, because two
Ed25519 keys can map to the same X25519 key.

### 4.4 Safety number and key ID

- **Safety number:**
  - Compute `n = SHA-256("openaim/v1/safety-number" ‖ lo ‖ hi)`, read it as an unsigned big-endian integer, and reduce it mod 10^40.
  - Print `n` as 40 zero-padded decimal digits in 8 groups of 5 (about 132.9 bits).
  - Both sides compute the same number.
- **Key ID (UI only):** `"~" ‖ base32(SHA-256(Ed))[:4]`.
- **Text form of a key:** lowercase RFC 4648 base32, no padding (52 characters).

## 5. `DATA` frames

### 5.1 Layouts

| Layout | Byte | Frame kind | Max frame | Fragment capacity | Max fragments | Max inner payload |
|--------|------|-----------|-----------|-------------------|---------------|-------------------|
| mesh | 1 | `DATA` | 200 B | 166 B | 4 | 664 B |
| ip | 2 | `DATA_IP` | 4096 B | 4062 B | 16 | 64 992 B |

The layout is part of the frame kind, so a receiver knows it before deriving keys. `DATA_IP` frames are never sent on mesh.

### 5.2 Conversation key and tag

A conversation direction has a 32-byte key `K`: `K_dir` for a buddy pair, or the epoch content key for a room (to be specified).

```
day      = floor((unix_time − 1735689600) / 86400)          // whole UTC days since 2025-01-01, uint32
conv_tag = HMAC(K, "openaim/v1/tag" ‖ day_be32)[:8]
```

The sender uses the tag for the day of sealing. The frame keeps that tag for the rest of its life (§5.5).

### 5.3 Synthetic message ID

```
K_siv  = Expand(K, "openaim/v1/siv")
msg_id = HMAC(K_siv, inner)[:8]          // inner = the whole inner payload, §6
```

### 5.4 Per-message key, nonce and associated data

```
count  = ceil(len(inner) / capacity)                         // 1 ≤ count ≤ max fragments
K_msg  = Expand(K, "openaim/v1/msg" ‖ conv_tag ‖ msg_id ‖ count_u8 ‖ layout_u8)
nonce  = 0x00000000 00000000 ‖ index_be32                    // 12 bytes
header = ver_kind ‖ conv_tag ‖ msg_id ‖ frag                 // 18 bytes
frag   = index << 4 | (count − 1)
```

### 5.5 Sealing

1. Split `inner` into `count` chunks. Chunk `i` is `inner[i·capacity : min((i+1)·capacity, len(inner))]`, so every chunk but the last is exactly `capacity` bytes.
2. Fragment `i` is `header_i ‖ ChaCha20-Poly1305-Seal(K_msg, nonce_i, plaintext = chunk_i, ad = header_i)`.
   The ciphertext plus tag is `len(chunk_i) + 16` bytes, so every fragment but the last is exactly the layout's frame size.
3. **Seal once.** The frames are persisted and are the message from then on. Retries, fallback routes and restarts re-send
   the same bytes. A message is never re-fragmented, re-timestamped or sealed again under the same `msg_id` (design.md §8.2).
   After a key rotation, queued plaintext becomes a new message with a new `msg_id` (design.md §5.5).

Sealing is deterministic: the same `(K, conv_tag, layout, inner)` always gives the same frames.

### 5.6 Why the derivation is safe

A `(K_msg, nonce)` pair can recur only for the same `(K, conv_tag, msg_id, count, layout, index)`. Except for a 64-bit
`msg_id` collision, that means the same `inner`, the same chunk and the same 18-byte header. Same key and nonce therefore
means the same plaintext **and** the same associated data, so neither the keystream nor the Poly1305 one-time key ever covers
two different inputs. `TestSealOnceInvariant` in `internal/frame` checks this by brute force.

## 6. Inner payload

```
content_type (1) | flags (1) | timestamp (4) | seq (uvarint) | body
```

- **`timestamp`:** seconds since 2025-01-01T00:00:00Z, uint32.
- **`seq`:** an unsigned LEB128 varint, minimally encoded. Receivers reject non-minimal encodings, so every payload has exactly one encoding and one `msg_id`.
- **`flags`:** bit 0 is compressed, bit 1 is ack-requested, bit 2 is clock-unsynced. Receivers reject other bits in this draft.
- **`content_type`:** 1 IM, 2 ACK, 3 PRESENCE, 4 PROFILE_REQ, 5 PROFILE, 6 AWAY_MSG, 7 TYPING (IP only), 8 ROOM_MSG, 9 ROOM_INVITE,
  10 ROOM_REKEY, 11 BUDDY_ACCEPT, 12 REACH, 13 CAPS, 14 ROTATE. The frame layer passes unknown types to the router.
- **`body`:** UTF-8 text for IM, protobuf for the others (§6.1). A one-fragment mesh IM has 166 − 7 = **159 B** of body when `seq < 128`.

### 6.1 Bodies

IM bodies are UTF-8 text. Every other content type has a protobuf body. The message definitions in
[proto/openaim/v1/bodies.proto](../proto/openaim/v1/bodies.proto) are normative. Senders encode deterministically, which
protobuf-go does with `Deterministic: true`.

| Content type | Body | Limits (receivers reject anything outside them) |
|--------------|------|------------------------------------------------|
| 1 IM | UTF-8 text | not empty |
| 2 ACK | `Ack` | 1–32 entries. Each `msg_id` is 8 bytes; `have` is nonzero and < 2^16. |
| 3 PRESENCE | `Presence` | `state` is ONLINE, AWAY or OFFLINE; `idle_minutes` ≤ 525 600 |
| 4 PROFILE_REQ | `ProfileReq` | asks for at least one part |
| 5 PROFILE | `Profile` | display name ≤ 64 B, text ≤ 1024 B |
| 6 AWAY_MSG | `AwayMsg` | text ≤ 1024 B |
| 7 TYPING | `Typing` | `state` is TYPING, PAUSED or IDLE |
| 11 BUDDY_ACCEPT | `BuddyAccept` | presence key 32 B; recovery key empty or a valid identity key (§4.2); display name ≤ 64 B; `reach` and `caps` valid if present |
| 12 REACH | `Reach` | `expires_at` > `issued_at`; ≤ 4 IP hints, each with a 1–64 B peer ID and ≤ 8 addresses of 1–128 B; ≤ 4 gateway and ≤ 4 mailbox hints with 32 B keys and tokens |
| 13 CAPS | `Caps` | `wire_version` ≥ 1; user agent ≤ 64 B |
| 14 ROTATE | `Rotate` | old and new keys valid (§4.2) and different; signature 64 B |
| 8–10 rooms | — | specified with rooms (M5) |

**Text.**
- IM bodies and every string field must be valid UTF-8.
- They contain no C0 control characters other than newline and tab, and no DEL or C1 controls (U+007F–U+009F).
- Buddies' text is shown in terminals, where ESC or CSI sequences could rewrite the screen. Bidirectional-override and look-alike tricks are left to the UI.

**ACKs name messages by `msg_id` alone.** An ACK travels in the reverse direction under a different `conv_tag`, and carrying
the original tag would cost 8 more bytes per entry on mesh. So the sender matches an ACK to its own messages to that buddy by `msg_id`.

**Typical sizes.** A presence update is 14 B and fits in one fragment along with everything else. A one-entry ACK is 14 B, and
8 entries are 128 B. A REACH with one IP hint (an IPv4 and an IPv6 address) plus a mesh node is 96 B. A BUDDY_ACCEPT carrying that REACH is 177 B, two mesh fragments.

## 7. Receiving

Receivers check things in this order. **Nothing touches dedup or reassembly state before step 4 has passed.**

1. **Header:**
   - version 1, kind `DATA` or `DATA_IP`
   - `count` ≤ the layout's maximum, and `index < count`
   - frame length ≤ the layout's frame size, and exactly that size unless this is the last fragment
2. **Tag lookup:** `conv_tag` must be one the receiver expects. That means the tags of each of its conversations for every day in the acceptance window. If more than one conversation has the tag, try each.
3. **AEAD:** derive `K_msg` from the header and open the fragment. On failure, drop it.
4. **Fragment 0 window check:** fragment 0 starts with the inner header. Reject its timestamp if it is more than 14 days old or more than 10 minutes ahead.
5. **Dedup:** if `(conv_tag, msg_id, frag)` has been seen in the last 30 days, the frame is a duplicate. The receiver may re-ack it with its fragment bitmap. Checking and recording must be one atomic step.
6. **Reassembly:**
   - Keep the fragment under `(conv_tag, msg_id, count)`.
   - Hold at most 8 incomplete messages per tag, evicting the oldest, and drop any older than 6 hours.
   - When all `count` fragments are present, join them in index order.
7. **Whole message:** require `HMAC(K_siv, inner)[:8] = msg_id`, parse the inner payload (§6), and check the window again. Then deliver.

## 8. Time

- The epoch is 2025-01-01T00:00:00Z. It's the origin of both `day` and `timestamp`.
- Clock sources and the clock-unsynced flag are described in design.md §8.9. This draft applies the acceptance window to every message, flagged or not (see §10).

## 9. Departures from design.md v0.3

Each of these was decided while writing this spec and implementing `internal/frame`. design.md has been updated where noted.

1. **`conv_tag` is bound into `K_msg`.**
   - Design §8.2 derived `K_msg` from `msg_id ‖ frag_count ‖ layout_version` only. But `conv_tag`, which rotates daily, is part of the associated data.
   - So the same inner payload sealed on two different days gets the same key and nonce with different associated data. That reuses the Poly1305 one-time key on two different inputs, which allows forgery.
   - Sealing the same payload twice is a bug, but seal-once is meant to hold even when callers have bugs. Binding `conv_tag` makes it hold.
   - The property test caught the reuse when the binding was removed. (design.md §8.2 updated.)
2. **The layout is carried in the frame kind** (`DATA` or `DATA_IP`). Design §8.3 named a `layout_version` input to `K_msg` but gave it no place in the header, so receivers couldn't derive the key.
3. **No padding.**
   - "Canonical size" means the fixed fragment size. Every fragment but the last is full-size, and the last is only as long as it needs to be.
   - Padding every frame to 200 B would hide message length but would cost up to ~4× the airtime for short IMs. That's left open (§10).
4. **Exact HKDF use.**
   - Only `K_pair` uses Extract (salt `openaim/v1`). Every other key is `Expand` from a uniform key.
   - All info labels are full `openaim/v1/…` strings. Design §8.2 wrote shorthand like `"dir"`.
5. **The window check moves earlier.** Fragment 0 is window-checked as soon as it authenticates (§7 step 4), so a stale replay never creates a reassembly buffer.
6. **Stricter inner encoding:** unknown flags are rejected and varints must be minimal (§6).
7. **The IP layout is defined:** 4096-byte frames, up to 16 fragments (§5.1).
8. **Body capacity:** a single mesh fragment carries 159 B of body (design §8.3 said ~157 B), and four fragments carry ~657 B.

## 10. Open questions

- **Length hiding.**
  - Without padding, observers can tell short messages from long ones.
  - Options: pad the last fragment to one of a few bucket sizes, or pad only on IP.
  - The cost is airtime, so it needs M0's measurements.
- **Unsynced clocks.**
  - A mesh-only node with no RTC, GPS or buddy time sources sends timestamps from a build-time floor. Those can fall outside the 14-day window, so the node can't be heard.
  - Options: exempt `clock-unsynced` frames from the window and rely on dedup alone, or have such nodes learn time from the first authenticated frame they receive.
- **Reassembly limits** (8 per tag, 6 hours) are first guesses. Slow mesh links with four fragments and three attempts may need longer.
- **Tag collisions:** with 8-byte tags, collisions are rare, and receivers try every matching conversation (§7 step 2). The cost of trying each is bounded by the size of the tag table.
- **Everything here goes to the external crypto review** (design.md §10.4, Q11).
