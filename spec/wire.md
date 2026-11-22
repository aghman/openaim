# OpenAIM wire format, draft v1

**Status: draft, not frozen.** The format changes freely until the external cryptography review at the end of M2
([design.md §10.4](../docs/design.md#104-review-gate)). After that, this document is normative and changes only with a new wire version.

The draft covers identity keys, the recovery phrase, pairwise keys, the `DATA` frame (sealing, fragmentation and receiving),
inner-payload bodies and the `FIRST_CONTACT` frame (§11, numbered last so earlier section numbers stay stable). Beacons,
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
| `openaim/v1/first-contact` | first contact: recipient hash `h_R` | §11.2 |
| `openaim/v1/first-contact/es`, `/ss` | first contact: chaining keys `ck1`, `ck2` | §11.2 |
| `openaim/v1/first-contact/siv` | first contact: synthetic-ID key | §11.2 |
| `openaim/v1/first-contact/s`, `/payload`, `/tail` | first contact: AEAD keys `K_s`, `K_p`, `K_t` | §11.2 |
| `openaim/v1/first-contact/dedup` | first contact: receiver-local dedup tag (never sent) | §11.5 |
| `openaim/v1/rdv`, `loc`, `token` | reserved, specified later | — |

## 3. Frames

The first byte of every frame is `ver_kind = version << 5 | kind`. In this draft `version` is **1**.

| Kind | Name | Status |
|------|------|--------|
| 1 | `DATA`: buddy or room message, mesh layout | specified (§5) |
| 2 | `DATA_IP`: buddy or room message, IP-only layout | specified (§5) |
| 3 | `FIRST_CONTACT`: request from a non-buddy, mesh layout | specified (§11) |
| 4 | `BEACON` | reserved |
| 5 | `NEARBY` | reserved |
| 6 | `GATEWAY_AD` | reserved |
| 7 | `FIRST_CONTACT_IP`: request from a non-buddy, IP-only layout | specified (§11) |

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

### 4.5 Recovery phrase

The recovery phrase is the 32-byte identity seed written as 24 words from the BIP-39 English list. The list is vendored
at `internal/identity/wordlist/english.txt` and pinned by its SHA-256, `2f5eed53…3b24dbda`.

```
bits  = seed (256 bits) ‖ SHA-256(seed)[0] (8 bits)       // 264 bits, MSB first
word_i = list[bits[11·i : 11·i + 11]]                     // i = 0 … 23
```

- **The same mnemonic encoding as BIP-39, nothing more.** The words encode the seed directly: there's no PBKDF2 step and no passphrase. An OpenAIM phrase is also a valid BIP-39 mnemonic, but the two are used differently, so a wallet would derive unrelated keys from it.
- **Lenient input:** readers accept any whitespace, any letter case, and the first four letters of each word, which are unique in the list.
- **Errors:** a wrong word count, an unknown word or a bad checksum is rejected. The 8-bit checksum catches a wrong word or a swap about 255 times in 256. Since a phrase is typed once, at restore time, the UI should also show the restored key ID so the user can compare it. Error messages give the word's position, never the word.

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
  10 ROOM_REKEY, 11 BUDDY_ACCEPT, 12 REACH, 13 CAPS, 14 ROTATE, 15 BUDDY_REQUEST (`FIRST_CONTACT` frames only, §11.6).
  The frame layer passes unknown types to the router.
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
| 15 BUDDY_REQUEST | `BuddyRequest` | display name ≤ 64 B; greeting ≤ 256 B; recovery key empty or a valid identity key (§4.2); `reach` and `caps` valid if present |
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
9. **A second first-contact kind.** Design §8.5 has one `FIRST_CONTACT` kind. This draft adds `FIRST_CONTACT_IP` (kind 7) for the IP
   layout, for the same reason `DATA_IP` exists: the receiver must know the layout before deriving keys, and an IP request with a full
   REACH doesn't fit 200-byte frames.
10. **First-contact fragmentation is defined** (§11.1). Design §8.5 gave fragment 0's layout only and said longer greetings use 2
    fragments. Fragments 1+ repeat `e` and omit `enc(s)` (58 B overhead, 142 B capacity). Mesh requests use at most 2 fragments
    (236 B of inner payload); IP requests use exactly 1.
11. **The first-contact key schedule binds more than the DH outputs** (§11.2). Design §8.5 says `enc(s)` is "encrypted under
    `DH(e, R_x)`" and the payload under a key from both DHs. Here the recipient's and sender's **Ed25519** keys and `e` itself are mixed
    into the chaining keys, and every AEAD key also binds `msg_id`, the fragment count and the layout, as `K_msg` does for `DATA`
    (§9 item 1). Without the `msg_id` binding, a repeated `e` would reuse `enc(s)`'s key and nonce with different associated data.
12. **The first-contact `msg_id` is keyed behind `ss`** (§11.2), not by a pairwise `K_siv`, which doesn't exist yet. It is what binds
    fragments 1+, which are opened under `es` alone, to the sender's static key.
13. **New content type 15 `BUDDY_REQUEST`** (§11.6). Design §8.4's list has no type for the request itself. Its body carries a
    display name, a greeting, an optional REACH as the contact hint (design §8.5's "contact hint"), and optionally the sender's recovery
    key and CAPS, mirroring `BUDDY_ACCEPT`.

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
- **First contact** (§11.7 lists what it does and doesn't provide):
  - **KCI and recipient compromise are inherent** to a one-way static-static handshake. If a recipient's key leaks, every first contact
    ever sent to it can be read, and requests to it can be forged from anyone. Only rotation (design §5.5) and future
    forward-secrecy work address this.
  - **Replays** within the 14-day window are stopped only by the receiver's dedup state, which must survive restarts. Should receivers
    also drop a second request from a sender who already has one pending, whatever its `msg_id`?
  - **Padding.** A first contact's length leaks the greeting's length, as for `DATA` (above).
  - **Reuse for gateway and mailbox registration** (design §8.5) may need a prologue binding the service's key or purpose into
    `h_R`. It's to be decided with M3.
  - **Recovery key on mesh.** A one-fragment mesh request has no room for the sender's recovery key (34 B). How a requester who
    omitted it delivers it after acceptance isn't specified yet.
  - **Two mesh fragments** is a first guess at the balance between greeting length and the trial-decryption cost every listener pays.
- **Everything here goes to the external crypto review** (design.md §10.4, Q11).

## 11. `FIRST_CONTACT` frames

A first contact is the first message to someone who isn't a buddy yet: a buddy request (design §5.4, §8.5). It uses a one-way
handshake modelled on Noise `X` (`e, es, s, ss`):

- **No identities in the clear.** The sender's identity key travels encrypted, and there's no recipient field.
- **Deniable.** The payload is authenticated by a static-static DH, not a signature.
- **Trial decryption.** A node tries every first contact it hears, at one X25519 per fragment.

In this section `S` is the sender, `R` the recipient, `S_ed` and `R_ed` their Ed25519 identity keys, `S_x` and `R_x` their X25519
forms (§4.1), and `s` and `r` their X25519 private scalars.

### 11.1 Layouts and frame format

| Layout | Frame kind | Max frame | Fragment 0 capacity | Fragment 1+ capacity | Max fragments | Max inner payload |
|--------|-----------|-----------|---------------------|----------------------|---------------|-------------------|
| mesh | 3 `FIRST_CONTACT` | 200 B | 94 B | 142 B | 2 | 236 B |
| ip | 7 `FIRST_CONTACT_IP` | 4096 B | 3990 B | — | 1 | 3990 B |

```
fragment 0:   ver_kind (1) | e (32) | msg_id (8) | frag (1) | enc_s (32 + 16) | enc_chunk_0 (n + 16)      overhead 106 B
fragment i:   ver_kind (1) | e (32) | msg_id (8) | frag (1) | enc_chunk_i (n + 16)                       overhead  58 B
header_i = the first 42 bytes;  frag = index << 4 | (count − 1), as in §5.4
```

- **`e`** is the sender's ephemeral X25519 public key. It must be a canonical u-coordinate: bit 255 clear and `u < p`. X25519 ignores the
  top bit and reduces mod `p`, so without this rule several encodings would name the same key.
- **Every fragment repeats `e`**, so each can be opened on its own and in any order. The cleartext `e ‖ msg_id` links a message's
  fragments to each other, as `conv_tag ‖ msg_id` does for `DATA`. It links nothing else.
- **Sizes.** As for `DATA`, every fragment but the last is exactly the layout's frame size. Fragment 0 is at least 113 B, because it
  carries the whole 7-byte inner header (§11.3).
- **Why so few fragments.** Every node that hears a first contact pays an X25519 per fragment to try it, and requests from strangers are
  the main spam surface (design §7.5). Two mesh fragments carry a display name, a greeting of about 140 B and a mesh contact hint (§11.6).
  One IP fragment carries a request with a full REACH. Anything longer waits until the request is accepted.

### 11.2 Key schedule

```
e_priv  = 32 fresh random bytes, clamped as RFC 7748 does;  e = X25519(e_priv, 9)
es      = X25519(e_priv, R_x)      = X25519(r, e)
ss      = X25519(s, R_x)           = X25519(r, S_x)

h_R     = SHA-256("openaim/v1/first-contact" ‖ R_ed)
ck1     = HKDF(ikm = es, salt = h_R, info = "openaim/v1/first-contact/es" ‖ e)
ck2     = HKDF(ikm = ss, salt = ck1, info = "openaim/v1/first-contact/ss" ‖ S_ed)
K_siv   = Expand(ck2, "openaim/v1/first-contact/siv")
msg_id  = HMAC(K_siv, inner)[:8]                      // inner = the whole inner payload, §6

cap_0, cap_1 = fragment 0 and fragment 1+ capacities (§11.1)
count   = 1 if len(inner) ≤ cap_0, else 1 + ceil((len(inner) − cap_0) / cap_1)
K_s     = Expand(ck1, "openaim/v1/first-contact/s"       ‖ msg_id ‖ count_u8 ‖ layout_u8)
K_p     = Expand(ck2, "openaim/v1/first-contact/payload" ‖ msg_id ‖ count_u8 ‖ layout_u8)
K_t     = Expand(ck1, "openaim/v1/first-contact/tail"    ‖ msg_id ‖ count_u8 ‖ layout_u8)
nonce_i = 0x00000000 00000000 ‖ index_be32            // as in §5.4
```

`layout_u8` is 1 for mesh and 2 for IP, as in §5.1. Both DH outputs must be nonzero (§4.2).

How this maps onto Noise `X`:

- **`h_R` is the pre-message `<- s`.** It binds the recipient's **Ed25519** key, not only its X25519 form (§4.3).
- **`ck1` is `MixKey(es)`.** It also binds `e` itself into the key, where Noise mixes `e` only into the transcript hash.
- **`ck2` is `MixKey(ss)`** and binds `S_ed`. So two Ed25519 keys that share an X25519 form (`S` and `−S`) give different keys.
- **Transcript.** Every AEAD takes its fragment's whole header, including `e` and `msg_id`, as associated data. The payload in fragment 0
  also takes `enc_s`, as Noise's `EncryptAndHash` chains `s` into the payload's associated data.
- **Fragments 1+ use `K_t`, from `ck1`.** That lets them be opened before fragment 0 arrives. The `msg_id` check on the whole message
  (§11.5 step 7) binds them to `S`'s static key.

### 11.3 Sealing

1. **Check the payload.**
   - `inner` must parse as an inner payload (§6). It is at least 7 bytes, so fragment 0 carries the whole inner header and the timestamp.
   - It must fit the layout's maximum.
2. **Check the keys.**
   - `R_ed` must pass §4.2.
   - Refuse `S_x = R_x`. That covers both a request to oneself and one to `−S`.
3. **Draw `e_priv`** from a cryptographically secure source and derive the keys (§11.2).
4. **Split `inner`.** Chunk 0 is `inner[0 : cap_0]`. Chunk `i ≥ 1` is `inner[cap_0 + (i−1)·cap_1 : cap_0 + i·cap_1]`, cut at the end of `inner`.
5. **Encrypt**, all with ChaCha20-Poly1305:
   ```
   enc_s      = Seal(K_s, nonce_0, plaintext = S_ed,    ad = header_0)
   fragment 0 = header_0 ‖ enc_s ‖ Seal(K_p, nonce_0, plaintext = chunk_0, ad = header_0 ‖ enc_s)
   fragment i = header_i ‖ Seal(K_t, nonce_i, plaintext = chunk_i, ad = header_i)          for i ≥ 1
   ```
6. **Seal once**, as for `DATA` (§5.5 step 3). The sender persists the frames, and retries, fallback routes and restarts re-send the
   same bytes. Sealing the request again draws a new `e`, which makes a new and unlinkable message with a new `msg_id`. The recipient
   then sees two requests from the same key, which the UI merges.

**Why `e` is random.** Deriving `e` from `s` and `inner` would make sealing deterministic, but anyone who later stole `s` could
recompute `e_priv` and `es`, and read every request `S` ever sent. A random `e` keeps past requests confidential after the sender's
key leaks (§11.7).

### 11.4 Why the derivation is safe

- **Unique keys and nonces.** Every AEAD key is `Expand(ck, label ‖ msg_id ‖ count ‖ layout)`. `K_s` and `K_p` use only nonce 0, and
  `K_t` only nonces 1 and up. So a `(key, nonce)` pair recurs only for the same `(ck, label, msg_id, count, layout, index)`.
- **What that pins down.**
  - `ck1` fixes `R_ed`, `e` and `es`, and `ck2` also fixes `S_ed` and `ss`.
  - Except for a 64-bit collision, `msg_id` fixes `inner`, and so every chunk.
  - Each header is a function of the layout, `e`, `msg_id`, `index` and `count`, and `enc_s` of `K_s`, `S_ed` and `header_0`.
  - So the same key and nonce mean the same plaintext **and** the same associated data, as in §5.6.
- **Even when randomness fails.** This holds when the sender's random source repeats `e`: two different requests still get different
  `msg_id`s and so different keys. That's why `msg_id`, the count and the layout are bound into the keys, not just the associated data.
  - Without the `msg_id` binding, a repeated `e` would seal the same `S_ed` under the same `K_s` and nonce with two different headers.
    That reuses the Poly1305 one-time key on two different inputs, which allows forgery.
  - `TestFirstContactSealOnce` in `internal/frame` checks the property by brute force with a random source that repeats `e`. It fails
    if either binding is removed.
- **What a repeated `e` still costs.** Observers can link the two requests. A predictable `e` would let an attacker read `S_ed` and
  fragments 1+, which are keyed from `ck1` alone, but not fragment 0's payload, which also needs `ss`.

### 11.5 Receiving

Receivers check things in this order. **Nothing touches dedup or reassembly state before step 4 has passed.**

1. **Header** (no crypto):
   - version 1, kind `FIRST_CONTACT` or `FIRST_CONTACT_IP`
   - `count` ≤ the layout's maximum, and `index < count`
   - frame length ≤ the layout's frame size, exactly that size unless this is the last fragment, and at least 113 B for fragment 0
   - `e` canonical (§11.1)
2. **Ephemeral DH:** `es = X25519(r, e)`. Drop the frame if it's all zero, which is what a small-order `e` gives. Derive `ck1`.
3. **AEAD:**
   - Fragment `i ≥ 1`: open it with `K_t`.
   - Fragment 0:
     1. Open `enc_s` with `K_s` to get `S_ed`.
     2. Reject `S_ed` if it fails §4.2, or if `S_x = R_x`.
     3. Compute `ss = X25519(r, S_x)`, which must not be all zero, then `ck2`.
     4. Open chunk 0 with `K_p`.
   - **One generic error.** Every failure in steps 2 and 3 is the same "authentication failed". A frame for someone else, a forgery
     and a hostile sender key look alike, and nothing is recorded.
4. **Fragment 0 window check:** reject its timestamp if it is more than 14 days old or more than 10 minutes ahead, as in §7 step 4.
5. **Dedup:**
   - The key is `(dedup_tag, msg_id, frag)`, with `dedup_tag = SHA-256("openaim/v1/first-contact/dedup" ‖ e)[:8]`. It's kept for
     30 days, and checking and recording are one atomic step, as in §7 step 5.
   - `dedup_tag` never goes on the wire. Its label keeps first-contact entries apart from `DATA` conversation tags in a shared store.
   - A duplicate is dropped. It is never answered on mesh.
6. **Reassembly:**
   - Keep the fragment under `(e, msg_id, count)`.
   - Hold at most 16 incomplete first contacts **in total**, evicting the oldest, and drop any older than 6 hours. The bound is global
     because anyone can make valid fragments with keys of their own.
7. **Whole message:**
   - Require `HMAC(K_siv, inner)[:8] = msg_id`, with `K_siv` from fragment 0. This binds fragments 1+ to `S`'s static key.
   - Parse the inner payload (§6) and check the window again.
   - Deliver `S_ed` and the inner payload.
8. **Above the frame layer:**
   - In this draft the content type must be `BUDDY_REQUEST` (§11.6); anything else is dropped. Types for gateway and mailbox
     registration come with M3.
   - The sender is shown as unverified (design §5.3).
   - Requests are never answered automatically on mesh (design §5.4).

**Cost.** A node that isn't the recipient spends one X25519, a few hashes and one failed AEAD per fragment. The recipient spends a second
X25519 on fragment 0. Rate limiting first contacts per transport, and proof-of-work through gateways and mailboxes (design §7.5),
are the caller's job.

### 11.6 Inner payload and `BUDDY_REQUEST`

The inner payload has the §6 format.

- **`content_type`** is 15, `BUDDY_REQUEST`. That type is valid only in first contacts; in a `DATA` frame it's dropped.
- **`flags`:** senders set none except clock-unsynced. Receivers ignore ack-requested, since requests aren't answered automatically.
- **`seq`:** senders set 0, so the inner header is 7 bytes. Receivers ignore it.
- **`body`** is a `BuddyRequest` protobuf ([bodies.proto](../proto/openaim/v1/bodies.proto)), with the limits in §6.1:
  `display_name`, `greeting`, an optional `reach` (the contact hint: where to send `BUDDY_ACCEPT`), and optionally the sender's
  `recovery_key` and `caps`. It holds no identity key, because the frame already authenticates `S_ed`.

**Budgets.**

| Route | Body capacity | Example |
|-------|---------------|---------|
| one mesh fragment | 94 − 7 = **87 B** | `SkaterDude99`, a 30 B greeting and a mesh-only REACH: 67 B |
| two mesh fragments | **229 B** | a 64 B name, a 120 B greeting and a mesh REACH: 209 B. Or a REACH with one IP hint (two addresses), a recovery key, CAPS and a 60 B greeting: 214 B |
| IP | **3983 B** | every field at its limit, with four IP hints: 770 B |

`TestFirstContactBudgets` in `internal/body` checks these.

### 11.7 Properties and limitations

**What a first contact provides:**

- **Identity hiding from observers.**
  - No frame carries `S_ed`, `R_ed` or their X25519 forms in the clear.
  - `S_ed` is encrypted under a key from `es`, which needs `e_priv` or `r`.
  - `e` is fresh for each message, and `msg_id` is a PRF output, so neither links requests to each other or to a key.
  - This holds against active attackers too, as long as they don't hold `r`.
- **Sender authentication without a signature.** A valid fragment 0 needs `ss`, so it was made by `S` or by `R`. A transcript proves
  nothing to a third party, because `R` could have made it: the request is deniable.
- **Recipient binding.** `R_ed` is in `h_R` and `R_x` in both DHs, so a request can't be redirected to someone else.
- **Confidentiality after sender compromise.** If `s` leaks later, past requests stay confidential, because reading them needs `e_priv`
  or `r`.
- **Ed25519 binding.** `S_ed` and `R_ed` are in the key schedule, so a claim to be `−S` derives different keys (§4.3).

**What it doesn't provide:**

- **Key-compromise impersonation.** Anyone holding `r` can forge requests to `R` from anyone. That's inherent to `X`, and it's also
  what makes requests deniable (design §10.3).
- **Forward secrecy against recipient compromise.** If `r` leaks, every recorded first contact to `R` can be opened, which reveals who
  sent it and what it said.
- **Replay protection beyond the window.**
  - A one-way handshake can't prove freshness. Only the timestamp window and dedup stop replays.
  - A receiver that loses its dedup state can be shown a request again within the 14 days. That's mostly harmless: it's the same
    sender, and the UI merges it.
  - A replay to anyone else fails to open.
- **Traffic-analysis resistance.**
  - The kind byte shows that a first contact was sent, and the frame length shows roughly how long it is.
  - Meshtastic's `from` node number is in the clear (design §8.6).
- **Full-strength tail authentication under a broken random source.** Each fragment 1+ is authenticated under `es`, so only someone who
  knows `e_priv` or `r` can make one. If `e` were predictable, the 64-bit `msg_id` check would be the only thing binding a fragment 1
  to `S`: a forgery would succeed with probability 2^-64 per attempt.
- **Protection against flooding.** Anyone with fresh keys can make valid frames, which cost every listener an X25519 and can churn the
  16-entry reassembly table. Rate limits and proof-of-work (§11.5) are what bound this.
