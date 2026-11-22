# OpenAIM DHT records (draft)

Status: draft, alongside `spec/wire.md`. The record format is implemented in `internal/transport/ip/dhtrecord.go`, and
the rendezvous layer on top of it in `internal/rendezvous`. Golden vectors for the rendezvous layer are in
[vectors/rendezvous_v1.json](vectors/rendezvous_v1.json), and
[vectors/verify_rendezvous_v1.py](vectors/verify_rendezvous_v1.py) recomputes them using only the Python standard library.

## DHT

- Kademlia, go-libp2p-kad-dht, protocol **`/openaim/kad/1.0.0`** (prefix `/openaim`). It is not the IPFS Amino DHT, and
  peers that speak only `/ipfs/kad/1.0.0` are never in its routing tables.
- Value records only. Provider records are disabled.
- One record namespace, `oa-rdv`. The IPFS `/pk` and `/ipns` namespaces are rejected, as is any other namespace.
- Storers keep a record for at most 36 hours after receiving it (the kad-dht default). Nodes don't republish other
  people's records, so publishers republish their own.

## Rendezvous record (`/oa-rdv/`)

A rendezvous record is **self-certifying**. Its key is the hash of an Ed25519 public key, and its value is signed with
the matching private key. Every DHT node checks both before storing or returning the record. A storer learns the
record's key, but it can't overwrite the record, because it doesn't have the private key. It can only drop the
record, and the other storers among the ~20 closest still hold it.

**Key:**

```
key   = "/oa-rdv/" ‖ lowercase-hex(SHA-256("openaim/v1/dht-rdv-key" ‖ pk))     (64 hex digits)
```

**Value** (at most 1024 bytes):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | version = `0x01`. Any other value is rejected. |
| 1 | 8 | `seq`, unsigned big-endian |
| 9 | 32 | `pk`, the Ed25519 public key |
| 41 | n | payload, opaque, 1 ≤ n ≤ 919 |
| 41+n | 64 | Ed25519 signature by `pk` over `"openaim/v1/dht-rdv-sig" ‖ SHA-256("openaim/v1/dht-rdv-key" ‖ pk) ‖ value[0 : 41+n]` |

**Validation:** the key has the exact form above, the size is within bounds, the version is 1, the hash of `pk` equals the
key, and the signature verifies under Go `crypto/ed25519` rules.

**Selection** between valid values for one key: the highest `seq` wins. Equal `seq`s go to the bytewise-greater
value, so every node picks the same record whatever order it sees them in. Invalid values are never picked. A put
whose value loses against the one a node already stores is refused by that node.

**`seq`:** publishers use the signing time in Unix milliseconds. That needs no stored counter across restarts, and it
reveals nothing a storer doesn't already learn from when the put arrives. It must **not** be a per-user counter, which
would link one user's records for different buddies. A publisher whose clock jumps far ahead locks itself out of that
key until the key changes the next day.


## Rendezvous derivation

Each buddy pair has two rendezvous records per day, one per direction. Publisher P's record for buddy B is keyed by
P's directional key toward B, `K = K_dir_P` (wire.md §4.3). P holds it as `Pair.Send` and B as `Pair.Recv`. `day`
is the UTC day number of wire.md §5.2, and the notation is that of wire.md §1.

```
seed  = HMAC(K, "openaim/v1/rdv" ‖ day_be32)          // 32 bytes: an RFC 8032 Ed25519 private key (seed)
pk    = Ed25519 public key of seed                     // [clamp(SHA-512(seed)[:32])]·B, RFC 8032 §5.1.5
kh    = SHA-256("openaim/v1/dht-rdv-key" ‖ pk)
key   = "/oa-rdv/" ‖ lowercase-hex(kh)                  // the DHT key, as above
L     = Expand(K, "openaim/v1/loc" ‖ day_be32)         // 32 bytes: the locator key
```

`seed` is design §6.1's `R`. Only P and B know `K`, so only they can derive `seed`, sign a record, find the key or
decrypt the payload. Both are keyed PRF outputs of `K` under distinct labels (`Expand(K, x)` is `HMAC(K, x ‖ 0x01)`),
so they're independent of each other and of the conversation tag `HMAC(K, "openaim/v1/tag" ‖ day_be32)`.

### Payload

The record's opaque payload (offset 41 in the table above) is:

```
ad         = kh ‖ value[0:41]                          // 73 bytes: key hash ‖ version ‖ seq_be64 ‖ pk
plaintext  = len_be16 ‖ locator ‖ 0x00 × pad            // locator: the protobuf below, len = its length
nonce      = 24 bytes from a CSPRNG, fresh for every record
payload    = nonce ‖ XChaCha20-Poly1305-Seal(L, nonce, plaintext, ad)
```

- **XChaCha20-Poly1305** is draft-irtf-cfrg-xchacha-03: the HChaCha20 subkey of `L` and `nonce[0:16]`, then RFC 8439
  ChaCha20-Poly1305 with the 12-byte nonce `0x00000000 ‖ nonce[16:24]`. Tag 16 bytes.
- **Padding:** `len(plaintext) = min(256·⌈(2 + len(locator)) / 256⌉, 879)`, where 879 = 919 − 24 − 16 is the most that
  fits. A locator longer than 877 bytes can't be published. Padding hides the number and kind of addresses from DHT
  nodes: almost every record is one 256-byte bucket, 401 bytes as a DHT value.
- **Associated data** binds the ciphertext to its record: the DHT key (through `kh`), the version, `seq` and `pk`.
  Nobody but the pair could move a payload to another record anyway (the signature covers it and only the pair can
  sign), but this way the binding holds for the ciphertext itself, whatever later record versions do with signatures.

**Why a random 192-bit nonce, not one derived from `seq`.** With ChaCha20-Poly1305 and `nonce = f(seq)`, a repeated
`seq` with a different plaintext would reuse the keystream and the Poly1305 key under `L`, and the two ciphertexts
are public to every DHT node, which could XOR them. `seq` is the signing time in milliseconds, and it does repeat:
two publishes in one millisecond, or a clock stepped backward by NTP, a VM restore or a restart (no counter is stored,
see `seq` above). Ruling that out would need the persistent state that time-as-`seq` was chosen to avoid. With a random
24-byte nonce, `(L, nonce)` repeats only by chance. Each `L` lives for one day, and a publisher seals a few dozen
records under it at most, so the chance is about `q² / 2^193` ≈ 2^-183. The cost is 24 bytes per record.

So `seq` may repeat without any harm to confidentiality or integrity. Two different records with one `seq` are only
a freshness problem: §Selection picks the bytewise-greater value on every node, which may be the older locator.
Publishers therefore use `seq = max(now_ms, last_seq + 1)` per key within a process, and a record from before a
restart is at least a millisecond older than one after it unless the clock went backward.

### Locator

`locator` is a `RendezvousLocator` ([proto/openaim/v1/rendezvous.proto](../proto/openaim/v1/rendezvous.proto)),
encoded deterministically. It is the IP reachability hint of design §7.1:

| Field | Receivers require |
|-------|-------------------|
| `ip.peer_id` | 1–64 bytes, a valid libp2p peer ID: the publisher's current network key |
| `ip.addrs` | at most 8, each 1–128 bytes (the REACH limits, wire.md §6.1). An address that isn't a valid binary multiaddr is ignored, not an error, so new transports can be added. |
| `issued_at`, `expires_at` | seconds since the OpenAIM epoch; `issued_at < expires_at ≤ issued_at + 129 600` (36 hours, the DHT's own expiry) |

Unknown fields are ignored. After the AEAD, receivers check `len(plaintext) ≥ 2`, `2 + len ≤ len(plaintext)` and that
every padding byte is zero. They don't check the padding bucket.

Publishers list relay circuit addresses first, then public, then private (LAN) ones, then the rest (loopback and
anything else), drop any trailing
`/p2p/<own peer ID>` (the `peer_id` field says it), and keep as many as fit in 8 addresses and 877 bytes.

## Publishing

A publisher keeps, for every buddy:

- **today's record**, and from 1 hour before the next UTC midnight also **tomorrow's**, so that a buddy whose lookup
  straddles the rollover finds a record under either day;
- `issued_at` = the signing time, `expires_at` = `issued_at` + 36 h, `seq` as above.

It (re)publishes a record:

- on start, and whenever the network host rotates (a new peer ID);
- when its addresses change: the host's own address-change events, or an explicit `Republish`;
- 12 hours after the last successful put of that record (storers lose records when their own hosts rotate, since every
  host generation starts with an empty datastore), except in the hour before its day ends;
- after a failed put, after 1 minute, doubling to at most 30 minutes.

Puts are rate-limited: at most 4 in flight and at least 200 ms between starts, so 100 buddies take about 20 seconds.
That's roughly 3 puts per buddy per day (the prepublish, one refresh, one rotation), so 300 small puts for 100 buddies.
A removed buddy's records are no longer published, so the ex-buddy, who still knows `K`, stops finding new ones.

## Lookup

To find buddy B, take `K = Pair.Recv` (B's key toward us) and try `day` = today and yesterday, and tomorrow too within
10 minutes of the next UTC midnight (B's clock may be ahead). For each:

1. derive `pk`, `key` and `L`, and get the DHT's best value under `key` (§Selection);
2. validate it as above, and check that its `pk` is the derived one;
3. open the payload with `L` and `ad`, and decode and check the locator;
4. require `now < expires_at` and `issued_at ≤ now + 10 minutes`.

The valid record with the highest `seq` gives B's current peer ID and addresses. A record past `expires_at`, or a day
older than yesterday, is never used, so replaying a stale record achieves nothing after a day and a half.

## What each party learns

**DHT nodes** that store a record, or see a query for it, learn:

- `key` and `pk`, which look random. They change every day, differ between the two directions of a pair and between
  a publisher's buddies, and can't be linked to identity keys, to each other or across days without `K`;
- `seq`, i.e. when the record was signed, which a storer sees anyway from when the put arrives;
- the padded payload length, which almost always just says "one bucket";
- that the record exists. They can withhold or drop it (an availability attack, limited by the ~20 replicas), but they
  can't read it (AEAD), forge or alter it (signature), or move it to another key or `seq` (key hash, AD).

What they learn **from the network, not from the record**, is the peer ID and IP address of whoever puts or gets a
key. A node that stores A's record for B sees A's current peer ID put it and B's current peer ID get it, and so
learns that those two network identities are buddies that day, though not who they are. All of one publisher's puts
come from one peer ID, in a burst after each rotation, so a node holding several of A's records can tell they're A's
that day. A Sybil adversary with many DHT nodes sees this for many pairs. v1 doesn't hide it; publishing and looking
up through relays or other hosts would.

**The buddy** learns the publisher's current peer ID and addresses, LAN and relay addresses included. That's the
point, and presence messages tell them the same thing. A buddy learns nothing about the publisher's other buddies:
each `K` is pair-specific.

**Both members of a pair can derive `seed` and `L` for both directions.** So B can write records under A's key toward B:
records claiming to be A's location, or an absurdly high `seq` that locks A out of that day's key. That's acceptable
because the only one who ever reads A's record for B is B. B can mislead or deny only its own lookups of A, never
anyone else's. (The same holds for A and B's record.) It also keeps the records **deniable**: the signing key is held
by both buddies, so a record proves nothing to a third party about which of them wrote it, as with frames
authenticated under `K_dir` (design §8). The signature exists to stop DHT nodes from overwriting records, not to prove
authorship.
