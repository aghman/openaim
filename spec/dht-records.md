# OpenAIM DHT records (draft)

Status: draft, alongside `spec/wire.md`. Implemented in `internal/transport/ip/dhtrecord.go`.

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

## Left to the rendezvous layer (later ticket)

- **Deriving the signing key.** Design §6.1 names the record key `R = HMAC(K_dir, "rdv" ‖ day)`. With self-certifying
  records, the HMAC output becomes the Ed25519 **seed** instead, `seed = HMAC(K_dir, "rdv" ‖ day)`, and the DHT key is
  derived from its public key as above. Both buddies can still compute it, and nobody else can write it.
- **The payload:** the current peer ID and addresses, `issued_at` and `expires_at` (§7.1), encrypted under
  `L = HKDF(K_dir, "loc" ‖ day)`.
- Republishing on every host rotation, on address changes, and before the 36-hour expiry.
