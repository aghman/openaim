# OpenAIM handle records and verification, draft v1

**Status: draft, not frozen.** This document specifies the DNS handle scheme of [design.md §5.3](../docs/design.md#53-screen-names-bluesky-style-dns-handles):
the handle syntax, the signed handle record, how clients look it up and verify it, and how they re-check pinned handles. It goes
to the external review with [wire.md](wire.md). `internal/handle` implements it. Where this document and design.md disagree,
this document wins; §9 lists the departures.

Notation follows [wire.md §1](wire.md#1-notation-and-primitives): `‖` is concatenation and integers are big-endian.

## 1. Handle syntax

A handle is a DNS name in a strict canonical form. A string is a valid handle when all of these hold:

- It is made of **labels** separated by `.`, with **at least two** labels and no empty label (so no leading, trailing or double dot).
- Each label is 1–63 bytes of `[a-z0-9-]` and doesn't start or end with `-`.
- No label starts with `xn--`. Punycode (internationalized) names are rejected in v1 because they can render as look-alikes of other names.
- The last label isn't all digits, so an IPv4 address such as `10.0.0.1` is never a handle (RFC 3696 §2).
- The whole handle is at most **244 bytes**, so that the record name `_openaim.<handle>` stays within DNS's 253-byte limit.

Uppercase is **not** valid in a handle. User input may be normalized first: trim surrounding whitespace, one leading `@` and
one trailing `.`, and lowercase ASCII letters `A–Z`. Nothing else is folded. Non-ASCII input is rejected, not mapped, so a
Cyrillic `а` can't quietly turn into a Latin `a`. Signatures always cover the canonical form.

## 2. The handle record

The record is one line of printable ASCII:

```
v=oa1; k=<key>; t=<issued>; i=<inbox hint>; s=<signature>
```

| Field | Required | Value |
|-------|----------|-------|
| `v` | yes, and **first** | exactly `oa1` |
| `k` | yes | the identity public key in its text form (wire.md §4.4): 52 characters of lowercase RFC 4648 base32, no padding. It must be the canonical encoding (decode then encode gives the same text) and a valid key (wire.md §4.2). |
| `t` | yes | when the record was issued, in Unix seconds: a non-negative decimal integer that fits in 63 bits, with no sign and no leading zeros (`0` itself is allowed) |
| `i` | no | the inbox hint, e.g. a multiaddr: 1–512 bytes from `!`–`~` (0x21–0x7e) except `;`. An absent field means "no hint". `i=` with an empty value is rejected, so each record has one spelling. |
| `s` | yes | the Ed25519 signature of §3: 64 bytes in standard padded base64 (RFC 4648 §4), 88 characters, canonical (no stray bits in the last character) |

**Parsing rules:**

- The whole record is at most **1024 bytes**. Every byte is in 0x20–0x7e, or a tab.
- Split on `;`. One trailing `;` is tolerated (as DKIM and DMARC allow); any other empty field is an error.
- Each field is `key=value`, split at the first `=`. Spaces and tabs are allowed around a field but not inside it, not even around the `=`.
- Fields after `v` may come in any order. A field that appears twice is an error.
- **Unknown fields are rejected, not ignored.** The signature covers only the fields of §3, so an extra field would be data anyone on the path could add or change. A record needing new fields needs a new version.
- `v` must be `oa1`. A record with any other version is an error if it is parsed; but see §4.3 for how records are picked out of a TXT set.

**Canonical form** (what writers produce): the fields in the order `v, k, t, i, s`, separated by `"; "`, with `i` left out
when there's no hint and no trailing `;`. Readers accept the whitespace variants above; parsing then re-serializing gives the
canonical form.

**Publishing in DNS.** The record is one TXT record at `_openaim.<handle>`. A DNS character-string holds at most 255 bytes, so a
longer record is split into several strings of the same TXT record. Readers join the strings with nothing between them.
Without an inbox hint the canonical record is 167 bytes; with one it can exceed 255.

## 3. The signed message

```
claim = u8 len(handle) ‖ handle ‖ key ‖ u64 issued ‖ u16 len(inbox) ‖ inbox
s     = Ed25519-Sign(identity key, "openaim/v1/handle-claim" ‖ claim)
```

- `handle` is the canonical handle (§1), at most 244 bytes, so its length fits in one byte.
- `key` is the **raw 32-byte** public key, not its base32 text. It is the key in `k` and the key that signs.
- `issued` is the value of `t` as an unsigned 64-bit integer.
- `inbox` is the value of `i`, or empty if there is none (at most 512 bytes, so its length fits in two bytes).

design.md writes the message as `"openaim/v1/handle-claim" ‖ handle ‖ k ‖ t ‖ i`. Concatenating the variable-length text
fields as they are would be ambiguous: for example `t = 12, i = "3/x"` and `t = 1, i = "23/x"` give the same bytes. Here every
variable-length field has a length prefix and every other field has a fixed size, so different claims always give different
messages. The label is prepended by the signing primitive, as for every OpenAIM signature (wire.md §2).

The signature binds the handle. A record copied from one handle's zone into another's fails verification, because the
verifier puts the handle it looked up, not anything in the record, into `claim`.

## 4. DNS lookup over DoH

### 4.1 No system resolver

Handle lookups never use the operating system's resolver. They go over **DNS-over-HTTPS** (RFC 8484) to configured resolvers.

- **Defaults:** `https://1.1.1.1/dns-query` (Cloudflare) and `https://9.9.9.9/dns-query` (Quad9). They are run by different
  operators, and they are IP literals whose certificates name the IP, so reaching them needs no DNS lookup at all. A
  configured resolver given by host name is resolved by the system; TLS still authenticates it.
- **At least two** resolvers must be configured, all `https://` URLs, with no duplicates.
- Requests have no proxy and follow no redirects. TLS 1.2 or later with normal WebPKI verification.

### 4.2 Query and response

- The query is a standard DNS message: one question `(_openaim.<handle>., TXT, IN)`, RD set, **ID 0** (RFC 8484 §4.1). It is sent
  as an HTTP `POST` with `Content-Type` and `Accept` set to `application/dns-message`.
- The response must have HTTP status 200 and `Content-Type: application/dns-message`, and the body is at most **16 KiB**.
  Each query has a **5 second** time limit.
- The DNS message must be a response (QR set) with ID 0, opcode 0 and TC clear, and must have exactly one question equal to the
  one asked (names compare case-insensitively).
- `NXDOMAIN`, or `NOERROR` with no matching record, means **no record**. Any other response code (such as `SERVFAIL`), and
  anything malformed, is a **resolver failure**.
- Answers of class IN at the question name are used. If the answer section has a `CNAME` chain from the question name, it is
  followed for at most 8 steps and the records at its end are used. Other answer records, and the authority and additional
  sections, are ignored.

### 4.3 Picking the record

From the TXT answers, each record's strings are joined (§2). A joined string is a **candidate** if it is `v=oa1` followed by
`;`, a space, a tab or nothing. Non-candidates (other TXT records at the name, records of future versions) are ignored.
Candidates are sorted and exact duplicates removed. No candidates means no record.

### 4.4 Resolvers must agree

Every configured resolver is asked, in parallel, and:

1. If **any** resolver fails (network error, timeout, bad HTTP response, bad DNS response, oversize, resolver error code), the lookup **fails**.
2. Otherwise every resolver must give the **same outcome**: the same list of candidates, or all "no record". Any difference fails the lookup (**disagree**).
3. If they agree on no record, the DNS lookup says **no record**.
4. If they agree on more than one candidate, the handle is **ambiguous** and fails.
5. Otherwise the single candidate is parsed with §2.

Rule 1 is deliberate. If a resolver that can be blocked or made to fail simply dropped out, an attacker able to interfere with
one resolver could make the other's answer count alone. While a record changes, resolvers can briefly disagree because of
caching; that fails the check, and it's retried later (§7). Registries should keep the TTL on `_openaim` records short.

**DNSSEC.** design.md §5.3 also accepts DNSSEC-validated answers. v1 doesn't: the AD bit from a DoH resolver only says that
resolver validated, so it is exactly as trustworthy as the resolver, and accepting it from a single resolver would undo rule 1.
Real DNSSEC support means validating the chain from the root on the client; that is future work.

## 5. HTTPS proof

`https://<handle>/.well-known/openaim` may serve the same record text (§2), for people whose DNS host makes TXT records awkward.

- **Address lookup:** the handle's A and AAAA records are fetched over DoH from the first configured resolver, and the next only
  if that one fails. Agreement isn't needed here, because TLS authenticates the server. At most 8 addresses are used.
- **SSRF guard:** a client must not connect to an address that isn't globally routable unicast. That excludes unspecified,
  loopback, private (RFC 1918, ULA), link-local, multicast, carrier-grade NAT, documentation, benchmarking, reserved and
  broadcast ranges, and the other IANA special-purpose ranges. IPv4-mapped, NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) IPv6
  addresses are judged by the IPv4 address inside them.
  - If **any** of the handle's addresses is forbidden, the fetch is refused, not just that address.
  - The check also runs **at connect time on the address actually being dialed**, so an answer that changes between lookup and
    connect (DNS rebinding) can't get past it.
- **TLS:** TLS 1.2 or later with a certificate valid for the handle under the system's WebPKI roots.
- **Request:** `GET`, port 443, no proxy, no compression, no connection reuse.
- **No redirects:** any 3xx response fails.
- **Status:** 200 is required. 404 and 410 mean **no proof**. Anything else is a failure.
- **Limits:** the body is at most **4 KiB**, checked against `Content-Length` and again while reading, and the whole fetch
  takes at most **10 seconds**.
- **Body:** leading and trailing spaces, tabs, CRs and LFs are trimmed, and what's left is parsed as one record (§2). The
  `Content-Type` isn't checked.

## 6. Verification

To verify a handle `h`:

1. Check `h` against §1. A bad handle is never looked up.
2. Look up the DNS record (§4).
3. If the resolvers **agree there is no record**, fetch the HTTPS proof (§5). If there is neither, the handle has no record.
4. If the DNS lookup **fails or disagrees**, verification fails. It does **not** fall back to the HTTPS proof: otherwise an
   attacker who could block a resolver could force the proof that isn't the one the owner published in DNS.
5. If there is a DNS record, the HTTPS proof isn't fetched, so the DNS record wins.
6. Check the signature (§3) with `h` as the handle.

The result is the identity key, the issue time, the inbox hint and where the record came from.

`t` is carried and signed but not otherwise checked in v1: a record isn't rejected for being old or dated in the future. It's
there so later rules (such as preferring the newer of two records during a rotation) have something signed to compare.

## 7. Pinning and re-checks

The buddy *is* the key; the handle is a label on it (design.md §5.3 rule 4). When a pinned handle is re-checked, the outcome is
one of:

| Status | When | What the client does |
|--------|------|----------------------|
| **verified** | the handle verifies and gives the pinned key | nothing |
| **moved** | the handle verifies but gives a **different** key | **never** replace the pinned key; show "⚠ moved/unverified" and alert. A real key change arrives as a signed rotation (design.md §5.5). |
| **unverified** | the handle answered but proves nothing: no record, a malformed or ambiguous record, a bad signature, a redirecting, forbidden-address or oversize proof | show "⚠ moved/unverified" |
| **unreachable** | no trustworthy answer: network failure, timeout, a resolver failure or disagreement, local misconfiguration | keep the previous status; retry |

**Schedule.** After a **verified** check, the next one is 30 days later ± 4 days. After any other outcome it's 1 day later
± 4 hours, so a warning clears soon after a record is fixed and a transient failure doesn't leave a handle unchecked for a
month. The offset is uniform random, so buddies added together aren't re-checked together. Re-checks go over DoH, so the
domain owner doesn't see the checker's IP address (only the HTTPS proof fallback reveals it).

## 8. Short display

A handle that is exactly one label under the user's **configured** default registry domain is shown as just that label:
`skaterdude99.<registry>` shows as `skaterdude99`. Every other handle, including deeper names under the registry, shows in
full. With no registry configured, nothing is shortened. The buddy info panel always shows the full handle.

## 9. Departures from design.md

| design.md | Here | Why |
|-----------|------|-----|
| Signed message `label ‖ handle ‖ k ‖ t ‖ i` | Length-prefixed, raw key, `t` as u64 (§3) | Plain concatenation of variable-length text is ambiguous. |
| "Standard length limits" | Handle ≤ 244 bytes; numeric last label rejected (§1) | So `_openaim.<handle>` fits in a DNS name, and IP addresses can't pose as handles. |
| DNSSEC-validated answers accepted | Not in v1 (§4.4) | A resolver's AD bit is only as trustworthy as that resolver. |
| Re-check outcomes "verified" or "moved" | Four outcomes (§7) | "Record gone" and "can't reach it" need different handling. |

## 10. Test vector

Identity seed: 32 bytes of `0x01`. Handle `alice.example.com`, issued `1767225600` (2026-01-01T00:00:00Z), inbox hint
`/dns/inbox.example.com/tcp/4001`.

```
key    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
claim  11 616c6963652e6578616d706c652e636f6d
       8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
       000000006955b900
       001f 2f646e732f696e626f782e6578616d706c652e636f6d2f7463702f34303031
record v=oa1; k=rkeohxlubhyzl7ks3mwtzos5olfgocn7dwkbeg7toseadnapn5oa; t=1767225600; i=/dns/inbox.example.com/tcp/4001; s=66a2WoIwaGR1g2dqJDRWWm+U/BjxE34HwEEejJpCrv2FqZ6MJGg7wQVBi5dKR7Zv/FbpzlSu3PflYWVP47pdCg==
```

The signature verifies with OpenSSL as a plain Ed25519 signature over `"openaim/v1/handle-claim" ‖ claim`.
`internal/handle` checks this vector in `TestGoldenRecord`.
