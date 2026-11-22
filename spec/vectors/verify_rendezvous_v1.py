#!/usr/bin/env python3
"""Independent check of spec/vectors/rendezvous_v1.json (spec/dht-records.md).

Uses only the Python standard library, with textbook RFC 8032 Ed25519,
RFC 8439 ChaCha20-Poly1305 and draft-irtf-cfrg-xchacha HChaCha20, so it
shares no code with the Go implementation. From k_dir, day, seq, the
locator's fields and the nonce it recomputes every byte of each record: the
signing seed and public key, the DHT key, the locator key L, the protobuf
locator, the padded plaintext, the associated data, the ciphertext and the
signed DHT value. It then opens the payload again.

    python3 -I spec/vectors/verify_rendezvous_v1.py spec/vectors/rendezvous_v1.json
"""
import hashlib
import hmac
import json
import sys

# --- Ed25519 (RFC 8032 §5.1) -------------------------------------------------

P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493  # group order
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def recover_x(y: int, sign: int) -> int:
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if x & 1 != sign:
        x = P - x
    return x


GY = 4 * pow(5, P - 2, P) % P
GX = recover_x(GY, 0)
G = (GX, GY, 1, GX * GY % P)  # extended coordinates


def point_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(s: int, p):
    r = (0, 1, 1, 0)
    while s:
        if s & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        s >>= 1
    return r


def point_compress(p) -> bytes:
    zi = pow(p[2], P - 2, P)
    x, y = p[0] * zi % P, p[1] * zi % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def ed_expand(seed: bytes):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed_public(seed: bytes) -> bytes:
    return point_compress(point_mul(ed_expand(seed)[0], G))


def ed_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = ed_expand(seed)
    pub = point_compress(point_mul(a, G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % Q
    rs = point_compress(point_mul(r, G))
    k = int.from_bytes(hashlib.sha512(rs + pub + msg).digest(), "little") % Q
    return rs + ((r + k * a) % Q).to_bytes(32, "little")


# --- XChaCha20-Poly1305 --------------------------------------------------------

M32 = 0xFFFFFFFF


def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & M32; s[d] ^= s[a]; s[d] = (s[d] << 16 | s[d] >> 16) & M32
    s[c] = (s[c] + s[d]) & M32; s[b] ^= s[c]; s[b] = (s[b] << 12 | s[b] >> 20) & M32
    s[a] = (s[a] + s[b]) & M32; s[d] ^= s[a]; s[d] = (s[d] << 8 | s[d] >> 24) & M32
    s[c] = (s[c] + s[d]) & M32; s[b] ^= s[c]; s[b] = (s[b] << 7 | s[b] >> 25) & M32


def chacha_rounds(state):
    s = list(state)
    for _ in range(10):
        quarter(s, 0, 4, 8, 12); quarter(s, 1, 5, 9, 13); quarter(s, 2, 6, 10, 14); quarter(s, 3, 7, 11, 15)
        quarter(s, 0, 5, 10, 15); quarter(s, 1, 6, 11, 12); quarter(s, 2, 7, 8, 13); quarter(s, 3, 4, 9, 14)
    return s


def words(b: bytes):
    return [int.from_bytes(b[i:i + 4], "little") for i in range(0, len(b), 4)]


CONSTANTS = words(b"expand 32-byte k")


def chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = CONSTANTS + words(key) + [counter] + words(nonce)
    out = chacha_rounds(state)
    return b"".join(((x + y) & M32).to_bytes(4, "little") for x, y in zip(out, state))


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    s = chacha_rounds(CONSTANTS + words(key) + words(nonce16))
    return b"".join(x.to_bytes(4, "little") for x in s[0:4] + s[12:16])


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], ks))
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc, p = 0, 2**130 - 5
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b"\x01", "little")) * r % p
    return ((acc + s) % 2**128).to_bytes(16, "little")


def pad16(b: bytes) -> bytes:
    return b"\x00" * (-len(b) % 16)


def aead_tag(key: bytes, nonce: bytes, ad: bytes, ct: bytes) -> bytes:
    otk = chacha_block(key, 0, nonce)[:32]
    mac = ad + pad16(ad) + ct + pad16(ct) + len(ad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    return poly1305(otk, mac)


def xchacha_seal(key: bytes, nonce24: bytes, pt: bytes, ad: bytes) -> bytes:
    sub, n12 = hchacha20(key, nonce24[:16]), b"\x00" * 4 + nonce24[16:]
    ct = chacha20_xor(sub, 1, n12, pt)
    return ct + aead_tag(sub, n12, ad, ct)


def xchacha_open(key: bytes, nonce24: bytes, sealed: bytes, ad: bytes):
    sub, n12 = hchacha20(key, nonce24[:16]), b"\x00" * 4 + nonce24[16:]
    ct, tag = sealed[:-16], sealed[-16:]
    if not hmac.compare_digest(aead_tag(sub, n12, ad, ct), tag):
        return None
    return chacha20_xor(sub, 1, n12, ct)


# --- Protobuf, base58, HKDF ----------------------------------------------------


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def pb_bytes(num: int, b: bytes) -> bytes:
    return varint(num << 3 | 2) + varint(len(b)) + b


def pb_uint(num: int, v: int) -> bytes:
    return varint(num << 3) + varint(v) if v else b""  # proto3: zero is omitted


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def hkdf_expand(prk: bytes, info: bytes) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()  # one block: 32 bytes


# --- The checks ----------------------------------------------------------------

MAX_PLAINTEXT = 1024 - (1 + 8 + 32) - 64 - 24 - 16  # 879
PAD_BLOCK = 256


def main(path: str) -> int:
    v = json.load(open(path))
    h = bytes.fromhex
    k_dir = h(v["k_dir"])
    checks = []

    def check(name, got, want):
        checks.append((name, got == want))
        if got != want:
            print(f"MISMATCH {name}: got {got.hex() if isinstance(got, bytes) else got}")

    for r in v["records"]:
        n = r["name"]
        day = r["day"].to_bytes(4, "big")
        seed = hmac.new(k_dir, b"openaim/v1/rdv" + day, hashlib.sha256).digest()
        check(n + " seed", seed, h(r["seed"]))
        pk = ed_public(seed)
        check(n + " ed25519_public", pk, h(r["ed25519_public"]))
        kh = hashlib.sha256(b"openaim/v1/dht-rdv-key" + pk).digest()
        check(n + " key_hash", kh, h(r["key_hash"]))
        check(n + " dht_key", "/oa-rdv/" + kh.hex(), r["dht_key"])
        l_key = hkdf_expand(k_dir, b"openaim/v1/loc" + day)
        check(n + " l", l_key, h(r["l"]))

        peer_id = b58decode(r["peer_id"])
        check(n + " peer_id_bytes", peer_id, h(r["peer_id_bytes"]))
        addrs = [h(a) for a in r["addrs_bytes"]]
        check(n + " ttl ≤ 36 h", 0 < r["expires_at"] - r["issued_at"] <= 36 * 3600, True)
        ip_hint = pb_bytes(1, peer_id) + b"".join(pb_bytes(2, a) for a in addrs)
        locator = pb_bytes(1, ip_hint) + pb_uint(2, r["issued_at"]) + pb_uint(3, r["expires_at"])
        check(n + " locator", locator, h(r["locator"]))
        size = min(-(-(2 + len(locator)) // PAD_BLOCK) * PAD_BLOCK, MAX_PLAINTEXT)
        plaintext = len(locator).to_bytes(2, "big") + locator
        plaintext += b"\x00" * (size - len(plaintext))
        check(n + " plaintext", plaintext, h(r["plaintext"]))

        seq = r["seq"].to_bytes(8, "big")
        header = b"\x01" + seq + pk
        ad = kh + header
        check(n + " ad", ad, h(r["ad"]))
        nonce = h(r["nonce"])
        payload = nonce + xchacha_seal(l_key, nonce, plaintext, ad)
        check(n + " payload", payload, h(r["payload"]))
        check(n + " payload opens", xchacha_open(l_key, nonce, h(r["payload"])[24:], ad), plaintext)
        bad_ad = kh + b"\x01" + (r["seq"] + 1).to_bytes(8, "big") + pk
        check(n + " payload under another seq fails", xchacha_open(l_key, nonce, payload[24:], bad_ad), None)

        unsigned = header + payload
        sig = ed_sign(seed, b"openaim/v1/dht-rdv-sig" + kh + unsigned)
        check(n + " value", unsigned + sig, h(r["value"]))
        check(n + " value size", len(unsigned + sig) <= 1024, True)

    bad = [name for name, ok in checks if not ok]
    print(f"{len(checks) - len(bad)}/{len(checks)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "spec/vectors/rendezvous_v1.json"))
