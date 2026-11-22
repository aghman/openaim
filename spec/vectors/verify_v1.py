#!/usr/bin/env python3
"""Independent check of spec/vectors/v1.json's key schedule.

Uses only the Python standard library, a textbook RFC 7748 X25519 and a
textbook RFC 8032 Ed25519, so it shares no code with the Go implementation.
It recomputes everything, including the FIRST_CONTACT key schedule and
headers (spec §11) and the rotation statement (spec §4.6), except the
ChaCha20-Poly1305 ciphertexts.

    python3 -I spec/vectors/verify_v1.py spec/vectors/v1.json
"""
import hashlib
import hmac
import json
import os
import sys

P = 2**255 - 19


def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 §5 Montgomery ladder."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


# RFC 8032 Ed25519, in extended coordinates (X, Y, Z, T). Not constant time:
# it only checks public vectors.
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, hh = b - a, d - c, d + c, b + a
    return (e * f % P, g * hh % P, f * g % P, e * hh % P)


def ed_mul(k: int, p):
    q = (0, 1, 1, 0)
    while k:
        if k & 1:
            q = ed_add(q, p)
        p, k = ed_add(p, p), k >> 1
    return q


def ed_encode(p) -> bytes:
    zi = pow(p[2], P - 2, P)
    x, y = p[0] * zi % P, p[1] * zi % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def ed_decode(b: bytes):
    """Strict decoding: y < p, and x = 0 only with the sign bit clear."""
    n = int.from_bytes(b, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P or (x == 0 and sign):
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


BY = 4 * pow(5, P - 2, P) % P
BASE = ed_decode(BY.to_bytes(32, "little"))


def sha512_int(*parts: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def ed_secret(seed: bytes):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    return a, h[32:]


def ed_public(seed: bytes) -> bytes:
    return ed_encode(ed_mul(ed_secret(seed)[0], BASE))


def ed_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = ed_secret(seed)
    pub = ed_encode(ed_mul(a, BASE))
    r = sha512_int(prefix, msg) % L
    big_r = ed_encode(ed_mul(r, BASE))
    k = sha512_int(big_r, pub, msg) % L
    return big_r + ((r + k * a) % L).to_bytes(32, "little")


def ed_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Cofactorless, rejecting S ≥ ℓ and comparing R byte for byte, as
    crypto/ed25519 does."""
    a = ed_decode(pub)
    if a is None or len(sig) != 64:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    k = sha512_int(sig[:32], pub, msg) % L
    # R' = S·B − k·A must encode to exactly R.
    neg_a = ((P - a[0]) % P, a[1], a[2], (P - a[3]) % P)
    return ed_encode(ed_add(ed_mul(s, BASE), ed_mul(k, neg_a))) == sig[:32]


def ed_to_x(ed: bytes) -> bytes:
    """Birational map: u = (1 + y) / (1 - y)."""
    y = int.from_bytes(ed, "little") & ((1 << 255) - 1)
    return ((1 + y) * pow(1 - y, P - 2, P) % P).to_bytes(32, "little")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, n: int = 32) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + t, i + 1
    return out[:n]


def main(path: str) -> int:
    v = json.load(open(path))
    h = bytes.fromhex
    a_seed, a_ed, b_ed = h(v["alice_seed"]), h(v["alice_ed25519"]), h(v["bob_ed25519"])
    checks = []

    def check(name, got, want):
        checks.append((name, got == want))
        if got != want:
            print(f"MISMATCH {name}: got {got.hex() if isinstance(got, bytes) else got}")

    check("alice_ed25519 (keygen)", ed_public(a_seed), a_ed)
    check("bob_ed25519 (keygen)", ed_public(h(v["bob_seed"])), b_ed)
    claim = b"openaim/v1/handle-claim" + b"example"
    check("alice_sig_handle_claim (sign)", ed_sign(a_seed, claim), h(v["alice_sig_handle_claim"]))
    check("alice_sig_handle_claim (verify)", ed_verify(a_ed, claim, h(v["alice_sig_handle_claim"])), True)

    a_scalar = hashlib.sha512(a_seed).digest()[:32]
    check("alice_x25519 (map)", ed_to_x(a_ed), h(v["alice_x25519"]))
    check("alice_x25519 (scalar)", x25519(a_scalar, (9).to_bytes(32, "little")), h(v["alice_x25519"]))
    check("bob_x25519 (map)", ed_to_x(b_ed), h(v["bob_x25519"]))

    shared = x25519(a_scalar, ed_to_x(b_ed))
    lo, hi = sorted([a_ed, b_ed])
    k_pair = hkdf_expand(hkdf_extract(b"openaim/v1", shared), b"openaim/v1/pair" + lo + hi)
    k_ab = hkdf_expand(k_pair, b"openaim/v1/dir" + a_ed)
    check("k_dir_alice_to_bob", k_ab, h(v["k_dir_alice_to_bob"]))
    check("k_dir_bob_to_alice", hkdf_expand(k_pair, b"openaim/v1/dir" + b_ed), h(v["k_dir_bob_to_alice"]))
    k_siv = hkdf_expand(k_ab, b"openaim/v1/siv")
    check("k_siv_alice_to_bob", k_siv, h(v["k_siv_alice_to_bob"]))
    tag = hmac.new(k_ab, b"openaim/v1/tag" + v["day"].to_bytes(4, "big"), hashlib.sha256).digest()[:8]
    check("conv_tag", tag, h(v["conv_tag_alice_to_bob"]))

    # Recovery phrase (spec §4.5): seed ‖ SHA-256(seed)[0], 24 × 11 bits.
    here = os.path.dirname(os.path.abspath(__file__))
    wordlist = open(os.path.join(here, "..", "..", "internal", "identity", "wordlist", "english.txt")).read().split()
    bits = int.from_bytes(a_seed + hashlib.sha256(a_seed).digest()[:1], "big")
    phrase = " ".join(wordlist[(bits >> (11 * (23 - i))) & 0x7FF] for i in range(24))
    check("alice_recovery_phrase", phrase, v["alice_recovery_phrase"])

    sn = int.from_bytes(hashlib.sha256(b"openaim/v1/safety-number" + lo + hi).digest(), "big") % 10**40
    digits = f"{sn:040d}"
    check("safety_number", " ".join(digits[i:i + 5] for i in range(0, 40, 5)), v["safety_number"])

    for m in v["messages"]:
        inner = h(m["inner"])
        msg_id = hmac.new(k_siv, inner, hashlib.sha256).digest()[:8]
        check(m["name"] + " msg_id", msg_id, h(m["msg_id"]))
        layout = {"mesh": 1, "ip": 2}[m["layout"]]
        k_msg = hkdf_expand(k_ab, b"openaim/v1/msg" + tag + msg_id + bytes([len(m["frames"]), layout]))
        check(m["name"] + " k_msg", k_msg, h(m["k_msg"]))
        for i, f in enumerate(h(x) for x in m["frames"]):
            hdr = bytes([1 << 5 | {1: 1, 2: 2}[layout]]) + tag + msg_id + bytes([i << 4 | (len(m["frames"]) - 1)])
            check(f"{m['name']} frame {i} header", f[:18], hdr)

    # FIRST_CONTACT (spec §11): Alice to Bob, recomputed from both sides.
    b_scalar = hashlib.sha512(h(v["bob_seed"])).digest()[:32]
    a_x, b_x = h(v["alice_x25519"]), h(v["bob_x25519"])
    fc = b"openaim/v1/first-contact"
    layouts = {"mesh": (1, 3, 200, 2), "ip": (2, 7, 4096, 1)}  # layout byte, kind, frame size, max fragments
    for c in v["first_contacts"]:
        n = c["name"]
        layout, kind, frame_len, max_frags = layouts[c["layout"]]
        e = x25519(h(c["ephemeral_seed"]), (9).to_bytes(32, "little"))
        check(n + " e", e, h(c["e"]))
        check(n + " e canonical", e[31] < 0x80 and int.from_bytes(e, "little") < P, True)
        es = x25519(h(c["ephemeral_seed"]), b_x)
        check(n + " es (sender)", es, h(c["es"]))
        check(n + " es (recipient)", x25519(b_scalar, e), h(c["es"]))
        ss = x25519(a_scalar, b_x)
        check(n + " ss (sender)", ss, h(c["ss"]))
        check(n + " ss (recipient)", x25519(b_scalar, a_x), h(c["ss"]))
        h_r = hashlib.sha256(fc + b_ed).digest()
        check(n + " h_r", h_r, h(c["h_r"]))
        ck1 = hkdf_expand(hkdf_extract(h_r, es), fc + b"/es" + e)
        check(n + " ck1", ck1, h(c["ck1"]))
        ck2 = hkdf_expand(hkdf_extract(ck1, ss), fc + b"/ss" + a_ed)
        check(n + " ck2", ck2, h(c["ck2"]))
        k_siv = hkdf_expand(ck2, fc + b"/siv")
        check(n + " k_siv", k_siv, h(c["k_siv"]))
        inner = h(c["inner"])
        check(n + " inner header", (inner[0], int.from_bytes(inner[2:6], "big")), (15, c["timestamp"]))
        msg_id = hmac.new(k_siv, inner, hashlib.sha256).digest()[:8]
        check(n + " msg_id", msg_id, h(c["msg_id"]))

        cap0, cap1 = frame_len - 106, frame_len - 58
        count = 1 if len(inner) <= cap0 else 1 + -(-(len(inner) - cap0) // cap1)
        frames = [h(x) for x in c["frames"]]
        check(n + " fragment count", (len(frames), len(frames) <= max_frags), (count, True))
        info = lambda label: fc + label + msg_id + bytes([count, layout])
        check(n + " k_s", hkdf_expand(ck1, info(b"/s")), h(c["k_s"]))
        check(n + " k_payload", hkdf_expand(ck2, info(b"/payload")), h(c["k_payload"]))
        if count > 1:
            check(n + " k_tail", hkdf_expand(ck1, info(b"/tail")), h(c["k_tail"]))
        check(n + " dedup_tag", hashlib.sha256(fc + b"/dedup" + e).digest()[:8], h(c["dedup_tag"]))
        for i, f in enumerate(frames):
            hdr = bytes([1 << 5 | kind]) + e + msg_id + bytes([i << 4 | (count - 1)])
            check(f"{n} frame {i} header", f[:42], hdr)
            start = 0 if i == 0 else cap0 + (i - 1) * cap1
            chunk = len(inner[start:start + (cap0 if i == 0 else cap1)])
            check(f"{n} frame {i} length", len(f), 42 + (48 if i == 0 else 0) + chunk + 16)
            leaks = [k for k in (a_ed, b_ed, a_x, b_x) if any(k[j:j + 8] in f for j in range(25))]
            check(f"{n} frame {i} hides keys", leaks, [])

    # Rotation statement (spec §4.6), signed by Alice's recovery key.
    r = v["rotation"]
    rec_seed, rec_ed = h(r["recovery_seed"]), h(r["recovery_ed25519"])
    old, new, t = h(r["old_ed25519"]), h(r["new_ed25519"]), r["issued_at"]
    sig = h(r["signature"])
    check("rotation recovery key (keygen)", ed_public(rec_seed), rec_ed)
    check("rotation new key (keygen)", ed_public(h(r["new_seed"])), new)
    check("rotation old key is alice's", old, a_ed)
    msg = b"openaim/v1/rotate" + old + new + t.to_bytes(4, "big")
    check("rotation signed_message", msg, h(r["signed_message"]))
    check("rotation signed_message length", len(msg), 85)
    y = lambda k: k[:31] + bytes([k[31] & 0x7F])  # same y means same X25519 form
    check("rotation keys distinct (rules 2, 4)", len({y(old), y(new), y(rec_ed)}), 3)
    check("rotation issued_at set", t > 0, True)
    check("rotation signature (sign)", ed_sign(rec_seed, msg), sig)
    check("rotation signature (verify)", ed_verify(rec_ed, msg, sig), True)
    check("rotation rejects the old key as signer", ed_verify(old, msg, sig), False)
    check("rotation rejects a tampered issued_at", ed_verify(rec_ed, msg[:-1] + bytes([msg[-1] ^ 1]), sig), False)
    s_plus_l = sig[:32] + (int.from_bytes(sig[32:], "little") + L).to_bytes(32, "little")
    check("rotation rejects S + l", ed_verify(rec_ed, msg, s_plus_l), False)

    def uvarint(n):
        out = b""
        while n >= 0x80:
            out, n = out + bytes([n & 0x7F | 0x80]), n >> 7
        return out + bytes([n])

    body = b"\x0a\x20" + old + b"\x12\x20" + new + b"\x18" + uvarint(t) + b"\x22\x40" + sig
    check("rotation rotate_body", body, h(r["rotate_body"]))

    bad = [n for n, ok in checks if not ok]
    print(f"{len(checks) - len(bad)}/{len(checks)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "spec/vectors/v1.json"))
