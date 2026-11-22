#!/usr/bin/env python3
"""Independent check of spec/vectors/v1.json's key schedule.

Uses only the Python standard library and a textbook RFC 7748 X25519, so it
shares no code with the Go implementation. It recomputes everything except
Ed25519 key generation and the ChaCha20-Poly1305 frames.

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

    bad = [n for n, ok in checks if not ok]
    print(f"{len(checks) - len(bad)}/{len(checks)} checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "spec/vectors/v1.json"))
