#!/usr/bin/env python3
"""An independent check of the transfer handshake vector (PROTOCOL §11.9): Noise
NNpsk0_25519_ChaChaPoly_SHA256 (Noise revision 34) written from the specification with the
Python standard library only: X25519 (RFC 7748), ChaCha20-Poly1305 (RFC 8439), HMAC-SHA256.

    python3 crates/backup-storage/vectors/transfer_check.py crates/backup-storage/vectors/transfer.json
"""
import hashlib
import hmac
import json
import struct
import sys

P = 2**255 - 19
A24 = 121665


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
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
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def chacha_block(key, counter, nonce):
    c = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s = c + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    x = list(s)

    def q(a, b, cc, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rotl(x[d] ^ x[a], 16)
        x[cc] = (x[cc] + x[d]) & 0xFFFFFFFF; x[b] = rotl(x[b] ^ x[cc], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = rotl(x[d] ^ x[a], 8)
        x[cc] = (x[cc] + x[d]) & 0xFFFFFFFF; x[b] = rotl(x[b] ^ x[cc], 7)

    for _ in range(10):
        q(0, 4, 8, 12); q(1, 5, 9, 13); q(2, 6, 10, 14); q(3, 7, 11, 15)
        q(0, 5, 10, 15); q(1, 6, 11, 12); q(2, 7, 8, 13); q(3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(x, s)])


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc, p = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b"\x01", "little")) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def aead_encrypt(key, n, ad, plain):
    nonce = b"\0\0\0\0" + struct.pack("<Q", n)
    otk = chacha_block(key, 0, nonce)[:32]
    ct = bytes(a ^ b for a, b in zip(plain, b"".join(chacha_block(key, 1 + i, nonce) for i in range(len(plain) // 64 + 1))))
    pad = lambda b: b + b"\0" * (-len(b) % 16)
    tag = poly1305(otk, pad(ad) + pad(ct) + struct.pack("<QQ", len(ad), len(ct)))
    return ct + tag


def hkdf(ck, ikm, n):
    temp = hmac.new(ck, ikm, hashlib.sha256).digest()
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = hmac.new(temp, prev + bytes([i]), hashlib.sha256).digest()
        out.append(prev)
    return out


class Sym:
    def __init__(self, name, prologue):
        self.h = name if len(name) == 32 else hashlib.sha256(name).digest()
        self.ck, self.k, self.n = self.h, None, 0
        self.mix_hash(prologue)

    def mix_hash(self, d):
        self.h = hashlib.sha256(self.h + d).digest()

    def mix_key(self, ikm):
        self.ck, self.k = hkdf(self.ck, ikm, 2)
        self.n = 0

    def mix_key_and_hash(self, ikm):
        self.ck, th, self.k = hkdf(self.ck, ikm, 3)
        self.mix_hash(th)
        self.n = 0

    def encrypt_and_hash(self, plain):
        ct = aead_encrypt(self.k, self.n, self.h, plain)
        self.n += 1
        self.mix_hash(ct)
        return ct


def main(path):
    v = json.load(open(path))
    name, prologue, psk = v["protocol"].encode(), bytes.fromhex(v["prologue"]), bytes.fromhex(v["psk"])
    ie, re_ = bytes.fromhex(v["initiator_ephemeral"]), bytes.fromhex(v["responder_ephemeral"])
    base = (9).to_bytes(32, "little")
    ie_pub, re_pub = x25519(ie, base), x25519(re_, base)
    # The responder commits to its ephemeral key before it sees the initiator's (D-0125).
    assert hashlib.sha256(b"songbird.v1/transfer-commit\0" + re_pub).hexdigest() == v["commitment"], "commitment"

    s = Sym(name, prologue)
    s.mix_key_and_hash(psk)                # psk
    s.mix_hash(ie_pub); s.mix_key(ie_pub)  # e (psk handshake: MixKey too)
    m1 = ie_pub + s.encrypt_and_hash(b"")
    assert m1.hex() == v["message_1"], "message 1"
    s.mix_hash(re_pub); s.mix_key(re_pub)  # e
    s.mix_key(x25519(re_, ie_pub))         # ee
    m2 = re_pub + s.encrypt_and_hash(b"")
    assert m2.hex() == v["message_2"], "message 2"
    assert s.h.hex() == v["handshake_hash"], "handshake hash"
    code = int.from_bytes(hashlib.sha256(b"songbird.v1/transfer-code\0" + s.h).digest()[:4], "big") % 1_000_000
    assert code == v["code"], "code"
    print(f"ok: the commitment, NNpsk0 messages, handshake hash and the code {code:06d}")


if __name__ == "__main__":
    main(sys.argv[1])
