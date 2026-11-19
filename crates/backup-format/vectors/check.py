#!/usr/bin/env python3
"""An independent check of the backup vectors (PROTOCOL §11), written from the specification
with the Python standard library only: Crockford base32, HKDF-SHA256, HMAC-SHA256, Padmé and
XChaCha20-Poly1305 (RFC 8439 and draft-irtf-cfrg-xchacha), none of it shared with the Rust code.

    python3 crates/backup-format/vectors/check.py crates/backup-format/vectors/v1/vectors.json
"""
import hashlib
import hmac
import json
import struct
import sys

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def hkdf(ikm, salt, info, n):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 7)


def rounds(s):
    for _ in range(10):
        quarter(s, 0, 4, 8, 12); quarter(s, 1, 5, 9, 13); quarter(s, 2, 6, 10, 14); quarter(s, 3, 7, 11, 15)
        quarter(s, 0, 5, 10, 15); quarter(s, 1, 6, 11, 12); quarter(s, 2, 7, 8, 13); quarter(s, 3, 4, 9, 14)


CONST = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def hchacha(key, nonce16):
    s = CONST + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    rounds(s)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def chacha_block(key, counter, nonce12):
    init = CONST + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce12))
    s = list(init)
    rounds(s)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(s, init)])


def chacha_xor(key, counter, nonce12, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce12)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc, p = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def xchacha_open(key, nonce24, aad, ct, tag):
    sub = hchacha(key, nonce24[:16])
    n12 = b"\0\0\0\0" + nonce24[16:]
    otk = chacha_block(sub, 0, n12)[:32]
    pad = lambda b: b + b"\0" * (-len(b) % 16)
    mac = poly1305(otk, pad(aad) + pad(ct) + struct.pack("<QQ", len(aad), len(ct)))
    assert hmac.compare_digest(mac, tag), "tag"
    return chacha_xor(sub, 1, n12, ct)


def padme(n):
    if n < 2:
        return n
    e = n.bit_length() - 1
    s = e.bit_length()
    mask = (1 << (e - s)) - 1
    return (n + mask) & ~mask


def unpad(p):
    n = struct.unpack(">I", p[:4])[0]
    assert len(p) == padme(max(n + 4, 1024)), "padding length"
    assert p[4 + n:] == b"\0" * (len(p) - 4 - n), "padding bytes"
    return p[4:4 + n]


def main(path):
    v = json.load(open(path))
    secret = bytes.fromhex(v["recovery_key"]["secret"])
    check = hashlib.sha256(b"songbird.v1/recovery-key\0" + secret).digest()[:8]
    bits = int.from_bytes(secret + check, "big")
    chars = "".join(ALPHABET[(bits >> (5 * (63 - i))) & 31] for i in range(64))
    assert "-".join(chars[i:i + 4] for i in range(0, 64, 4)) == v["recovery_key"]["display"]

    k = {}
    for label in ["vault-id", "vault-access", "manifest", "chunk", "chunk-name"]:
        k[label] = hkdf(secret, b"songbird.v1/backup", b"songbird.v1/backup/" + label.encode(), 32)
    keys = v["keys"]
    assert k["vault-id"].hex() == keys["vault_id"]
    assert k["vault-access"].hex() == keys["vault_access"]
    assert hashlib.sha256(b"songbird.v1/vault-access\0" + k["vault-access"]).hexdigest() == keys["access_hash"]
    for label, name in [("manifest", "manifest"), ("chunk", "chunk"), ("chunk-name", "chunk_name")]:
        assert k[label].hex() == keys[name], label
    gear = hkdf(secret, b"songbird.v1/backup", b"songbird.v1/backup/chunker", 2048)
    assert [gear[i * 8:i * 8 + 8].hex() for i in range(4)] == keys["gear_first_4"]

    def open_chunk(name, obj):
        assert obj[:4] == b"SBC\x01"
        head, ct, tag = obj[:28], obj[28:-16], obj[-16:]
        plain = unpad(xchacha_open(k["chunk"], obj[4:28], head + name, ct, tag))
        assert hmac.new(k["chunk-name"], plain, hashlib.sha256).digest() == name, "name"
        return plain

    c = v["chunk"]
    plain = open_chunk(bytes.fromhex(c["name"]), bytes.fromhex(c["object"]))
    assert plain.hex() == c["plaintext"]

    m = bytes.fromhex(v["backup"]["manifest"])
    assert m[:4] == b"SBM\x01"
    generation = struct.unpack(">Q", m[4:12])[0]
    manifest = unpad(xchacha_open(k["manifest"], m[12:36], m[:36] + k["vault-id"], m[36:-16], m[-16:]))
    total = 0
    for name, obj in v["backup"]["chunks"].items():
        total += len(open_chunk(bytes.fromhex(name), bytes.fromhex(obj)))
    print(f"ok: key, {len(k) + 1} derived keys, chunk, manifest generation {generation} "
          f"({len(manifest)} bytes), {len(v['backup']['chunks'])} chunks ({total} bytes)")


if __name__ == "__main__":
    main(sys.argv[1])
