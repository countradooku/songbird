#!/usr/bin/env python3
"""An independent check of the token vectors (PROTOCOL §14.4), written from the specifications
with the Python standard library only: ristretto255 (RFC 9496: decode, encode, the one-way map),
expand_message_xmd (RFC 9380), and the POPRF of RFC 9497 (key derivation, blinding, evaluation,
the DLEQ proof). None of it is shared with the Rust code.

It first reproduces RFC 9497's own POPRF vector (A.1.3.1), then Songbird's.

    python3 crates/tokens/vectors/check.py crates/tokens/vectors/v1.json
"""
import hashlib
import json
import sys

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def inv(x):
    return pow(x, P - 2, P)


D = (-121665 * inv(121666)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def is_negative(x):
    return x % P & 1


def ct_abs(x):
    return (-x) % P if is_negative(x) else x % P


def sqrt_ratio_m1(u, v):
    """RFC 9496 §4.2."""
    u, v = u % P, v % P
    v3 = v * v % P * v % P
    v7 = v3 * v3 % P * v % P
    r = u * v3 % P * pow(u * v7 % P, (P - 5) // 8, P) % P
    check = v * r % P * r % P
    correct = check == u
    flipped = check == (-u) % P
    flipped_i = check == (-u * SQRT_M1) % P
    if flipped or flipped_i:
        r = r * SQRT_M1 % P
    return (correct or flipped), ct_abs(r)


# RFC 9496 §4.1 fixes which root: the value below, checked against its definition (a = -1).
SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
assert SQRT_AD_MINUS_ONE * SQRT_AD_MINUS_ONE % P == (-D - 1) % P
INVSQRT_A_MINUS_D = sqrt_ratio_m1(1, -1 - D)[1]
ONE_MINUS_D_SQ = (1 - D * D) % P
D_MINUS_ONE_SQ = (D - 1) * (D - 1) % P

IDENTITY = (0, 1, 1, 0)


def add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(k, pt):
    out, acc = IDENTITY, pt
    k %= L
    while k:
        if k & 1:
            out = add(out, acc)
        acc = add(acc, acc)
        k >>= 1
    return out


def neg(pt):
    x, y, z, t = pt
    return ((-x) % P, y, z, (-t) % P)


def decode(b):
    """RFC 9496 §4.3.1."""
    s = int.from_bytes(b, "little")
    if len(b) != 32 or s >= P or is_negative(s):
        raise ValueError("non-canonical")
    ss = s * s % P
    u1, u2 = (1 - ss) % P, (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-(D * u1 % P * u1) - u2_sqr) % P
    was_square, invsqrt = sqrt_ratio_m1(1, v * u2_sqr)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x % P * v % P
    x = ct_abs(2 * s * den_x)
    y = u1 * den_y % P
    t = x * y % P
    if not was_square or is_negative(t) or y == 0:
        raise ValueError("invalid")
    return (x, y, 1, t)


def encode(pt):
    """RFC 9496 §4.3.2."""
    x0, y0, z0, t0 = pt
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = sqrt_ratio_m1(1, u1 * u2 % P * u2)
    den1 = invsqrt * u1 % P
    den2 = invsqrt * u2 % P
    z_inv = den1 * den2 % P * t0 % P
    ix0, iy0 = x0 * SQRT_M1 % P, y0 * SQRT_M1 % P
    enchanted = den1 * INVSQRT_A_MINUS_D % P
    rotate = is_negative(t0 * z_inv)
    x, y = (iy0, ix0) if rotate else (x0, y0)
    den_inv = enchanted if rotate else den2
    if is_negative(x * z_inv):
        y = (-y) % P
    s = ct_abs(den_inv * (z0 - y))
    return s.to_bytes(32, "little")


def elligator(t):
    """RFC 9496 §4.3.4, MAP."""
    r = SQRT_M1 * t % P * t % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D) * (r + D) % P
    was_square, s = sqrt_ratio_m1(u, v)
    s_prime = (-ct_abs(s * t)) % P
    s = s if was_square else s_prime
    c = (P - 1) if was_square else r
    n = (c * (r - 1) % P * D_MINUS_ONE_SQ - v) % P
    w0 = 2 * s * v % P
    w1 = n * SQRT_AD_MINUS_ONE % P
    w2 = (1 - s * s) % P
    w3 = (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


def from_uniform(b):
    mask = (1 << 255) - 1
    t1 = (int.from_bytes(b[:32], "little") & mask) % P
    t2 = (int.from_bytes(b[32:], "little") & mask) % P
    return add(elligator(t1), elligator(t2))


BASE = decode(bytes.fromhex("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"))


def i2osp(n, k):
    return n.to_bytes(k, "big")


def xmd(msg, dst, n=64):
    """RFC 9380 §5.3.1 with SHA-512 (b = 64, s = 128)."""
    assert n == 64 and len(dst) <= 255
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha512(b"\0" * 128 + msg + i2osp(n, 2) + b"\0" + dst_prime).digest()
    return hashlib.sha512(b0 + b"\x01" + dst_prime).digest()


CTX = b"OPRFV1-\x02-ristretto255-SHA512"


def h2g(msg):
    return from_uniform(xmd(msg, b"HashToGroup-" + CTX))


def h2s(msg, dst=b"HashToScalar-" + CTX):
    return int.from_bytes(xmd(msg, dst), "little") % L


def derive_key_pair(seed, info):
    for counter in range(256):
        sk = h2s(seed + i2osp(len(info), 2) + info + bytes([counter]), b"DeriveKeyPair" + CTX)
        if sk:
            return sk, mul(sk, BASE)
    raise ValueError("derive")


def info_scalar(info):
    return h2s(b"Info" + i2osp(len(info), 2) + info)


def generate_proof(k, a, b, cs, ds, r):
    """RFC 9497 §2.2.1 (ComputeCompositesFast)."""
    bm = encode(b)
    seed_dst = b"Seed-" + CTX
    seed = hashlib.sha512(i2osp(32, 2) + bm + i2osp(len(seed_dst), 2) + seed_dst).digest()
    m = IDENTITY
    for i, (c, d) in enumerate(zip(cs, ds)):
        di = h2s(i2osp(64, 2) + seed + i2osp(i, 2) + i2osp(32, 2) + encode(c)
                 + i2osp(32, 2) + encode(d) + b"Composite")
        m = add(m, mul(di, c))
    z = mul(k, m)
    t2, t3 = mul(r, a), mul(r, m)
    tr = b"".join(i2osp(32, 2) + encode(x) for x in (b, m, z, t2, t3)) + b"Challenge"
    c = h2s(tr)
    s = (r - c * k) % L
    return c.to_bytes(32, "little") + s.to_bytes(32, "little")


def finalize_hash(inp, info, n):
    return hashlib.sha512(i2osp(len(inp), 2) + inp + i2osp(len(info), 2) + info
                          + i2osp(32, 2) + encode(n) + b"Finalize").digest()


def poprf(sk, nonce, info, blind, r):
    """Blind, BlindEvaluate (with proof), Finalize: every intermediate value."""
    t = (sk + info_scalar(info)) % L
    pin = h2g(nonce)
    blinded = mul(blind, pin)
    evaluated = mul(pow(t, L - 2, L), blinded)
    proof = generate_proof(t, BASE, mul(t, BASE), [evaluated], [blinded], r)
    unblinded = mul(pow(blind, L - 2, L), evaluated)
    out = finalize_hash(nonce, info, unblinded)
    # Evaluate (the server alone) gives the same output.
    assert out == finalize_hash(nonce, info, mul(pow(t, L - 2, L), pin))
    return encode(blinded), encode(evaluated), proof, out


def check_rfc():
    sk, pk = derive_key_pair(bytes([0xA3] * 32), b"test key")
    assert sk.to_bytes(32, "little").hex() == "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07"
    assert encode(pk).hex() == "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"
    blind = int.from_bytes(bytes.fromhex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"), "little")
    r = int.from_bytes(bytes.fromhex("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"), "little")
    b, e, proof, out = poprf(sk, b"\x00", b"test info", blind, r)
    assert b.hex() == "c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"
    assert e.hex() == "1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874"
    assert proof.hex() == ("41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100d"
                           "e32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206")
    assert out.hex() == ("ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d"
                         "38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221")


def check_songbird(v):
    key_info = b"songbird.v1/token-key\0" + bytes([v["key_id"]])
    sk, pk = derive_key_pair(bytes.fromhex(v["secret"]), key_info)
    assert encode(pk).hex() == v["public_key"], "public key"
    info = bytes.fromhex(v["info"])
    assert info[:18] == b"songbird.v1/token\0" and len(info) == 24, "info layout"
    nonce = bytes.fromhex(v["nonce"])
    blind = int.from_bytes(bytes.fromhex(v["blind"]), "little")
    r = int.from_bytes(bytes.fromhex(v["proof_random"]), "little")
    b, e, proof, out = poprf(sk, nonce, info, blind, r)
    assert b.hex() == v["blinded"], "blinded"
    assert e.hex() == v["evaluated"], "evaluated"
    assert proof.hex() == v["proof"], "proof"
    assert out.hex() == v["output"], "output"
    nullifier = hashlib.sha256(b"songbird.v1/token-nullifier\0" + bytes([v["key_id"]]) + info + nonce).digest()
    assert nullifier.hex() == v["nullifier"], "nullifier"


def main():
    assert encode(BASE).hex() == "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
    check_rfc()
    with open(sys.argv[1]) as f:
        check_songbird(json.load(f))
    print("token vectors: RFC 9497 A.1.3.1 and Songbird's v1 reproduced")


if __name__ == "__main__":
    main()
