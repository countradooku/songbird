//! XEdDSA over Curve25519 (Prompt 3, M3; D-0050): the signatures a device identity key makes over
//! its prekeys, as libsignal makes and checks them (implemented from libsignal's specification
//! and code, not linked, D-0047; `tests/xeddsa_vectors.rs` checks both directions against
//! libsignal).
//!
//! A device identity key is an X25519 public key: the Montgomery `u` coordinate. A signature is
//! `R [32] || s [32]`, Ed25519-shaped, with the sign of the signer's Edwards point in the top bit
//! of `s` (libsignal's variant of the XEdDSA paper, for compatibility with its Java library).
//!
//! # Verification, and where it is stricter than libsignal
//!
//! `A` = the Edwards point with Montgomery `u` and the sign bit from the signature; `h =
//! SHA-512(R || A || message)` reduced mod l; accept iff `s·B − h·A` encodes to `R`. libsignal
//! accepts any `s` below 2^253 and reduces it; Songbird requires `s < l` (an honest signer always
//! produces it) so a signature has one encoding only. Public keys must also be honest
//! ([`x25519_public_key_ok`]): canonical `u`, on the curve, of prime order.

use aws_lc_rs::digest;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

/// Public key length (the Montgomery `u`).
pub const PUBLIC_LEN: usize = 32;
/// Signature length.
pub const SIGNATURE_LEN: usize = 64;

/// The field prime p = 2^255 − 19, little-endian.
const P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Whether a little-endian 32-byte number is below p.
fn below_p(u: &[u8; 32]) -> bool {
    for (a, b) in u.iter().zip(P.iter()).rev() {
        if a != b {
            return a < b;
        }
    }
    false
}

fn sha512_scalar(parts: &[&[u8]]) -> Scalar {
    let mut ctx = digest::Context::new(&digest::SHA512);
    for p in parts {
        ctx.update(p);
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(ctx.finish().as_ref());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Whether `u` is an honest X25519 public key: canonical (`u < p`), on the curve (not its
/// twist), and of prime order (no small-order or mixed-order points). X25519 public keys from
/// clamped secrets always pass.
#[must_use]
pub fn x25519_public_key_ok(u: &[u8; PUBLIC_LEN]) -> bool {
    if !below_p(u) {
        return false;
    }
    match MontgomeryPoint(*u).to_edwards(0) {
        Some(e) => !e.is_small_order() && e.is_torsion_free(),
        None => false,
    }
}

/// Verifies an XEdDSA signature by the X25519 key `u` over `message`.
#[must_use]
pub fn verify(public: &[u8; PUBLIC_LEN], message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    if !x25519_public_key_ok(public) {
        return false;
    }
    let sign = signature[63] >> 7;
    let Some(point) = MontgomeryPoint(*public).to_edwards(sign) else {
        return false;
    };
    let mut cap_r = [0u8; 32];
    cap_r.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    s_bytes[31] &= 0x7F;
    let Some(response) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    let challenge = sha512_scalar(&[&cap_r, point.compress().as_bytes(), message]);
    let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&challenge, &(-point), &response);
    // Public values: a plain comparison leaks nothing.
    check.compress().to_bytes() == cap_r
}

/// An XEdDSA signer for an X25519 private key (clients and tests; the server never signs). The
/// key is clamped as X25519 clamps it, so the public key is the X25519 one.
pub struct Signer {
    a: Scalar,
    a_bytes: [u8; 32],
    edwards_public: [u8; 32],
    public: [u8; PUBLIC_LEN],
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signer(..)")
    }
}

impl Signer {
    /// From 32 bytes of private key material.
    #[must_use]
    pub fn new(private: &[u8; 32]) -> Self {
        let mut k = *private;
        k[0] &= 0b1111_1000;
        k[31] &= 0b0111_1111;
        k[31] |= 0b0100_0000;
        let a = Scalar::from_bytes_mod_order(k);
        let point = a * ED25519_BASEPOINT_POINT;
        Self {
            a,
            a_bytes: k,
            edwards_public: point.compress().to_bytes(),
            public: point.to_montgomery().to_bytes(),
        }
    }

    /// The X25519 public key.
    #[must_use]
    pub fn public(&self) -> [u8; PUBLIC_LEN] {
        self.public
    }

    /// Signs with 64 bytes of fresh randomness (libsignal's construction).
    #[must_use]
    pub fn sign(&self, message: &[u8], random: &[u8; 64]) -> [u8; SIGNATURE_LEN] {
        let mut prefix = [0xFFu8; 32];
        prefix[0] = 0xFE;
        let r = sha512_scalar(&[&prefix, &self.a_bytes, message, random]);
        let cap_r = (r * ED25519_BASEPOINT_POINT).compress();
        let h = sha512_scalar(&[cap_r.as_bytes(), &self.edwards_public, message]);
        let s = h * self.a + r;
        let mut out = [0u8; SIGNATURE_LEN];
        out[..32].copy_from_slice(cap_r.as_bytes());
        out[32..].copy_from_slice(s.as_bytes());
        out[63] &= 0x7F;
        out[63] |= self.edwards_public[31] & 0x80;
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use curve25519_dalek::constants::EIGHT_TORSION;

    use super::*;

    #[test]
    fn signatures_verify_and_tampering_does_not() {
        let s = Signer::new(&[3; 32]);
        let sig = s.sign(b"prekey", &[9; 64]);
        assert!(verify(&s.public(), b"prekey", &sig));
        assert!(!verify(&s.public(), b"prekez", &sig));
        assert!(!verify(&Signer::new(&[4; 32]).public(), b"prekey", &sig));
        for i in 0..SIGNATURE_LEN {
            let mut t = sig;
            t[i] ^= 1;
            assert!(!verify(&s.public(), b"prekey", &t), "byte {i}");
        }
    }

    #[test]
    fn a_non_canonical_s_is_refused() {
        // s + l (libsignal would reduce and accept it while it stays below 2^253).
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let signer = Signer::new(&[5; 32]);
        let sig = signer.sign(b"m", &[1; 64]);
        let sign_bit = sig[63] & 0x80;
        let mut t = sig;
        t[63] &= 0x7F;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(t[32 + i]) + u16::from(L[i]) + carry;
            t[32 + i] = u8::try_from(v & 0xFF).unwrap();
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(t[63] & 0x80, 0, "still fits in 255 bits");
        t[63] |= sign_bit;
        assert!(!verify(&signer.public(), b"m", &t));
    }

    #[test]
    fn dishonest_public_keys_are_refused() {
        // Small-order points (as Montgomery u), a non-canonical u, a twist point.
        for t in EIGHT_TORSION {
            assert!(!x25519_public_key_ok(t.to_montgomery().as_bytes()));
        }
        let honest = Signer::new(&[6; 32]).public();
        assert!(x25519_public_key_ok(&honest));
        // u = 9 is the base point (honest); 9 + p is the same number, non-canonically encoded.
        let mut nine = [0u8; 32];
        nine[0] = 9;
        assert!(x25519_public_key_ok(&nine));
        let mut non_canonical = P;
        non_canonical[0] += 9;
        assert!(!x25519_public_key_ok(&non_canonical));
        // A point on the twist (the first small u that is not on the curve).
        let twist = (2u8..=255)
            .map(|v| {
                let mut u = [0u8; 32];
                u[0] = v;
                u
            })
            .find(|u| MontgomeryPoint(*u).to_edwards(0).is_none())
            .unwrap();
        assert!(!x25519_public_key_ok(&twist));
        // A mixed-order key: an honest point plus a torsion point.
        let e = MontgomeryPoint(honest).to_edwards(0).unwrap();
        assert!(!x25519_public_key_ok(
            (e + EIGHT_TORSION[1]).to_montgomery().as_bytes()
        ));
    }
}
