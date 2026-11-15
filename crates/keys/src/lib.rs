//! Server-side checks of identity key material (D-0048).
//!
//! The server never trusts a public key just because a signature verifies under it. An Ed25519
//! public key of small order (the identity point, or one of the seven other torsion points)
//! accepts signatures nobody computed with a private key: with `A` the identity point, any
//! `s` and `R = sB` verify for every message. A key with a torsion component (`A = P + T`)
//! verifies differently under cofactored and cofactorless equations, so two implementations can
//! disagree about one signature. Honest keys are `aB` for a secret scalar `a`: canonical
//! encodings of points in the prime-order subgroup. Every Ed25519 key the server stores passes
//! [`ed25519_public_key_ok`] first.
//!
//! Signatures are verified with aws-lc-rs (the constitution's crypto library), which refuses
//! non-canonical `S`. `curve25519-dalek` is used only for the point checks aws-lc-rs does not
//! expose; it will carry `XEdDSA` and the username hash in later milestones (owner's decision,
//! D-0047: implement the protocols, do not link libsignal).
#![forbid(unsafe_code)]

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use curve25519_dalek::edwards::CompressedEdwardsY;

/// Ed25519 public key length.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Whether `key` is the canonical encoding of an Ed25519 point of prime order `l`: it decodes,
/// re-encodes to the same bytes (no `y >= p`, no negative zero), is not of small order and has
/// no torsion component.
#[must_use]
pub fn ed25519_public_key_ok(key: &[u8; ED25519_PUBLIC_LEN]) -> bool {
    let Some(p) = CompressedEdwardsY(*key).decompress() else {
        return false;
    };
    p.compress().as_bytes() == key && !p.is_small_order() && p.is_torsion_free()
}

/// Verifies an Ed25519 signature with a key that passes [`ed25519_public_key_ok`]. Constant work
/// whether the key is refused or the signature is wrong is not needed here: the key is the
/// caller's own, never a secret.
#[must_use]
pub fn ed25519_verify(
    key: &[u8; ED25519_PUBLIC_LEN],
    message: &[u8],
    signature: &[u8; ED25519_SIGNATURE_LEN],
) -> bool {
    ed25519_public_key_ok(key)
        && UnparsedPublicKey::new(&ED25519, key)
            .verify(message, signature)
            .is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
    use curve25519_dalek::constants::EIGHT_TORSION;
    use curve25519_dalek::edwards::EdwardsPoint;
    use proptest::prelude::*;

    use super::*;

    fn pk(k: &Ed25519KeyPair) -> [u8; 32] {
        k.public_key().as_ref().try_into().unwrap()
    }

    #[test]
    fn honest_keys_pass_and_sign() {
        let k = Ed25519KeyPair::generate().unwrap();
        let key = pk(&k);
        assert!(ed25519_public_key_ok(&key));
        let sig: [u8; 64] = k.sign(b"m").as_ref().try_into().unwrap();
        assert!(ed25519_verify(&key, b"m", &sig));
        assert!(!ed25519_verify(&key, b"n", &sig));
    }

    #[test]
    fn every_small_order_point_is_refused() {
        for t in EIGHT_TORSION {
            assert!(!ed25519_public_key_ok(t.compress().as_bytes()));
        }
        // The identity point accepts a forged signature for any message: R = sB, any s. aws-lc-rs
        // alone would take it; the point check refuses it first.
        let identity = EdwardsPoint::default().compress().to_bytes();
        let s = curve25519_dalek::Scalar::from(5u8);
        let r = EdwardsPoint::mul_base(&s).compress().to_bytes();
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&r);
        forged[32..].copy_from_slice(s.as_bytes());
        let aws_alone = UnparsedPublicKey::new(&ED25519, &identity)
            .verify(b"anything", &forged)
            .is_ok();
        assert!(
            aws_alone,
            "aws-lc-rs now refuses small-order keys itself; the point check stays regardless"
        );
        assert!(!ed25519_verify(&identity, b"anything", &forged));
    }

    #[test]
    fn mixed_order_and_non_canonical_encodings_are_refused() {
        let k = Ed25519KeyPair::generate().unwrap();
        let p = CompressedEdwardsY(pk(&k)).decompress().unwrap();
        for t in EIGHT_TORSION.iter().skip(1) {
            assert!(!ed25519_public_key_ok((p + t).compress().as_bytes()));
        }
        // y = 1 encoded as p + 1 (a non-canonical identity point), and the identity point with
        // the sign bit set (x = 0 has no negative).
        let mut non_canonical = [0xFFu8; 32];
        non_canonical[0] = 0xEE;
        non_canonical[31] = 0x7F;
        assert!(!ed25519_public_key_ok(&non_canonical));
        let mut neg_zero = EdwardsPoint::default().compress().to_bytes();
        neg_zero[31] |= 0x80;
        assert!(!ed25519_public_key_ok(&neg_zero));
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(b in any::<[u8; 32]>()) {
            let _ = ed25519_public_key_ok(&b);
        }
    }
}
