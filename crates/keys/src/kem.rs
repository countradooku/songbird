//! ML-KEM-1024 public keys (FIPS 203), the post-quantum prekeys of PQXDH (Prompt 3, M3;
//! D-0050: ML-KEM-1024 only, the owner's decision; libsignal's pre-standard Kyber1024 is not
//! accepted).
//!
//! On the wire a key is libsignal's serialization: the type byte `0x0A` and the 1,568-byte
//! encapsulation key. The server checks what FIPS 203 §7.2 requires of an encapsulation key
//! before use (every 12-bit coefficient of `t` below q = 3329, so the key decodes and re-encodes
//! to itself), then has aws-lc-rs parse it.

use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_1024};

/// libsignal's type byte for ML-KEM-1024.
pub const TYPE_ML_KEM_1024: u8 = 0x0A;
/// Encapsulation key length.
pub const KEY_LEN: usize = 1568;
/// Serialized length: type byte and key.
pub const SERIALIZED_LEN: usize = 1 + KEY_LEN;
/// The modulus q.
const Q: u16 = 3329;
/// Bytes of `t` (k = 4 polynomials of 256 coefficients, 12 bits each).
const T_LEN: usize = 4 * 384;

/// Whether every 12-bit coefficient of the key's `t` is below q (FIPS 203 §7.2, modulus check).
#[must_use]
pub fn modulus_check(key: &[u8; KEY_LEN]) -> bool {
    key.get(..T_LEN).is_some_and(|t| {
        t.as_chunks::<3>().0.iter().all(|[a, b, c]| {
            let lo = u16::from(*a) | (u16::from(*b & 0x0F) << 8);
            let hi = u16::from(*b >> 4) | (u16::from(*c) << 4);
            lo < Q && hi < Q
        })
    })
}

/// Whether `serialized` is a valid ML-KEM-1024 public key in libsignal's serialization.
#[must_use]
pub fn public_key_ok(serialized: &[u8]) -> bool {
    let Some((&kind, key)) = serialized.split_first() else {
        return false;
    };
    let Ok(key) = <&[u8; KEY_LEN]>::try_from(key) else {
        return false;
    };
    kind == TYPE_ML_KEM_1024
        && modulus_check(key)
        && EncapsulationKey::new(&ML_KEM_1024, key).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use aws_lc_rs::kem::DecapsulationKey;

    use super::*;

    fn honest() -> Vec<u8> {
        let dk = DecapsulationKey::generate(&ML_KEM_1024).unwrap();
        let ek = dk.encapsulation_key().unwrap();
        let mut out = vec![TYPE_ML_KEM_1024];
        out.extend_from_slice(ek.key_bytes().unwrap().as_ref());
        out
    }

    #[test]
    fn honest_keys_pass_and_everything_else_does_not() {
        let k = honest();
        assert_eq!(k.len(), SERIALIZED_LEN);
        assert!(public_key_ok(&k));
        // Kyber1024's type byte, a short key, a long key.
        let mut kyber = k.clone();
        kyber[0] = 0x08;
        assert!(!public_key_ok(&kyber));
        assert!(!public_key_ok(&k[..SERIALIZED_LEN - 1]));
        let mut long = k.clone();
        long.push(0);
        assert!(!public_key_ok(&long));
        assert!(!public_key_ok(&[]));
    }

    #[test]
    fn a_coefficient_at_or_above_q_is_refused() {
        let mut k = honest();
        // The first coefficient set to 0xFFF (4095 >= 3329).
        k[1] = 0xFF;
        k[2] |= 0x0F;
        assert!(!public_key_ok(&k));
        // aws-lc-rs 1.19 parses such a key without complaint: the explicit check is what
        // refuses it (if aws-lc-rs starts refusing, the check stays regardless).
        assert!(
            EncapsulationKey::new(&ML_KEM_1024, &k[1..]).is_ok(),
            "aws-lc-rs now applies the modulus check itself"
        );
        // The largest valid coefficient, q - 1 = 3328 = 0xD00, in the second slot.
        let mut k = honest();
        k[2] &= 0x0F;
        k[3] = 0xD0;
        assert!(modulus_check(<&[u8; KEY_LEN]>::try_from(&k[1..]).unwrap()));
        k[3] = 0xD1; // 3344
        assert!(!modulus_check(<&[u8; KEY_LEN]>::try_from(&k[1..]).unwrap()));
    }
}
