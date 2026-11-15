//! Sealed sender (Prompt 3, M5, D-0054): the unidentified-access key a client derives from its
//! profile key, and how a sender combines several recipients' keys.

use aws_lc_rs::hkdf;

/// Access key length.
pub const ACCESS_KEY_LEN: usize = 16;

struct Len16;

impl hkdf::KeyType for Len16 {
    fn len(&self) -> usize {
        ACCESS_KEY_LEN
    }
}

/// `HKDF-SHA256(salt = "songbird.v1", ikm = profile_key, info = "unidentified-access")[..16]`.
/// Whoever holds the profile key (the account's contacts) can send to it sealed; the server
/// stores only this key, which reveals nothing of the profile key.
#[must_use]
pub fn access_key(profile_key: &[u8; 32]) -> [u8; ACCESS_KEY_LEN] {
    let mut out = [0u8; ACCESS_KEY_LEN];
    // HKDF with a 16-byte output never fails.
    let _ = hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird.v1")
        .extract(profile_key)
        .expand(&[b"unidentified-access"], Len16)
        .and_then(|o| o.fill(&mut out));
    out
}

/// The key a sealed send to several accounts presents: the XOR of their access keys (one
/// header, any number of recipient accounts; the server recomputes it from what it stores).
#[must_use]
pub fn combine<'a>(
    keys: impl IntoIterator<Item = &'a [u8; ACCESS_KEY_LEN]>,
) -> [u8; ACCESS_KEY_LEN] {
    let mut out = [0u8; ACCESS_KEY_LEN];
    for k in keys {
        for (o, b) in out.iter_mut().zip(k) {
            *o ^= b;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_keys_are_deterministic_and_distinct() {
        assert_eq!(access_key(&[1; 32]), access_key(&[1; 32]));
        assert_ne!(access_key(&[1; 32]), access_key(&[2; 32]));
        let (a, b) = (access_key(&[1; 32]), access_key(&[2; 32]));
        assert_eq!(combine([&a]), a);
        assert_eq!(combine([&a, &b, &b]), a);
        assert_ne!(combine([&a, &b]), a);
    }
}
