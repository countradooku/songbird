//! Message franking on the server (Prompt 4, M3; `docs/PROTOCOL.md` §5.13, D-0061).
//!
//! A franked send carries the sender's commitment to the content. The send path stamps every
//! envelope for another account with a MAC under the franking key, binding the commitment to the
//! time, the sender's account and the recipient's account ([`songbird_proto::envelope`]). A report
//! later brings the stamp back with the content and the franking key that opens the commitment
//! (`api`, M5): only then does the server learn what was said, and only because the recipient
//! chose to show it.
//!
//! Keys come from the secrets store. Every service that sends stamps with the current key; `api`
//! also keeps the previous ones to verify reports (rotation by `key_id`).

use aws_lc_rs::{digest, hkdf, hmac};
use songbird_proto::envelope::{KEY_ID_LEN, MAC_LEN, Stamp, stamp_input};

/// A franking key and its identifier. `Debug` shows only the identifier.
#[derive(Clone)]
pub struct Franker {
    key: hmac::Key,
    key_id: [u8; KEY_ID_LEN],
}

impl std::fmt::Debug for Franker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Franker")
            .field("key_id", &hex::encode(self.key_id))
            .finish_non_exhaustive()
    }
}

impl Franker {
    /// The key derived from a 32-byte secret (HKDF-SHA256, its own label). Its identifier is the
    /// first 8 bytes of SHA-256 over a label and the derived key: public, and reveals nothing of
    /// the key.
    ///
    /// # Errors
    /// Only if HKDF refuses the length (never for 32 bytes).
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, aws_lc_rs::error::Unspecified> {
        let mut k = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird.v1")
            .extract(secret)
            .expand(&[b"franking"], hkdf::HKDF_SHA256)?
            .fill(&mut k)?;
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"songbird.v1/franking-key-id\0");
        ctx.update(&k);
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(ctx.finish().as_ref().get(..KEY_ID_LEN).unwrap_or(&[0; 8]));
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            key_id,
        })
    }

    /// The key's identifier.
    #[must_use]
    pub const fn key_id(&self) -> [u8; KEY_ID_LEN] {
        self.key_id
    }

    /// Stamps `commitment` for an envelope from `sender` to `recipient` (all zeros where the
    /// server does not know or there is none) at `stamped_at_ms`.
    #[must_use]
    pub fn stamp(
        &self,
        commitment: &[u8; MAC_LEN],
        stamped_at_ms: u64,
        sender: &[u8; 16],
        recipient: &[u8; 16],
    ) -> Stamp {
        let input = stamp_input(&self.key_id, commitment, stamped_at_ms, sender, recipient);
        let mut tag = [0u8; MAC_LEN];
        tag.copy_from_slice(hmac::sign(&self.key, &input).as_ref());
        Stamp {
            key_id: self.key_id,
            commitment: *commitment,
            stamped_at_ms,
            tag,
        }
    }

    /// Whether `stamp` was made by this key for exactly this sender and recipient (constant
    /// time).
    #[must_use]
    pub fn verify(&self, stamp: &Stamp, sender: &[u8; 16], recipient: &[u8; 16]) -> bool {
        stamp.key_id == self.key_id
            && hmac::verify(
                &self.key,
                &stamp_input(
                    &stamp.key_id,
                    &stamp.commitment,
                    stamp.stamped_at_ms,
                    sender,
                    recipient,
                ),
                &stamp.tag,
            )
            .is_ok()
    }
}

/// The current franking key and the previous ones still accepted for reports.
#[derive(Debug, Clone)]
pub struct Frankers {
    /// Stamps new sends.
    pub current: Franker,
    /// Verify reports of older stamps.
    pub previous: Vec<Franker>,
}

impl Frankers {
    /// The key that made `stamp`, if it is one of these.
    #[must_use]
    pub fn by_id(&self, key_id: &[u8; KEY_ID_LEN]) -> Option<&Franker> {
        std::iter::once(&self.current)
            .chain(&self.previous)
            .find(|f| f.key_id == *key_id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn stamp_known_answer() {
        // Recomputed independently with Python's hmac and hashlib (HKDF by hand).
        let f = Franker::from_secret(&[0x46; 32]).unwrap();
        let s = f.stamp(&[1; 32], 1_800_000_000_000, &[0x0a; 16], &[0x0b; 16]);
        assert_eq!(hex::encode(f.key_id()), "3df2c8855889e63b");
        assert_eq!(
            hex::encode(s.tag),
            "114c33cc2b8f1a5e0ad8943b34ebb738c10f3397504e858b44b8e06e45a8b3b6"
        );
    }

    #[test]
    fn stamps_verify_only_for_their_key_sender_and_recipient() {
        let f = Franker::from_secret(&[7; 32]).unwrap();
        let s = f.stamp(&[1; 32], 1_800_000_000_000, &[2; 16], &[3; 16]);
        assert!(f.verify(&s, &[2; 16], &[3; 16]));
        assert!(!f.verify(&s, &[9; 16], &[3; 16]), "another sender");
        assert!(!f.verify(&s, &[2; 16], &[9; 16]), "another recipient");
        let mut t = s;
        t.stamped_at_ms += 1;
        assert!(!f.verify(&t, &[2; 16], &[3; 16]), "another time");
        let mut t = s;
        t.commitment[0] ^= 1;
        assert!(!f.verify(&t, &[2; 16], &[3; 16]), "another commitment");
        let g = Franker::from_secret(&[8; 32]).unwrap();
        assert_ne!(f.key_id(), g.key_id());
        assert!(!g.verify(&s, &[2; 16], &[3; 16]), "another key");
        let both = Frankers {
            current: g,
            previous: vec![f.clone()],
        };
        assert!(
            both.by_id(&s.key_id)
                .unwrap()
                .verify(&s, &[2; 16], &[3; 16])
        );
        assert!(!format!("{f:?}").contains("key:"));
    }
}
