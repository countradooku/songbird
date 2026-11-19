//! Family seats (Prompt 11, M4; PROTOCOL §14.6; D-0126 §5, D-0130): the client side of the
//! family mailbox.
//!
//! The owner's app makes a **management token** (it alone can add, replace or remove slots) and,
//! per member, an [`Invite`]: a random slot ID and a 32-byte slot secret, shared in a link
//! (`https://songbird.chat/family#<family>.<slot>.<secret>`, the fragment never sent to a server).
//! From the secret come two values that never meet: a **bearer** the member's app shows the
//! server to read or leave its slot (the server keeps `SHA-256` of it), and a **key** that seals
//! the month's token in the slot (ChaCha20-Poly1305), which the server never sees. So the
//! server can neither open a seat nor tie it to an account.

use aws_lc_rs::aead::{self, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::{digest, hkdf};

/// Domain separation of the management token's hash.
pub const MANAGE_CONTEXT: &[u8] = b"songbird.v1/family-manage\0";
/// The link's prefix.
pub const LINK_PREFIX: &str = "https://songbird.chat/family#";

/// `SHA-256(context || value)`.
fn hash(context: &[u8], v: &[u8]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(context);
    ctx.update(v);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// What the server stores for a management token (the owner sends it once, at creation).
#[must_use]
pub fn manage_hash(token: &[u8; 32]) -> [u8; 32] {
    hash(MANAGE_CONTEXT, token)
}

/// What the server stores for a slot's bearer (the owner sends it when it makes the slot).
#[must_use]
pub fn bearer_hash(bearer: &[u8; 32]) -> [u8; 32] {
    hash(b"songbird.v1/family-bearer\0", bearer)
}

/// One member's seat: where it is and the secret that opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// The family.
    pub family: [u8; 16],
    /// The slot.
    pub slot: [u8; 16],
    secret: [u8; 32],
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite").finish_non_exhaustive()
    }
}

fn derive(secret: &[u8; 32], label: &[u8], family: &[u8; 16], slot: &[u8; 16]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let info = [label, family.as_slice(), slot.as_slice()];
    hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird.v1/family-seat")
        .extract(secret)
        .expand(&info, hkdf::HKDF_SHA256)
        .ok()?
        .fill(&mut out)
        .ok()?;
    Some(out)
}

impl Invite {
    /// A new seat in `family`: a random slot ID and secret.
    ///
    /// # Errors
    /// The random source failed.
    pub fn new(family: [u8; 16]) -> Result<Self, getrandom::Error> {
        let mut slot = [0u8; 16];
        let mut secret = [0u8; 32];
        getrandom::fill(&mut slot)?;
        getrandom::fill(&mut secret)?;
        Ok(Self {
            family,
            slot,
            secret,
        })
    }

    /// The link the owner shares with the member.
    #[must_use]
    pub fn link(&self) -> String {
        format!(
            "{LINK_PREFIX}{}.{}.{}",
            hex::encode(self.family),
            hex::encode(self.slot),
            hex::encode(self.secret)
        )
    }

    /// Parses a link (strictly).
    #[must_use]
    pub fn parse(link: &str) -> Option<Self> {
        let rest = link.strip_prefix(LINK_PREFIX)?;
        let mut it = rest.split('.');
        let (f, s, k, None) = (it.next()?, it.next()?, it.next()?, it.next()) else {
            return None;
        };
        let mut out = Self {
            family: [0; 16],
            slot: [0; 16],
            secret: [0; 32],
        };
        hex::decode_to_slice(f, &mut out.family).ok()?;
        hex::decode_to_slice(s, &mut out.slot).ok()?;
        hex::decode_to_slice(k, &mut out.secret).ok()?;
        Some(out)
    }

    /// The bearer the member shows the server (never the key).
    #[must_use]
    pub fn bearer(&self) -> [u8; 32] {
        derive(&self.secret, b"bearer", &self.family, &self.slot).unwrap_or([0; 32])
    }

    fn key(&self) -> Option<LessSafeKey> {
        let k = derive(&self.secret, b"key", &self.family, &self.slot)?;
        Some(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &k).ok()?,
        ))
    }

    fn aad(&self) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[..16].copy_from_slice(&self.family);
        a[16..].copy_from_slice(&self.slot);
        a
    }

    /// Seals `plaintext` (a month's token) for this seat: `nonce (12) || ciphertext || tag`.
    ///
    /// # Errors
    /// The random source or the AEAD failed (never in practice).
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key = self.key().ok_or("key")?;
        let mut n = [0u8; aead::NONCE_LEN];
        getrandom::fill(&mut n).map_err(|_| "random")?;
        let mut buf = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(n),
            Aad::from(self.aad()),
            &mut buf,
        )
        .map_err(|_| "seal")?;
        let mut out = n.to_vec();
        out.extend(buf);
        Ok(out)
    }

    /// Opens a box sealed for this seat.
    #[must_use]
    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        let (n, ct) = sealed.split_at_checked(aead::NONCE_LEN)?;
        let nonce = Nonce::try_assume_unique_for_key(n).ok()?;
        let mut buf = ct.to_vec();
        let pt = self
            .key()?
            .open_in_place(nonce, Aad::from(self.aad()), &mut buf)
            .ok()?;
        Some(pt.to_vec())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn a_seat_round_trips_and_nothing_else_opens_it() {
        let a = Invite::new([1; 16]).unwrap();
        let link = a.link();
        assert!(link.starts_with(LINK_PREFIX));
        let b = Invite::parse(&link).unwrap();
        assert_eq!(a, b);
        let sealed = a.seal(b"a month's token").unwrap();
        assert_eq!(b.open(&sealed).unwrap(), b"a month's token");
        // Another seat, the same slot in another family, or a flipped bit: nothing.
        let other = Invite::new([1; 16]).unwrap();
        assert!(other.open(&sealed).is_none());
        let mut moved = a.clone();
        moved.family = [2; 16];
        assert!(moved.open(&sealed).is_none());
        let mut flipped = sealed.clone();
        flipped[20] ^= 1;
        assert!(a.open(&flipped).is_none());
        assert!(a.open(&sealed[..10]).is_none());
        // The bearer the server sees is neither the secret nor the key.
        assert_ne!(a.bearer(), a.secret);
        assert!(!link.contains(&hex::encode(a.bearer())));
        assert!(!format!("{a:?}").contains(&hex::encode(a.secret)));
        for bad in [
            "",
            "https://songbird.chat/family#00.11",
            &link.replace('#', "?"),
            &format!("{link}.00"),
        ] {
            assert!(Invite::parse(bad).is_none(), "{bad}");
        }
    }
}
