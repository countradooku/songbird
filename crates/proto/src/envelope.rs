//! What the server writes into envelopes (Prompt 4, M3; `docs/PROTOCOL.md` §5.13, D-0061).
//!
//! Envelopes are client ciphertext, opaque to the server. Two formats are the server's own, and
//! no user envelope may take them: the send path refuses any envelope beginning with
//! [`RESERVED_PREFIX`] (reject reason 9). The prefix covers both formats and any later one:
//!
//! - a system frame ([`crate::system`], `F5 53 42 53 59 53 00 01`);
//! - a **franking stamp** in front of a franked envelope (this module):
//!
//! ```text
//! magic F5 53 42 46 52 4B 00 01 | version u8 (1) | key_id [8] | commitment [32]
//!   | stamped_at_ms u64 | tag [32] | the client's envelope (at least 1 byte)
//! ```
//!
//! `tag = HMAC-SHA256(franking key, "songbird.v1/franking-stamp\0" || key_id || commitment ||
//! stamped_at_ms || sender account [16] || recipient account [16])`, where the sender is all zeros
//! for a sealed send (the server does not know it) and the recipient is all zeros for a group's
//! shared body. The tag is a MAC only the server can check: it names neither account in the clear,
//! and recipients cannot verify it, only keep it for a report (§5.14). The recipient checks
//! instead that `commitment` opens to the content it decrypted (`songbird_content`), and drops the
//! message if it does not.
//!
//! This crate stays free of cryptography: the MAC is computed by `songbird-send`
//! (`franking::Franker`) over [`stamp_input`].

use bytes::{BufMut as _, Bytes, BytesMut};

/// Every format the server writes into an envelope begins with these bytes; user envelopes may
/// not (`0xF5` never starts UTF-8, and no session-layer format begins with it).
pub const RESERVED_PREFIX: [u8; 3] = [0xF5, b'S', b'B'];
/// The first bytes of a franking stamp.
pub const FRANKED_MAGIC: [u8; 8] = [0xF5, b'S', b'B', b'F', b'R', b'K', 0x00, 0x01];
/// The stamp format version this crate writes and reads.
pub const FRANKED_VERSION: u8 = 1;
/// Length of the franking key's identifier.
pub const KEY_ID_LEN: usize = 8;
/// Length of the commitment and of the tag.
pub const MAC_LEN: usize = 32;
/// Bytes of the stamp before the client's envelope.
pub const FRANKED_HEADER_LEN: usize = FRANKED_MAGIC.len() + 1 + KEY_ID_LEN + MAC_LEN + 8 + MAC_LEN;
/// Domain separation of the stamp's MAC.
pub const STAMP_CONTEXT: &[u8] = b"songbird.v1/franking-stamp\0";
/// Length of [`stamp_input`].
pub const STAMP_INPUT_LEN: usize = STAMP_CONTEXT.len() + KEY_ID_LEN + MAC_LEN + 8 + 16 + 16;

/// Whether an envelope begins with the prefix only the server may write.
#[must_use]
pub fn is_reserved(envelope: &[u8]) -> bool {
    envelope.starts_with(&RESERVED_PREFIX)
}

/// A franking stamp. `Debug` shows only the time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Which franking key made the tag (rotation).
    pub key_id: [u8; KEY_ID_LEN],
    /// The sender's commitment to the content.
    pub commitment: [u8; MAC_LEN],
    /// When the server accepted the send (ms since the Unix epoch).
    pub stamped_at_ms: u64,
    /// The server's MAC over [`stamp_input`].
    pub tag: [u8; MAC_LEN],
}

impl std::fmt::Debug for Stamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stamp")
            .field("stamped_at_ms", &self.stamped_at_ms)
            .finish_non_exhaustive()
    }
}

/// Why bytes are not a franked envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StampError {
    /// Not the franking magic.
    #[error("not a franked envelope")]
    NotFranked,
    /// A version this crate does not read.
    #[error("unknown franking stamp version")]
    Version,
    /// Shorter than a stamp and one byte of envelope.
    #[error("franked envelope truncated")]
    Truncated,
}

/// The bytes the stamp's tag authenticates.
#[must_use]
pub fn stamp_input(
    key_id: &[u8; KEY_ID_LEN],
    commitment: &[u8; MAC_LEN],
    stamped_at_ms: u64,
    sender: &[u8; 16],
    recipient: &[u8; 16],
) -> [u8; STAMP_INPUT_LEN] {
    let mut out = [0u8; STAMP_INPUT_LEN];
    let mut pos = 0;
    for part in [
        STAMP_CONTEXT,
        key_id.as_slice(),
        commitment.as_slice(),
        &stamped_at_ms.to_be_bytes(),
        sender.as_slice(),
        recipient.as_slice(),
    ] {
        if let Some(dst) = out.get_mut(pos..pos + part.len()) {
            dst.copy_from_slice(part);
        }
        pos += part.len();
    }
    out
}

impl Stamp {
    /// The stamp followed by `envelope`, in one allocation.
    #[must_use]
    pub fn prepend(&self, envelope: &[u8]) -> Bytes {
        let mut b = BytesMut::with_capacity(FRANKED_HEADER_LEN + envelope.len());
        b.put_slice(&FRANKED_MAGIC);
        b.put_u8(FRANKED_VERSION);
        b.put_slice(&self.key_id);
        b.put_slice(&self.commitment);
        b.put_u64(self.stamped_at_ms);
        b.put_slice(&self.tag);
        b.put_slice(envelope);
        b.freeze()
    }

    /// Splits a franked envelope into its stamp and the client's envelope.
    ///
    /// # Errors
    /// [`StampError`].
    pub fn split(franked: &[u8]) -> Result<(Self, &[u8]), StampError> {
        if !franked.starts_with(&FRANKED_MAGIC) {
            return Err(StampError::NotFranked);
        }
        if franked.len() <= FRANKED_HEADER_LEN {
            return Err(StampError::Truncated);
        }
        let (head, envelope) = franked.split_at(FRANKED_HEADER_LEN);
        let mut r = head.get(FRANKED_MAGIC.len()..).unwrap_or_default();
        let mut take = |n: usize| {
            let (a, rest) = r.split_at(n.min(r.len()));
            r = rest;
            a
        };
        if take(1) != [FRANKED_VERSION] {
            return Err(StampError::Version);
        }
        let mut s = Self {
            key_id: [0; KEY_ID_LEN],
            commitment: [0; MAC_LEN],
            stamped_at_ms: 0,
            tag: [0; MAC_LEN],
        };
        s.key_id.copy_from_slice(take(KEY_ID_LEN));
        s.commitment.copy_from_slice(take(MAC_LEN));
        let mut t = [0u8; 8];
        t.copy_from_slice(take(8));
        s.stamped_at_ms = u64::from_be_bytes(t);
        s.tag.copy_from_slice(take(MAC_LEN));
        Ok((s, envelope))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn stamp() -> Stamp {
        Stamp {
            key_id: [1; 8],
            commitment: [2; 32],
            stamped_at_ms: 1_800_000_000_000,
            tag: [3; 32],
        }
    }

    #[test]
    fn stamps_round_trip_and_split_exactly() {
        let f = stamp().prepend(b"ciphertext");
        assert_eq!(f.len(), FRANKED_HEADER_LEN + 10);
        assert!(is_reserved(&f));
        let (s, env) = Stamp::split(&f).unwrap();
        assert_eq!(s, stamp());
        assert_eq!(env, b"ciphertext");
        assert_eq!(
            format!("{s:?}"),
            "Stamp { stamped_at_ms: 1800000000000, .. }"
        );
    }

    #[test]
    fn malformed_stamps_are_refused() {
        let f = stamp().prepend(b"x");
        assert_eq!(
            Stamp::split(&f[..FRANKED_HEADER_LEN]),
            Err(StampError::Truncated)
        );
        assert_eq!(Stamp::split(b"plain"), Err(StampError::NotFranked));
        let mut v = f.to_vec();
        v[8] = 2;
        assert_eq!(Stamp::split(&v), Err(StampError::Version));
        for cut in 0..f.len() {
            let _ = Stamp::split(&f[..cut]);
        }
    }

    #[test]
    fn the_reserved_prefix_covers_system_frames_and_stamps() {
        assert!(is_reserved(&crate::system::MAGIC));
        assert!(is_reserved(&FRANKED_MAGIC));
        assert!(!is_reserved(&[0xF5, b'S']));
        assert!(!is_reserved(b"\x33ciphertext"));
    }

    #[test]
    fn the_stamp_input_is_every_field_in_order() {
        let i = stamp_input(&[1; 8], &[2; 32], 7, &[4; 16], &[5; 16]);
        assert!(i.starts_with(STAMP_CONTEXT));
        let rest = &i[STAMP_CONTEXT.len()..];
        assert_eq!(&rest[..8], &[1; 8]);
        assert_eq!(&rest[8..40], &[2; 32]);
        assert_eq!(&rest[40..48], &7u64.to_be_bytes());
        assert_eq!(&rest[48..64], &[4; 16]);
        assert_eq!(&rest[64..80], &[5; 16]);
    }
}
