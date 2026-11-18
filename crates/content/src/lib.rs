//! Songbird's encrypted content (Prompt 4; `docs/PROTOCOL.md` §5; decision D-0059).
//!
//! What the session layer encrypts: a [`schema::Plaintext`] holding an encoded
//! [`schema::Content`] and its franking key, padded to 160-byte buckets. The specification is
//! `proto/content.proto`; apps in other languages generate their types from it.
//!
//! **No service links this crate.** The server stores and relays ciphertext and never decodes
//! content (the constitution's privacy model); `tests/no_service_links_content.rs` enforces it.
//! What the server must act on (a franking commitment, a disappearing timer, the access key or a
//! request) travels in fixed fields of the `Send` frame instead (PROTOCOL §1.2).
//!
//! ```text
//! seal:  Content ─encode─▶ bytes ─┬─▶ Plaintext{content, franking_key} ─encode─▶ pad ─▶ session layer
//!                                 └─▶ commitment = HMAC(franking_key, ctx ‖ bytes) ─▶ Send frame
//! open:  session layer ─▶ unpad ─▶ Plaintext ─▶ Content (bounded, validated)
//! ```
//!
//! [`state`] holds the reference semantics every app must reproduce: tallies, reactions, edits,
//! pins, timers and message status, all independent of arrival order.
#![forbid(unsafe_code)]

pub mod attachment;
pub mod call;
pub mod pack;
pub mod presence;
pub mod profile;
pub mod schema;
pub mod state;
pub mod validate;

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use prost::Message as _;

pub use schema::{Content, Plaintext};

/// The schema version this crate writes and reads.
pub const VERSION: u32 = 1;
/// Plaintexts are padded to a multiple of this many bytes, so an envelope's size tells the
/// server little about its content.
pub const PAD_BLOCK: usize = 160;
/// Largest padded plaintext accepted (the default envelope limit is 64 KiB, PROTOCOL §1.3);
/// checked before anything is decoded.
pub const MAX_PADDED: usize = 64 * 1024;
/// Largest encoded [`Content`].
pub const MAX_CONTENT: usize = 61_440;
/// Account, message, group, call and sticker-pack IDs.
pub const ID_LEN: usize = 16;
/// Franking keys, profile keys, sticker-pack keys, digests.
pub const KEY_LEN: usize = 32;

/// Domain separation of the franking commitment.
pub const FRANKING_CONTEXT: &[u8] = b"songbird.v1/franking\0";

/// Why a plaintext was refused. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Larger than [`MAX_PADDED`] or [`MAX_CONTENT`].
    #[error("plaintext too large")]
    TooLarge,
    /// The padding is not `0x80 0x00*` to a multiple of [`PAD_BLOCK`].
    #[error("bad padding")]
    Padding,
    /// Not protobuf of the expected shape.
    #[error("malformed protobuf")]
    Decode,
    /// A field breaks its bound (the field's path).
    #[error("invalid field: {0}")]
    Invalid(&'static str),
    /// A ciphertext does not open (another key, a changed byte), or a primitive failed.
    #[error("does not open")]
    Crypto,
}

/// A decoded, validated plaintext. `Debug` shows only whether it is franked.
#[derive(Clone, PartialEq)]
pub struct Opened {
    /// The content.
    pub content: Content,
    /// Its encoding, exactly as received (what franking commits to and a report submits).
    pub content_bytes: Vec<u8>,
    /// The franking key, when the message is franked.
    pub franking_key: Option<[u8; KEY_LEN]>,
    /// The sender's profile key, when it shares one. Outside the committed content, so a report
    /// never reveals it.
    pub profile_key: Option<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("franked", &self.franking_key.is_some())
            .finish_non_exhaustive()
    }
}

impl Opened {
    /// Whether this reader is too old to show the message ("update to see this message").
    #[must_use]
    pub const fn needs_update(&self) -> bool {
        self.content.required_version > VERSION
    }

    /// Whether the commitment the server stamped (from the franked envelope's header) opens to
    /// this content under its franking key. Recipients drop a franked message for which it does
    /// not (PROTOCOL §5.3); a message without a franking key never matches.
    #[must_use]
    pub fn franking_matches(&self, stamped: &[u8; KEY_LEN]) -> bool {
        self.franking_key.is_some_and(|k| {
            verify_slices_are_equal(&commitment(&k, &self.content_bytes), stamped).is_ok()
        })
    }
}

/// The franking commitment: `HMAC-SHA256(franking_key, "songbird.v1/franking\0" || content)`.
#[must_use]
pub fn commitment(franking_key: &[u8; KEY_LEN], content: &[u8]) -> [u8; KEY_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, franking_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(FRANKING_CONTEXT);
    ctx.update(content);
    let mut out = [0; KEY_LEN];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// Pads to the next multiple of [`PAD_BLOCK`]: `bytes || 0x80 || 0x00*` (always at least one
/// byte of padding).
#[must_use]
pub fn pad(bytes: &[u8]) -> Vec<u8> {
    let len = (bytes.len() / PAD_BLOCK + 1) * PAD_BLOCK;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(bytes);
    out.push(0x80);
    out.resize(len, 0);
    out
}

/// Removes [`pad`]'s padding.
///
/// # Errors
/// [`Error::Padding`] unless the length is a non-zero multiple of [`PAD_BLOCK`] ending in
/// `0x80 0x00*`; [`Error::TooLarge`] above [`MAX_PADDED`].
pub fn unpad(padded: &[u8]) -> Result<&[u8], Error> {
    if padded.len() > MAX_PADDED {
        return Err(Error::TooLarge);
    }
    if padded.is_empty() || !padded.len().is_multiple_of(PAD_BLOCK) {
        return Err(Error::Padding);
    }
    let end = padded.iter().rposition(|b| *b != 0).ok_or(Error::Padding)?;
    if padded.get(end) != Some(&0x80) {
        return Err(Error::Padding);
    }
    // At most one block of padding: a longer run would hide nothing and has two encodings.
    if padded.len() - end > PAD_BLOCK {
        return Err(Error::Padding);
    }
    padded.get(..end).ok_or(Error::Padding)
}

/// Encodes, frames and pads `content`; with a franking key, also returns the commitment for the
/// `Send` frame's `FRANKED` block.
///
/// # Errors
/// [`Error::Invalid`] if `content` breaks a bound; [`Error::TooLarge`] above [`MAX_CONTENT`].
pub fn seal(
    content: &Content,
    franking_key: Option<[u8; KEY_LEN]>,
) -> Result<(Vec<u8>, Option<[u8; KEY_LEN]>), Error> {
    seal_with_profile_key(content, franking_key, None)
}

/// [`seal`], also sharing the sender's profile key (accepting a request, or after a rotation):
/// it travels beside the content, never inside what franking commits to.
///
/// # Errors
/// As [`seal`].
pub fn seal_with_profile_key(
    content: &Content,
    franking_key: Option<[u8; KEY_LEN]>,
    profile_key: Option<[u8; KEY_LEN]>,
) -> Result<(Vec<u8>, Option<[u8; KEY_LEN]>), Error> {
    validate::content(content)?;
    let bytes = content.encode_to_vec();
    if bytes.len() > MAX_CONTENT {
        return Err(Error::TooLarge);
    }
    let commit = franking_key.map(|k| commitment(&k, &bytes));
    let plain = Plaintext {
        content: bytes,
        franking_key: franking_key.map(|k| k.to_vec()).unwrap_or_default(),
        profile_key: profile_key.map(|k| k.to_vec()).unwrap_or_default(),
    };
    Ok((pad(&plain.encode_to_vec()), commit))
}

/// Unpads, decodes and validates a plaintext. Bounded: the size is checked before decoding, and
/// every repeated field, string and bytes field afterwards ([`validate`]).
///
/// # Errors
/// [`Error`].
pub fn open(padded: &[u8]) -> Result<Opened, Error> {
    let bytes = unpad(padded)?;
    let plain = Plaintext::decode(bytes).map_err(|_| Error::Decode)?;
    if plain.content.len() > MAX_CONTENT {
        return Err(Error::TooLarge);
    }
    let key = |b: &[u8], field| match b.len() {
        0 => Ok(None),
        KEY_LEN => {
            let mut k = [0; KEY_LEN];
            k.copy_from_slice(b);
            Ok(Some(k))
        }
        _ => Err(Error::Invalid(field)),
    };
    let franking_key = key(&plain.franking_key, "plaintext.franking_key")?;
    let profile_key = key(&plain.profile_key, "plaintext.profile_key")?;
    let content = decode_content(&plain.content)?;
    Ok(Opened {
        content,
        content_bytes: plain.content,
        franking_key,
        profile_key,
    })
}

/// Decodes and validates an encoded [`Content`] (also what a report carries).
///
/// # Errors
/// [`Error`].
pub fn decode_content(bytes: &[u8]) -> Result<Content, Error> {
    if bytes.len() > MAX_CONTENT {
        return Err(Error::TooLarge);
    }
    let content = Content::decode(bytes).map_err(|_| Error::Decode)?;
    validate::content(&content)?;
    Ok(content)
}

#[cfg(test)]
mod tests;
