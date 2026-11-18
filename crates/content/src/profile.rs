//! The encrypted profile (PROTOCOL §4.8, §10.4; Prompt 3 M5, Prompt 9 M2, D-0103).
//!
//! The server stores the profile as an opaque blob (at most 8,192 bytes) under a version that
//! only grows. This module defines what is inside and how it is sealed, so every app agrees:
//!
//! ```text
//! blob = nonce [12] ‖ AES-256-GCM-SIV(key, nonce, aad = "songbird.v1/profile\0" ‖ be64(version),
//!                                     be32(len) ‖ ProfilePlain ‖ zeros to a multiple of 256)
//! key  = HKDF-SHA256(salt = "songbird.v1/profile", ikm = profile key, info = "profile")
//! ```
//!
//! The version is bound into the ciphertext, so the server cannot serve an old profile under a
//! newer version number. Padding to 256 bytes hides most of the length of the about line and
//! the status.
//!
//! **Visibility** ("who sees my photo, about, status": My contacts or Nobody, D-0101 question 7)
//! is applied by leaving the field out: only contacts hold the profile key, so the blob is the
//! contacts' view. Narrowing a field rotates the profile key (as blocking does), so a former
//! contact holding the old key reads nothing new.
//!
//! **A custom status** carries its expiry; readers stop showing it at that time with no further
//! message. After any change, the app sends its contacts a [`ProfileChanged`] (sealed, stored,
//! `SILENT`), and they fetch the profile again.

use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hkdf;
use prost::Message as _;
use zeroize::Zeroizing;

use crate::{Error, KEY_LEN};

/// Largest profile blob the server accepts (`songbird_proto::profile::MAX_PROFILE`).
pub const MAX_BLOB: usize = 8192;
/// Profile plaintexts are padded to a multiple of this.
pub const PAD: usize = 256;
/// Longest display name (bytes).
pub const MAX_NAME: usize = 128;
/// Longest about line (bytes).
pub const MAX_ABOUT: usize = 280;
/// Longest status text (bytes).
pub const MAX_STATUS: usize = 140;
/// Longest status emoji (bytes).
pub const MAX_EMOJI: usize = 32;
/// Most profile links, and their longest (bytes).
pub const MAX_LINKS: usize = 5;
/// Longest profile link.
pub const MAX_LINK: usize = 256;

const AAD: &[u8] = b"songbird.v1/profile\0";

/// What a profile holds.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProfilePlain {
    /// The display name.
    #[prost(string, tag = "1")]
    pub name: String,
    /// The about line; empty when not shared.
    #[prost(string, tag = "2")]
    pub about: String,
    /// The custom status; absent when none or not shared.
    #[prost(message, optional, tag = "3")]
    pub status: Option<Status>,
    /// The avatar; absent when none or not shared.
    #[prost(message, optional, tag = "4")]
    pub avatar: Option<Avatar>,
    /// Profile links (the user's own website and the like).
    #[prost(string, repeated, tag = "5")]
    pub links: Vec<String>,
}

/// A Yahoo-style custom status ("In a meeting until 3").
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Status {
    /// The text.
    #[prost(string, tag = "1")]
    pub text: String,
    /// An emoji shown with it.
    #[prost(string, tag = "2")]
    pub emoji: String,
    /// When it stops showing (ms since the epoch); 0: until changed.
    #[prost(uint64, tag = "3")]
    pub expires_ms: u64,
}

/// The encrypted avatar object (`PUT /v1/profile/avatar`) and its key.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Avatar {
    /// The object ID the server answered (32 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    /// The key the avatar is encrypted under (32 bytes).
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
}

/// Tells contacts the sender's profile changed: fetch it again if `version` is newer than the
/// one held. Sent sealed, stored and `SILENT` (no wake-up).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ProfileChanged {
    /// The new profile version.
    #[prost(uint64, tag = "1")]
    pub version: u64,
}

impl ProfilePlain {
    /// The status to show at `now_ms`: none once it expired.
    #[must_use]
    pub fn status_at(&self, now_ms: u64) -> Option<&Status> {
        self.status
            .as_ref()
            .filter(|s| s.expires_ms == 0 || now_ms < s.expires_ms)
    }

    /// Checks every bound.
    ///
    /// # Errors
    /// [`Error::Invalid`] naming the field.
    pub fn validate(&self) -> Result<(), Error> {
        let check = |ok: bool, f: &'static str| if ok { Ok(()) } else { Err(Error::Invalid(f)) };
        check(self.name.len() <= MAX_NAME, "profile.name")?;
        check(self.about.len() <= MAX_ABOUT, "profile.about")?;
        if let Some(s) = &self.status {
            check(!s.text.is_empty() || !s.emoji.is_empty(), "profile.status")?;
            check(s.text.len() <= MAX_STATUS, "profile.status.text")?;
            check(s.emoji.len() <= MAX_EMOJI, "profile.status.emoji")?;
        }
        if let Some(a) = &self.avatar {
            check(a.id.len() == 32, "profile.avatar.id")?;
            check(a.key.len() == KEY_LEN, "profile.avatar.key")?;
        }
        check(self.links.len() <= MAX_LINKS, "profile.links")?;
        check(
            self.links
                .iter()
                .all(|l| !l.is_empty() && l.len() <= MAX_LINK),
            "profile.links",
        )
    }
}

fn key(profile_key: &[u8; KEY_LEN]) -> Result<LessSafeKey, Error> {
    let mut k = Zeroizing::new([0u8; 32]);
    hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird.v1/profile")
        .extract(profile_key)
        .expand(&[b"profile"], hkdf::HKDF_SHA256)
        .and_then(|o| o.fill(k.as_mut()))
        .map_err(|_| Error::Crypto)?;
    let u = UnboundKey::new(&AES_256_GCM_SIV, k.as_ref()).map_err(|_| Error::Crypto)?;
    Ok(LessSafeKey::new(u))
}

fn aad(version: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD.len() + 8);
    a.extend_from_slice(AAD);
    a.extend_from_slice(&version.to_be_bytes());
    a
}

/// Seals a profile for `version` (the version it will be uploaded with).
///
/// # Errors
/// [`Error::Invalid`] for a field out of bounds; [`Error::TooLarge`]; [`Error::Crypto`].
pub fn seal(profile_key: &[u8; KEY_LEN], version: u64, p: &ProfilePlain) -> Result<Vec<u8>, Error> {
    p.validate()?;
    let body = Zeroizing::new(p.encode_to_vec());
    let framed = 4 + body.len();
    let padded = framed.div_ceil(PAD).max(1) * PAD;
    if NONCE_LEN + padded + 16 > MAX_BLOB {
        return Err(Error::TooLarge);
    }
    let mut buf = Vec::with_capacity(padded + 16);
    buf.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| Error::TooLarge)?
            .to_be_bytes(),
    );
    buf.extend_from_slice(&body);
    buf.resize(padded, 0);
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| Error::Crypto)?;
    key(profile_key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(version)),
            &mut buf,
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Opens a profile served at `version`.
///
/// # Errors
/// [`Error::Crypto`] if it does not open under this key and version (another key, a changed
/// byte, or an older profile served under a newer version); [`Error::Invalid`] for bad contents.
pub fn open(profile_key: &[u8; KEY_LEN], version: u64, blob: &[u8]) -> Result<ProfilePlain, Error> {
    if blob.len() > MAX_BLOB {
        return Err(Error::TooLarge);
    }
    let (nonce, ct) = blob.split_first_chunk::<NONCE_LEN>().ok_or(Error::Crypto)?;
    let mut buf = Zeroizing::new(ct.to_vec());
    let plain = key(profile_key)?
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad(version)),
            &mut buf,
        )
        .map_err(|_| Error::Crypto)?;
    let (len, rest) = plain
        .split_first_chunk::<4>()
        .ok_or(Error::Invalid("profile"))?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| Error::Invalid("profile"))?;
    let body = rest.get(..len).ok_or(Error::Invalid("profile"))?;
    if rest.get(len..).is_some_and(|z| z.iter().any(|b| *b != 0)) {
        return Err(Error::Invalid("profile"));
    }
    let p = ProfilePlain::decode(body).map_err(|_| Error::Invalid("profile"))?;
    p.validate()?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;

    fn sample() -> ProfilePlain {
        ProfilePlain {
            name: "Ana".into(),
            about: "Hiking, film, coffee".into(),
            status: Some(Status {
                text: "In a meeting until 3".into(),
                emoji: "📅".into(),
                expires_ms: 1_000,
            }),
            avatar: None,
            links: vec!["ana.example".into()],
        }
    }

    #[test]
    fn profiles_round_trip_bound_to_their_version() {
        let k = [7; 32];
        let b = seal(&k, 5, &sample()).unwrap();
        assert_eq!(open(&k, 5, &b).unwrap(), sample());
        assert_eq!(
            open(&k, 6, &b),
            Err(Error::Crypto),
            "an old profile under a new version"
        );
        assert_eq!(open(&[8; 32], 5, &b), Err(Error::Crypto));
        assert_eq!((b.len() - NONCE_LEN - 16) % PAD, 0);
    }

    #[test]
    fn a_status_disappears_at_its_expiry() {
        let p = sample();
        assert!(p.status_at(999).is_some());
        assert!(p.status_at(1_000).is_none());
        let forever = ProfilePlain {
            status: Some(Status {
                expires_ms: 0,
                ..sample().status.unwrap()
            }),
            ..sample()
        };
        assert!(forever.status_at(u64::MAX).is_some());
    }

    #[test]
    fn fields_are_bounded_and_a_full_profile_fits_the_server_limit() {
        let mut p = sample();
        p.about = "a".repeat(MAX_ABOUT + 1);
        assert_eq!(p.validate(), Err(Error::Invalid("profile.about")));
        let full = ProfilePlain {
            name: "n".repeat(MAX_NAME),
            about: "a".repeat(MAX_ABOUT),
            status: Some(Status {
                text: "s".repeat(MAX_STATUS),
                emoji: "e".repeat(MAX_EMOJI),
                expires_ms: u64::MAX,
            }),
            avatar: Some(Avatar {
                id: vec![1; 32],
                key: vec![2; 32],
            }),
            links: vec!["l".repeat(MAX_LINK); MAX_LINKS],
        };
        assert!(seal(&[1; 32], 1, &full).unwrap().len() <= MAX_BLOB);
    }
}
