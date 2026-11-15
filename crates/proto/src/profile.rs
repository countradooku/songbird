//! Encrypted profiles and sealed sender (`docs/PROTOCOL.md` §4.8; Prompt 3, M5; D-0054).
//!
//! # Profile upload (`PUT /v1/profile`)
//!
//! ```text
//! version u8 (1) | profile_version u64 | access_key [16] | flags u8 (1 anyone may send sealed)
//!   | len u16 | blob (1..=8192)
//! ```
//!
//! `blob` is the profile (name, avatar pointer, about, status line, profile links) encrypted by
//! the client under its profile key, which it shares only with contacts; the server stores it
//! opaque. `access_key` is the unidentified-access key derived from the profile key
//! (`songbird_keys::sealed::access_key`); a sealed send to the account must present it.
//!
//! # Sender certificate (`GET /v1/certificate`)
//!
//! ```text
//! version u8 (1) | key_id [8] | account [16] | device [16] | identity_key [33] | expires_ms u64
//!   | signature [64]
//! ```
//!
//! Ed25519 by the server's certificate key over `"songbird.v1/sender-certificate\0"` followed by
//! every byte before the signature. The sender puts it inside the end-to-end encrypted envelope;
//! the recipient checks it against the pinned certificate key and the sender's identity key.

use songbird_types::id::ID_LEN;
use songbird_types::{AccountId, DeviceId};

/// Format version.
pub const VERSION: u8 = 1;
/// Largest encrypted profile.
pub const MAX_PROFILE: usize = 8192;
/// Unidentified-access key length.
pub const ACCESS_KEY_LEN: usize = 16;
/// Largest encrypted avatar.
pub const MAX_AVATAR: usize = 512 * 1024;
/// Domain separation of the certificate signature.
pub const CERTIFICATE_CONTEXT: &[u8] = b"songbird.v1/sender-certificate\0";
/// Certificate length.
pub const CERTIFICATE_LEN: usize = 1 + 8 + ID_LEN + ID_LEN + 33 + 8 + 64;

const FLAG_OPEN: u8 = 1;

/// Why bytes did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed profile message")]
pub struct ProfileError;

/// A profile upload.
#[derive(Clone, PartialEq, Eq)]
pub struct ProfileUpload {
    /// Strictly increasing.
    pub profile_version: u64,
    /// The unidentified-access key for sealed sends to this account.
    pub access_key: [u8; ACCESS_KEY_LEN],
    /// Anyone may send sealed to this account (no access key needed).
    pub open: bool,
    /// The encrypted profile.
    pub blob: Vec<u8>,
}

impl std::fmt::Debug for ProfileUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileUpload")
            .field("profile_version", &self.profile_version)
            .field("blob", &self.blob.len())
            .finish_non_exhaustive()
    }
}

impl ProfileUpload {
    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 8 + ACCESS_KEY_LEN + 1 + 2 + self.blob.len());
        b.push(VERSION);
        b.extend_from_slice(&self.profile_version.to_be_bytes());
        b.extend_from_slice(&self.access_key);
        b.push(if self.open { FLAG_OPEN } else { 0 });
        b.extend_from_slice(
            &u16::try_from(self.blob.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        b.extend_from_slice(&self.blob);
        b
    }

    /// Decodes the whole input.
    ///
    /// # Errors
    /// [`ProfileError`].
    pub fn decode(input: &[u8]) -> Result<Self, ProfileError> {
        let (&version, rest) = input.split_first().ok_or(ProfileError)?;
        let (v, rest) = rest.split_first_chunk::<8>().ok_or(ProfileError)?;
        let (key, rest) = rest
            .split_first_chunk::<ACCESS_KEY_LEN>()
            .ok_or(ProfileError)?;
        let (&flags, rest) = rest.split_first().ok_or(ProfileError)?;
        let (len, blob) = rest.split_first_chunk::<2>().ok_or(ProfileError)?;
        let len = usize::from(u16::from_be_bytes(*len));
        if version != VERSION
            || flags & !FLAG_OPEN != 0
            || len == 0
            || len > MAX_PROFILE
            || blob.len() != len
        {
            return Err(ProfileError);
        }
        Ok(Self {
            profile_version: u64::from_be_bytes(*v),
            access_key: *key,
            open: flags & FLAG_OPEN != 0,
            blob: blob.to_vec(),
        })
    }
}

/// A sender certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderCertificate {
    /// The signing key's ID (first 8 bytes of SHA-256 of its public key).
    pub key_id: [u8; 8],
    /// The sender's account.
    pub account: AccountId,
    /// The sender's device.
    pub device: DeviceId,
    /// The sender device's identity key (`0x05 || u`).
    pub identity_key: [u8; 33],
    /// Not valid at or after this time (Unix milliseconds).
    pub expires_ms: u64,
    /// Ed25519 by the certificate key over [`SenderCertificate::signed_bytes`].
    pub signature: [u8; 64],
}

fn arr<const N: usize>(input: &[u8], at: usize) -> Result<[u8; N], ProfileError> {
    input
        .get(at..at + N)
        .and_then(|s| s.try_into().ok())
        .ok_or(ProfileError)
}

impl SenderCertificate {
    fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(CERTIFICATE_LEN);
        b.push(VERSION);
        b.extend_from_slice(&self.key_id);
        b.extend_from_slice(self.account.as_bytes());
        b.extend_from_slice(self.device.as_bytes());
        b.extend_from_slice(&self.identity_key);
        b.extend_from_slice(&self.expires_ms.to_be_bytes());
        b
    }

    /// What the signature covers: [`CERTIFICATE_CONTEXT`] then every byte before it.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut b = CERTIFICATE_CONTEXT.to_vec();
        b.extend_from_slice(&self.body());
        b
    }

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decodes exactly [`CERTIFICATE_LEN`] bytes.
    ///
    /// # Errors
    /// [`ProfileError`].
    pub fn decode(input: &[u8]) -> Result<Self, ProfileError> {
        if input.len() != CERTIFICATE_LEN || input.first() != Some(&VERSION) {
            return Err(ProfileError);
        }
        Ok(Self {
            key_id: arr(input, 1)?,
            account: AccountId::from_bytes(arr(input, 9)?),
            device: DeviceId::from_bytes(arr(input, 25)?),
            identity_key: arr(input, 41)?,
            expires_ms: u64::from_be_bytes(arr(input, 74)?),
            signature: arr(input, 82)?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn uploads_and_certificates_round_trip_and_decode_strictly() {
        let u = ProfileUpload {
            profile_version: 3,
            access_key: [1; 16],
            open: true,
            blob: vec![9; 100],
        };
        let b = u.encode();
        assert_eq!(ProfileUpload::decode(&b), Ok(u.clone()));
        for cut in 0..b.len() {
            assert!(ProfileUpload::decode(&b[..cut]).is_err());
        }
        let mut long = b.clone();
        long.push(0);
        assert!(ProfileUpload::decode(&long).is_err());
        let mut flags = b;
        flags[25] = 2;
        assert!(ProfileUpload::decode(&flags).is_err());
        let big = ProfileUpload {
            blob: vec![0; MAX_PROFILE + 1],
            ..u.clone()
        };
        assert!(ProfileUpload::decode(&big.encode()).is_err());
        let empty = ProfileUpload { blob: vec![], ..u };
        assert!(ProfileUpload::decode(&empty.encode()).is_err());

        let c = SenderCertificate {
            key_id: [1; 8],
            account: AccountId::from_bytes([2; 16]),
            device: DeviceId::from_bytes([3; 16]),
            identity_key: [5; 33],
            expires_ms: 1_000,
            signature: [7; 64],
        };
        let b = c.encode();
        assert_eq!(b.len(), CERTIFICATE_LEN);
        assert_eq!(SenderCertificate::decode(&b), Ok(c.clone()));
        assert!(SenderCertificate::decode(&b[..CERTIFICATE_LEN - 1]).is_err());
        assert_eq!(
            &c.signed_bytes()[..CERTIFICATE_CONTEXT.len()],
            CERTIFICATE_CONTEXT
        );
    }

    proptest! {
        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = ProfileUpload::decode(&b);
            let _ = SenderCertificate::decode(&b);
        }
    }
}
