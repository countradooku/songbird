//! Device authentication transcript (`docs/PROTOCOL.md` §2.2).
//!
//! The device signs, with its Ed25519 authentication key:
//!
//! ```text
//! "songbird.v1/device-auth\0" || u8 len(server_name) || server_name || nonce[32]
//!   || device_id[16] || protocol_version u32 (big-endian)
//! ```
//!
//! - The context string separates this signature from every other use of the key.
//! - The server name binds the signature to one endpoint: a malicious server cannot replay it
//!   to another (the client takes the name from its own configuration, never from `Hello`).
//! - The nonce is fresh per connection (32 random bytes): a recorded signature is useless.
//! - The device ID and protocol version stop a signature for one device or version being
//!   presented as another.
//!
//! This crate only builds the bytes; signing lives in the client and verification in the
//! server, so the protocol crate needs no cryptography dependency.

use songbird_types::DeviceId;
use songbird_types::id::ID_LEN;

use crate::NONCE_LEN;
use crate::control::MAX_SERVER_NAME_LEN;

/// Domain-separation prefix.
pub const CONTEXT: &[u8] = b"songbird.v1/device-auth\0";

/// Why a transcript could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TranscriptError {
    /// Server name empty or longer than 253 bytes.
    #[error("server name length")]
    ServerName,
    /// Nonce not 32 bytes.
    #[error("nonce length")]
    Nonce,
}

/// Longest transcript.
pub const MAX_TRANSCRIPT_LEN: usize =
    CONTEXT.len() + 1 + MAX_SERVER_NAME_LEN + NONCE_LEN + ID_LEN + 4;

/// The bytes a device signs.
///
/// # Errors
/// [`TranscriptError`] for a bad server name or nonce length.
pub fn transcript(
    server_name: &str,
    nonce: &[u8],
    device: &DeviceId,
    protocol_version: u32,
) -> Result<Vec<u8>, TranscriptError> {
    let name_len = u8::try_from(server_name.len()).map_err(|_| TranscriptError::ServerName)?;
    if server_name.is_empty() || server_name.len() > MAX_SERVER_NAME_LEN {
        return Err(TranscriptError::ServerName);
    }
    if nonce.len() != NONCE_LEN {
        return Err(TranscriptError::Nonce);
    }
    let mut out = Vec::with_capacity(MAX_TRANSCRIPT_LEN);
    out.extend_from_slice(CONTEXT);
    out.push(name_len);
    out.extend_from_slice(server_name.as_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(&protocol_version.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector() {
        let t = transcript(
            "chat.example",
            &[0x11; NONCE_LEN],
            &DeviceId::from_bytes([0x22; ID_LEN]),
            1,
        )
        .unwrap();
        let expected = format!(
            "{}{}{}{}{}{}",
            hex::encode(CONTEXT),
            "0c",
            hex::encode("chat.example"),
            "11".repeat(32),
            "22".repeat(16),
            "00000001"
        );
        assert_eq!(hex::encode(&t), expected);
        assert!(t.len() <= MAX_TRANSCRIPT_LEN);
    }

    #[test]
    fn rejects_bad_inputs() {
        let d = DeviceId::from_bytes([0; ID_LEN]);
        assert_eq!(
            transcript("", &[0; NONCE_LEN], &d, 1),
            Err(TranscriptError::ServerName)
        );
        assert_eq!(
            transcript(&"a".repeat(254), &[0; NONCE_LEN], &d, 1),
            Err(TranscriptError::ServerName)
        );
        assert_eq!(
            transcript("x", &[0; 31], &d, 1),
            Err(TranscriptError::Nonce)
        );
    }

    #[test]
    fn every_field_changes_the_transcript() {
        let d = DeviceId::from_bytes([1; ID_LEN]);
        let base = transcript("a.example", &[0; NONCE_LEN], &d, 1).unwrap();
        assert_ne!(
            base,
            transcript("b.example", &[0; NONCE_LEN], &d, 1).unwrap()
        );
        assert_ne!(
            base,
            transcript("a.example", &[1; NONCE_LEN], &d, 1).unwrap()
        );
        assert_ne!(
            base,
            transcript(
                "a.example",
                &[0; NONCE_LEN],
                &DeviceId::from_bytes([2; ID_LEN]),
                1
            )
            .unwrap()
        );
        assert_ne!(
            base,
            transcript("a.example", &[0; NONCE_LEN], &d, 2).unwrap()
        );
    }
}
