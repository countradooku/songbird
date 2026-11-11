//! Device authentication transcript (`docs/PROTOCOL.md` §2.2).
//!
//! The device signs, with its Ed25519 authentication key:
//!
//! ```text
//! "songbird.v1/device-auth\0" || u8 len(server_name) || server_name || nonce[32]
//!   || device_id[16] || protocol_version u32 (big-endian) || channel_binding[32]
//! ```
//!
//! The only variable-length field (the server name) is length-prefixed; every other field has a
//! fixed length, so the encoding is unambiguous.
//!
//! - The context string separates this signature from every other use of the key.
//! - The server name binds the signature to one endpoint: a malicious server cannot replay it
//!   to another (the client takes the name from its own configuration, never from `Hello`).
//! - The nonce is fresh per connection (32 random bytes): a recorded signature is useless.
//! - The device ID and protocol version stop a signature for one device or version being
//!   presented as another.
//! - The channel binding ties the signature to this TLS connection (RFC 9266 `tls-exporter`:
//!   32 bytes exported with label [`EXPORTER_LABEL`] and no context). An attacker who terminates
//!   TLS in the middle (a misissued certificate, an interception proxy) and relays the nonce to
//!   the device gets a signature over *its* TLS session's exporter, which the server's side of a
//!   different session does not match. Without TLS (development only) it is
//!   [`NO_CHANNEL_BINDING`]. WhatsApp's Noise handshake gets the same property by construction
//!   (D-0018).
//!
//! This crate only builds the bytes; signing lives in the client and verification in the
//! server, so the protocol crate needs no cryptography dependency.

use songbird_types::DeviceId;
use songbird_types::id::ID_LEN;

use crate::NONCE_LEN;
use crate::control::MAX_SERVER_NAME_LEN;

/// Domain-separation prefix.
pub const CONTEXT: &[u8] = b"songbird.v1/device-auth\0";

/// TLS exporter label for the channel binding (RFC 9266).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
/// Length of the channel binding.
pub const CHANNEL_BINDING_LEN: usize = 32;
/// Channel binding of a connection without TLS (development and tests only; the server requires
/// TLS outside development).
pub const NO_CHANNEL_BINDING: [u8; CHANNEL_BINDING_LEN] = [0; CHANNEL_BINDING_LEN];

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
    CONTEXT.len() + 1 + MAX_SERVER_NAME_LEN + NONCE_LEN + ID_LEN + 4 + CHANNEL_BINDING_LEN;

/// The bytes a device signs.
///
/// # Errors
/// [`TranscriptError`] for a bad server name or nonce length.
pub fn transcript(
    server_name: &str,
    nonce: &[u8],
    device: &DeviceId,
    protocol_version: u32,
    channel_binding: &[u8; CHANNEL_BINDING_LEN],
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
    out.extend_from_slice(channel_binding);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The fixed-nonce test vector is in `tests/vectors.rs` (published in PROTOCOL.md §13). These
    // tests do not depend on the nonce's value, so they use a fresh random one.
    fn nonce() -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        getrandom::fill(&mut n).unwrap();
        n
    }

    #[test]
    fn length_is_bounded() {
        let t = transcript(
            &"a".repeat(253),
            &nonce(),
            &DeviceId::random().unwrap(),
            1,
            &NO_CHANNEL_BINDING,
        )
        .unwrap();
        assert_eq!(t.len(), MAX_TRANSCRIPT_LEN);
        assert!(t.starts_with(CONTEXT));
    }

    #[test]
    fn rejects_bad_inputs() {
        let d = DeviceId::random().unwrap();
        let n = nonce();
        assert_eq!(
            transcript("", &n, &d, 1, &NO_CHANNEL_BINDING),
            Err(TranscriptError::ServerName)
        );
        assert_eq!(
            transcript(&"a".repeat(254), &n, &d, 1, &NO_CHANNEL_BINDING),
            Err(TranscriptError::ServerName)
        );
        assert_eq!(
            transcript("x", n.get(..31).unwrap(), &d, 1, &NO_CHANNEL_BINDING),
            Err(TranscriptError::Nonce)
        );
    }

    #[test]
    fn every_field_changes_the_transcript() {
        let d = DeviceId::random().unwrap();
        let n = nonce();
        let base = transcript("a.example", &n, &d, 1, &NO_CHANNEL_BINDING).unwrap();
        assert_ne!(
            base,
            transcript("b.example", &n, &d, 1, &NO_CHANNEL_BINDING).unwrap()
        );
        assert_ne!(
            base,
            transcript("a.example", &nonce(), &d, 1, &NO_CHANNEL_BINDING).unwrap()
        );
        assert_ne!(
            base,
            transcript(
                "a.example",
                &n,
                &DeviceId::random().unwrap(),
                1,
                &NO_CHANNEL_BINDING
            )
            .unwrap()
        );
        assert_ne!(
            base,
            transcript("a.example", &n, &d, 2, &NO_CHANNEL_BINDING).unwrap()
        );
        assert_ne!(base, transcript("a.example", &n, &d, 1, &[1; 32]).unwrap());
    }
}
