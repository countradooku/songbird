//! Control frames: rare messages with a protobuf body (`prost`), framed by a one-byte type in
//! [`crate::frame`].
//!
//! Protobuf lets these evolve (new optional fields) without a new frame type. They are never on
//! the per-message hot path. Each body is at most [`crate::Limits::max_control_bytes`] long; the
//! frame decoder checks that before handing the bytes to `prost`, so a decoded `bytes` or
//! `string` field can never be larger than the frame it came from.
//!
//! `Debug` is written by hand for every message that carries an identifier or key material
//! (invariant 6): `prost`'s derived `Debug` would print them.

use std::fmt;

use songbird_types::DeviceId;

use crate::frame::FrameError;
use crate::{IDEMPOTENCY_KEY_LEN, NONCE_LEN, PROTOCOL_VERSION, SIGNATURE_LEN};

/// Longest `client_version` string accepted.
pub const MAX_CLIENT_VERSION_LEN: usize = 64;
/// Longest `server_name` accepted (a DNS name).
pub const MAX_SERVER_NAME_LEN: usize = 253;
/// Most protocol versions a server may advertise.
pub const MAX_PROTOCOL_VERSIONS: usize = 8;
/// Most device IDs in one list of a [`DeviceMismatch`].
pub const MAX_MISMATCH_DEVICES: usize = 1024;

/// First frame on every connection, sent by the server.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Hello {
    /// Fresh random challenge, [`NONCE_LEN`] bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
    /// Server wall clock, milliseconds since the Unix epoch (clients use it for clock skew only).
    #[prost(uint64, tag = "2")]
    pub server_time_ms: u64,
    /// Protocol versions the server speaks, preferred first.
    #[prost(uint32, repeated, tag = "3")]
    pub protocol_versions: Vec<u32>,
    /// Incremented by every restore from backup; clients resend unreceipted messages when it
    /// grows (`docs/PROTOCOL.md` §3.6).
    #[prost(uint64, tag = "4")]
    pub store_generation: u64,
    /// The name the device must sign (the public host name of the endpoint).
    #[prost(string, tag = "5")]
    pub server_name: String,
}

impl Hello {
    /// Checks field shapes.
    ///
    /// # Errors
    /// [`FrameError::Control`] naming the first bad field.
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.nonce.len() != NONCE_LEN {
            return Err(FrameError::Control("hello.nonce length"));
        }
        if self.protocol_versions.is_empty() || self.protocol_versions.len() > MAX_PROTOCOL_VERSIONS
        {
            return Err(FrameError::Control("hello.protocol_versions count"));
        }
        if self.server_name.is_empty() || self.server_name.len() > MAX_SERVER_NAME_LEN {
            return Err(FrameError::Control("hello.server_name length"));
        }
        Ok(())
    }
}

/// The device's answer to [`Hello`], within the authentication timeout.
#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Auth {
    /// The device, 16 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub device_id: Vec<u8>,
    /// Ed25519 signature by the device's authentication key over
    /// [`crate::auth::transcript`], [`SIGNATURE_LEN`] bytes.
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    /// Highest `seq` the device has stored durably and acknowledged; delivery resumes after it.
    #[prost(uint64, tag = "3")]
    pub last_acked_seq: u64,
    /// Free-form client build string, at most [`MAX_CLIENT_VERSION_LEN`] printable ASCII bytes.
    #[prost(string, tag = "4")]
    pub client_version: String,
    /// The protocol version the client chose from [`Hello::protocol_versions`].
    #[prost(uint32, tag = "5")]
    pub protocol_version: u32,
}

impl Auth {
    /// Checks field shapes and returns the device ID.
    ///
    /// # Errors
    /// [`FrameError::Control`] naming the first bad field.
    pub fn validate(&self) -> Result<DeviceId, FrameError> {
        let device = DeviceId::from_slice(&self.device_id)
            .map_err(|_| FrameError::Control("auth.device_id length"))?;
        if self.signature.len() != SIGNATURE_LEN {
            return Err(FrameError::Control("auth.signature length"));
        }
        if self.client_version.len() > MAX_CLIENT_VERSION_LEN
            || !self
                .client_version
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(FrameError::Control("auth.client_version"));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(FrameError::Control("auth.protocol_version unsupported"));
        }
        Ok(device)
    }
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Auth")
            .field("device_id", &"<redacted>")
            .field("signature", &"<redacted>")
            .field("last_acked_seq", &self.last_acked_seq)
            .field("client_version", &self.client_version)
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

/// Authentication succeeded; live delivery follows.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct AuthOk {
    /// Same value as in [`Hello`], repeated so it is bound to the authenticated session.
    #[prost(uint64, tag = "1")]
    pub store_generation: u64,
    /// Delivery resumes with the first `seq` after this one.
    #[prost(uint64, tag = "2")]
    pub resume_after_seq: u64,
}

/// A connection-level error sent just before the server closes the socket, when the close
/// code alone is not enough. Carries no free text: codes are documented in `PROTOCOL.md`.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Error {
    /// Same numbering as the close code that follows.
    #[prost(uint32, tag = "1")]
    pub code: u32,
    /// Suggested wait before reconnecting, in milliseconds (0: use the close-code range rule).
    #[prost(uint32, tag = "2")]
    pub retry_after_ms: u32,
}

/// Why a send was rejected because the sender's view of a recipient account's devices is out of
/// date. The client re-encrypts for the corrected device list and retries.
#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct DeviceMismatch {
    /// Devices the sender must add.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub missing: Vec<Vec<u8>>,
    /// Devices the sender must drop (they no longer exist).
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub extra: Vec<Vec<u8>>,
    /// Devices whose keys changed since the sender's session was set up.
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub stale: Vec<Vec<u8>>,
}

impl DeviceMismatch {
    /// Checks list sizes and that every entry is a 16-byte device ID.
    ///
    /// # Errors
    /// [`FrameError::Control`] naming the first bad list.
    pub fn validate(&self) -> Result<(), FrameError> {
        for (list, name) in [
            (&self.missing, "mismatch.missing"),
            (&self.extra, "mismatch.extra"),
            (&self.stale, "mismatch.stale"),
        ] {
            if list.len() > MAX_MISMATCH_DEVICES
                || list.iter().any(|d| d.len() != songbird_types::id::ID_LEN)
            {
                return Err(FrameError::Control(name));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DeviceMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceMismatch")
            .field("missing", &self.missing.len())
            .field("extra", &self.extra.len())
            .field("stale", &self.stale.len())
            .finish()
    }
}

// Compile-time guard: the idempotency key is an ID-sized value.
const _: () = assert!(IDEMPOTENCY_KEY_LEN == songbird_types::id::ID_LEN);
