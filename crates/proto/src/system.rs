//! Server-signed system frames (D-0037, D-0044): notices the server itself sends a device, such
//! as "your device list changed". They are never user messages.
//!
//! A system frame travels as an ordinary mailbox envelope, so it is stored before it is
//! acknowledged, ordered by `seq`, delivered after an offline device reconnects and wakes it with
//! a push, exactly like a message. What makes it the server's:
//!
//! - **A reserved format.** It begins with [`MAGIC`]. The send path refuses any user envelope
//!   that begins with it (reject reason 9, `ReservedEnvelope`), so no user can make another
//!   device's client even consider a forged notice.
//! - **A signature.** Ed25519 by the server's system key over [`DOMAIN`] followed by every byte
//!   before the signature. The app pins the public key; [`SystemFrame::key_id`] names which key
//!   (rotation). A frame that does not verify is dropped and never shown.
//! - **Bound to one device and one moment.** The recipient device is inside the signed bytes (a
//!   notice cannot be replayed to another device), with the issue time and a random notice ID
//!   (clients drop repeats).
//!
//! This module is the format only (this crate stays free of cryptography so it builds for every
//! client target): the server signs [`signing_input`](SystemFrame::signing_input) with
//! `songbird-send`'s `system::SystemSigner`, and clients verify it with `songbird-client`.
//!
//! ```text
//! magic [8] | version u8 | key_id [8] | device [16] | issued_at_ms u64 | notice_id [16]
//!   | kind u16 | body_len u16 | body [body_len] | signature [64]
//! ```

use bytes::{BufMut as _, Bytes, BytesMut};
use songbird_types::{AccountId, DeviceId};

use crate::SIGNATURE_LEN;
use crate::frame::FrameError;

/// The first bytes of every system frame. `0xF5` is not a valid first byte of UTF-8 text, and
/// the eight bytes together are what the send path refuses in user envelopes.
pub const MAGIC: [u8; 8] = [0xF5, b'S', b'B', b'S', b'Y', b'S', 0x00, 0x01];
/// The format version this crate writes and reads.
pub const VERSION: u8 = 1;
/// Length of the signing key's identifier (the first bytes of SHA-256 of the public key).
pub const KEY_ID_LEN: usize = 8;
/// Length of a notice ID.
pub const NOTICE_ID_LEN: usize = 16;
/// Largest body.
pub const MAX_BODY: usize = 1024;
/// Domain separation: prefixed to the signed bytes, so a system-frame signature is never valid
/// for anything else the key could sign (and no device signature is ever valid as one).
pub const DOMAIN: &[u8] = b"songbird-system-frame-v1\0";
/// Bytes before the body.
pub const HEADER_LEN: usize = MAGIC.len() + 1 + KEY_ID_LEN + 16 + 8 + NOTICE_ID_LEN + 2 + 2;
/// Largest encoded frame.
pub const MAX_LEN: usize = HEADER_LEN + MAX_BODY + SIGNATURE_LEN;

/// Whether an envelope is in the system-frame format (signed or not).
#[must_use]
pub fn is_system(envelope: &[u8]) -> bool {
    envelope.starts_with(&MAGIC)
}

/// What a notice is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An account's device list changed (body: [`DeviceListChanged`]); fetch it again before the
    /// next send to that account.
    DeviceListChanged,
    /// This device's one-time prekeys are running low (body: [`PrekeysLow`]); upload more.
    PrekeysLow,
    /// This device's single-use MLS KeyPackages are running low (body: `n u16`, how many are
    /// left); upload more.
    KeyPackagesLow,
    /// A kind this version does not know (forward compatibility: verify, then ignore).
    Other(u16),
}

impl Kind {
    /// Wire value.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::DeviceListChanged => 1,
            Self::PrekeysLow => 2,
            Self::KeyPackagesLow => 3,
            Self::Other(c) => c,
        }
    }

    /// From a wire value.
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            1 => Self::DeviceListChanged,
            2 => Self::PrekeysLow,
            3 => Self::KeyPackagesLow,
            c => Self::Other(c),
        }
    }
}

/// Body of [`Kind::DeviceListChanged`]: whose device list changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceListChanged {
    /// The account.
    pub account: AccountId,
}

impl DeviceListChanged {
    /// Encoded body.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(self.account.as_bytes())
    }

    /// Parses a body.
    ///
    /// # Errors
    /// [`FrameError::Truncated`] or [`FrameError::Trailing`].
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        let bytes: [u8; 16] = match body.len() {
            n if n < 16 => return Err(FrameError::Truncated),
            16 => body.try_into().map_err(|_| FrameError::Truncated)?,
            _ => return Err(FrameError::Trailing),
        };
        Ok(Self {
            account: AccountId::from_bytes(bytes),
        })
    }
}

/// Body of [`Kind::PrekeysLow`]: how many one-time prekeys the device has left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrekeysLow {
    /// One-time X25519 prekeys left.
    pub ec: u16,
    /// One-time ML-KEM-1024 prekeys left.
    pub kem: u16,
}

impl PrekeysLow {
    /// Encoded body: `ec u16 | kem u16`.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut b = Vec::with_capacity(4);
        b.extend_from_slice(&self.ec.to_be_bytes());
        b.extend_from_slice(&self.kem.to_be_bytes());
        Bytes::from(b)
    }

    /// Parses a body.
    ///
    /// # Errors
    /// [`FrameError::Truncated`] or [`FrameError::Trailing`].
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        let b: [u8; 4] = match body.len() {
            n if n < 4 => return Err(FrameError::Truncated),
            4 => body.try_into().map_err(|_| FrameError::Truncated)?,
            _ => return Err(FrameError::Trailing),
        };
        Ok(Self {
            ec: u16::from_be_bytes([b[0], b[1]]),
            kem: u16::from_be_bytes([b[2], b[3]]),
        })
    }
}

/// A system frame without its signature.
#[derive(Clone, PartialEq, Eq)]
pub struct SystemFrame {
    /// Which server key signs it.
    pub key_id: [u8; KEY_ID_LEN],
    /// The one device it is for.
    pub device: DeviceId,
    /// When the server issued it.
    pub issued_at_ms: u64,
    /// Random; clients drop a notice they have seen (it is also the send's idempotency key).
    pub notice_id: [u8; NOTICE_ID_LEN],
    /// What it is about.
    pub kind: Kind,
    /// Kind-specific body, at most [`MAX_BODY`] bytes.
    pub body: Bytes,
}

impl std::fmt::Debug for SystemFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemFrame")
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// A received system frame: the frame, the bytes its signature covers (without [`DOMAIN`]) and
/// the signature. Nothing in it is trusted until the signature verifies.
#[derive(Debug, Clone)]
pub struct Unverified {
    /// The decoded frame.
    pub frame: SystemFrame,
    /// Every byte before the signature.
    pub signed: Bytes,
    /// The Ed25519 signature.
    pub signature: [u8; SIGNATURE_LEN],
}

impl Unverified {
    /// The message the signature must verify over: [`DOMAIN`] then the signed bytes.
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        message(&self.signed)
    }
}

fn message(signed: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + signed.len());
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(signed);
    m
}

impl SystemFrame {
    fn encode_unsigned(&self) -> Result<BytesMut, FrameError> {
        if self.body.len() > MAX_BODY {
            return Err(FrameError::TooLarge {
                what: "system frame body",
                got: self.body.len(),
                limit: MAX_BODY,
            });
        }
        let body_len = u16::try_from(self.body.len()).map_err(|_| FrameError::Truncated)?;
        let mut b = BytesMut::with_capacity(HEADER_LEN + self.body.len() + SIGNATURE_LEN);
        b.put_slice(&MAGIC);
        b.put_u8(VERSION);
        b.put_slice(&self.key_id);
        b.put_slice(self.device.as_bytes());
        b.put_u64(self.issued_at_ms);
        b.put_slice(&self.notice_id);
        b.put_u16(self.kind.code());
        b.put_u16(body_len);
        b.put_slice(&self.body);
        Ok(b)
    }

    /// The message the server signs: [`DOMAIN`] followed by the frame's bytes up to the
    /// signature.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`] for a body over [`MAX_BODY`].
    pub fn signing_input(&self) -> Result<Vec<u8>, FrameError> {
        Ok(message(&self.encode_unsigned()?))
    }

    /// The envelope: the frame followed by its signature.
    ///
    /// # Errors
    /// [`FrameError::TooLarge`] for a body over [`MAX_BODY`].
    pub fn encode_signed(&self, signature: &[u8; SIGNATURE_LEN]) -> Result<Bytes, FrameError> {
        let mut b = self.encode_unsigned()?;
        b.put_slice(signature);
        Ok(b.freeze())
    }

    /// Parses an envelope in the system-frame format (bounded, no allocation but the returned
    /// slices of `envelope`). The signature still has to be verified.
    ///
    /// # Errors
    /// [`FrameError`]: not a system frame, another version, truncated, too large or trailing
    /// bytes.
    pub fn decode(envelope: &Bytes) -> Result<Unverified, FrameError> {
        let e = envelope.as_ref();
        if !is_system(e) {
            return Err(FrameError::Control("not a system frame"));
        }
        if e.len() > MAX_LEN {
            return Err(FrameError::TooLarge {
                what: "system frame",
                got: e.len(),
                limit: MAX_LEN,
            });
        }
        if e.len() < HEADER_LEN + SIGNATURE_LEN {
            return Err(FrameError::Truncated);
        }
        let mut r = Reader { e, at: MAGIC.len() };
        if r.take(1)? != [VERSION] {
            return Err(FrameError::Control("system frame version unsupported"));
        }
        let key_id: [u8; KEY_ID_LEN] = r.array()?;
        let device = DeviceId::from_bytes(r.array()?);
        let issued_at_ms = u64::from_be_bytes(r.array()?);
        let notice_id: [u8; NOTICE_ID_LEN] = r.array()?;
        let kind = Kind::from_code(u16::from_be_bytes(r.array()?));
        let body_len = usize::from(u16::from_be_bytes(r.array()?));
        if body_len > MAX_BODY {
            return Err(FrameError::TooLarge {
                what: "system frame body",
                got: body_len,
                limit: MAX_BODY,
            });
        }
        let body_at = r.at;
        r.take(body_len)?;
        let signed_len = r.at;
        let signature: [u8; SIGNATURE_LEN] = r.array()?;
        if r.at != e.len() {
            return Err(FrameError::Trailing);
        }
        Ok(Unverified {
            frame: Self {
                key_id,
                device,
                issued_at_ms,
                notice_id,
                kind,
                body: envelope.slice(body_at..body_at + body_len),
            },
            signed: envelope.slice(..signed_len),
            signature,
        })
    }
}

/// A bounds-checked cursor over a received frame.
struct Reader<'a> {
    e: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        let end = self.at.checked_add(n).ok_or(FrameError::Truncated)?;
        let s = self.e.get(self.at..end).ok_or(FrameError::Truncated)?;
        self.at = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        self.take(N)?.try_into().map_err(|_| FrameError::Truncated)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn frame() -> SystemFrame {
        SystemFrame {
            key_id: [7; KEY_ID_LEN],
            device: DeviceId::from_bytes([1; 16]),
            issued_at_ms: 1_763_000_000_000,
            notice_id: [9; NOTICE_ID_LEN],
            kind: Kind::DeviceListChanged,
            body: DeviceListChanged {
                account: AccountId::from_bytes([2; 16]),
            }
            .encode(),
        }
    }

    #[test]
    fn system_frames_round_trip_and_sign_everything_but_the_signature() {
        let f = frame();
        let sig = [0xAB; SIGNATURE_LEN];
        let env = f.encode_signed(&sig).unwrap();
        assert!(is_system(&env));
        let u = SystemFrame::decode(&env).unwrap();
        assert_eq!(u.frame, f);
        assert_eq!(u.signature, sig);
        assert_eq!(u.message(), f.signing_input().unwrap());
        assert!(u.message().starts_with(DOMAIN));
        assert_eq!(
            DeviceListChanged::decode(&u.frame.body).unwrap().account,
            AccountId::from_bytes([2; 16])
        );
        // The vector is fixed: any change to the layout fails here.
        assert_eq!(env.len(), HEADER_LEN + 16 + SIGNATURE_LEN);
        assert_eq!(
            hex::encode(&env[..HEADER_LEN]),
            concat!(
                "f553425359530001",                 // magic
                "01",                               // version
                "0707070707070707",                 // key_id
                "01010101010101010101010101010101", // device
                "0000019a7afd1e00",                 // issued_at_ms
                "09090909090909090909090909090909", // notice_id
                "0001",                             // kind: device list changed
                "0010",                             // body_len
            )
        );
    }

    #[test]
    fn malformed_system_frames_are_refused() {
        let env = frame().encode_signed(&[0; SIGNATURE_LEN]).unwrap();
        // Truncated anywhere.
        for n in 0..env.len() {
            assert!(SystemFrame::decode(&env.slice(..n)).is_err(), "length {n}");
        }
        // Trailing byte.
        let mut long = env.to_vec();
        long.push(0);
        assert_eq!(
            SystemFrame::decode(&Bytes::from(long)).unwrap_err(),
            FrameError::Trailing
        );
        // Another version.
        let mut v2 = env.to_vec();
        v2[MAGIC.len()] = 2;
        assert!(SystemFrame::decode(&Bytes::from(v2)).is_err());
        // An oversized body is refused before encoding and before decoding.
        let mut big = frame();
        big.body = Bytes::from(vec![0; MAX_BODY + 1]);
        assert!(big.signing_input().is_err());
        // Not a system frame at all.
        assert!(SystemFrame::decode(&Bytes::from_static(b"ciphertext")).is_err());
    }

    #[test]
    fn debug_output_hides_identifiers() {
        let s = format!("{:?}", frame());
        assert!(!s.contains("01010101") && !s.contains("[1, 1"));
    }

    proptest! {
        #[test]
        fn decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1200)) {
            let mut with_magic = MAGIC.to_vec();
            with_magic.extend_from_slice(&data);
            let _ = SystemFrame::decode(&Bytes::from(with_magic));
            let _ = SystemFrame::decode(&Bytes::from(data));
        }
    }
}
