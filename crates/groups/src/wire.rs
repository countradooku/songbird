//! Hand-written, allocation-free parsers for what the delivery service reads on its own:
//! the plaintext prefix of an MLS `PrivateMessage` (hot path) and Songbird's commit bundle.
//!
//! RFC 9420 §6: `MLSMessage { uint16 version = mls10 (1); uint16 wire_format; ... }`, and
//! `PrivateMessage { opaque group_id<V>; uint64 epoch; ContentType content_type;
//! opaque authenticated_data<V>; opaque encrypted_sender_data<V>; opaque ciphertext<V>; }`.
//! `<V>` lengths are RFC 9420 §2.1.2 variable-length integers; Songbird requires the minimal
//! encoding (as D-0051 does), so every message has one encoding.

/// `mls10`.
pub const MLS10: u16 = 1;
/// RFC 9420 wire formats.
pub const WIRE_PUBLIC: u16 = 1;
pub const WIRE_PRIVATE: u16 = 2;
pub const WIRE_WELCOME: u16 = 3;
pub const WIRE_GROUP_INFO: u16 = 4;
/// RFC 9420 content types.
pub const CONTENT_APPLICATION: u8 = 1;
pub const CONTENT_PROPOSAL: u8 = 2;
pub const CONTENT_COMMIT: u8 = 3;

/// Songbird group IDs are 16 bytes (the `Send` frame's `group`).
pub const GROUP_ID_LEN: usize = 16;

/// Why a message was refused by a parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("truncated")]
    Truncated,
    #[error("not minimal")]
    NotMinimal,
    #[error("trailing bytes")]
    Trailing,
    #[error("unsupported version")]
    Version,
    #[error("unexpected wire format")]
    WireFormat,
    #[error("group ID is not 16 bytes")]
    GroupId,
    #[error("too large")]
    TooLarge,
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.buf.len() < n {
            return Err(WireError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        self.take(1)?.first().copied().ok_or(WireError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([
            b.first().copied().unwrap_or(0),
            b.get(1).copied().unwrap_or(0),
        ]))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    /// RFC 9420 §2.1.2 variable-length integer, minimal encoding only (here: the `GroupInfo`
    /// signature length).
    fn varint(&mut self) -> Result<usize, WireError> {
        let first = self.u8()?;
        let value = match first >> 6 {
            0 => return Ok(usize::from(first)),
            1 => {
                let v = (u32::from(first & 0x3f) << 8) | u32::from(self.u8()?);
                if v < 64 {
                    return Err(WireError::NotMinimal);
                }
                v
            }
            // Longer lengths never precede a 64-byte signature.
            _ => return Err(WireError::TooLarge),
        };
        usize::try_from(value).map_err(|_| WireError::TooLarge)
    }

    fn finish(&self) -> Result<(), WireError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

/// The `PrivateMessage` prefix the send path reads lives in `songbird-proto`, so delivery never
/// links OpenMLS (D-0067).
pub use songbird_proto::mls::{PrivatePrefix, private_prefix};

/// Songbird's commit bundle (PROTOCOL §6): what a committer uploads.
///
/// `version u8 (1) | commit_len u32 | commit | welcome_len u32 | welcome | info_len u32 | info`,
/// each part an `MLSMessage`; `welcome_len` is 0 when no device is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bundle<'a> {
    pub commit: &'a [u8],
    pub welcome: Option<&'a [u8]>,
    pub group_info: &'a [u8],
}

/// The only bundle version.
pub const BUNDLE_V1: u8 = 1;

impl<'a> Bundle<'a> {
    /// Splits a bundle; `max` bounds the whole input before anything else is read.
    pub fn parse(bytes: &'a [u8], max: usize) -> Result<Self, WireError> {
        if bytes.len() > max {
            return Err(WireError::TooLarge);
        }
        let mut r = Reader { buf: bytes };
        if r.u8()? != BUNDLE_V1 {
            return Err(WireError::Version);
        }
        let n = usize::try_from(r.u32()?).map_err(|_| WireError::TooLarge)?;
        let commit = r.take(n)?;
        let n = usize::try_from(r.u32()?).map_err(|_| WireError::TooLarge)?;
        let welcome = if n == 0 { None } else { Some(r.take(n)?) };
        let n = usize::try_from(r.u32()?).map_err(|_| WireError::TooLarge)?;
        let group_info = r.take(n)?;
        r.finish()?;
        if commit.is_empty() || group_info.is_empty() {
            return Err(WireError::Truncated);
        }
        Ok(Self {
            commit,
            welcome,
            group_info,
        })
    }

    /// Encodes a bundle (clients and tests).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let welcome = self.welcome.unwrap_or(&[]);
        let mut out =
            Vec::with_capacity(13 + self.commit.len() + welcome.len() + self.group_info.len());
        out.push(BUNDLE_V1);
        for part in [self.commit, welcome, self.group_info] {
            // Parts above 4 GiB cannot exist under any limit; saturate rather than panic.
            out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }
}

/// The wire format of an `MLSMessage` (its first four bytes), for routing a message to the
/// right parser without decoding it.
pub fn wire_format(msg: &[u8]) -> Result<u16, WireError> {
    let mut r = Reader { buf: msg };
    if r.u16()? != MLS10 {
        return Err(WireError::Version);
    }
    r.u16()
}

/// The `signer` leaf index of a `GroupInfo` whose signature is Ed25519 (every Songbird
/// ciphersuite): the four bytes before the final `signature<V>` of 64 bytes.
pub fn group_info_signer(msg: &[u8]) -> Result<u32, WireError> {
    // ... signer u32 | 0x40 0x40 (64 as a two-byte varint) | signature [64]
    let n = msg.len();
    let tail = msg
        .get(n.checked_sub(70).ok_or(WireError::Truncated)?..)
        .ok_or(WireError::Truncated)?;
    let mut r = Reader { buf: tail };
    let signer = r.u32()?;
    if r.varint()? != 64 || r.buf.len() != 64 {
        return Err(WireError::WireFormat);
    }
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_round_trip_and_are_bounded() {
        let b = Bundle {
            commit: b"commit",
            welcome: Some(b"welcome"),
            group_info: b"info",
        };
        let bytes = b.encode();
        assert_eq!(Bundle::parse(&bytes, 1 << 20), Ok(b));
        let n = Bundle {
            commit: b"c",
            welcome: None,
            group_info: b"i",
        };
        assert_eq!(Bundle::parse(&n.encode(), 1 << 20), Ok(n));
        assert_eq!(
            Bundle::parse(&bytes, bytes.len() - 1),
            Err(WireError::TooLarge)
        );
        let mut t = bytes.clone();
        t.push(0);
        assert_eq!(Bundle::parse(&t, 1 << 20), Err(WireError::Trailing));
        for cut in 0..bytes.len() {
            assert!(Bundle::parse(&bytes[..cut], 1 << 20).is_err());
        }
    }
}

#[cfg(test)]
mod signer_tests {
    use super::*;

    #[test]
    fn the_signer_sits_before_a_64_byte_signature() {
        let mut m = vec![0, 1, 0, 4, 0xAA, 0xBB];
        m.extend_from_slice(&7u32.to_be_bytes());
        m.extend_from_slice(&[0x40, 0x40]);
        m.extend_from_slice(&[0x55; 64]);
        assert_eq!(group_info_signer(&m), Ok(7));
        let mut short = m.clone();
        short.pop();
        assert!(group_info_signer(&short).is_err());
        let at = m.len() - 65;
        m[at] = 0x3F;
        assert!(group_info_signer(&m).is_err());
    }
}
