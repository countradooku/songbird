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

    fn u64(&mut self) -> Result<u64, WireError> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u64::from_be_bytes(b))
    }

    /// RFC 9420 §2.1.2 variable-length integer, minimal encoding only.
    fn varint(&mut self) -> Result<usize, WireError> {
        let first = self.u8()?;
        let (len, value) = match first >> 6 {
            0 => return Ok(usize::from(first)),
            1 => {
                let v = (u32::from(first & 0x3f) << 8) | u32::from(self.u8()?);
                if v < 64 {
                    return Err(WireError::NotMinimal);
                }
                (2, v)
            }
            2 => {
                let rest = self.take(3)?;
                let mut v = u32::from(first & 0x3f);
                for b in rest {
                    v = (v << 8) | u32::from(*b);
                }
                if v < 16_384 {
                    return Err(WireError::NotMinimal);
                }
                (4, v)
            }
            // 8-byte lengths are refused by RFC 9420 §2.1.2.
            _ => return Err(WireError::TooLarge),
        };
        let _ = len;
        usize::try_from(value).map_err(|_| WireError::TooLarge)
    }

    fn vec(&mut self) -> Result<&'a [u8], WireError> {
        let n = self.varint()?;
        self.take(n)
    }

    fn finish(&self) -> Result<(), WireError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

/// What the server reads from a `PrivateMessage` without decrypting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatePrefix {
    pub group: [u8; GROUP_ID_LEN],
    pub epoch: u64,
    pub content_type: u8,
}

/// Parses a whole `MLSMessage` carrying a `PrivateMessage`: every field, no trailing bytes,
/// no allocation.
pub fn private_prefix(msg: &[u8]) -> Result<PrivatePrefix, WireError> {
    let mut r = Reader { buf: msg };
    if r.u16()? != MLS10 {
        return Err(WireError::Version);
    }
    if r.u16()? != WIRE_PRIVATE {
        return Err(WireError::WireFormat);
    }
    let group: [u8; GROUP_ID_LEN] = r.vec()?.try_into().map_err(|_| WireError::GroupId)?;
    let epoch = r.u64()?;
    let content_type = r.u8()?;
    let _aad = r.vec()?;
    let _sender_data = r.vec()?;
    let _ciphertext = r.vec()?;
    r.finish()?;
    Ok(PrivatePrefix {
        group,
        epoch,
        content_type,
    })
}

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

    fn private(group: &[u8], epoch: u64, ct: u8) -> Vec<u8> {
        let mut m = vec![0, 1, 0, 2, u8::try_from(group.len()).unwrap()];
        m.extend_from_slice(group);
        m.extend_from_slice(&epoch.to_be_bytes());
        m.push(ct);
        m.extend_from_slice(&[0, 1, 0xaa, 2, 0xbb, 0xcc]);
        m
    }

    #[test]
    fn private_prefix_reads_group_epoch_and_type() {
        let m = private(&[7; 16], 42, CONTENT_APPLICATION);
        assert_eq!(
            private_prefix(&m),
            Ok(PrivatePrefix {
                group: [7; 16],
                epoch: 42,
                content_type: CONTENT_APPLICATION
            })
        );
    }

    #[test]
    fn private_prefix_refuses_every_malformation() {
        let good = private(&[7; 16], 1, 1);
        assert_eq!(
            private_prefix(&private(&[7; 15], 1, 1)),
            Err(WireError::GroupId)
        );
        let mut v = good.clone();
        v[1] = 2;
        assert_eq!(private_prefix(&v), Err(WireError::Version));
        let mut w = good.clone();
        w[3] = 1;
        assert_eq!(private_prefix(&w), Err(WireError::WireFormat));
        let mut t = good.clone();
        t.push(0);
        assert_eq!(private_prefix(&t), Err(WireError::Trailing));
        for cut in 0..good.len() {
            assert!(
                private_prefix(&good[..cut]).is_err(),
                "prefix of {cut} bytes accepted"
            );
        }
        // A one-byte length written in two bytes is not minimal.
        let mut nm = vec![0, 1, 0, 2, 0x40, 16];
        nm.extend_from_slice(&good[5..]);
        assert_eq!(private_prefix(&nm), Err(WireError::NotMinimal));
    }

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
