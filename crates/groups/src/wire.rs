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
/// `version u8 | commit_len u32 | commit | welcome_len u32 | welcome | info_len u32 | info`
/// and, in version 2 only, `log_len u32 | log` (a change-log entry, D-0070). The first three
/// parts are `MLSMessage`s; `welcome_len` is 0 when no device is added; `log_len` is never 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bundle<'a> {
    pub commit: &'a [u8],
    pub welcome: Option<&'a [u8]>,
    pub group_info: &'a [u8],
    /// The committer's signed, encrypted change-log entry (`LogEntry`), if any.
    pub log: Option<&'a [u8]>,
}

/// A bundle without a change-log entry.
pub const BUNDLE_V1: u8 = 1;
/// A bundle with one.
pub const BUNDLE_V2: u8 = 2;

/// A change-log entry (D-0070): `ciphertext_len u16 | ciphertext | signature [64]`. The
/// ciphertext is encrypted by the members under a key the server never sees; the signature is
/// the committer's leaf key over [`log_signed_content`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogEntry<'a> {
    pub ciphertext: &'a [u8],
    pub signature: &'a [u8; 64],
}

/// Longest change-log ciphertext.
pub const MAX_LOG_CIPHERTEXT: usize = 2048;

impl<'a> LogEntry<'a> {
    /// Parses an entry, exactly.
    pub fn parse(b: &'a [u8]) -> Result<Self, WireError> {
        let mut r = Reader { buf: b };
        let n = usize::from(r.u16()?);
        if n == 0 || n > MAX_LOG_CIPHERTEXT {
            return Err(WireError::TooLarge);
        }
        let ciphertext = r.take(n)?;
        let signature: &[u8; 64] = r.take(64)?.try_into().map_err(|_| WireError::Truncated)?;
        r.finish()?;
        Ok(Self {
            ciphertext,
            signature,
        })
    }

    /// Encodes an entry (clients and tests).
    #[must_use]
    pub fn encode(ciphertext: &[u8], signature: &[u8; 64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + ciphertext.len() + 64);
        out.extend_from_slice(
            &u16::try_from(ciphertext.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(ciphertext);
        out.extend_from_slice(signature);
        out
    }
}

/// What a change-log entry's signature covers: a label, the group, the epoch the commit was
/// made from, and the ciphertext. Bound to one commit, so an entry cannot be replayed onto
/// another epoch or group.
#[must_use]
pub fn log_signed_content(
    group: &[u8; GROUP_ID_LEN],
    from_epoch: u64,
    ciphertext: &[u8],
) -> Vec<u8> {
    let label = b"songbird.v1/change-log\0";
    let mut out = Vec::with_capacity(label.len() + 16 + 8 + ciphertext.len());
    out.extend_from_slice(label);
    out.extend_from_slice(group);
    out.extend_from_slice(&from_epoch.to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

impl<'a> Bundle<'a> {
    /// Splits a bundle; `max` bounds the whole input before anything else is read.
    pub fn parse(bytes: &'a [u8], max: usize) -> Result<Self, WireError> {
        if bytes.len() > max {
            return Err(WireError::TooLarge);
        }
        let mut r = Reader { buf: bytes };
        let version = r.u8()?;
        if version != BUNDLE_V1 && version != BUNDLE_V2 {
            return Err(WireError::Version);
        }
        let n = usize::try_from(r.u32()?).map_err(|_| WireError::TooLarge)?;
        let commit = r.take(n)?;
        let n = usize::try_from(r.u32()?).map_err(|_| WireError::TooLarge)?;
        let welcome = if n == 0 { None } else { Some(r.take(n)?) };
        let n = usize::try_from(r.u32()?).map_err(|_| WireError::TooLarge)?;
        let group_info = r.take(n)?;
        let log = if version == BUNDLE_V2 {
            let n = usize::try_from(r.u32()?).map_err(|_| WireError::TooLarge)?;
            if n == 0 {
                return Err(WireError::Truncated);
            }
            Some(r.take(n)?)
        } else {
            None
        };
        r.finish()?;
        if commit.is_empty() || group_info.is_empty() {
            return Err(WireError::Truncated);
        }
        Ok(Self {
            commit,
            welcome,
            group_info,
            log,
        })
    }

    /// Encodes a bundle (clients and tests): version 2 when it carries a log entry.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let welcome = self.welcome.unwrap_or(&[]);
        let log = self.log.unwrap_or(&[]);
        let mut out = Vec::with_capacity(
            17 + self.commit.len() + welcome.len() + self.group_info.len() + log.len(),
        );
        out.push(if self.log.is_some() {
            BUNDLE_V2
        } else {
            BUNDLE_V1
        });
        let parts: &[&[u8]] = if self.log.is_some() {
            &[self.commit, welcome, self.group_info, log]
        } else {
            &[self.commit, welcome, self.group_info]
        };
        for part in parts {
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
    #![allow(
        clippy::many_single_char_names,
        reason = "tests: short names for bundles"
    )]
    use super::*;

    #[test]
    fn bundles_round_trip_and_are_bounded() {
        let b = Bundle {
            commit: b"commit",
            welcome: Some(b"welcome"),
            group_info: b"info",
            log: None,
        };
        let bytes = b.encode();
        assert_eq!(bytes.first(), Some(&BUNDLE_V1));
        assert_eq!(Bundle::parse(&bytes, 1 << 20), Ok(b));
        let n = Bundle {
            commit: b"c",
            welcome: None,
            group_info: b"i",
            log: None,
        };
        assert_eq!(Bundle::parse(&n.encode(), 1 << 20), Ok(n));
        // With a change-log entry: version 2, and the entry round-trips.
        let entry = LogEntry::encode(b"sealed", &[7; 64]);
        let l = Bundle {
            commit: b"c",
            welcome: None,
            group_info: b"i",
            log: Some(&entry),
        };
        let lb = l.encode();
        assert_eq!(lb.first(), Some(&BUNDLE_V2));
        assert_eq!(Bundle::parse(&lb, 1 << 20), Ok(l));
        let e = LogEntry::parse(&entry).unwrap();
        assert_eq!((e.ciphertext, e.signature), (&b"sealed"[..], &[7; 64]));
        assert!(LogEntry::parse(&entry[..entry.len() - 1]).is_err());
        assert!(LogEntry::parse(&LogEntry::encode(&[], &[0; 64])).is_err());
        // A version-2 bundle with an empty log part is refused.
        let mut empty = n.encode();
        empty[0] = BUNDLE_V2;
        empty.extend_from_slice(&0u32.to_be_bytes());
        assert!(Bundle::parse(&empty, 1 << 20).is_err());
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
