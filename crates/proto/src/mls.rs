//! The plaintext prefix of an MLS `PrivateMessage` (Prompt 5, D-0067): all the send path reads
//! of a group message, without decrypting it and without OpenMLS (delivery never links it).
//!
//! RFC 9420 §6: `MLSMessage { uint16 version = mls10 (1); uint16 wire_format; ... }` and
//! `PrivateMessage { opaque group_id<V>; uint64 epoch; ContentType content_type;
//! opaque authenticated_data<V>; opaque encrypted_sender_data<V>; opaque ciphertext<V>; }`.
//! `<V>` lengths are RFC 9420 §2.1.2 variable-length integers; Songbird requires the minimal
//! encoding, so every message has one encoding. The whole message is parsed, with no trailing
//! bytes, and nothing is allocated.

/// `mls10`.
pub const MLS10: u16 = 1;
/// RFC 9420 wire format `mls_private_message`.
pub const WIRE_PRIVATE: u16 = 2;
/// RFC 9420 content type `application`.
pub const CONTENT_APPLICATION: u8 = 1;
/// Songbird group IDs are 16 bytes.
pub const GROUP_ID_LEN: usize = 16;

/// Why a `PrivateMessage` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PrefixError {
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

/// What the server reads from a `PrivateMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivatePrefix {
    pub group: [u8; GROUP_ID_LEN],
    pub epoch: u64,
    pub content_type: u8,
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PrefixError> {
        if self.buf.len() < n {
            return Err(PrefixError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PrefixError> {
        self.take(N)?.try_into().map_err(|_| PrefixError::Truncated)
    }

    fn varint(&mut self) -> Result<usize, PrefixError> {
        let [first] = self.array::<1>()?;
        let value = match first >> 6 {
            0 => u32::from(first),
            1 => {
                let [b] = self.array::<1>()?;
                let v = (u32::from(first & 0x3f) << 8) | u32::from(b);
                if v < 64 {
                    return Err(PrefixError::NotMinimal);
                }
                v
            }
            2 => {
                let rest = self.array::<3>()?;
                let v = rest
                    .iter()
                    .fold(u32::from(first & 0x3f), |v, b| (v << 8) | u32::from(*b));
                if v < 16_384 {
                    return Err(PrefixError::NotMinimal);
                }
                v
            }
            // 8-byte lengths are refused by RFC 9420 §2.1.2.
            _ => return Err(PrefixError::TooLarge),
        };
        usize::try_from(value).map_err(|_| PrefixError::TooLarge)
    }

    fn vec(&mut self) -> Result<&'a [u8], PrefixError> {
        let n = self.varint()?;
        self.take(n)
    }
}

/// Parses a whole `MLSMessage` carrying a `PrivateMessage`.
///
/// # Errors
/// [`PrefixError`] for anything but exactly one well-formed `PrivateMessage`.
pub fn private_prefix(msg: &[u8]) -> Result<PrivatePrefix, PrefixError> {
    let mut r = Reader { buf: msg };
    if u16::from_be_bytes(r.array()?) != MLS10 {
        return Err(PrefixError::Version);
    }
    if u16::from_be_bytes(r.array()?) != WIRE_PRIVATE {
        return Err(PrefixError::WireFormat);
    }
    let group: [u8; GROUP_ID_LEN] = r.vec()?.try_into().map_err(|_| PrefixError::GroupId)?;
    let epoch = u64::from_be_bytes(r.array()?);
    let [content_type] = r.array()?;
    let _aad = r.vec()?;
    let _sender_data = r.vec()?;
    let _ciphertext = r.vec()?;
    if !r.buf.is_empty() {
        return Err(PrefixError::Trailing);
    }
    Ok(PrivatePrefix {
        group,
        epoch,
        content_type,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
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
    fn reads_group_epoch_and_type() {
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
    fn refuses_every_malformation() {
        let good = private(&[7; 16], 1, 1);
        assert_eq!(
            private_prefix(&private(&[7; 15], 1, 1)),
            Err(PrefixError::GroupId)
        );
        let mut v = good.clone();
        v[1] = 2;
        assert_eq!(private_prefix(&v), Err(PrefixError::Version));
        let mut w = good.clone();
        w[3] = 1;
        assert_eq!(private_prefix(&w), Err(PrefixError::WireFormat));
        let mut t = good.clone();
        t.push(0);
        assert_eq!(private_prefix(&t), Err(PrefixError::Trailing));
        for cut in 0..good.len() {
            assert!(
                private_prefix(&good[..cut]).is_err(),
                "prefix of {cut} bytes accepted"
            );
        }
        // A one-byte length written in two bytes is not minimal.
        let mut nm = vec![0, 1, 0, 2, 0x40, 16];
        nm.extend_from_slice(&good[5..]);
        assert_eq!(private_prefix(&nm), Err(PrefixError::NotMinimal));
    }
}
