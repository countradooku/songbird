//! A report with message franking (Prompt 4, M5; `docs/PROTOCOL.md` §5.14, D-0063): what a
//! recipient sends to show the server one message it received.
//!
//! ```text
//! POST /v1/reports:
//! version u8 (1) | reason u8 | key_id [8] | commitment [32] | stamped_at_ms u64 | tag [32]
//!   | sender [16] | franking_key [32] | content_len u32 | content [content_len]
//! ```
//!
//! The stamp fields are the ones the reporter's app kept from the franked envelope
//! ([`crate::envelope::Stamp`]); `sender` is the account the app decrypted the message from;
//! `content` is the encoded `Content` exactly as received (1 to 61,440 bytes) and `franking_key`
//! the key from its plaintext. The server checks that its own stamp binds the commitment, the time,
//! the sender (or none, for a sealed send) and the reporter's account (or none, for a group's
//! shared body), and that the commitment opens to the content under the key.

use bytes::{BufMut as _, BytesMut};

use crate::envelope::{KEY_ID_LEN, MAC_LEN, Stamp};

/// The format version.
pub const VERSION: u8 = 1;
/// Largest reported content (the content limit of `songbird_content`).
pub const MAX_CONTENT: usize = 61_440;
/// Bytes before the content.
pub const HEADER_LEN: usize = 1 + 1 + KEY_ID_LEN + MAC_LEN + 8 + MAC_LEN + 16 + 32 + 4;
/// Largest report.
pub const MAX_LEN: usize = HEADER_LEN + MAX_CONTENT;

/// Why the message is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Unwanted bulk or commercial messages.
    Spam,
    /// Harassment or threats.
    Harassment,
    /// Content that may be illegal.
    Illegal,
    /// Pretending to be someone else.
    Impersonation,
    /// Anything else.
    Other,
}

impl Reason {
    /// Wire value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Spam => 1,
            Self::Harassment => 2,
            Self::Illegal => 3,
            Self::Impersonation => 4,
            Self::Other => 5,
        }
    }

    /// From a wire value; unknown values are refused (a report is acted on by people).
    #[must_use]
    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(Self::Spam),
            2 => Some(Self::Harassment),
            3 => Some(Self::Illegal),
            4 => Some(Self::Impersonation),
            5 => Some(Self::Other),
            _ => None,
        }
    }

    /// A name for moderators.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::Harassment => "harassment",
            Self::Illegal => "illegal",
            Self::Impersonation => "impersonation",
            Self::Other => "other",
        }
    }
}

/// A decoded report. `Debug` shows only the reason and sizes.
#[derive(Clone, PartialEq, Eq)]
pub struct Report {
    /// Why.
    pub reason: Reason,
    /// The stamp from the franked envelope.
    pub stamp: Stamp,
    /// The account the message came from, as the reporter's app saw it.
    pub sender: [u8; 16],
    /// The franking key from the message's plaintext.
    pub franking_key: [u8; 32],
    /// The encoded content, exactly as received.
    pub content: Vec<u8>,
}

impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Report")
            .field("reason", &self.reason)
            .field("content_len", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// Why bytes are not a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    /// Too long, too short, trailing bytes, or an empty or oversized content.
    #[error("report malformed")]
    Malformed,
    /// Another version.
    #[error("unknown report version")]
    Version,
    /// An unknown reason.
    #[error("unknown report reason")]
    Reason,
}

impl Report {
    /// Encodes the report.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = BytesMut::with_capacity(HEADER_LEN + self.content.len());
        b.put_u8(VERSION);
        b.put_u8(self.reason.code());
        b.put_slice(&self.stamp.key_id);
        b.put_slice(&self.stamp.commitment);
        b.put_u64(self.stamp.stamped_at_ms);
        b.put_slice(&self.stamp.tag);
        b.put_slice(&self.sender);
        b.put_slice(&self.franking_key);
        b.put_u32(u32::try_from(self.content.len()).unwrap_or(u32::MAX));
        b.put_slice(&self.content);
        b.to_vec()
    }

    /// Decodes a report: the length is checked before anything is copied, and trailing bytes are
    /// refused.
    ///
    /// # Errors
    /// [`ReportError`].
    pub fn decode(b: &[u8]) -> Result<Self, ReportError> {
        if b.len() <= HEADER_LEN || b.len() > MAX_LEN {
            return Err(ReportError::Malformed);
        }
        let (head, content) = b.split_at(HEADER_LEN);
        let mut r = head;
        let mut take = |n: usize| {
            let (a, rest) = r.split_at(n.min(r.len()));
            r = rest;
            a
        };
        if take(1) != [VERSION] {
            return Err(ReportError::Version);
        }
        let reason = take(1)
            .first()
            .and_then(|c| Reason::from_code(*c))
            .ok_or(ReportError::Reason)?;
        let mut stamp = Stamp {
            key_id: [0; KEY_ID_LEN],
            commitment: [0; MAC_LEN],
            stamped_at_ms: 0,
            tag: [0; MAC_LEN],
        };
        stamp.key_id.copy_from_slice(take(KEY_ID_LEN));
        stamp.commitment.copy_from_slice(take(MAC_LEN));
        let mut t = [0u8; 8];
        t.copy_from_slice(take(8));
        stamp.stamped_at_ms = u64::from_be_bytes(t);
        stamp.tag.copy_from_slice(take(MAC_LEN));
        let mut sender = [0u8; 16];
        sender.copy_from_slice(take(16));
        let mut franking_key = [0u8; 32];
        franking_key.copy_from_slice(take(32));
        let mut n = [0u8; 4];
        n.copy_from_slice(take(4));
        if usize::try_from(u32::from_be_bytes(n)).ok() != Some(content.len()) {
            return Err(ReportError::Malformed);
        }
        Ok(Self {
            reason,
            stamp,
            sender,
            franking_key,
            content: content.to_vec(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            reason: Reason::Harassment,
            stamp: Stamp {
                key_id: [1; 8],
                commitment: [2; 32],
                stamped_at_ms: 1_800_000_000_000,
                tag: [3; 32],
            },
            sender: [4; 16],
            franking_key: [5; 32],
            content: b"content".to_vec(),
        }
    }

    #[test]
    fn reports_round_trip_and_decode_strictly() {
        let r = report();
        let b = r.encode();
        assert_eq!(b.len(), HEADER_LEN + 7);
        assert_eq!(Report::decode(&b).unwrap(), r);
        for cut in 0..b.len() {
            assert!(Report::decode(&b[..cut]).is_err(), "cut {cut}");
        }
        let mut long = b.clone();
        long.push(0);
        assert_eq!(Report::decode(&long), Err(ReportError::Malformed));
        let mut v = b.clone();
        v[0] = 2;
        assert_eq!(Report::decode(&v), Err(ReportError::Version));
        let mut v = b.clone();
        v[1] = 9;
        assert_eq!(Report::decode(&v), Err(ReportError::Reason));
        let mut big = report();
        big.content = vec![0; MAX_CONTENT + 1];
        assert_eq!(Report::decode(&big.encode()), Err(ReportError::Malformed));
        assert!(!format!("{r:?}").contains("content\""));
    }
}
