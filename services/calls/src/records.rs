//! Live call records in `valkey-hot` (threat model §1; D-0085 §1). Names are keyed hashes
//! ([`crate::ids::CallKeys`]); every record expires with the call's longest life and is deleted
//! when LiveKit reports its room finished (M3).
//!
//! ```text
//! cl:r:<tag(room)>   version u8 (1) | kind u8 | media u8 | created_ms u64 | body
//!                      kind 1, a 1:1 call:  caller account [16] | callee account [16]
//!                      kind 2, a group call: group tag [16]
//!                      kind 3, a link call:  link tag [16]
//! cl:g:<tag(group)>  version u8 (1) | room [16] | media u8 | created_ms u64
//! ```

use songbird_types::AccountId;
use songbird_valkey::ValkeyConn;

use crate::ids::{CallKeys, RoomId, Tag};

const VERSION: u8 = 1;

/// Audio-only or video: sets the participant cap and what may be published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media {
    /// Audio only.
    Audio,
    /// Video.
    Video,
}

impl Media {
    /// The wire byte (1 audio, 2 video, as `CallEvent.Kind`).
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Audio => 1,
            Self::Video => 2,
        }
    }

    /// From the wire byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Audio),
            2 => Some(Self::Video),
            _ => None,
        }
    }
}

/// Who a call admits.
#[derive(Clone, PartialEq, Eq)]
pub enum Kind {
    /// The two accounts' devices.
    OneToOne {
        /// The caller.
        caller: AccountId,
        /// The callee.
        callee: AccountId,
    },
    /// The current roster of the group with this tag.
    Group(Tag),
    /// Holders of the link with this tag (M3).
    Link(Tag),
}

impl std::fmt::Debug for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OneToOne { .. } => "OneToOne",
            Self::Group(_) => "Group",
            Self::Link(_) => "Link",
        })
    }
}

/// A live call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// Who it admits.
    pub kind: Kind,
    /// Audio or video.
    pub media: Media,
    /// When it was created (ms since the epoch).
    pub created_ms: u64,
}

impl Call {
    /// The stored form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(43);
        out.push(VERSION);
        let (kind, body): (u8, Vec<u8>) = match &self.kind {
            Kind::OneToOne { caller, callee } => (
                1,
                [caller.as_bytes().as_slice(), callee.as_bytes().as_slice()].concat(),
            ),
            Kind::Group(t) => (2, t.to_vec()),
            Kind::Link(t) => (3, t.to_vec()),
        };
        out.push(kind);
        out.push(self.media.byte());
        out.extend_from_slice(&self.created_ms.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Parses the stored form; anything else is `None`.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        let (&[version, kind, media], rest) = b.split_first_chunk::<3>()?;
        if version != VERSION {
            return None;
        }
        let (created, body) = rest.split_first_chunk::<8>()?;
        let tag = |b: &[u8]| <[u8; 16]>::try_from(b).ok();
        let kind = match kind {
            1 => {
                let (a, c) = body.split_at_checked(16)?;
                Kind::OneToOne {
                    caller: AccountId::from_bytes(tag(a)?),
                    callee: AccountId::from_bytes(tag(c)?),
                }
            }
            2 => Kind::Group(tag(body)?),
            3 => Kind::Link(tag(body)?),
            _ => return None,
        };
        Some(Self {
            kind,
            media: Media::from_byte(media)?,
            created_ms: u64::from_be_bytes(*created),
        })
    }
}

/// A group's pointer to its live call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCall {
    /// The room.
    pub room: RoomId,
    /// Audio or video.
    pub media: Media,
    /// When it started.
    pub created_ms: u64,
}

impl GroupCall {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(26);
        out.push(VERSION);
        out.extend_from_slice(self.room.as_bytes());
        out.push(self.media.byte());
        out.extend_from_slice(&self.created_ms.to_be_bytes());
        out
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let (&version, rest) = b.split_first()?;
        if version != VERSION || rest.len() != 25 {
            return None;
        }
        let (room, rest) = rest.split_first_chunk::<16>()?;
        let (&media, rest) = rest.split_first()?;
        Some(Self {
            room: RoomId::from_bytes(*room),
            media: Media::from_byte(media)?,
            created_ms: u64::from_be_bytes(rest.try_into().ok()?),
        })
    }
}

/// `valkey-hot` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("valkey-hot unavailable")]
pub struct StoreError;

/// The call records.
#[derive(Debug)]
pub struct Records<'a> {
    keys: &'a CallKeys,
    hot: &'a ValkeyConn,
    ttl_secs: u64,
}

impl<'a> Records<'a> {
    /// Records under `keys`, living `ttl_secs` at most.
    #[must_use]
    pub const fn new(keys: &'a CallKeys, hot: &'a ValkeyConn, ttl_secs: u64) -> Self {
        Self {
            keys,
            hot,
            ttl_secs,
        }
    }

    /// Stores a new call's record.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put(&self, room: &RoomId, call: &Call) -> Result<(), StoreError> {
        self.hot
            .query::<()>(
                redis::cmd("SET")
                    .arg(self.keys.call_record(room))
                    .arg(call.encode())
                    .arg("EX")
                    .arg(self.ttl_secs),
            )
            .await
            .map_err(|_| StoreError)
    }

    /// A call's record, if it is live.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn get(&self, room: &RoomId) -> Result<Option<Call>, StoreError> {
        let v: Option<Vec<u8>> = self
            .hot
            .query(redis::cmd("GET").arg(self.keys.call_record(room)))
            .await
            .map_err(|_| StoreError)?;
        Ok(v.as_deref().and_then(Call::decode))
    }

    /// Forgets a call (and, for a group call, the group's pointer if it still names this room).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn forget(&self, room: &RoomId) -> Result<Option<Call>, StoreError> {
        let call = self.get(room).await?;
        self.hot
            .query::<()>(redis::cmd("DEL").arg(self.keys.call_record(room)))
            .await
            .map_err(|_| StoreError)?;
        Ok(call)
    }

    /// Makes `candidate` the group's live call unless it has one; returns the live one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn claim_group(
        &self,
        group: &[u8; 16],
        candidate: &GroupCall,
    ) -> Result<GroupCall, StoreError> {
        let name = self.keys.group_record(group);
        let set: Option<String> = self
            .hot
            .query(
                redis::cmd("SET")
                    .arg(&name)
                    .arg(candidate.encode())
                    .arg("NX")
                    .arg("EX")
                    .arg(self.ttl_secs),
            )
            .await
            .map_err(|_| StoreError)?;
        if set.is_some() {
            return Ok(*candidate);
        }
        self.group(group).await?.ok_or(StoreError)
    }

    /// The group's live call, if any.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn group(&self, group: &[u8; 16]) -> Result<Option<GroupCall>, StoreError> {
        let v: Option<Vec<u8>> = self
            .hot
            .query(redis::cmd("GET").arg(self.keys.group_record(group)))
            .await
            .map_err(|_| StoreError)?;
        Ok(v.as_deref().and_then(GroupCall::decode))
    }

    /// Drops the group's pointer if it still names `room` (a finished room; a newer call that
    /// replaced it is kept).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn release_group_tag(&self, tag: &Tag, room: &RoomId) -> Result<(), StoreError> {
        let name = format!("cl:g:{}", hex::encode(tag));
        let v: Option<Vec<u8>> = self
            .hot
            .query(redis::cmd("GET").arg(&name))
            .await
            .map_err(|_| StoreError)?;
        if v.as_deref()
            .and_then(GroupCall::decode)
            .is_some_and(|g| g.room == *room)
        {
            self.hot
                .query::<()>(redis::cmd("DEL").arg(&name))
                .await
                .map_err(|_| StoreError)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn records_round_trip_and_refuse_anything_else() {
        let calls = [
            Call {
                kind: Kind::OneToOne {
                    caller: AccountId::from_bytes([1; 16]),
                    callee: AccountId::from_bytes([2; 16]),
                },
                media: Media::Video,
                created_ms: 1_800_000_000_000,
            },
            Call {
                kind: Kind::Group([3; 16]),
                media: Media::Audio,
                created_ms: 5,
            },
            Call {
                kind: Kind::Link([4; 16]),
                media: Media::Video,
                created_ms: 6,
            },
        ];
        for c in calls {
            let b = c.encode();
            assert_eq!(Call::decode(&b), Some(c.clone()));
            for n in 0..b.len() {
                assert_eq!(Call::decode(&b[..n]), None);
            }
            let mut longer = b.clone();
            longer.push(0);
            assert_eq!(Call::decode(&longer), None);
        }
        let g = GroupCall {
            room: RoomId::from_bytes([9; 16]),
            media: Media::Audio,
            created_ms: 7,
        };
        assert_eq!(GroupCall::decode(&g.encode()), Some(g));
        assert_eq!(GroupCall::decode(&g.encode()[1..]), None);
        let mut bad = g.encode();
        bad[17] = 3;
        assert_eq!(GroupCall::decode(&bad), None);
    }

    #[test]
    fn debug_names_no_account() {
        let c = Call {
            kind: Kind::OneToOne {
                caller: AccountId::from_bytes([0xAB; 16]),
                callee: AccountId::from_bytes([0xCD; 16]),
            },
            media: Media::Video,
            created_ms: 1,
        };
        let d = format!("{c:?}");
        assert!(!d.contains("ab") && !d.contains("171"), "{d}");
    }
}
