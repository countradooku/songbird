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
//! cl:q:<tag(link)>   a hash: lobby handle (32 hex) → version u8 (1) | state u8 | device tag [16] |
//!                      sealed card (≤ 512 bytes); at most 64 entries, 10 minutes
//! cl:w:<tag(event)>  a webhook event already handled (an hour)
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
    /// The stored form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(26);
        out.push(VERSION);
        out.extend_from_slice(self.room.as_bytes());
        out.push(self.media.byte());
        out.extend_from_slice(&self.created_ms.to_be_bytes());
        out
    }

    /// Parses the stored form; anything else is `None`.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
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

/// Most people waiting in one link's lobby.
pub const MAX_LOBBY: usize = 64;
/// How long a lobby keeps a waiting joiner (refreshed while people keep arriving).
pub const LOBBY_TTL_SECS: u64 = 600;
/// Largest sealed card a joiner leaves in the lobby (PROTOCOL §8.4).
pub const MAX_CARD: usize = 512;

/// Where a lobby entry stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// Waiting for an admin.
    Waiting,
    /// Admitted: the joiner's next poll gets a ticket.
    Admitted,
    /// Declined: the joiner's next poll gets 404.
    Declined,
}

impl Waiting {
    const fn byte(self) -> u8 {
        match self {
            Self::Waiting => 0,
            Self::Admitted => 1,
            Self::Declined => 2,
        }
    }

    const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Waiting),
            1 => Some(Self::Admitted),
            2 => Some(Self::Declined),
            _ => None,
        }
    }
}

/// One joiner in a lobby: a keyed tag of its device (only that device may redeem the entry),
/// its sealed card (opaque: the server cannot open it), where it stands.
#[derive(Clone, PartialEq, Eq)]
pub struct LobbyEntry {
    /// Where it stands.
    pub state: Waiting,
    /// Keyed tag of the waiting device.
    pub device: Tag,
    /// The sealed card.
    pub card: Vec<u8>,
}

impl std::fmt::Debug for LobbyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LobbyEntry")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl LobbyEntry {
    /// The stored form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(18 + self.card.len());
        out.push(VERSION);
        out.push(self.state.byte());
        out.extend_from_slice(&self.device);
        out.extend_from_slice(&self.card);
        out
    }

    /// Parses the stored form; anything else is `None`.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        let (&[version, state], rest) = b.split_first_chunk::<2>()?;
        let (device, card) = rest.split_first_chunk::<16>()?;
        if version != VERSION || card.len() > MAX_CARD {
            return None;
        }
        Some(Self {
            state: Waiting::from_byte(state)?,
            device: *device,
            card: card.to_vec(),
        })
    }
}

/// A lobby is full or `valkey-hot` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LobbyError {
    /// [`MAX_LOBBY`] people are already waiting.
    #[error("lobby full")]
    Full,
    /// `valkey-hot` failed.
    #[error("valkey-hot unavailable")]
    Store,
}

impl Records<'_> {
    fn lobby_name(link: &Tag) -> String {
        format!("cl:q:{}", hex::encode(link))
    }

    /// Adds a waiting joiner; returns its random 16-byte handle.
    ///
    /// # Errors
    /// [`LobbyError`].
    pub async fn lobby_add(
        &self,
        link: &Tag,
        device: Tag,
        card: Vec<u8>,
    ) -> Result<[u8; 16], LobbyError> {
        let name = Self::lobby_name(link);
        let n: usize = self
            .hot
            .query(redis::cmd("HLEN").arg(&name))
            .await
            .map_err(|_| LobbyError::Store)?;
        if n >= MAX_LOBBY {
            return Err(LobbyError::Full);
        }
        let mut handle = [0u8; 16];
        aws_lc_rs::rand::fill(&mut handle).map_err(|_| LobbyError::Store)?;
        let entry = LobbyEntry {
            state: Waiting::Waiting,
            device,
            card,
        };
        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("HSET")
            .arg(&name)
            .arg(hex::encode(handle))
            .arg(entry.encode())
            .ignore()
            .cmd("EXPIRE")
            .arg(&name)
            .arg(LOBBY_TTL_SECS)
            .ignore();
        self.hot
            .query_pipe::<()>(&pipe)
            .await
            .map_err(|_| LobbyError::Store)?;
        Ok(handle)
    }

    /// One entry.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn lobby_get(
        &self,
        link: &Tag,
        handle: &[u8; 16],
    ) -> Result<Option<LobbyEntry>, StoreError> {
        let v: Option<Vec<u8>> = self
            .hot
            .query(
                redis::cmd("HGET")
                    .arg(Self::lobby_name(link))
                    .arg(hex::encode(handle)),
            )
            .await
            .map_err(|_| StoreError)?;
        Ok(v.as_deref().and_then(LobbyEntry::decode))
    }

    /// Everyone still waiting: their handles and sealed cards.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn lobby_waiting(&self, link: &Tag) -> Result<Vec<([u8; 16], Vec<u8>)>, StoreError> {
        let all: Vec<(String, Vec<u8>)> = self
            .hot
            .query(redis::cmd("HGETALL").arg(Self::lobby_name(link)))
            .await
            .map_err(|_| StoreError)?;
        let mut out: Vec<([u8; 16], Vec<u8>)> = all
            .into_iter()
            .filter_map(|(h, v)| {
                let mut handle = [0u8; 16];
                hex::decode_to_slice(&h, &mut handle).ok()?;
                let e = LobbyEntry::decode(&v)?;
                (e.state == Waiting::Waiting).then_some((handle, e.card))
            })
            .collect();
        out.sort_unstable();
        Ok(out)
    }

    /// Sets an entry's state if it is still waiting; `false` if there is no such entry.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn lobby_decide(
        &self,
        link: &Tag,
        handle: &[u8; 16],
        admit: bool,
    ) -> Result<bool, StoreError> {
        let Some(mut e) = self.lobby_get(link, handle).await? else {
            return Ok(false);
        };
        if e.state != Waiting::Waiting {
            return Ok(true);
        }
        e.state = if admit {
            Waiting::Admitted
        } else {
            Waiting::Declined
        };
        self.hot
            .query::<()>(
                redis::cmd("HSET")
                    .arg(Self::lobby_name(link))
                    .arg(hex::encode(handle))
                    .arg(e.encode()),
            )
            .await
            .map_err(|_| StoreError)?;
        Ok(true)
    }

    /// Removes an entry (redeemed or declined).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn lobby_remove(&self, link: &Tag, handle: &[u8; 16]) -> Result<(), StoreError> {
        self.hot
            .query::<()>(
                redis::cmd("HDEL")
                    .arg(Self::lobby_name(link))
                    .arg(hex::encode(handle)),
            )
            .await
            .map_err(|_| StoreError)
    }

    /// Drops a link's lobby (revoked).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn lobby_clear(&self, link: &Tag) -> Result<(), StoreError> {
        self.hot
            .query::<()>(redis::cmd("DEL").arg(Self::lobby_name(link)))
            .await
            .map_err(|_| StoreError)
    }

    /// Marks a webhook event ID seen; `false` if it was seen already (a replay or a retry).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn first_sighting(&self, event: &str) -> Result<bool, StoreError> {
        let set: Option<String> = self
            .hot
            .query(
                redis::cmd("SET")
                    .arg(self.keys.webhook_record(event))
                    .arg(1)
                    .arg("NX")
                    .arg("EX")
                    .arg(3_600),
            )
            .await
            .map_err(|_| StoreError)?;
        Ok(set.is_some())
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
