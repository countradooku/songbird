//! Songbird calls (Prompt 7; PROTOCOL §8; decisions D-0085 to D-0089).
//!
//! The library behind `api`'s `/v1/calls…` endpoints and the `calls` service:
//!
//! - [`ids`]: random rooms, participant identities that are pseudonyms per room, keyed record
//!   names;
//! - [`token`]: LiveKit tokens with the least grants (`livekit-api`, `access-token` only);
//! - [`twirp`]: LiveKit's room service, on hyper and rustls with aws-lc-rs;
//! - [`records`]: live calls in `valkey-hot`, for the call's life only.
//!
//! Who may call whom, budgets and wake-ups are `api`'s (it holds the registry). No media key
//! ever reaches this crate: apps derive them from their Signal sessions and MLS groups (§8.2).
//! Nothing here logs a room, an identity, an account or a device (invariant 6).
#![forbid(unsafe_code)]

pub mod config;
pub mod ids;
pub mod records;
pub mod token;
pub mod twirp;
pub mod webhook;

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use songbird_types::DeviceId;
use songbird_valkey::ValkeyConn;

pub use config::{CallLimits, CallSettings};
pub use ids::{CallKeys, RoomId};
pub use records::{Call, GroupCall, Kind, Media, Records};
pub use token::{Minter, Publish};
pub use twirp::{RoomClient, TwirpError};

/// What a device needs to join: the call, LiveKit's URL, a token and its identity there.
#[derive(Debug, Clone, Serialize)]
pub struct Ticket {
    /// The call ID (hex): the room, and what signalling names.
    pub call: String,
    /// LiveKit's URL.
    pub url: String,
    /// The participant token.
    pub token: String,
    /// The device's identity in the room (the key schedule binds sender keys to it).
    pub identity: String,
}

/// Why a call operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// `valkey-hot`, LiveKit or the random source failed: retry.
    #[error("unavailable")]
    Unavailable,
}

impl From<TwirpError> for CallError {
    fn from(_: TwirpError) -> Self {
        Self::Unavailable
    }
}

impl From<records::StoreError> for CallError {
    fn from(_: records::StoreError) -> Self {
        Self::Unavailable
    }
}

/// Calls, ready: keys, the token minter, the room client and the limits.
pub struct Calls {
    /// Identities and record names.
    pub keys: CallKeys,
    /// Tokens.
    pub minter: Arc<Minter>,
    /// LiveKit's room service.
    pub rooms: RoomClient,
    /// Limits.
    pub limits: CallLimits,
    livekit_url: String,
}

impl std::fmt::Debug for Calls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Calls")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Calls {
    /// From the settings: resolves both secrets and builds the clients.
    ///
    /// # Errors
    /// What could not be loaded (no secret material in the message).
    pub fn from_settings(s: &CallSettings) -> Result<Self, String> {
        let secret = s.secret.resolve_key32().map_err(|e| e.to_string())?;
        let api_secret = s.api_secret.resolve().map_err(|e| e.to_string())?;
        let api_secret = zeroize::Zeroizing::new(api_secret.expose().trim().to_owned());
        if api_secret.len() < 32 {
            return Err("calls.api_secret must be at least 32 characters".into());
        }
        let tls = match &s.tls {
            Some(t) => Some((twirp::tls_connector(t)?, t.server_name.clone())),
            None => None,
        };
        Self::new(
            &secret,
            &s.api_key,
            api_secret,
            &s.livekit_url,
            &s.api_url,
            tls,
            s.limits,
        )
        .map_err(str::to_owned)
    }

    /// From resolved parts (tests, tools).
    ///
    /// # Errors
    /// A malformed `api_url`, or `https` without TLS.
    pub fn new(
        secret: &[u8; 32],
        api_key: &str,
        api_secret: zeroize::Zeroizing<String>,
        livekit_url: &str,
        api_url: &str,
        tls: Option<(tokio_rustls::TlsConnector, String)>,
        limits: CallLimits,
    ) -> Result<Self, &'static str> {
        let minter = Arc::new(Minter::new(
            api_key,
            api_secret,
            Duration::from_secs(limits.token_ttl_secs),
        ));
        let rooms = RoomClient::new(api_url, tls, Arc::clone(&minter), Duration::from_secs(5))?;
        Ok(Self {
            keys: CallKeys::new(secret),
            minter,
            rooms,
            limits,
            livekit_url: livekit_url.to_owned(),
        })
    }

    /// Call records in `hot`.
    #[must_use]
    pub fn records<'a>(&'a self, hot: &'a ValkeyConn) -> Records<'a> {
        Records::new(
            &self.keys,
            hot,
            u64::from(self.limits.max_call_hours) * 3_600,
        )
    }

    /// The participant cap for `media`.
    #[must_use]
    pub const fn cap(&self, media: Media) -> u32 {
        match media {
            Media::Audio => self.limits.audio_participants,
            Media::Video => self.limits.video_participants,
        }
    }

    /// Creates `room` in LiveKit with the call's cap and timeouts (idempotent).
    ///
    /// # Errors
    /// [`CallError::Unavailable`].
    pub async fn open_room(&self, room: &RoomId, media: Media) -> Result<(), CallError> {
        self.rooms
            .create_room(
                room,
                self.limits.empty_timeout_secs,
                self.limits.departure_timeout_secs,
                self.cap(media),
            )
            .await
            .map_err(Into::into)
    }

    /// A ticket for `device` in `room`.
    ///
    /// # Errors
    /// [`CallError::Unavailable`].
    pub fn ticket(
        &self,
        room: &RoomId,
        device: &DeviceId,
        publish: Publish,
    ) -> Result<Ticket, CallError> {
        let identity = self.keys.identity(room, device);
        let token = self
            .minter
            .participant(room, &identity, publish)
            .map_err(|_| CallError::Unavailable)?;
        Ok(Ticket {
            call: room.name(),
            url: self.livekit_url.clone(),
            token,
            identity,
        })
    }

    /// Disconnects everyone in `room` whose identity is not one of `allowed` devices';
    /// returns how many were removed. Used when a group's roster changes mid-call.
    ///
    /// # Errors
    /// [`CallError::Unavailable`]; a room that no longer exists removes nobody.
    pub async fn reconcile(
        &self,
        room: &RoomId,
        allowed: impl Iterator<Item = DeviceId>,
    ) -> Result<usize, CallError> {
        let present = match self.rooms.participants(room).await {
            Ok(p) => p,
            Err(TwirpError::NotFound) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        if present.is_empty() {
            return Ok(0);
        }
        let allowed: std::collections::HashSet<String> =
            allowed.map(|d| self.keys.identity(room, &d)).collect();
        let mut removed = 0;
        for identity in present.iter().filter(|i| !allowed.contains(*i)) {
            self.rooms.remove(room, identity).await?;
            removed += 1;
        }
        Ok(removed)
    }
}
