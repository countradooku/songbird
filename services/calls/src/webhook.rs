//! LiveKit webhooks (Prompt 7, M3; PROTOCOL §8.8; D-0088): used for cleanup and capacity
//! metrics only, never stored.
//!
//! LiveKit `POST`s each event as JSON with an `Authorization` token signed by the API secret whose
//! `sha256` claim is the body's hash. An event is handled only if the signature verifies, it is at
//! most five minutes old (or ahead), and its ID was not seen in the last hour (a replay or a retry
//! is answered 200 and does nothing). Then:
//!
//! - `room_finished` forgets the call's record (and a group's pointer to it);
//! - `participant_joined` of an identity removed from the room disconnects it again (D-0091);
//! - an event whose cleanup failed is unmarked, so LiveKit's retry runs it;
//! - room and participant events count into aggregate counters (no label names a room).

use std::sync::Arc;

use songbird_service::telemetry::sharded::ShardedCounter as Counter;
use songbird_valkey::ValkeyConn;

use crate::records::Kind;
use crate::{Calls, RoomId};

/// Largest webhook body read.
pub const MAX_BODY: usize = 64 * 1024;
/// How far an event's time may be from ours.
pub const MAX_SKEW_SECS: i64 = 300;

/// Aggregate counters (`calls_*`): capacity, without naming a room or a participant.
#[derive(Debug, Clone, Default)]
pub struct WebhookMetrics {
    /// Events handled.
    pub received: Counter,
    /// Refused: bad signature, stale, unreadable.
    pub refused: Counter,
    /// Repeats (retries or replays) answered without effect.
    pub repeated: Counter,
    /// Rooms started.
    pub rooms_started: Counter,
    /// Rooms finished.
    pub rooms_finished: Counter,
    /// Participants joined.
    pub participants_joined: Counter,
    /// Participants left.
    pub participants_left: Counter,
    /// Tracks published (audio, video and screen shares together).
    pub tracks_published: Counter,
    /// Removed members who reconnected and were disconnected again.
    pub denied: Counter,
}

impl WebhookMetrics {
    /// Registers them.
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            ("calls_webhooks", "LiveKit webhooks handled", &self.received),
            (
                "calls_webhooks_refused",
                "LiveKit webhooks refused (signature, age, format)",
                &self.refused,
            ),
            (
                "calls_webhooks_repeated",
                "LiveKit webhooks seen before",
                &self.repeated,
            ),
            ("calls_rooms_started", "Rooms started", &self.rooms_started),
            (
                "calls_rooms_finished",
                "Rooms finished",
                &self.rooms_finished,
            ),
            (
                "calls_participants_joined",
                "Participants joined",
                &self.participants_joined,
            ),
            (
                "calls_participants_left",
                "Participants left",
                &self.participants_left,
            ),
            (
                "calls_tracks_published",
                "Tracks published",
                &self.tracks_published,
            ),
            (
                "calls_rejoins_refused",
                "Removed members who reconnected and were disconnected again",
                &self.denied,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// What to answer LiveKit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// 200: handled, or a repeat.
    Ok,
    /// 400: not a webhook body.
    Malformed,
    /// 401: the signature, the hash or the time is wrong.
    Refused,
    /// 503: `valkey-hot` failed; LiveKit retries.
    Unavailable,
}

/// The webhook receiver.
pub struct Webhooks {
    calls: Arc<Calls>,
    hot: ValkeyConn,
    /// Counters.
    pub metrics: WebhookMetrics,
}

impl std::fmt::Debug for Webhooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhooks").finish_non_exhaustive()
    }
}

fn now_secs() -> i64 {
    i64::try_from(crate::now_ms() / 1_000).unwrap_or(i64::MAX)
}

impl Webhooks {
    /// A receiver for `calls`' LiveKit, cleaning up in `hot`.
    #[must_use]
    pub fn new(calls: Arc<Calls>, hot: ValkeyConn, metrics: WebhookMetrics) -> Self {
        Self {
            calls,
            hot,
            metrics,
        }
    }

    /// Handles one webhook.
    pub async fn handle(&self, authorization: &str, body: &[u8]) -> Answer {
        if body.len() > MAX_BODY {
            self.metrics.refused.inc();
            return Answer::Malformed;
        }
        let Ok(text) = std::str::from_utf8(body) else {
            self.metrics.refused.inc();
            return Answer::Malformed;
        };
        let Ok(event) = self.calls.minter.webhook(text, authorization) else {
            self.metrics.refused.inc();
            return Answer::Refused;
        };
        if event.id.is_empty()
            || event.id.len() > 128
            || now_secs().abs_diff(event.created_at) > MAX_SKEW_SECS.unsigned_abs()
        {
            self.metrics.refused.inc();
            return Answer::Refused;
        }
        let records = self.calls.records(&self.hot);
        match records.first_sighting(&event.id).await {
            Ok(true) => {}
            Ok(false) => {
                self.metrics.repeated.inc();
                return Answer::Ok;
            }
            Err(_) => return Answer::Unavailable,
        }
        let answer = self.apply(&records, &event).await;
        if answer == Answer::Unavailable {
            // Let LiveKit's retry run it again.
            let _ = records.unsee(&event.id).await;
        } else {
            self.metrics.received.inc();
        }
        answer
    }

    async fn apply(
        &self,
        records: &crate::Records<'_>,
        event: &livekit_protocol::WebhookEvent,
    ) -> Answer {
        let room = event.room.as_ref().and_then(|r| RoomId::parse(&r.name));
        match event.event.as_str() {
            "room_started" => self.metrics.rooms_started.inc(),
            "room_finished" => {
                self.metrics.rooms_finished.inc();
                if let Some(room) = room {
                    match records.forget(&room).await {
                        Ok(Some(call)) => {
                            if let Kind::Group(tag) = call.kind
                                && records.release_group_tag(&tag, &room).await.is_err()
                            {
                                return Answer::Unavailable;
                            }
                        }
                        Ok(None) => {}
                        Err(_) => return Answer::Unavailable,
                    }
                }
            }
            "participant_joined" => {
                self.metrics.participants_joined.inc();
                // A removed member back with a token it still held (D-0091).
                if let (Some(room), Some(p)) = (room, event.participant.as_ref()) {
                    match records.denied(&room, &p.identity).await {
                        Ok(false) => {}
                        Ok(true) => {
                            if self.calls.rooms.remove(&room, &p.identity).await.is_err() {
                                return Answer::Unavailable;
                            }
                            self.metrics.denied.inc();
                        }
                        Err(_) => return Answer::Unavailable,
                    }
                }
            }
            "participant_left" | "participant_connection_aborted" => {
                self.metrics.participants_left.inc();
            }
            "track_published" => self.metrics.tracks_published.inc(),
            _ => {}
        }
        Answer::Ok
    }
}
