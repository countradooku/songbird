//! LiveKit access tokens (`livekit-api`, feature `access-token` only; D-0085 §5).
//!
//! A participant token admits one identity to one room, for [`CallLimits::token_ttl_secs`]
//! (the time to connect; LiveKit refreshes a connected participant's token itself). It grants the
//! least that a call needs: join, subscribe, and, for those who may speak, publish data (encrypted
//! cards and keys travel there) and only the sources the call allows. No admin, recording, ingress or agent
//! grant; no name, metadata or attributes, and no right to set them.
//!
//! [`CallLimits::token_ttl_secs`]: crate::config::CallLimits::token_ttl_secs

use std::time::Duration;

use livekit_api::access_token::{AccessToken, TokenVerifier, VideoGrants};
use livekit_api::webhooks::WebhookReceiver;
use zeroize::Zeroizing;

use crate::ids::RoomId;

/// What a participant may publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publish {
    /// Nothing: a listener (a read-only member of a channel's call).
    Nothing,
    /// The microphone only (a group's audio-only call).
    Audio,
    /// Microphone, camera and screen sharing.
    Everything,
}

impl Publish {
    fn sources(self) -> Vec<String> {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect();
        match self {
            Self::Nothing => Vec::new(),
            Self::Audio => s(&["microphone"]),
            Self::Everything => s(&["microphone", "camera", "screen_share", "screen_share_audio"]),
        }
    }
}

/// Signs tokens with the LiveKit API key and secret.
pub struct Minter {
    api_key: String,
    api_secret: Zeroizing<String>,
    ttl: Duration,
}

impl std::fmt::Debug for Minter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minter")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

/// A token could not be signed (no detail: the inputs are ours).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("token signing failed")]
pub struct TokenError;

impl Minter {
    /// A minter for participant tokens valid `ttl`.
    #[must_use]
    pub fn new(api_key: &str, api_secret: Zeroizing<String>, ttl: Duration) -> Self {
        Self {
            api_key: api_key.to_owned(),
            api_secret,
            ttl,
        }
    }

    /// Verifies a LiveKit webhook: the `Authorization` header is a token signed with the API
    /// secret whose `sha256` claim is the body's hash (`livekit-api`, feature `webhooks`).
    ///
    /// # Errors
    /// [`TokenError`] for a bad signature, an expired token, another hash or an unreadable body.
    pub fn webhook(
        &self,
        body: &str,
        authorization: &str,
    ) -> Result<livekit_protocol::WebhookEvent, TokenError> {
        WebhookReceiver::new(TokenVerifier::with_api_key(&self.api_key, &self.api_secret))
            .receive(body, authorization)
            .map_err(|_| TokenError)
    }

    /// A token admitting `identity` to `room`.
    ///
    /// # Errors
    /// [`TokenError`].
    pub fn participant(
        &self,
        room: &RoomId,
        identity: &str,
        publish: Publish,
    ) -> Result<String, TokenError> {
        let grants = VideoGrants {
            room_join: true,
            room: room.name(),
            can_publish: Some(publish != Publish::Nothing),
            can_subscribe: Some(true),
            // Listeners send nothing, data included (a channel's read-only members).
            can_publish_data: Some(publish != Publish::Nothing),
            can_publish_sources: publish.sources(),
            can_update_own_metadata: Some(false),
            ..VideoGrants::default()
        };
        AccessToken::with_api_key(&self.api_key, &self.api_secret)
            .with_ttl(self.ttl)
            .with_identity(identity)
            .with_grants(grants)
            .to_jwt()
            .map_err(|_| TokenError)
    }

    /// A short token for the server API: `room_create` and `room_list` (create, delete, find
    /// rooms) or `room_admin` on one room (list and remove participants).
    ///
    /// # Errors
    /// [`TokenError`].
    pub fn admin(&self, room: Option<&RoomId>) -> Result<String, TokenError> {
        let grants = match room {
            None => VideoGrants {
                room_create: true,
                room_list: true,
                ..VideoGrants::default()
            },
            Some(r) => VideoGrants {
                room_admin: true,
                room: r.name(),
                ..VideoGrants::default()
            },
        };
        AccessToken::with_api_key(&self.api_key, &self.api_secret)
            .with_ttl(Duration::from_secs(60))
            .with_grants(grants)
            .to_jwt()
            .map_err(|_| TokenError)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
    use super::*;

    fn minter() -> Minter {
        Minter::new(
            "devkey",
            Zeroizing::new("a-test-secret-of-at-least-32-bytes!!".into()),
            Duration::from_secs(120),
        )
    }

    #[test]
    fn participant_tokens_grant_the_least() {
        let m = minter();
        let room = RoomId::from_bytes([7; 16]);
        let jwt = m.participant(&room, "0011", Publish::Everything).unwrap();
        let c = TokenVerifier::with_api_key("devkey", &m.api_secret)
            .verify(&jwt)
            .unwrap();
        assert_eq!(c.sub, "0011");
        assert_eq!(c.name, "");
        assert_eq!(c.metadata, "");
        assert!(c.attributes.is_empty());
        assert!(c.room_config.is_none());
        let v = &c.video;
        assert!(v.room_join && v.room == room.name());
        assert!(!v.room_create && !v.room_list && !v.room_record && !v.room_admin);
        assert!(!v.ingress_admin && !v.hidden && !v.recorder && !v.agent);
        assert_eq!(v.can_update_own_metadata, Some(false));
        assert_eq!(v.can_publish, Some(true));
        assert_eq!(c.exp.saturating_sub(c.nbf), 120);
        assert!(!c.sip.admin && !c.sip.call);

        let audio = m.participant(&room, "0011", Publish::Audio).unwrap();
        let c = TokenVerifier::with_api_key("devkey", &m.api_secret)
            .verify(&audio)
            .unwrap();
        assert_eq!(c.video.can_publish_sources, vec!["microphone".to_owned()]);
        let listen = m.participant(&room, "0011", Publish::Nothing).unwrap();
        let c = TokenVerifier::with_api_key("devkey", &m.api_secret)
            .verify(&listen)
            .unwrap();
        assert_eq!(c.video.can_publish, Some(false));
        assert_eq!(c.video.can_publish_data, Some(false));
        assert_eq!(c.video.can_publish_sources, Vec::<String>::new());

        // Signed by our secret only.
        assert!(
            TokenVerifier::with_api_key("devkey", "another-secret-of-at-least-32-bytes!")
                .verify(&jwt)
                .is_err()
        );
    }

    #[test]
    fn admin_tokens_are_scoped_and_short() {
        let m = minter();
        let room = RoomId::from_bytes([7; 16]);
        let v = TokenVerifier::with_api_key("devkey", &m.api_secret);
        let c = v.verify(&m.admin(None).unwrap()).unwrap();
        assert!(c.video.room_create && c.video.room_list);
        assert!(!c.video.room_admin && !c.video.room_join && !c.video.room_record);
        let c = v.verify(&m.admin(Some(&room)).unwrap()).unwrap();
        assert!(c.video.room_admin && c.video.room == room.name() && !c.video.room_create);
        assert_eq!(c.exp.saturating_sub(c.nbf), 60);
    }
}
