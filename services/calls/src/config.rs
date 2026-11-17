//! Call settings shared by `api` (`[api.calls]`) and the `calls` service (`[calls]`).

use std::path::PathBuf;

use serde::Deserialize;
use songbird_types::SecretRef;
use songbird_types::config::{Validate, Validator};

/// LiveKit and the call limits (D-0085).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSettings {
    /// 32 bytes (64 hex characters), the same on every `api` and `calls` node: keys participant
    /// identities and the call records.
    pub secret: SecretRef,
    /// What apps connect to (`wss://calls.<domain>`); returned with every token.
    pub livekit_url: String,
    /// LiveKit's server API (Twirp) as `api` reaches it: `http://` in development, `https://`
    /// through the calls host's mutual-TLS tunnel when deployed.
    pub api_url: String,
    /// LiveKit's API key (an identifier, not a secret).
    pub api_key: String,
    /// LiveKit's API secret: signs tokens and webhooks.
    pub api_secret: SecretRef,
    /// Mutual TLS to [`CallSettings::api_url`] (required when it is `https://`).
    #[serde(default)]
    pub tls: Option<TwirpTls>,
    /// Limits.
    #[serde(default)]
    pub limits: CallLimits,
}

impl Validate for CallSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.livekit_url.starts_with("wss://") || self.livekit_url.starts_with("ws://"),
            "livekit_url",
            "must be a ws:// or wss:// URL",
        );
        v.check(
            self.api_url.starts_with("https://") || self.api_url.starts_with("http://"),
            "api_url",
            "must be an http:// or https:// URL",
        );
        v.check(
            !self.api_url.starts_with("https://") || self.tls.is_some(),
            "tls",
            "is required for an https:// api_url",
        );
        v.check(
            (1..=128).contains(&self.api_key.len())
                && self.api_key.bytes().all(|b| b.is_ascii_graphic()),
            "api_key",
            "must be 1 to 128 visible ASCII characters",
        );
        v.section("limits", &self.limits);
    }
}

/// Mutual TLS to LiveKit's API tunnel (the internal CA, D-0012).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwirpTls {
    /// The name in the tunnel's certificate.
    pub server_name: String,
    /// The internal CA.
    pub ca: PathBuf,
    /// This node's certificate chain.
    pub cert_chain: PathBuf,
    /// Its key.
    pub key: SecretRef,
}

/// `limits`: caps, timeouts and budgets (D-0085).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CallLimits {
    /// Participants in a video call.
    pub video_participants: u32,
    /// Participants in an audio-only call.
    pub audio_participants: u32,
    /// How long a participant token is valid: the time to connect (LiveKit refreshes it once
    /// connected).
    pub token_ttl_secs: u64,
    /// A room nobody has joined closes after this long.
    pub empty_timeout_secs: u32,
    /// A room closes this long after the last participant left.
    pub departure_timeout_secs: u32,
    /// A call record lives at most this long (a call longer than this keeps its room but can
    /// admit nobody new).
    pub max_call_hours: u32,
    /// Group calls ring (wake) every member only up to this many accounts.
    pub ring_max_accounts: u32,
    /// Calls an account may start per hour.
    pub calls_per_hour: u32,
    /// Their burst.
    pub call_burst: u32,
    /// Wake-ups an account may receive per hour (ringing spam).
    pub wakes_per_hour: u32,
    /// Their burst.
    pub wake_burst: u32,
    /// Joins (tokens) per device per hour.
    pub joins_per_hour: u32,
    /// Their burst.
    pub join_burst: u32,
}

impl Default for CallLimits {
    fn default() -> Self {
        Self {
            // D-0085 §3.
            video_participants: 32,
            audio_participants: 128,
            token_ttl_secs: 120,
            empty_timeout_secs: 180,
            departure_timeout_secs: 20,
            max_call_hours: 24,
            ring_max_accounts: 32,
            calls_per_hour: 60,
            call_burst: 20,
            wakes_per_hour: 60,
            wake_burst: 20,
            joins_per_hour: 600,
            join_burst: 60,
        }
    }
}

impl Validate for CallLimits {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (2..=1_000).contains(&self.video_participants),
            "video_participants",
            "must be in 2..=1000",
        );
        v.check(
            (self.video_participants..=1_000).contains(&self.audio_participants),
            "audio_participants",
            "must be in video_participants..=1000",
        );
        v.check(
            (10..=600).contains(&self.token_ttl_secs),
            "token_ttl_secs",
            "must be in 10..=600",
        );
        v.check(
            (10..=3_600).contains(&self.empty_timeout_secs),
            "empty_timeout_secs",
            "must be in 10..=3600",
        );
        v.check(
            (1..=600).contains(&self.departure_timeout_secs),
            "departure_timeout_secs",
            "must be in 1..=600",
        );
        v.check(
            (1..=48).contains(&self.max_call_hours),
            "max_call_hours",
            "must be in 1..=48",
        );
        v.check(
            (2..=self.audio_participants).contains(&self.ring_max_accounts),
            "ring_max_accounts",
            "must be in 2..=audio_participants",
        );
        for (name, n) in [
            ("calls_per_hour", self.calls_per_hour),
            ("call_burst", self.call_burst),
            ("wakes_per_hour", self.wakes_per_hour),
            ("wake_burst", self.wake_burst),
            ("joins_per_hour", self.joins_per_hour),
            ("join_burst", self.join_burst),
        ] {
            v.check((1..=100_000).contains(&n), name, "must be in 1..=100000");
        }
    }
}
