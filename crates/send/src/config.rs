//! Configuration shared by every service that links the send path.

use serde::Deserialize;
use songbird_proto::Limits;
use songbird_types::config::{Validate, Validator};

/// Frame limits (`[delivery.limits]`, `[api.send.limits]`): one struct, so the WebSocket `Send`
/// frame and `PUT /v1/messages` are held to the same bounds (see `songbird_proto::Limits`).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// Largest envelope.
    pub max_envelope_bytes: usize,
    /// Most recipients per send.
    pub max_recipients: usize,
    /// Largest `Send` frame.
    pub max_send_bytes: usize,
    /// Largest ephemeral payload.
    pub max_ephemeral_bytes: usize,
    /// Largest control-frame body.
    pub max_control_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        let l = Limits::DEFAULT;
        Self {
            max_envelope_bytes: l.max_envelope_bytes,
            max_recipients: l.max_recipients,
            max_send_bytes: l.max_send_bytes,
            max_ephemeral_bytes: l.max_ephemeral_bytes,
            max_control_bytes: l.max_control_bytes,
        }
    }
}

impl LimitsConfig {
    /// As protocol limits.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        Limits {
            max_envelope_bytes: self.max_envelope_bytes,
            max_recipients: self.max_recipients,
            max_send_bytes: self.max_send_bytes,
            max_ephemeral_bytes: self.max_ephemeral_bytes,
            max_control_bytes: self.max_control_bytes,
        }
    }
}

impl Validate for LimitsConfig {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (1..=1024 * 1024).contains(&self.max_envelope_bytes),
            "max_envelope_bytes",
            "must be in 1..=1048576",
        );
        v.check(
            (1..=u16::MAX.into()).contains(&self.max_recipients),
            "max_recipients",
            "must be in 1..=65535",
        );
        v.check(
            (64..=16 * 1024 * 1024).contains(&self.max_send_bytes),
            "max_send_bytes",
            "must be in 64..=16777216",
        );
        v.check(
            (1..=64 * 1024).contains(&self.max_ephemeral_bytes),
            "max_ephemeral_bytes",
            "must be in 1..=65536",
        );
        v.check(
            (256..=64 * 1024).contains(&self.max_control_bytes),
            "max_control_bytes",
            "must be in 256..=65536",
        );
    }
}
