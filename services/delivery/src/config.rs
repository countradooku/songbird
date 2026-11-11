//! Delivery configuration (`[delivery]` section), validated at startup.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use songbird_proto::Limits;
use songbird_service::HasCommon;
use songbird_types::SecretRef;
use songbird_types::config::{CommonConfig, Validate, Validator};

/// The delivery service's configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryConfig {
    /// Shared settings.
    pub common: CommonConfig,
    /// Delivery settings.
    pub delivery: DeliverySettings,
}

impl HasCommon for DeliveryConfig {
    fn common(&self) -> &CommonConfig {
        &self.common
    }
}

impl Validate for DeliveryConfig {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
        v.section("delivery", &self.delivery);
        let d = &self.delivery;
        if self.common.environment.is_deployed() {
            v.check(
                d.tls.is_some(),
                "delivery.tls",
                "is required in staging and production",
            );
            v.check(
                d.directory.file.is_none(),
                "delivery.directory.file",
                "a static device directory is for development and CI only",
            );
        }
        v.check(
            d.session.drain_window_ms < self.common.shutdown_grace_secs.saturating_mul(1000),
            "delivery.session.drain_window_ms",
            "must be shorter than common.shutdown_grace_secs",
        );
    }
}

/// `[delivery]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverySettings {
    /// WebSocket listener.
    pub listen: SocketAddr,
    /// The public host name devices sign during authentication.
    pub server_name: String,
    /// TLS for the listener (required outside development).
    #[serde(default)]
    pub tls: Option<TlsSettings>,
    /// Frame limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Connection and session behaviour.
    #[serde(default)]
    pub session: SessionConfig,
    /// Where device authentication keys come from.
    #[serde(default)]
    pub directory: DirectoryConfig,
    /// The in-memory mailbox (milestone 1).
    #[serde(default)]
    pub mailbox: MemoryMailboxConfig,
}

impl Validate for DeliverySettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            songbird_types::dns::is_valid_host(self.server_name.as_bytes()),
            "server_name",
            "must be a DNS host name",
        );
        v.section("limits", &self.limits);
        v.section("session", &self.session);
        v.section("mailbox", &self.mailbox);
    }
}

/// `[delivery.tls]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    /// PEM certificate chain, leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
}

/// `[delivery.directory]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryConfig {
    /// TOML file of `[[devices]] id = "<hex>", auth_key = "<hex>"` (development and CI). The
    /// identity service (Prompt 3) replaces it.
    pub file: Option<PathBuf>,
}

/// `[delivery.mailbox]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MemoryMailboxConfig {
    /// Unacknowledged envelopes kept per device before sends to it are refused (retryable).
    pub max_per_device: usize,
    /// Store generation announced in `Hello`.
    pub store_generation: u64,
}

impl Default for MemoryMailboxConfig {
    fn default() -> Self {
        Self {
            max_per_device: 10_000,
            store_generation: 1,
        }
    }
}

impl Validate for MemoryMailboxConfig {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (1..=1_000_000).contains(&self.max_per_device),
            "max_per_device",
            "must be in 1..=1000000",
        );
        v.check(
            self.store_generation >= 1,
            "store_generation",
            "must be >= 1",
        );
    }
}

/// `[delivery.limits]`: frame limits (see `songbird_proto::Limits`).
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

/// `[delivery.session]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionConfig {
    /// Connections held at once; more are closed with 4101 and a retry hint.
    pub max_connections: usize,
    /// Sustained new connections per second (token bucket); more are closed with 4101.
    pub accepts_per_sec: u32,
    /// Accept burst.
    pub accept_burst: u32,
    /// TLS plus HTTP upgrade must finish within this.
    pub handshake_timeout_ms: u64,
    /// `Auth` must arrive within this after `Hello`.
    pub auth_timeout_ms: u64,
    /// WebSocket ping after this much inbound silence.
    pub ping_interval_secs: u32,
    /// Close after this much inbound silence.
    pub idle_timeout_secs: u32,
    /// A socket write that makes no progress for this long marks a slow consumer (close 4100).
    pub write_timeout_ms: u64,
    /// Stored-envelope notifications queued per session before it is marked lagged.
    pub live_inbox: usize,
    /// Ephemeral events queued per session before they are dropped.
    pub ephemeral_inbox: usize,
    /// Envelopes fetched per mailbox read while draining.
    pub drain_page: usize,
    /// Mailbox check per session to catch lost notifications (jittered ±20 %).
    pub safety_sweep_secs: u64,
    /// After SIGTERM, sessions close with 4200 at random times within this window.
    pub drain_window_ms: u64,
    /// Sustained sends per second per connection.
    pub sends_per_sec: u32,
    /// Send burst.
    pub send_burst: u32,
    /// Sustained frames per second per connection (all types); exceeding closes with 4103.
    pub frames_per_sec: u32,
    /// Frame burst.
    pub frame_burst: u32,
    /// Sustained ephemeral events per second per connection; excess is dropped.
    pub ephemeral_per_sec: u32,
    /// Ephemeral burst.
    pub ephemeral_burst: u32,
    /// Per-connection receive buffer (the main per-idle-connection memory cost).
    pub read_buffer_bytes: usize,
    /// Per-connection write coalescing buffer.
    pub write_buffer_bytes: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_connections: 100_000,
            accepts_per_sec: 2_000,
            accept_burst: 4_000,
            handshake_timeout_ms: 5_000,
            auth_timeout_ms: 5_000,
            ping_interval_secs: 25,
            idle_timeout_secs: 60,
            write_timeout_ms: 10_000,
            live_inbox: 256,
            ephemeral_inbox: 32,
            drain_page: 256,
            safety_sweep_secs: 120,
            drain_window_ms: 2_000,
            sends_per_sec: 50,
            send_burst: 200,
            frames_per_sec: 400,
            frame_burst: 800,
            ephemeral_per_sec: 20,
            ephemeral_burst: 40,
            read_buffer_bytes: 4 * 1024,
            write_buffer_bytes: 4 * 1024,
        }
    }
}

impl SessionConfig {
    /// Handshake timeout.
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }
    /// Auth timeout.
    #[must_use]
    pub const fn auth_timeout(&self) -> Duration {
        Duration::from_millis(self.auth_timeout_ms)
    }
    /// Write timeout.
    #[must_use]
    pub const fn write_timeout(&self) -> Duration {
        Duration::from_millis(self.write_timeout_ms)
    }
}

impl Validate for SessionConfig {
    fn validate(&self, v: &mut Validator) {
        let mut range = |ok: bool, f: &str, msg: &str| v.check(ok, f, msg);
        range(
            (1..=10_000_000).contains(&self.max_connections),
            "max_connections",
            "must be in 1..=10000000",
        );
        range(self.accepts_per_sec >= 1, "accepts_per_sec", "must be >= 1");
        range(
            self.accept_burst >= self.accepts_per_sec,
            "accept_burst",
            "must be >= accepts_per_sec",
        );
        range(
            (100..=60_000).contains(&self.handshake_timeout_ms),
            "handshake_timeout_ms",
            "must be in 100..=60000",
        );
        range(
            (100..=60_000).contains(&self.auth_timeout_ms),
            "auth_timeout_ms",
            "must be in 100..=60000",
        );
        range(
            (1..=300).contains(&self.ping_interval_secs),
            "ping_interval_secs",
            "must be in 1..=300",
        );
        range(
            self.idle_timeout_secs > self.ping_interval_secs && self.idle_timeout_secs <= 900,
            "idle_timeout_secs",
            "must be above ping_interval_secs and at most 900",
        );
        range(
            (100..=120_000).contains(&self.write_timeout_ms),
            "write_timeout_ms",
            "must be in 100..=120000",
        );
        range(
            (1..=65_536).contains(&self.live_inbox),
            "live_inbox",
            "must be in 1..=65536",
        );
        range(
            (1..=4_096).contains(&self.ephemeral_inbox),
            "ephemeral_inbox",
            "must be in 1..=4096",
        );
        range(
            (1..=10_000).contains(&self.drain_page),
            "drain_page",
            "must be in 1..=10000",
        );
        range(
            (1..=3_600).contains(&self.safety_sweep_secs),
            "safety_sweep_secs",
            "must be in 1..=3600",
        );
        range(self.sends_per_sec >= 1, "sends_per_sec", "must be >= 1");
        range(
            self.send_burst >= self.sends_per_sec,
            "send_burst",
            "must be >= sends_per_sec",
        );
        range(self.frames_per_sec >= 1, "frames_per_sec", "must be >= 1");
        range(
            self.frame_burst >= self.frames_per_sec,
            "frame_burst",
            "must be >= frames_per_sec",
        );
        range(
            self.ephemeral_burst >= self.ephemeral_per_sec,
            "ephemeral_burst",
            "must be >= ephemeral_per_sec",
        );
        range(
            (1024..=1024 * 1024).contains(&self.read_buffer_bytes),
            "read_buffer_bytes",
            "must be in 1024..=1048576",
        );
        range(
            (1024..=1024 * 1024).contains(&self.write_buffer_bytes),
            "write_buffer_bytes",
            "must be in 1024..=1048576",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> Result<DeliveryConfig, String> {
        songbird_types::config::load_from_parts(text, Vec::<(String, String)>::new(), "SONGBIRD")
            .map_err(|e| e.to_string())
    }

    const DEV: &str = r#"
        [common]
        environment = "dev"
        [delivery]
        listen = "127.0.0.1:0"
        server_name = "localhost"
    "#;

    #[test]
    fn dev_defaults_are_valid() {
        let c = load(DEV).unwrap();
        assert_eq!(c.delivery.limits.limits(), Limits::DEFAULT);
    }

    #[test]
    fn production_requires_tls_and_refuses_static_directory() {
        let text = DEV.replace("\"dev\"", "\"production\"")
            + "[delivery.directory]\nfile = \"devices.toml\"\n";
        let e = load(&text).unwrap_err();
        assert!(e.contains("delivery.tls"), "{e}");
        assert!(e.contains("delivery.directory.file"), "{e}");
    }

    #[test]
    fn bad_values_are_reported() {
        let text = DEV.to_owned()
            + "[delivery.session]\nidle_timeout_secs = 10\nping_interval_secs = 25\nlive_inbox = 0\n";
        let e = load(&text).unwrap_err();
        assert!(
            e.contains("idle_timeout_secs") && e.contains("live_inbox"),
            "{e}"
        );
        let text = DEV.replace("localhost", "not a host");
        assert!(load(&text).unwrap_err().contains("server_name"));
    }
}
