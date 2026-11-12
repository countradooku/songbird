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
            v.check(
                d.mailbox.backend == MailboxBackend::Iggy,
                "delivery.mailbox.backend",
                "must be iggy in staging and production",
            );
            v.check(
                d.mailbox
                    .iggy
                    .as_ref()
                    .is_some_and(|s| s.tls_ca.is_some() && s.tls_domain.is_some()),
                "delivery.mailbox.iggy.tls_ca",
                "and tls_domain are required in staging and production",
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
    /// Mailbox store.
    #[serde(default)]
    pub mailbox: MailboxConfig,
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

/// Mailbox store backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailboxBackend {
    /// In memory, lost on restart (development and tests).
    #[default]
    Memory,
    /// SurrealDB with group commit (M2's first design; development).
    Surrealdb,
    /// Apache Iggy log (deployments, D-0029).
    Iggy,
}

/// `[delivery.mailbox]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MailboxConfig {
    /// Which store.
    pub backend: MailboxBackend,
    /// Unacknowledged envelopes kept per device before sends to it are refused (retryable).
    pub max_per_device: usize,
    /// Store generation announced in `Hello` (memory backend; SurrealDB keeps its own).
    pub store_generation: u64,
    /// SurrealDB settings (required for that backend).
    pub surrealdb: Option<SurrealSettings>,
    /// Iggy settings (required for that backend).
    pub iggy: Option<IggySettings>,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            backend: MailboxBackend::Memory,
            max_per_device: 10_000,
            store_generation: 1,
            surrealdb: None,
            iggy: None,
        }
    }
}

impl Validate for MailboxConfig {
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
        v.check(
            self.backend != MailboxBackend::Surrealdb || self.surrealdb.is_some(),
            "surrealdb",
            "is required when backend = \"surrealdb\"",
        );
        v.check(
            self.backend != MailboxBackend::Iggy || self.iggy.is_some(),
            "iggy",
            "is required when backend = \"iggy\"",
        );
        if let Some(s) = &self.surrealdb {
            v.section("surrealdb", s);
        }
        if let Some(s) = &self.iggy {
            v.section("iggy", s);
        }
    }
}

/// `[delivery.mailbox.surrealdb]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurrealSettings {
    /// `host:port` of the RPC endpoint.
    pub addr: String,
    /// Host name for TLS and the `Host` header.
    pub host: String,
    /// PEM CA certificate for the server's TLS (required outside development).
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,
    /// Root user.
    pub user: String,
    /// Root password.
    pub pass: SecretRef,
    /// Namespace.
    #[serde(default = "default_ns")]
    pub namespace: String,
    /// Database.
    #[serde(default = "default_ns")]
    pub database: String,
    /// 64 hex characters keying idempotency records; the same on every node.
    pub idempotency_secret: SecretRef,
    /// Most sends per group-commit transaction.
    #[serde(default = "default_max_batch")]
    pub max_batch: usize,
    /// Longest a send waits for others to share its transaction, in microseconds (0: commit
    /// what is queued at once; batches still form while a commit is in flight).
    #[serde(default = "default_max_wait_us")]
    pub max_wait_us: u64,
    /// Batched ACK deletes are written this often.
    #[serde(default = "default_ack_interval_ms")]
    pub ack_interval_ms: u64,
    /// Connect and per-request timeout.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_ns() -> String {
    "songbird".into()
}
const fn default_max_batch() -> usize {
    256
}
const fn default_max_wait_us() -> u64 {
    // No artificial wait: a batch is whatever queued during the previous commit (measured best
    // at every load, D-0027).
    0
}
const fn default_ack_interval_ms() -> u64 {
    50
}
const fn default_timeout_ms() -> u64 {
    5_000
}

impl Validate for SurrealSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            songbird_types::dns::is_valid_host(self.host.as_bytes()),
            "host",
            "must be a DNS host name",
        );
        v.check(!self.addr.is_empty(), "addr", "must be host:port");
        v.check(
            (1..=4096).contains(&self.max_batch),
            "max_batch",
            "must be in 1..=4096",
        );
        v.check(
            self.max_wait_us <= 100_000,
            "max_wait_us",
            "must be at most 100000",
        );
        v.check(
            (1..=1_000).contains(&self.ack_interval_ms),
            "ack_interval_ms",
            "must be in 1..=1000",
        );
        v.check(
            (100..=60_000).contains(&self.timeout_ms),
            "timeout_ms",
            "must be in 100..=60000",
        );
    }
}

/// `[delivery.mailbox.iggy]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IggySettings {
    /// `host:port` of the TCP endpoint.
    pub addr: String,
    /// TLS server name (required outside development).
    #[serde(default)]
    pub tls_domain: Option<String>,
    /// PEM CA certificate for the server's TLS (required outside development).
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,
    /// User.
    pub user: String,
    /// Password.
    pub pass: SecretRef,
    /// Stream name.
    #[serde(default = "default_ns")]
    pub stream: String,
    /// Topic name.
    #[serde(default = "default_topic")]
    pub topic: String,
    /// Partitions, one writer each (fixed when the topic is created).
    #[serde(default = "default_partitions")]
    pub partitions: u32,
    /// 64 hex characters keying idempotency records; the same on every node.
    pub idempotency_secret: SecretRef,
    /// Directory of the mailbox key stores (a directory per partition) on this host's persistent disk;
    /// losing it loses the pending messages (D-0031).
    pub key_dir: PathBuf,
    /// 64 hex characters: the master key sealing the key stores.
    pub master_key: SecretRef,
    /// A new key window is opened this often, in seconds.
    #[serde(default = "default_key_window_secs")]
    pub key_window_secs: u64,
    /// The key store is written this often when it changed, in milliseconds: an acknowledged
    /// message's key leaves the disk within about this long.
    #[serde(default = "default_key_interval_ms")]
    pub key_interval_ms: u64,
    /// Most sends per append.
    #[serde(default = "default_max_batch")]
    pub max_batch: usize,
    /// ACK checkpoints are written this often.
    #[serde(default = "default_ack_interval_ms")]
    pub ack_interval_ms: u64,
    /// How long a send waits for its writers.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Pending entries older than this are copied forward so old segments can be deleted.
    #[serde(default = "default_relocate_after_secs")]
    pub relocate_after_secs: u64,
    /// Sealed segments below the low-water offset are deleted after this (topic
    /// `message_expiry`, applied when the topic is created).
    #[serde(default = "default_segment_expiry_secs")]
    pub segment_expiry_secs: u64,
    /// Segment size in MiB (applied when the topic is created): smaller segments are deleted
    /// sooner after delivery on a quiet node.
    #[serde(default = "default_segment_mib")]
    pub segment_mib: u64,
    /// Log records cached in memory per partition for reads, in MiB.
    #[serde(default = "default_cache_mib")]
    pub cache_mib: usize,
}

fn default_topic() -> String {
    "mailbox".into()
}
const fn default_partitions() -> u32 {
    4
}
const fn default_relocate_after_secs() -> u64 {
    900
}
const fn default_segment_expiry_secs() -> u64 {
    600
}
const fn default_segment_mib() -> u64 {
    16
}
const fn default_cache_mib() -> usize {
    64
}
const fn default_key_window_secs() -> u64 {
    600
}
const fn default_key_interval_ms() -> u64 {
    1_000
}

impl Validate for IggySettings {
    fn validate(&self, v: &mut Validator) {
        v.check(!self.addr.is_empty(), "addr", "must be host:port");
        if let Some(d) = &self.tls_domain {
            v.check(
                songbird_types::dns::is_valid_host(d.as_bytes()),
                "tls_domain",
                "must be a DNS host name",
            );
        }
        v.check(
            (1..=1024).contains(&self.partitions),
            "partitions",
            "must be in 1..=1024",
        );
        v.check(
            (1..=4096).contains(&self.max_batch),
            "max_batch",
            "must be in 1..=4096",
        );
        v.check(
            (1..=1_000).contains(&self.ack_interval_ms),
            "ack_interval_ms",
            "must be in 1..=1000",
        );
        v.check(
            (100..=60_000).contains(&self.timeout_ms),
            "timeout_ms",
            "must be in 100..=60000",
        );
        v.check(
            (60..=7 * 24 * 3600).contains(&self.relocate_after_secs),
            "relocate_after_secs",
            "must be in 60..=604800",
        );
        // The low-water offset protects what is still needed; the expiry only delays deletion.
        v.check(
            (60..=24 * 3600).contains(&self.segment_expiry_secs),
            "segment_expiry_secs",
            "must be in 60..=86400",
        );
        v.check(
            (1..=1024).contains(&self.segment_mib),
            "segment_mib",
            "must be in 1..=1024",
        );
        v.check(
            (1..=65_536).contains(&self.cache_mib),
            "cache_mib",
            "must be in 1..=65536",
        );
        v.check(
            self.key_dir.is_absolute(),
            "key_dir",
            "must be an absolute path",
        );
        v.check(
            (50..=10_000).contains(&self.key_interval_ms),
            "key_interval_ms",
            "must be in 50..=10000",
        );
        v.check(
            (60..=3_600).contains(&self.key_window_secs),
            "key_window_secs",
            "must be in 60..=3600",
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
    /// Most envelopes sent on a connection and not yet acknowledged; delivery pauses at the
    /// limit and resumes on the next ACK (D-0020).
    pub max_unacked: u64,
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
            // Mobile networks stall for tens of seconds; a stalled reader holds no one else up
            // (bounded window, non-blocking routing), so the close can be patient.
            write_timeout_ms: 30_000,
            max_unacked: 256,
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
            (1..=65_536).contains(&self.max_unacked),
            "max_unacked",
            "must be in 1..=65536",
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
