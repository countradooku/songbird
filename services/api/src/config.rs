//! `api` configuration (`[api]`), validated at start-up.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use songbird_service::HasCommon;
use songbird_types::SecretRef;
use songbird_types::config::{CommonConfig, Validate, Validator};

/// The configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Shared settings.
    pub common: CommonConfig,
    /// `api` settings; absent in development, the service idles (smoke test without stores).
    #[serde(default)]
    pub api: Option<ApiSettings>,
}

impl HasCommon for ApiConfig {
    fn common(&self) -> &CommonConfig {
        &self.common
    }
}

impl Validate for ApiConfig {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
        let deployed = self.common.environment.is_deployed();
        let Some(api) = &self.api else {
            v.check(!deployed, "api", "is required in staging and production");
            return;
        };
        v.section("api", api);
        if deployed {
            v.check(
                api.tls.is_some(),
                "api.tls",
                "is required in staging and production",
            );
            v.check(
                api.s3.tls_ca.is_some(),
                "api.s3.tls_ca",
                "is required in staging and production",
            );
            v.check(
                api.surrealdb.tls_ca.is_some(),
                "api.surrealdb.tls_ca",
                "is required in staging and production",
            );
            v.check(
                api.valkey_hot.tls() && api.jobs.valkey.tls(),
                "api.valkey_hot.tls_ca",
                "and api.jobs.valkey.tls_ca are required in staging and production",
            );
            if let Some(s) = &api.send {
                v.check(
                    s.valkey.tls(),
                    "api.send.valkey.tls_ca",
                    "is required in staging and production",
                );
            }
        }
    }
}

/// `[api]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSettings {
    /// Public HTTPS listener.
    pub listen: SocketAddr,
    /// The host name devices sign (`api.<domain>`).
    pub server_name: String,
    /// TLS (required outside development).
    #[serde(default)]
    pub tls: Option<TlsSettings>,
    /// The account registry.
    pub surrealdb: songbird_accounts::SurrealSettings,
    /// `valkey-hot`: single-use nonces.
    pub valkey_hot: songbird_valkey::ValkeySettings,
    /// The job queue.
    pub jobs: JobsSettings,
    /// Attachment storage.
    pub s3: S3Settings,
    /// The push service's X25519 public key (64 hex characters; public, not a secret): push
    /// registrations are sealed to it.
    pub push_public_key: String,
    /// 64 hex characters keying push-token rows (shared with `push` and `worker`).
    pub push_index_secret: SecretRef,
    /// Attachment limits.
    #[serde(default)]
    pub attachments: AttachmentLimits,
    /// Account creation for operators and tests (Prompt 3 replaces it with registration).
    #[serde(default)]
    pub admin: Option<AdminSettings>,
    /// Concurrent connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// `PUT /v1/messages` (D-0037, D-0044); absent: the endpoint answers 503.
    #[serde(default)]
    pub send: Option<SendSettings>,
}

const fn default_max_connections() -> usize {
    4096
}

impl Validate for ApiSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            songbird_types::dns::is_valid_host(self.server_name.as_bytes()),
            "server_name",
            "must be a DNS host name",
        );
        v.section("surrealdb", &self.surrealdb);
        v.section("valkey_hot", &self.valkey_hot);
        v.section("jobs", &self.jobs);
        v.section("s3", &self.s3);
        v.section("attachments", &self.attachments);
        let mut k = [0u8; 32];
        v.check(
            hex::decode_to_slice(&self.push_public_key, &mut k).is_ok(),
            "push_public_key",
            "must be 64 hex characters",
        );
        if let Some(a) = &self.admin {
            v.section("admin", a);
        }
        v.check(
            (1..=1_000_000).contains(&self.max_connections),
            "max_connections",
            "must be in 1..=1000000",
        );
        if let Some(s) = &self.send {
            v.section("send", s);
        }
    }
}

/// `[api.tls]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    /// PEM chain, leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
}

/// `[api.jobs]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobsSettings {
    /// `valkey-jobs`.
    pub valkey: songbird_valkey::ValkeySettings,
    /// 64 hex characters sealing jobs.
    pub secret: SecretRef,
}

impl Validate for JobsSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("valkey", &self.valkey);
    }
}

/// `[api.s3]`: `api`'s own least-privilege `RustFS` credential (D-0035).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Settings {
    /// `host:port` (the mutual-TLS tunnel in deployments).
    pub addr: String,
    /// TLS server name (with `tls_ca`).
    #[serde(default)]
    pub tls_domain: Option<String>,
    /// PEM root of the internal CA; TLS is on when set.
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,
    /// Bucket of attachments.
    pub bucket: String,
    /// Access key ID.
    pub access_key: SecretRef,
    /// Secret access key.
    pub secret_key: SecretRef,
}

impl Validate for S3Settings {
    fn validate(&self, v: &mut Validator) {
        v.check(self.addr.contains(':'), "addr", "must be host:port");
        v.check(
            self.tls_ca.is_none() || self.tls_domain.is_some(),
            "tls_domain",
            "is required with tls_ca",
        );
        v.check(
            (3..=63).contains(&self.bucket.len()),
            "bucket",
            "must be 3 to 63 characters",
        );
    }
}

/// `[api.attachments]`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AttachmentLimits {
    /// Largest attachment (padded size), bytes.
    pub max_bytes: u64,
    /// Most recipient fetches one attachment may be granted.
    pub max_fetches: u32,
    /// How long an upload grant stays valid, seconds.
    pub grant_ttl_secs: u64,
}

impl Default for AttachmentLimits {
    fn default() -> Self {
        Self {
            max_bytes: 100 << 20,
            max_fetches: 1024,
            grant_ttl_secs: 3600,
        }
    }
}

impl Validate for AttachmentLimits {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (1..=(5 << 30)).contains(&self.max_bytes),
            "max_bytes",
            "must be in 1..=5 GiB",
        );
        v.check(
            (1..=100_000).contains(&self.max_fetches),
            "max_fetches",
            "must be in 1..=100000",
        );
        v.check(
            (60..=86_400).contains(&self.grant_ttl_secs),
            "grant_ttl_secs",
            "must be in 60..=86400",
        );
    }
}

/// `[api.admin]`: a node link accepting only `admin.` certificates (internal CA).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSettings {
    /// Listener (private address).
    pub listen: SocketAddr,
    /// This service's name (`api.<host>.songbird.internal`).
    pub node_name: String,
    /// PEM chain, leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
    /// PEM root of the internal CA.
    pub ca: PathBuf,
}

impl Validate for AdminSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.node_name.starts_with("api.") && self.node_name.ends_with(".songbird.internal"),
            "node_name",
            "must be api.<host>.songbird.internal",
        );
        v.check(
            songbird_types::config::is_internal_ip(self.listen.ip()),
            "listen",
            "must be a private or loopback address",
        );
    }
}

/// `[api.send]`: `PUT /v1/messages` through the shared send path (D-0037). `api` owns no mailbox
/// partition: it stores on each partition's owner over node links, admitted there for the store
/// of a send only (D-0044). Everything that must match the delivery nodes is named so.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendSettings {
    /// Frame limits: the delivery nodes' `[delivery.limits]`.
    #[serde(default)]
    pub limits: songbird_send::LimitsConfig,
    /// Sustained sends per second per device: the delivery nodes' `session.sends_per_sec`.
    #[serde(default = "default_sends_per_sec")]
    pub sends_per_sec: u32,
    /// Send burst: the delivery nodes' `session.send_burst`.
    #[serde(default = "default_send_burst")]
    pub send_burst: u32,
    /// Iggy stream of the mailbox: the delivery nodes' `mailbox.iggy.stream`.
    pub stream: String,
    /// Iggy topic: the delivery nodes' `mailbox.iggy.topic`.
    pub topic: String,
    /// Partitions: the delivery nodes' `mailbox.iggy.partitions`.
    pub partitions: u32,
    /// The delivery nodes' `mailbox.iggy.idempotency_secret` (64 hex characters), so a retry
    /// over the WebSocket after an HTTP attempt is recognised.
    pub idempotency_secret: SecretRef,
    /// Longest wait for a partition owner's answer, milliseconds.
    #[serde(default = "default_send_timeout_ms")]
    pub timeout_ms: u64,
    /// The delivery nodes' `cluster.lease_ttl_ms`: partition owners are read every third of it.
    #[serde(default = "default_lease_ttl_ms")]
    pub lease_ttl_ms: u64,
    /// This service's node-link identity (`api.<host>.songbird.internal`, internal CA).
    pub node_name: String,
    /// PEM chain, leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
    /// PEM root of the internal CA.
    pub ca: PathBuf,
    /// The router's Valkey (`[delivery.router.valkey]`): routing and the partition leases.
    pub valkey: songbird_valkey::ValkeySettings,
    /// The router's cluster secret (64 hex characters).
    pub cluster_secret: SecretRef,
    /// How often the device directory is checked for changes, milliseconds.
    #[serde(default = "default_directory_poll_ms")]
    pub directory_poll_ms: u64,
    /// At most one push job per device per this window, milliseconds.
    #[serde(default = "default_push_debounce_ms")]
    pub push_debounce_ms: u64,
}

const fn default_sends_per_sec() -> u32 {
    50
}
const fn default_send_burst() -> u32 {
    200
}
const fn default_send_timeout_ms() -> u64 {
    5_000
}
const fn default_lease_ttl_ms() -> u64 {
    3_000
}
const fn default_directory_poll_ms() -> u64 {
    1_000
}
const fn default_push_debounce_ms() -> u64 {
    5_000
}

impl Validate for SendSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("limits", &self.limits);
        v.check(
            (1..=1_000).contains(&self.sends_per_sec),
            "sends_per_sec",
            "must be in 1..=1000",
        );
        v.check(
            (1..=100_000).contains(&self.send_burst),
            "send_burst",
            "must be in 1..=100000",
        );
        v.check(
            !self.stream.is_empty() && !self.topic.is_empty(),
            "stream",
            "and topic must be set",
        );
        v.check(
            (1..=4096).contains(&self.partitions),
            "partitions",
            "must be in 1..=4096",
        );
        v.check(
            (100..=60_000).contains(&self.timeout_ms),
            "timeout_ms",
            "must be in 100..=60000",
        );
        v.check(
            (1_000..=60_000).contains(&self.lease_ttl_ms),
            "lease_ttl_ms",
            "must be in 1000..=60000",
        );
        v.check(
            self.node_name.starts_with("api.") && self.node_name.ends_with(".songbird.internal"),
            "node_name",
            "must be api.<host>.songbird.internal",
        );
        v.section("valkey", &self.valkey);
        v.check(
            (100..=60_000).contains(&self.directory_poll_ms),
            "directory_poll_ms",
            "must be in 100..=60000",
        );
        v.check(
            (100..=3_600_000).contains(&self.push_debounce_ms),
            "push_debounce_ms",
            "must be in 100..=3600000",
        );
    }
}
