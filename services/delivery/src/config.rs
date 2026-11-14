//! Delivery configuration (`[delivery]` section), validated at startup.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
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
                d.registry.is_some(),
                "delivery.registry",
                "is required in staging and production",
            );
            v.check(
                d.jobs.is_some(),
                "delivery.jobs",
                "is required in staging and production (push wake-ups)",
            );
            v.check(
                d.internal.is_some(),
                "delivery.internal",
                "is required in staging and production (account deletion)",
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
            v.check(
                d.router.backend == RouterBackend::Local
                    || d.router
                        .valkey
                        .as_ref()
                        .is_some_and(|s| s.tls_ca.is_some() && s.tls_cert.is_some()),
                "delivery.router.valkey.tls_ca",
                "and tls_cert are required in staging and production",
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
    /// Thread-per-core runtime.
    #[serde(default)]
    pub runtime: RuntimeSettings,
    /// Routing between nodes.
    #[serde(default)]
    pub router: RouterConfig,
    /// Several nodes sharing the mailbox (D-0034); absent: this node runs every partition.
    #[serde(default)]
    pub cluster: Option<ClusterSettings>,
    /// The account registry the directory is loaded from (D-0036); absent: the static file.
    #[serde(default)]
    pub registry: Option<RegistrySettings>,
    /// The job queue push wake-ups go to (D-0036); absent: no push jobs.
    #[serde(default)]
    pub jobs: Option<JobsSettings>,
    /// The link `worker` deletes devices through (D-0036); absent: account deletion cannot reach
    /// this node.
    #[serde(default)]
    pub internal: Option<InternalSettings>,
}

/// `[delivery.registry]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySettings {
    /// Where the registry lives.
    pub surrealdb: songbird_accounts::SurrealSettings,
    /// How often the directory version is polled, in milliseconds (a deleted device can
    /// authenticate for about this long).
    #[serde(default = "default_poll_ms")]
    pub poll_ms: u64,
}

const fn default_poll_ms() -> u64 {
    1_000
}

impl Validate for RegistrySettings {
    fn validate(&self, v: &mut Validator) {
        v.section("surrealdb", &self.surrealdb);
        v.check(
            (100..=10_000).contains(&self.poll_ms),
            "poll_ms",
            "must be in 100..=10000",
        );
    }
}

/// `[delivery.jobs]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobsSettings {
    /// `valkey-jobs`.
    pub valkey: songbird_valkey::ValkeySettings,
    /// 64 hex characters sealing jobs (shared with `push` and `worker`).
    pub secret: SecretRef,
    /// At most one wake-up per device per this many milliseconds.
    #[serde(default = "default_debounce_ms")]
    pub push_debounce_ms: u64,
}

const fn default_debounce_ms() -> u64 {
    2_000
}

impl Validate for JobsSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("valkey", &self.valkey);
        v.check(
            (100..=60_000).contains(&self.push_debounce_ms),
            "push_debounce_ms",
            "must be in 100..=60000",
        );
    }
}

/// `[delivery.internal]`: mutual TLS from the internal CA; only `worker.` certificates.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalSettings {
    /// Listener (private address).
    pub listen: SocketAddr,
    /// This node's name (its certificate's, `delivery.<host>.songbird.internal`).
    pub node_name: String,
    /// PEM certificate chain, leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
    /// PEM root of the internal CA.
    pub ca: PathBuf,
}

impl Validate for InternalSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.node_name.starts_with("delivery.")
                && self.node_name.ends_with(".songbird.internal"),
            "node_name",
            "must be delivery.<host>.songbird.internal",
        );
        v.check(
            songbird_types::config::is_internal_ip(self.listen.ip()),
            "listen",
            "must be a private or loopback address",
        );
    }
}

/// `[delivery.cluster]`: this node in a cluster of delivery nodes sharing the Iggy topic. Leases
/// and membership live in the router's Valkey; nodes talk over node links with mutual TLS.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterSettings {
    /// This node's name, the one its certificate is for (`delivery.<host>.songbird.internal`).
    pub node_name: String,
    /// Where the node link listener binds (private address).
    pub link_listen: SocketAddr,
    /// The address other nodes reach it at.
    pub link_advertise: SocketAddr,
    /// PEM certificate chain (internal CA), leaf first.
    pub cert_chain: PathBuf,
    /// PEM private key.
    pub key: SecretRef,
    /// PEM root of the internal CA.
    pub ca: PathBuf,
    /// Partition lease length in milliseconds (renewed every third of it; a dead owner's
    /// partitions move after about this long).
    #[serde(default = "default_lease_ttl_ms")]
    pub lease_ttl_ms: u64,
    /// This node's failure domain (zone or rack, `[a-z0-9-]`, at most 32 bytes): each
    /// partition's second standby is placed in a zone neither its owner nor its first standby
    /// is in. Empty: no zones.
    #[serde(default)]
    pub zone: String,
    /// Services that only send, admitted to the node link for the store of a send and nothing
    /// else (D-0044): `["api."]` when `api` serves `PUT /v1/messages`. Default: none.
    #[serde(default)]
    pub senders: Vec<String>,
}

/// Prefixes that may be listed in `[delivery.cluster] senders` (D-0044): services that link the
/// send path. Never `delivery.` (those are full members) or `push.`, `admin.` (they never send).
pub const SENDER_PREFIXES: [&str; 3] = ["api.", "calls.", "worker."];

const fn default_lease_ttl_ms() -> u64 {
    3_000
}

impl Validate for ClusterSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.node_name.starts_with("delivery.")
                && self.node_name.ends_with(".songbird.internal"),
            "node_name",
            "must be delivery.<host>.songbird.internal",
        );
        v.check(
            (1_000..=60_000).contains(&self.lease_ttl_ms),
            "lease_ttl_ms",
            "must be in 1000..=60000",
        );
        v.check(
            self.zone.len() <= 32
                && self
                    .zone
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "zone",
            "must be [a-z0-9-], at most 32 bytes",
        );
        v.check(
            self.senders
                .iter()
                .all(|p| SENDER_PREFIXES.contains(&p.as_str())),
            "senders",
            "may list only api., calls. and worker.",
        );
    }
}

/// Router backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouterBackend {
    /// Within this process only (one node).
    #[default]
    Local,
    /// Across nodes over Valkey pub/sub (D-0034).
    Valkey,
}

/// `[delivery.router]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RouterConfig {
    /// Backend.
    pub backend: RouterBackend,
    /// Valkey settings (required for `valkey`).
    pub valkey: Option<ValkeyRouterSettings>,
}

/// `[delivery.router.valkey]`: Valkey sees only keyed channel names and sealed payloads
/// (D-0034).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValkeyRouterSettings {
    /// `host:port`.
    pub addr: String,
    /// TLS server name (required with `tls_ca`).
    #[serde(default)]
    pub tls_domain: Option<String>,
    /// PEM root of the internal CA; TLS is on when set.
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,
    /// ACL user (default user when absent).
    #[serde(default)]
    pub user: Option<String>,
    /// Password.
    pub pass: SecretRef,
    /// PEM client certificate chain (Valkey requires client certificates in deployments).
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// PEM client key.
    #[serde(default)]
    pub tls_key: Option<SecretRef>,
    /// 64 hex characters, the same on every node: channel names and payload keys derive from it.
    pub cluster_secret: SecretRef,
    /// Subscriber connections.
    #[serde(default = "default_subscribers")]
    pub subscribers: usize,
}

const fn default_subscribers() -> usize {
    4
}

impl Validate for RouterConfig {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.backend != RouterBackend::Valkey || self.valkey.is_some(),
            "valkey",
            "is required for the valkey backend",
        );
        if let Some(s) = &self.valkey {
            v.check(!s.addr.is_empty(), "valkey.addr", "must be host:port");
            v.check(
                (1..=64).contains(&s.subscribers),
                "valkey.subscribers",
                "must be in 1..=64",
            );
            v.check(
                s.tls_ca.is_none() || s.tls_domain.is_some(),
                "valkey.tls_domain",
                "is required with tls_ca",
            );
            v.check(
                s.tls_cert.is_some() == s.tls_key.is_some(),
                "valkey.tls_key",
                "and tls_cert go together",
            );
        }
    }
}

/// `[delivery.runtime]`: one pinned worker thread per core, each with its own listener
/// (`SO_REUSEPORT`) and current-thread runtime (D-0032). The mailbox runs on the main thread.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeSettings {
    /// Worker cores; 0 means every CPU this process may use (`taskset`, cgroup cpuset). On a
    /// single server, confine delivery so the stores keep cores of their own.
    pub workers: usize,
    /// Pin each worker to its own CPU.
    pub pin: bool,
    /// Listen backlog of each core's listener.
    pub backlog: i32,
    /// Threads of the mailbox's own runtime; 0 means one per Iggy partition (one for the other
    /// backends). Leave CPUs for them: give `workers` fewer CPUs than the process may use.
    pub storage_threads: usize,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            workers: 0,
            pin: true,
            backlog: 4096,
            storage_threads: 0,
        }
    }
}

impl RuntimeSettings {
    /// The worker count to start: `workers`, or every allowed CPU when 0.
    #[must_use]
    pub fn worker_count(&self) -> usize {
        if self.workers == 0 {
            songbird_runtime::allowed_cpus().len().max(1)
        } else {
            self.workers
        }
    }
}

impl RuntimeSettings {
    /// The mailbox runtime's thread count: `storage_threads`, or one per Iggy partition.
    #[must_use]
    pub fn storage_thread_count(&self, mailbox: &MailboxConfig) -> usize {
        if self.storage_threads > 0 {
            return self.storage_threads;
        }
        match (mailbox.backend, &mailbox.iggy) {
            (MailboxBackend::Iggy, Some(i)) => usize::try_from(i.partitions).unwrap_or(1).max(1),
            _ => 1,
        }
    }
}

impl Validate for RuntimeSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(self.workers <= 1024, "workers", "must be at most 1024");
        v.check(
            self.storage_threads <= 256,
            "storage_threads",
            "must be at most 256",
        );
        v.check(
            (1..=65_535).contains(&self.backlog),
            "backlog",
            "must be in 1..=65535",
        );
    }
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
        v.section("runtime", &self.runtime);
        v.section("router", &self.router);
        if let Some(r) = &self.registry {
            v.section("registry", r);
            v.check(
                self.directory.file.is_none(),
                "directory.file",
                "and registry are exclusive",
            );
        }
        if let Some(j) = &self.jobs {
            v.section("jobs", j);
        }
        if let Some(i) = &self.internal {
            v.section("internal", i);
        }
        if let Some(c) = &self.cluster {
            v.section("cluster", c);
            v.check(
                self.mailbox.backend == MailboxBackend::Iggy,
                "cluster",
                "needs the iggy mailbox",
            );
            v.check(
                self.router.backend == RouterBackend::Valkey,
                "cluster",
                "needs the valkey router (leases live there)",
            );
        }
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

/// `[delivery.limits]`: frame limits (the send path's, shared with `api`).
pub use songbird_send::LimitsConfig;

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
    use songbird_proto::Limits;

    fn load(text: &str) -> Result<DeliveryConfig, String> {
        songbird_types::config::load_from_parts(text, Vec::<(String, String)>::new(), "SONGBIRD")
            .map_err(|e| e.to_string())
    }

    #[test]
    fn cluster_senders_admit_only_services_that_send() {
        let cluster = |senders: &[&str]| ClusterSettings {
            node_name: "delivery.a.songbird.internal".into(),
            link_listen: "127.0.0.1:7000".parse().unwrap(),
            link_advertise: "127.0.0.1:7000".parse().unwrap(),
            cert_chain: "chain.pem".into(),
            key: SecretRef::Env("KEY".into()),
            ca: "ca.pem".into(),
            lease_ttl_ms: 3_000,
            zone: String::new(),
            senders: senders.iter().map(|s| (*s).to_owned()).collect(),
        };
        let violations = |c: &ClusterSettings| {
            let mut v = Validator::default();
            c.validate(&mut v);
            v.violations().len()
        };
        assert_eq!(violations(&cluster(&[])), 0);
        assert_eq!(violations(&cluster(&["api.", "worker."])), 0);
        // A full member, a service that never sends, or a prefix without its dot: refused.
        for bad in ["delivery.", "push.", "admin.", "api", ""] {
            assert_eq!(violations(&cluster(&[bad])), 1, "{bad}");
        }
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
