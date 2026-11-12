//! Settings of the Iggy mailbox and its connections.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use iggy::prelude::{
    AutoLogin, Client as _, ClientWrapper, Credentials, IggyClient, IggyError, TcpClient,
    TcpClientConfig,
};
use secrecy::SecretString;

/// How to reach Iggy (TCP, optionally TLS with the internal CA).
#[derive(Clone)]
pub struct IggyConnection {
    /// `host:port`.
    pub addr: String,
    /// TLS server name; `None` for plain TCP (development and CI only).
    pub tls_domain: Option<String>,
    /// PEM file of the CA that signs the server certificate (with TLS).
    pub tls_ca_file: Option<String>,
    /// User.
    pub user: String,
    /// Password (from a secret file or the environment, never logged).
    pub pass: String,
}

impl std::fmt::Debug for IggyConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IggyConnection")
            .field("tls", &self.tls_domain.is_some())
            .finish_non_exhaustive()
    }
}

impl IggyConnection {
    /// A new connection, signed in.
    ///
    /// # Errors
    /// Connecting or signing in failed.
    pub async fn client(&self) -> Result<IggyClient, IggyError> {
        // Our TLS uses aws-lc-rs (locked stack); make it the process default before the SDK
        // builds any TLS configuration.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cfg = TcpClientConfig {
            server_address: self.addr.clone(),
            tls_enabled: self.tls_domain.is_some(),
            tls_domain: self.tls_domain.clone().unwrap_or_default(),
            tls_ca_file: self.tls_ca_file.clone(),
            tls_validate_certificate: true,
            auto_login: AutoLogin::Enabled(Credentials::UsernamePassword(
                self.user.clone(),
                SecretString::from(self.pass.clone()),
            )),
            nodelay: true,
            ..TcpClientConfig::default()
        };
        let tcp = TcpClient::create(Arc::new(cfg))?;
        let client = IggyClient::new(ClientWrapper::Tcp(tcp));
        client.connect().await?;
        Ok(client)
    }
}

/// Mailbox settings.
#[derive(Clone)]
pub struct IggyConfig {
    /// Connection settings (each writer and reader opens its own connection).
    pub connection: IggyConnection,
    /// Stream name.
    pub stream: String,
    /// Topic name.
    pub topic: String,
    /// Partitions (fixed once the topic exists; one writer each).
    pub partitions: u32,
    /// First producer id; partition `p` uses `producer_base + p`.
    pub producer_base: u64,
    /// Most sends per append.
    pub max_batch: usize,
    /// Requests queued per writer before `store` waits.
    pub queue: usize,
    /// Soft limit of pending entries per device.
    pub max_per_device: u64,
    /// ACK checkpoint interval.
    pub ack_interval: Duration,
    /// How long `store` waits for its writers.
    pub timeout: Duration,
    /// Compaction interval.
    pub compaction_interval: Duration,
    /// Pending entries older than this are copied forward by compaction.
    pub relocate_after: Duration,
    /// Sealed segments below the low-water offset are deleted after this (topic
    /// `message_expiry`, set when the topic is created).
    pub segment_expiry: Duration,
    /// Size of the topic's segments (set when the topic is created). Iggy deletes whole sealed
    /// segments only, so the time to fill one is part of how long delivered ciphertext stays on
    /// disk: size it to the traffic.
    pub segment_bytes: u64,
    /// Record payloads kept in memory per partition for reads (bytes).
    pub cache_bytes: usize,
    /// HMAC key for idempotency tags.
    pub idempotency_secret: [u8; 32],
    /// Store generation (increment after restoring Iggy from a backup).
    pub store_generation: u64,
    /// Directory of the key stores (a directory per partition), on this host's persistent disk (D-0031).
    pub key_dir: PathBuf,
    /// Master key sealing the key stores (from a secret; the same on a replacement host).
    pub master_key: [u8; 32],
    /// A new key window is opened this often.
    pub key_window: Duration,
    /// The key store is written this often (when it changed): an acknowledged message's key
    /// leaves the disk within about this long.
    pub key_interval: Duration,
    /// Idempotency entries are written to the idempotency topic this often (off the write path);
    /// until then they hold the low-water offset back.
    pub idem_flush: Duration,
    /// Cluster mode (D-0034): several nodes share the topic, each partition owned by one of them.
    /// `None`: this node runs every partition.
    pub cluster: Option<super::ClusterConfig>,
    /// Fault injection for tests: stop a multi-partition send after its home record, as a crash
    /// would (the re-driver must complete it).
    #[doc(hidden)]
    pub fault_skip_remote_parts: bool,
}

impl std::fmt::Debug for IggyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IggyConfig")
            .field("partitions", &self.partitions)
            .field("max_batch", &self.max_batch)
            .finish_non_exhaustive()
    }
}

impl IggyConfig {
    /// Defaults for everything but the connection, the secrets and the key directory.
    #[must_use]
    pub fn new(
        connection: IggyConnection,
        idempotency_secret: [u8; 32],
        key_dir: PathBuf,
        master_key: [u8; 32],
    ) -> Self {
        Self {
            connection,
            stream: "songbird".into(),
            topic: "mailbox".into(),
            partitions: 4,
            producer_base: 1,
            max_batch: 256,
            queue: 65_536,
            max_per_device: 10_000,
            ack_interval: Duration::from_millis(50),
            timeout: Duration::from_secs(5),
            compaction_interval: Duration::from_mins(1),
            relocate_after: Duration::from_mins(15),
            segment_expiry: Duration::from_mins(10),
            segment_bytes: 16 << 20,
            cache_bytes: 64 << 20,
            idempotency_secret,
            store_generation: 1,
            key_dir,
            master_key,
            key_window: Duration::from_mins(10),
            key_interval: Duration::from_secs(1),
            idem_flush: Duration::from_secs(1),
            cluster: None,
            fault_skip_remote_parts: false,
        }
    }
}
