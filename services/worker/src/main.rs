//! Songbird `worker` service binary. See the library for the design (D-0036).
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use serde::Deserialize;
use songbird_jobs::{ConsumeConfig, Queue, QueueConfig, Stream};
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, HasCommon, Service};
use songbird_types::SecretRef;
use songbird_types::config::{CommonConfig, Validate, Validator};
use songbird_worker::{DeliveryLink, Worker, WorkerMetrics};
use tokio::sync::watch;

// Sanitizer builds keep the system allocator: ASan and TSan see only allocations they intercept.
#[cfg(not(songbird_sanitizer))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// The configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerConfig {
    common: CommonConfig,
    /// Absent in development: the service idles (smoke test without stores).
    #[serde(default)]
    worker: Option<WorkerSettings>,
}

impl HasCommon for WorkerConfig {
    fn common(&self) -> &CommonConfig {
        &self.common
    }
}

impl Validate for WorkerConfig {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
        let deployed = self.common.environment.is_deployed();
        let Some(w) = &self.worker else {
            v.check(!deployed, "worker", "is required in staging and production");
            return;
        };
        v.section("worker", w);
        if deployed {
            v.check(
                w.deletion_journal.as_ref().is_some_and(|j| j.tls),
                "worker.deletion_journal",
                "is required in staging and production, over TLS (D-0041)",
            );
            v.check(
                w.requests_secret.is_some(),
                "worker.requests_secret",
                "is required in staging and production (deleting blocks, D-0062)",
            );
            v.check(
                w.push_tokens.as_ref().is_some_and(|p| {
                    p.tls_ca.is_some()
                        && p.user != w.surrealdb.user
                        && p.database != w.surrealdb.database
                }),
                "worker.push_tokens",
                "is required in staging and production, with TLS, its own user and its own database",
            );
            v.check(
                w.s3.tls_ca.is_some() && w.surrealdb.tls_ca.is_some() && w.jobs.valkey.tls(),
                "worker.s3.tls_ca",
                "worker.surrealdb.tls_ca and worker.jobs.valkey.tls_ca are required in staging and production",
            );
        }
    }
}

/// `[worker]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSettings {
    surrealdb: songbird_accounts::SurrealSettings,
    /// Push registrations' own database and credential (D-0095); development may omit it (a
    /// database beside the registry's).
    #[serde(default)]
    push_tokens: Option<songbird_accounts::SurrealSettings>,
    jobs: JobsSettings,
    s3: S3Settings,
    push_index_secret: SecretRef,
    delivery: DeliverySettings,
    /// The deletion journal in the off-site backup bucket (D-0041); development may omit it.
    #[serde(default)]
    deletion_journal: Option<JournalSettings>,
    /// Milliseconds for every delivery node to drop a disabled device (its directory poll
    /// interval with a margin).
    #[serde(default = "default_propagation_ms")]
    propagation_ms: u64,
    /// Seconds between sweeps.
    #[serde(default = "default_sweep_secs")]
    sweep_secs: u64,
    /// Key transparency on akd (Prompt 3, D-0057): the VRF key's 32-byte seed (64 hex
    /// characters). Absent: nothing is published (development).
    #[serde(default)]
    kt_vrf_key: Option<SecretRef>,
    /// `[api.requests] secret` (Prompt 4, D-0062): finds a deleted account's block rows.
    /// Required in staging and production.
    #[serde(default)]
    requests_secret: Option<SecretRef>,
}

const fn default_propagation_ms() -> u64 {
    3_000
}

const fn default_sweep_secs() -> u64 {
    60
}

impl Validate for WorkerSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("surrealdb", &self.surrealdb);
        v.section("jobs.valkey", &self.jobs.valkey);
        v.section("delivery", &self.delivery);
        v.check(
            (100..=60_000).contains(&self.propagation_ms),
            "propagation_ms",
            "must be in 100..=60000",
        );
        v.check(
            (1..=3_600).contains(&self.sweep_secs),
            "sweep_secs",
            "must be in 1..=3600",
        );
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobsSettings {
    valkey: songbird_valkey::ValkeySettings,
    secret: SecretRef,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct S3Settings {
    addr: String,
    #[serde(default)]
    tls_domain: Option<String>,
    #[serde(default)]
    tls_ca: Option<PathBuf>,
    bucket: String,
    access_key: SecretRef,
    secret_key: SecretRef,
}

/// `[worker.deletion_journal]`: where tombstones go (the backup bucket) and the journal key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalSettings {
    /// S3 `host:port`, e.g. `hel1.your-objectstorage.com:443` (D-0042).
    addr: String,
    bucket: String,
    #[serde(default = "default_region")]
    region: String,
    /// TLS with the public web roots (the off-site provider); off only for a local `RustFS`.
    #[serde(default = "default_true")]
    tls: bool,
    /// The journal's put-only key (it can write `deletions/` and nothing else).
    access_key: SecretRef,
    secret_key: SecretRef,
    /// 64 hex characters.
    key: SecretRef,
}

fn default_region() -> String {
    "hel1".into()
}

const fn default_true() -> bool {
    true
}

/// The keys of block rows (Prompt 4, D-0062), from `requests_secret`, checked against the
/// fingerprint every node pins in the registry: a worker with another secret would find none of a
/// deleted account's block rows and still report the deletion verified.
async fn block_keys(
    secret: Option<&SecretRef>,
    registry: &songbird_accounts::Registry,
) -> Result<Option<songbird_accounts::blocks::GateKeys>, BoxError> {
    let Some(k) = secret else {
        return Ok(None);
    };
    let secret = k.resolve_key32()?;
    let keys = songbird_accounts::blocks::GateKeys::from_cluster_secret(&secret)
        .map_err(|_| BoxError::from("block key derivation failed"))?;
    if !registry
        .pin_fingerprint("requests", &keys.fingerprint())
        .await?
    {
        return Err(BoxError::from(
            "requests_secret differs from the other nodes' (registry pin)",
        ));
    }
    Ok(Some(keys))
}

fn journal(s: &JournalSettings) -> Result<songbird_worker::Journal, BoxError> {
    let mut cfg = songbird_s3::Config::new(
        s.addr.clone(),
        s.bucket.clone(),
        s.access_key.resolve()?,
        s.secret_key.resolve()?,
    );
    cfg.region.clone_from(&s.region);
    if s.tls {
        let host = s.addr.rsplit_once(':').map_or(s.addr.as_str(), |(h, _)| h);
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        host.clone_into(&mut cfg.host);
        cfg.tls = Some(songbird_s3::Tls {
            config: Arc::new(config),
            server_name: host.to_owned(),
        });
    }
    Ok(songbird_worker::Journal {
        s3: songbird_s3::Client::new(cfg)?,
        key: *s.key.resolve_key32()?,
    })
}

/// `[worker.delivery]`: the delivery nodes' device links, and this worker's identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliverySettings {
    /// This worker's name (its certificate's, `worker.<host>.songbird.internal`).
    node_name: String,
    cert_chain: PathBuf,
    key: SecretRef,
    ca: PathBuf,
    /// Delivery nodes: address and certificate name.
    nodes: Vec<Node>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    addr: SocketAddr,
    name: String,
}

impl Validate for DeliverySettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.node_name.starts_with("worker.") && self.node_name.ends_with(".songbird.internal"),
            "node_name",
            "must be worker.<host>.songbird.internal",
        );
        v.check(
            !self.nodes.is_empty() && self.nodes.len() <= 64,
            "nodes",
            "must list 1 to 64 delivery nodes",
        );
        v.check(
            self.nodes
                .iter()
                .all(|n| n.name.starts_with("delivery.") && n.name.ends_with(".songbird.internal")),
            "nodes.name",
            "must be delivery.<host>.songbird.internal",
        );
    }
}

struct WorkerService {
    settings: Option<WorkerSettings>,
    metrics: WorkerMetrics,
}

fn s3_config(s: &S3Settings) -> Result<songbird_s3::Config, BoxError> {
    let mut cfg = songbird_s3::Config::new(
        s.addr.clone(),
        s.bucket.clone(),
        s.access_key.resolve()?,
        s.secret_key.resolve()?,
    );
    if let (Some(ca), Some(domain)) = (&s.tls_ca, &s.tls_domain) {
        let file = std::fs::File::open(ca)?;
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_reader_iter(BufReader::new(file)) {
            roots.add(c?)?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.tls = Some(songbird_s3::Tls {
            config: Arc::new(config),
            server_name: domain.clone(),
        });
        cfg.host.clone_from(domain);
    }
    Ok(cfg)
}

impl Service for WorkerService {
    const NAME: &'static str = "worker";
    type Config = WorkerConfig;

    fn new(config: WorkerConfig, metrics: &mut Metrics) -> Result<Self, BoxError> {
        // The registry's write-conflict retries and busy answers (D-0093).
        for (name, help, read) in songbird_accounts::METRICS {
            metrics.register_counter_fn(name, help, read)?;
        }
        let m = WorkerMetrics::default();
        m.register(metrics)?;
        Ok(Self {
            settings: config.worker,
            metrics: m,
        })
    }

    async fn run(self, mut ctx: Ctx) -> Result<(), BoxError> {
        let Some(s) = &self.settings else {
            tracing::info!("no [worker] section: idle (development)");
            return songbird_service::idle_until_shutdown(ctx).await;
        };
        let db = songbird_accounts::Db::connect(s.surrealdb.config()?).await?;
        let registry = Arc::new(songbird_accounts::Registry::connect(db).await?);
        let push_store = Arc::new(match &s.push_tokens {
            Some(p) => {
                songbird_accounts::PushStore::connect(
                    songbird_accounts::Db::connect(p.config()?).await?,
                )
                .await?
            }
            None => songbird_accounts::PushStore::beside(&registry).await?,
        });
        let queue = Arc::new(
            Queue::connect(
                s.jobs.valkey.client()?,
                &s.jobs.secret.resolve_key32()?.clone(),
                QueueConfig::new(format!("worker-{}", std::process::id())),
            )
            .await?,
        );
        queue
            .ensure_groups(&[Stream::Deletion, Stream::Cleanup])
            .await?;
        let d = &s.delivery;
        let chain = std::fs::read(&d.cert_chain)?;
        let key = d.key.resolve()?;
        let ca = std::fs::read(&d.ca)?;
        let tls =
            songbird_link::LinkTls::from_pem(&chain, key.expose().as_bytes(), &ca, &d.node_name)?;
        let nodes = d
            .nodes
            .iter()
            .map(|n| songbird_link::LinkClient::new(n.addr, &n.name, tls.clone()))
            .collect();
        // The akd writer (the only one), on its own connection.
        let kt = match &s.kt_vrf_key {
            Some(k) => {
                let store = songbird_akd::SurrealStore::connect(Arc::new(
                    songbird_accounts::Db::connect(s.surrealdb.config()?).await?,
                ))
                .await
                .map_err(|e| e.to_string())?;
                Some(Arc::new(
                    songbird_akd::Publisher::open(
                        store,
                        songbird_akd::SecretVrf::new(&*k.resolve_key32()?),
                    )
                    .await
                    .map_err(|e| e.to_string())?,
                ))
            }
            None => None,
        };
        let block_keys = block_keys(s.requests_secret.as_ref(), &registry).await?;
        let worker = Arc::new(Worker {
            push_store,
            registry,
            s3: songbird_s3::Client::new(s3_config(&s.s3)?)?,
            queue: Arc::clone(&queue),
            delivery: DeliveryLink::Nodes(nodes),
            push_index_secret: *s.push_index_secret.resolve_key32()?,
            journal: s.deletion_journal.as_ref().map(journal).transpose()?,
            propagation: Duration::from_millis(s.propagation_ms),
            kt,
            block_keys,
            metrics: self.metrics,
        });
        let (stop_tx, stop_rx) = watch::channel(false);
        let mut tasks = Vec::new();
        for stream in [Stream::Deletion, Stream::Cleanup] {
            let w = Arc::clone(&worker);
            tasks.push(tokio::spawn(songbird_jobs::consume(
                Arc::clone(&queue),
                stream,
                ConsumeConfig {
                    concurrency: if stream == Stream::Deletion { 8 } else { 64 },
                    ..ConsumeConfig::default()
                },
                move |job| {
                    let w = Arc::clone(&w);
                    async move { w.handle(job).await }
                },
                stop_rx.clone(),
            )));
        }
        let w = Arc::clone(&worker);
        let every = Duration::from_secs(s.sweep_secs);
        let mut stop = stop_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tokio::select! {
                    _ = tick.tick() => w.sweep().await,
                    _ = stop.changed() => return,
                }
            }
        }));
        ctx.health.set_ready(true);
        ctx.shutdown().await;
        ctx.health.set_ready(false);
        let _ = stop_tx.send(true);
        for t in tasks {
            let _ = t.await;
        }
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    songbird_service::main::<WorkerService>()
}
