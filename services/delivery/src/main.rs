//! Songbird `delivery` service binary. See the library crate for the design.
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use songbird_delivery::config::{
    ClusterSettings, IggySettings, MailboxBackend, RouterBackend, SurrealSettings,
    ValkeyRouterSettings,
};
use songbird_delivery::{
    DeliveryConfig, DeliveryMetrics, DeliverySettings, Directory, Pusher, Shared, server,
};
use songbird_link::LinkTls;
use songbird_mailbox::AnyMailbox;
use songbird_mailbox::iggy::{ClusterConfig, IggyConfig, IggyConnection, IggyMailbox};
use songbird_mailbox::memory::MemoryMailbox;
use songbird_mailbox::surreal::{SurrealConfig, SurrealMailbox};
use songbird_router::valkey::{ValkeyRouter, ValkeyRouterConfig};
use songbird_router::{AnyRouter, LocalRouter};
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, Service};
use tokio::sync::watch;

// mimalloc (master prompt §4). `--features system-allocator` builds with the system allocator
// instead, only to measure the two against each other (M7, D-0043).
// Sanitizer builds keep the system allocator too: ASan and TSan see only allocations they intercept.
#[cfg(not(any(feature = "system-allocator", songbird_sanitizer)))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

struct Delivery {
    settings: DeliverySettings,
    directory: Directory,
    metrics: DeliveryMetrics,
    tls: Option<tokio_rustls::TlsAcceptor>,
    store: Store,
    route: Option<ValkeyRouterConfig>,
    /// The account registry and its poll interval (D-0036).
    registry: Option<(songbird_surreal::Config, Duration)>,
    /// The job queue for push wake-ups: client, jobs secret, debounce.
    jobs: Option<(redis::Client, [u8; 32], Duration)>,
    /// The worker's device link: TLS and listener.
    internal: Option<(LinkTls, std::net::SocketAddr)>,
}

/// Valkey connection settings resolved at startup: URL with credentials, CA, client identity.
struct ValkeyConn {
    url: String,
    tls_ca_pem: Option<Vec<u8>>,
    tls_client: Option<(Vec<u8>, Vec<u8>)>,
}

fn valkey_conn(s: &ValkeyRouterSettings) -> Result<ValkeyConn, BoxError> {
    let pass = s.pass.resolve()?;
    let user = s.user.clone().unwrap_or_default();
    let (scheme, host_port) = match &s.tls_domain {
        // With TLS the URL names the certificate's host (it must resolve to Valkey).
        Some(domain) if s.tls_ca.is_some() => {
            let port = s.addr.rsplit_once(':').map_or("6379", |(_, p)| p);
            ("rediss", format!("{domain}:{port}"))
        }
        _ => ("redis", s.addr.clone()),
    };
    let tls_client = match (&s.tls_cert, &s.tls_key) {
        (Some(cert), Some(key)) => Some((
            std::fs::read(cert)?,
            key.resolve()?.expose().as_bytes().to_vec(),
        )),
        _ => None,
    };
    Ok(ValkeyConn {
        url: format!("{scheme}://{user}:{}@{host_port}/", pass.expose()),
        tls_ca_pem: s.tls_ca.as_ref().map(std::fs::read).transpose()?,
        tls_client,
    })
}

/// Resolves the Valkey router settings (secrets, CA) at startup, before anything listens.
fn router_config(s: &ValkeyRouterSettings) -> Result<ValkeyRouterConfig, BoxError> {
    let conn = valkey_conn(s)?;
    let mut node_id = [0u8; 8];
    aws_lc_rs::rand::fill(&mut node_id).map_err(|_| "no system randomness")?;
    Ok(ValkeyRouterConfig {
        url: conn.url,
        tls_ca_pem: conn.tls_ca_pem,
        tls_client: conn.tls_client,
        cluster_secret: idempotency_secret(&s.cluster_secret)
            .map_err(|_| "cluster_secret must be 64 hex characters")?,
        subscribers: s.subscribers,
        node_id: u64::from_be_bytes(node_id),
    })
}

/// Resolves cluster mode (D-0034): node link TLS and the lease store (the router's Valkey).
fn cluster_config(
    c: &ClusterSettings,
    valkey: &ValkeyRouterSettings,
) -> Result<ClusterConfig, BoxError> {
    let chain = std::fs::read(&c.cert_chain)?;
    let key = c.key.resolve()?;
    let ca = std::fs::read(&c.ca)?;
    let link_tls = LinkTls::from_pem(&chain, key.expose().as_bytes(), &ca, &c.node_name)?;
    let conn = valkey_conn(valkey)?;
    Ok(ClusterConfig {
        node_name: c.node_name.clone(),
        link_listen: c.link_listen,
        link_advertise: c.link_advertise,
        link_tls,
        valkey_url: conn.url,
        valkey_tls_ca_pem: conn.tls_ca_pem,
        valkey_tls_client: conn.tls_client,
        lease_ttl: Duration::from_millis(c.lease_ttl_ms),
        zone: c.zone.clone(),
        senders: c.senders.clone(),
    })
}

/// The mailbox store chosen by configuration, resolved before anything listens.
enum Store {
    Memory,
    Surreal(Box<SurrealConfig>),
    Iggy(Box<IggyConfig>),
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery").finish_non_exhaustive()
    }
}

fn idempotency_secret(r: &songbird_types::SecretRef) -> Result<[u8; 32], BoxError> {
    let secret_hex = r.resolve()?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(secret_hex.expose().trim(), &mut out)
        .map_err(|_| "idempotency_secret must be 64 hex characters")?;
    Ok(out)
}

/// Resolves the Iggy settings (secrets) at startup, before anything listens.
fn iggy_config(
    s: &IggySettings,
    max_per_device: usize,
    generation: u64,
) -> Result<IggyConfig, BoxError> {
    let connection = IggyConnection {
        addr: s.addr.clone(),
        tls_domain: s.tls_domain.clone(),
        tls_ca_file: s
            .tls_ca
            .as_ref()
            .map(|p| p.to_str().map(str::to_owned).ok_or("tls_ca must be UTF-8"))
            .transpose()?,
        user: s.user.clone(),
        pass: s.pass.resolve()?.expose().to_owned(),
    };
    let mut cfg = IggyConfig::new(
        connection,
        idempotency_secret(&s.idempotency_secret)?,
        s.key_dir.clone(),
        idempotency_secret(&s.master_key).map_err(|_| "master_key must be 64 hex characters")?,
    );
    cfg.key_window = Duration::from_secs(s.key_window_secs);
    cfg.key_interval = Duration::from_millis(s.key_interval_ms);
    cfg.stream.clone_from(&s.stream);
    cfg.topic.clone_from(&s.topic);
    cfg.partitions = s.partitions;
    cfg.max_batch = s.max_batch;
    cfg.max_per_device = u64::try_from(max_per_device).unwrap_or(u64::MAX);
    cfg.ack_interval = Duration::from_millis(s.ack_interval_ms);
    cfg.timeout = Duration::from_millis(s.timeout_ms);
    cfg.relocate_after = Duration::from_secs(s.relocate_after_secs);
    cfg.segment_expiry = Duration::from_secs(s.segment_expiry_secs);
    cfg.segment_bytes = s.segment_mib.saturating_mul(1 << 20);
    cfg.cache_bytes = s.cache_mib.saturating_mul(1 << 20);
    cfg.store_generation = generation;
    Ok(cfg)
}

/// Resolves the SurrealDB settings (secrets, CA) at startup, before anything listens.
fn surreal_config(s: &SurrealSettings, max_per_device: usize) -> Result<SurrealConfig, BoxError> {
    let tls = match &s.tls_ca {
        None => None,
        Some(path) => {
            let file = std::fs::File::open(path)?;
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_reader_iter(BufReader::new(file)) {
                roots.add(cert?)?;
            }
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth();
            Some(Arc::new(cfg))
        }
    };
    let idempotency_secret = idempotency_secret(&s.idempotency_secret)?;
    Ok(SurrealConfig {
        rpc: songbird_surreal::Config {
            addr: s.addr.clone(),
            host: s.host.clone(),
            tls,
            user: s.user.clone(),
            pass: s.pass.resolve()?.expose().to_owned(),
            namespace: s.namespace.clone(),
            database: s.database.clone(),
            timeout: Duration::from_millis(s.timeout_ms),
            max_message_bytes: 64 << 20,
        },
        max_batch: s.max_batch,
        max_wait: Duration::from_micros(s.max_wait_us),
        ack_interval: Duration::from_millis(s.ack_interval_ms),
        max_per_device: u64::try_from(max_per_device).unwrap_or(u64::MAX),
        idempotency_secret,
    })
}

impl Service for Delivery {
    const NAME: &'static str = "delivery";
    type Config = DeliveryConfig;

    fn new(config: DeliveryConfig, metrics: &mut Metrics) -> Result<Self, BoxError> {
        let d = config.delivery;
        let directory = match &d.directory.file {
            Some(path) => Directory::load(path)?,
            None => Directory::empty(),
        };
        tracing::info!(devices = directory.len(), "device directory loaded");
        let tls = d.tls.as_ref().map(server::tls_acceptor).transpose()?;
        let store = match d.mailbox.backend {
            MailboxBackend::Memory => Store::Memory,
            MailboxBackend::Surrealdb => {
                let s = d
                    .mailbox
                    .surrealdb
                    .as_ref()
                    .ok_or("mailbox.surrealdb is required")?;
                Store::Surreal(Box::new(surreal_config(s, d.mailbox.max_per_device)?))
            }
            MailboxBackend::Iggy => {
                let s = d.mailbox.iggy.as_ref().ok_or("mailbox.iggy is required")?;
                let mut cfg = iggy_config(s, d.mailbox.max_per_device, d.mailbox.store_generation)?;
                if let Some(c) = &d.cluster {
                    let valkey = d
                        .router
                        .valkey
                        .as_ref()
                        .ok_or("cluster needs router.valkey")?;
                    cfg.cluster = Some(cluster_config(c, valkey)?);
                }
                Store::Iggy(Box::new(cfg))
            }
        };
        let route = match d.router.backend {
            RouterBackend::Local => None,
            RouterBackend::Valkey => Some(router_config(
                d.router
                    .valkey
                    .as_ref()
                    .ok_or("router.valkey is required")?,
            )?),
        };
        let registry = d
            .registry
            .as_ref()
            .map(|r| Ok::<_, BoxError>((r.surrealdb.config()?, Duration::from_millis(r.poll_ms))))
            .transpose()?;
        let jobs = d
            .jobs
            .as_ref()
            .map(|j| {
                Ok::<_, BoxError>((
                    j.valkey.client()?,
                    *j.secret.resolve_key32()?,
                    Duration::from_millis(j.push_debounce_ms),
                ))
            })
            .transpose()?;
        let internal = d
            .internal
            .as_ref()
            .map(|i| {
                let chain = std::fs::read(&i.cert_chain)?;
                let key = i.key.resolve()?;
                let ca = std::fs::read(&i.ca)?;
                let tls = LinkTls::from_pem(&chain, key.expose().as_bytes(), &ca, &i.node_name)?;
                Ok::<_, BoxError>((tls, i.listen))
            })
            .transpose()?;
        let m = DeliveryMetrics::default();
        m.register(metrics)?;
        Ok(Self {
            settings: d,
            directory,
            metrics: m,
            tls,
            store,
            route,
            registry,
            jobs,
            internal,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the start-up and shutdown sequence, in order"
    )]
    async fn run(self, mut ctx: Ctx) -> Result<(), BoxError> {
        let runtime = self.settings.runtime;
        // The mailbox runs on its own multi-thread runtime (D-0032): each Iggy partition's writer
        // gets a thread, apart from the delivery cores and from this control thread.
        let storage_threads = runtime.storage_thread_count(&self.settings.mailbox);
        let storage = StorageRuntime(Some(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(storage_threads)
                .thread_name("storage")
                .enable_all()
                .build()?,
        ));
        let (max_per_device, generation) = (
            self.settings.mailbox.max_per_device,
            self.settings.mailbox.store_generation,
        );
        let store = self.store;
        let mailbox = storage
            .handle()
            .spawn(open_mailbox(store, max_per_device, generation))
            .await??;
        tracing::info!(storage_threads, "mailbox runtime started");
        // The router's subscriber tasks also live on the storage runtime.
        let router = storage.handle().spawn(open_router(self.route)).await??;
        let cores = runtime.worker_count();
        // One listener per core on the same address: the kernel spreads connections (D-0032).
        let listeners =
            songbird_runtime::reuseport_listeners(self.settings.listen, cores, runtime.backlog)?;
        tracing::info!(
            tls = self.tls.is_some(),
            cores,
            pinned = runtime.pin,
            "websocket listeners bound"
        );
        let listeners: Arc<std::sync::Mutex<Vec<Option<std::net::TcpListener>>>> = Arc::new(
            std::sync::Mutex::new(listeners.into_iter().map(Some).collect()),
        );
        let (stop_tx, stop_rx) = watch::channel(false);
        let (directory, follow) = load_directory(self.registry, self.directory).await?;
        let franking = franker(self.settings.franking_key.as_ref())?;
        let mut shared = Shared::new(
            self.settings,
            directory,
            mailbox,
            router,
            self.metrics.clone(),
        );
        shared = shared.with_policy(songbird_delivery::Policy { franking });
        let mut pusher_task = None;
        if let Some(jobs) = self.jobs {
            let (pusher, task) = start_pusher(jobs, &self.metrics, stop_rx.clone()).await?;
            shared = shared.with_push(pusher);
            pusher_task = Some(task);
        }
        let shared = Arc::new(shared);
        let follower = follow.map(|(registry, version, generation, every)| {
            shared
                .generation
                .store(generation, std::sync::atomic::Ordering::Release);
            tokio::spawn(songbird_delivery::directory::follow_registry(
                registry,
                Arc::clone(&shared.directory),
                Arc::clone(&shared.generation),
                version,
                every,
                stop_rx.clone(),
            ))
        });
        let internal = match self.internal {
            Some(i) => Some(start_internal(i, Arc::clone(&shared), stop_rx.clone()).await?),
            None => None,
        };
        // The mailbox's tasks stay on this (main) thread's runtime; the cores reach them through
        // channels.
        let tls = self.tls;
        let worker_shared = shared.clone();
        let workers = songbird_runtime::start(
            songbird_runtime::Config {
                workers: cores,
                pin: runtime.pin,
            },
            move |core| {
                let listener = listeners
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_mut(core.index)
                    .and_then(Option::take);
                let (tls, shared, stop) = (tls.clone(), worker_shared.clone(), stop_rx.clone());
                async move {
                    songbird_service::telemetry::sharded::set_core_shard(core.index);
                    let Some(listener) = listener else { return };
                    match tokio::net::TcpListener::from_std(listener) {
                        Ok(l) => server::serve_core(l, tls, shared, stop, core).await,
                        Err(e) => {
                            tracing::error!(core = core.index, error = %e, "cannot use listener");
                        }
                    }
                }
            },
        )?;
        let serve = tokio::task::spawn_blocking(move || workers.join());
        ctx.health.set_ready(true);
        // A fenced Iggy writer (another node took the partitions over) makes this node unready.
        let watch_shared = shared.clone();
        let health = ctx.health.clone();
        let watcher = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                if let AnyMailbox::Iggy(m) = &watch_shared.mailbox
                    && !m.is_healthy()
                {
                    tracing::error!("mailbox writer fenced; marking not ready");
                    health.set_ready(false);
                    return;
                }
            }
        });
        ctx.shutdown().await;
        watcher.abort();
        let _ = stop_tx.send(true);
        let panicked = serve.await?;
        for t in [pusher_task, follower, internal].into_iter().flatten() {
            let _ = t.await;
        }
        // Cluster mode: key stores written and replicated, leases released, so the standbys take
        // over at once instead of after a lease period.
        if let AnyMailbox::Iggy(m) = &shared.mailbox {
            m.shutdown().await;
        }
        drop(shared);
        drop(storage);
        if panicked > 0 {
            return Err(format!("{panicked} delivery cores panicked").into());
        }
        Ok(())
    }
}

type Follow = (Arc<songbird_accounts::Registry>, i64, u64, Duration);

/// The directory: from the registry when configured (D-0036), else the static file.
async fn load_directory(
    registry: Option<(songbird_surreal::Config, Duration)>,
    fallback: Directory,
) -> Result<(Directory, Option<Follow>), BoxError> {
    let Some((cfg, every)) = registry else {
        return Ok((fallback, None));
    };
    let db = songbird_accounts::Db::connect(cfg).await?;
    let registry = Arc::new(songbird_accounts::Registry::connect(db).await?);
    let version = registry.directory_version().await?;
    let generation = registry.store_generation().await?;
    let directory = Directory::from_registry(&registry).await?;
    tracing::info!(
        devices = directory.len(),
        "device directory loaded from the registry"
    );
    tracing::info!(generation, "store generation from the registry");
    Ok((directory, Some((registry, version, generation, every))))
}

/// Push jobs for offline devices (D-0036).
async fn start_pusher(
    (client, secret, debounce): (redis::Client, [u8; 32], Duration),
    metrics: &DeliveryMetrics,
    stop: watch::Receiver<bool>,
) -> Result<(Pusher, tokio::task::JoinHandle<()>), BoxError> {
    let queue = songbird_jobs::Queue::connect(
        client,
        &secret,
        songbird_jobs::QueueConfig::new("delivery".into()),
    )
    .await?;
    let (pusher, rx) = Pusher::new(metrics.push());
    let task = tokio::spawn(songbird_delivery::push::run(
        Arc::new(queue),
        rx,
        debounce,
        metrics.push(),
        stop,
    ));
    tracing::info!("push jobs enabled");
    Ok((pusher, task))
}

/// The worker's device link (D-0036).
async fn start_internal(
    (tls, listen): (LinkTls, std::net::SocketAddr),
    shared: Arc<Shared<AnyMailbox, AnyRouter>>,
    stop: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>, BoxError> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("worker device link listening");
    Ok(tokio::spawn(songbird_link::serve(
        listener,
        tls,
        "worker.".into(),
        songbird_delivery::internal::handler(shared),
        Arc::new(songbird_link::LinkStats::default()),
        stop,
    )))
}

/// Connects the configured mailbox (on the storage runtime: its tasks stay there).
async fn open_mailbox(
    store: Store,
    max_per_device: usize,
    generation: u64,
) -> Result<AnyMailbox, BoxError> {
    Ok(match store {
        Store::Surreal(cfg) => {
            let m = SurrealMailbox::connect(*cfg).await?;
            tracing::info!("surrealdb mailbox connected");
            AnyMailbox::Surreal(m)
        }
        Store::Iggy(cfg) => {
            let m = IggyMailbox::connect(*cfg).await?;
            tracing::info!("iggy mailbox connected and replayed");
            AnyMailbox::Iggy(m)
        }
        Store::Memory => AnyMailbox::Memory(MemoryMailbox::new(max_per_device, generation)),
    })
}

/// The configured router (Valkey: connected on the storage runtime, where its subscribers run).
async fn open_router(cfg: Option<ValkeyRouterConfig>) -> Result<AnyRouter, BoxError> {
    Ok(match cfg {
        None => AnyRouter::Local(LocalRouter::new()),
        Some(cfg) => {
            let r = ValkeyRouter::connect(cfg).await?;
            tracing::info!("valkey router connected");
            AnyRouter::Valkey(Box::new(r))
        }
    })
}

/// The mailbox's runtime, shut down in the background when dropped, on every path out of `run`
/// (dropping a runtime in place inside another runtime's context panics).
struct StorageRuntime(Option<tokio::runtime::Runtime>);

impl StorageRuntime {
    fn handle(&self) -> tokio::runtime::Handle {
        match &self.0 {
            Some(rt) => rt.handle().clone(),
            None => tokio::runtime::Handle::current(),
        }
    }
}

impl Drop for StorageRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

fn main() -> std::process::ExitCode {
    sockudo_ws::init_clock();
    songbird_service::main::<Delivery>()
}

/// The franking key from the secrets store (Prompt 4, D-0061), if configured.
fn franker(
    key: Option<&songbird_types::SecretRef>,
) -> Result<Option<songbird_send::Franker>, BoxError> {
    key.map(|k| {
        let secret = k.resolve_key32()?;
        songbird_send::Franker::from_secret(&secret)
            .map_err(|_| BoxError::from("franking key derivation failed"))
    })
    .transpose()
}
