//! Songbird `delivery` service binary. See the library crate for the design.
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use songbird_delivery::config::{IggySettings, MailboxBackend, SurrealSettings};
use songbird_delivery::{
    DeliveryConfig, DeliveryMetrics, DeliverySettings, Directory, Shared, server,
};
use songbird_mailbox::AnyMailbox;
use songbird_mailbox::iggy::{IggyConfig, IggyConnection, IggyMailbox};
use songbird_mailbox::memory::MemoryMailbox;
use songbird_mailbox::surreal::{SurrealConfig, SurrealMailbox};
use songbird_router::LocalRouter;
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, Service};
use tokio::sync::watch;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

struct Delivery {
    settings: DeliverySettings,
    directory: Directory,
    metrics: DeliveryMetrics,
    tls: Option<tokio_rustls::TlsAcceptor>,
    store: Store,
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
                Store::Iggy(Box::new(iggy_config(
                    s,
                    d.mailbox.max_per_device,
                    d.mailbox.store_generation,
                )?))
            }
        };
        let m = DeliveryMetrics::default();
        m.register(metrics)?;
        Ok(Self {
            settings: d,
            directory,
            metrics: m,
            tls,
            store,
        })
    }

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
        let cores = runtime.worker_count();
        // One listener per core on the same address: the kernel spreads connections (D-0032).
        let listeners =
            songbird_runtime::reuseport_listeners(self.settings.listen, cores, runtime.backlog)?;
        tracing::info!(
            tls = self.tls.is_some(),
            cores,
            pin = runtime.pin,
            "websocket listeners bound"
        );
        let listeners: Arc<std::sync::Mutex<Vec<Option<std::net::TcpListener>>>> = Arc::new(
            std::sync::Mutex::new(listeners.into_iter().map(Some).collect()),
        );
        let shared = Arc::new(Shared::new(
            self.settings,
            self.directory,
            mailbox,
            LocalRouter::new(),
            self.metrics,
        ));
        let (stop_tx, stop_rx) = watch::channel(false);
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
        drop(shared);
        drop(storage);
        if panicked > 0 {
            return Err(format!("{panicked} delivery cores panicked").into());
        }
        Ok(())
    }
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
