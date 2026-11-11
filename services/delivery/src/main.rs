//! Songbird `delivery` service binary. See the library crate for the design.
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use songbird_delivery::config::{MailboxBackend, SurrealSettings};
use songbird_delivery::{
    DeliveryConfig, DeliveryMetrics, DeliverySettings, Directory, Shared, server,
};
use songbird_mailbox::AnyMailbox;
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
    surreal: Option<SurrealConfig>,
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery").finish_non_exhaustive()
    }
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
    let secret_hex = s.idempotency_secret.resolve()?;
    let mut idempotency_secret = [0u8; 32];
    hex::decode_to_slice(secret_hex.expose().trim(), &mut idempotency_secret)
        .map_err(|_| "idempotency_secret must be 64 hex characters")?;
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
        let surreal = match (d.mailbox.backend, &d.mailbox.surrealdb) {
            (MailboxBackend::Surrealdb, Some(s)) => {
                Some(surreal_config(s, d.mailbox.max_per_device)?)
            }
            (MailboxBackend::Surrealdb, None) => return Err("mailbox.surrealdb is required".into()),
            (MailboxBackend::Memory, _) => None,
        };
        let m = DeliveryMetrics::default();
        m.register(metrics)?;
        Ok(Self {
            settings: d,
            directory,
            metrics: m,
            tls,
            surreal,
        })
    }

    async fn run(self, mut ctx: Ctx) -> Result<(), BoxError> {
        let mailbox = match self.surreal {
            Some(cfg) => {
                let m = SurrealMailbox::connect(cfg).await?;
                tracing::info!("surrealdb mailbox connected");
                AnyMailbox::Surreal(m)
            }
            None => AnyMailbox::Memory(MemoryMailbox::new(
                self.settings.mailbox.max_per_device,
                self.settings.mailbox.store_generation,
            )),
        };
        let listener = tokio::net::TcpListener::bind(self.settings.listen).await?;
        tracing::info!(tls = self.tls.is_some(), "websocket listener bound");
        let shared = Arc::new(Shared::new(
            self.settings,
            self.directory,
            mailbox,
            LocalRouter::new(),
            self.metrics,
        ));
        let (stop_tx, stop_rx) = watch::channel(false);
        let serve = tokio::spawn(server::serve(listener, self.tls, shared, stop_rx));
        ctx.health.set_ready(true);
        ctx.shutdown().await;
        let _ = stop_tx.send(true);
        serve.await?;
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    sockudo_ws::init_clock();
    songbird_service::main::<Delivery>()
}
