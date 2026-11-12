//! Songbird `api` service binary. See the library for the design (D-0036).
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use songbird_api::config::{ApiConfig, ApiSettings, S3Settings, TlsSettings};
use songbird_api::{ApiMetrics, App};
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, Service};
use tokio::sync::watch;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// How often the outbox is relayed to the job queue (a deletion relays at once; this catches
/// what a failure left).
const RELAY_EVERY: Duration = Duration::from_secs(2);

struct Api {
    settings: Option<ApiSettings>,
    metrics: ApiMetrics,
    tls: Option<tokio_rustls::TlsAcceptor>,
}

fn tls_acceptor(t: &TlsSettings) -> Result<tokio_rustls::TlsAcceptor, BoxError> {
    let file = std::fs::File::open(&t.cert_chain)?;
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(BufReader::new(file)).collect::<Result<_, _>>()?;
    let secret = t.key.resolve()?;
    let key = PrivateKeyDer::from_pem_slice(secret.expose().as_bytes())
        .map_err(|_| "api.tls.key is not a PEM private key")?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
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

/// Builds the application from settings (connects to every store).
///
/// # Errors
/// A store is unreachable or a secret unreadable.
async fn build(s: &ApiSettings, metrics: ApiMetrics) -> Result<Arc<App>, BoxError> {
    let db = songbird_accounts::Db::connect(s.surrealdb.config()?).await?;
    let registry = Arc::new(songbird_accounts::Registry::connect(db).await?);
    let s3 = songbird_s3::Client::new(s3_config(&s.s3)?)?;
    s3.create_bucket().await?;
    let queue = songbird_jobs::Queue::connect(
        s.jobs.valkey.client()?,
        &s.jobs.secret.resolve_key32()?.clone(),
        songbird_jobs::QueueConfig::new("api".into()),
    )
    .await?;
    let hot = songbird_valkey::ValkeyConn::connect(s.valkey_hot.client()?).await?;
    let mut push_public = [0u8; 32];
    hex::decode_to_slice(&s.push_public_key, &mut push_public)?;
    Ok(Arc::new(App {
        server_name: s.server_name.clone(),
        registry,
        s3,
        queue: Arc::new(queue),
        hot,
        push_public,
        push_index_secret: *s.push_index_secret.resolve_key32()?,
        limits: s.attachments,
        metrics,
    }))
}

impl Service for Api {
    const NAME: &'static str = "api";
    type Config = ApiConfig;

    fn new(config: ApiConfig, metrics: &mut Metrics) -> Result<Self, BoxError> {
        let tls = config
            .api
            .as_ref()
            .and_then(|a| a.tls.as_ref())
            .map(tls_acceptor)
            .transpose()?;
        let m = ApiMetrics::default();
        m.register(metrics)?;
        Ok(Self {
            settings: config.api,
            metrics: m,
            tls,
        })
    }

    async fn run(self, mut ctx: Ctx) -> Result<(), BoxError> {
        let Some(settings) = self.settings else {
            tracing::info!("no [api] section: idle (development)");
            return songbird_service::idle_until_shutdown(ctx).await;
        };
        let app = build(&settings, self.metrics).await?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let listener = tokio::net::TcpListener::bind(settings.listen).await?;
        tracing::info!(tls = self.tls.is_some(), "api listening");
        let server = tokio::spawn(songbird_api::server::serve(
            listener,
            self.tls,
            Arc::clone(&app),
            settings.max_connections,
            stop_rx.clone(),
        ));
        let mut admin = None;
        if let Some(a) = &settings.admin {
            let chain = std::fs::read(&a.cert_chain)?;
            let key = a.key.resolve()?;
            let ca = std::fs::read(&a.ca)?;
            let tls = songbird_link::LinkTls::from_pem(
                &chain,
                key.expose().as_bytes(),
                &ca,
                &a.node_name,
            )?;
            let l = tokio::net::TcpListener::bind(a.listen).await?;
            admin = Some(tokio::spawn(songbird_link::serve(
                l,
                tls,
                "admin.".into(),
                songbird_api::admin::handler(Arc::clone(&app.registry)),
                Arc::new(songbird_link::LinkStats::default()),
                stop_rx.clone(),
            )));
        }
        let relay_app = Arc::clone(&app);
        let mut relay_stop = stop_rx.clone();
        let relay = tokio::spawn(async move {
            let mut tick = tokio::time::interval(RELAY_EVERY);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = relay_stop.changed() => return,
                }
                if let Err(e) =
                    songbird_jobs::relay(relay_app.registry.as_ref(), &relay_app.queue).await
                {
                    tracing::warn!(error = %e, "outbox relay failed");
                }
            }
        });
        ctx.health.set_ready(true);
        ctx.shutdown().await;
        ctx.health.set_ready(false);
        let _ = stop_tx.send(true);
        let _ = server.await;
        let _ = relay.await;
        if let Some(a) = admin {
            let _ = a.await;
        }
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    songbird_service::main::<Api>()
}
