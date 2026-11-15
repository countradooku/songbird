//! Songbird `api` service binary. See the library for the design (D-0036).
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use songbird_api::config::{ApiConfig, ApiSettings, S3Settings, SendSettings, TlsSettings};
use songbird_api::messages::{Messages, SendStack};
use songbird_api::{ApiMetrics, App};
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, Service};
use tokio::sync::watch;

// Sanitizer builds keep the system allocator: ASan and TSan see only allocations they intercept.
#[cfg(not(songbird_sanitizer))]
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

/// `PUT /v1/messages`: the send path over a send-only mailbox client (stores on the partition
/// owners over node links, D-0044), a publish-only router, the registry's directory and push
/// jobs. Returns the endpoint and its background tasks (directory follower, push batcher).
async fn build_messages(
    s: &SendSettings,
    registry: &Arc<songbird_accounts::Registry>,
    queue: &Arc<songbird_jobs::Queue>,
    metrics: &ApiMetrics,
    stop: &watch::Receiver<bool>,
) -> Result<(Messages, Vec<tokio::task::JoinHandle<()>>), BoxError> {
    let chain = std::fs::read(&s.cert_chain)?;
    let key = s.key.resolve()?;
    let ca = std::fs::read(&s.ca)?;
    let link_tls =
        songbird_link::LinkTls::from_pem(&chain, key.expose().as_bytes(), &ca, &s.node_name)?;
    let mailbox =
        songbird_mailbox::iggy::IggySender::connect(songbird_mailbox::iggy::IggySenderConfig {
            stream: s.stream.clone(),
            topic: s.topic.clone(),
            partitions: s.partitions,
            idempotency_secret: *s.idempotency_secret.resolve_key32()?,
            timeout: Duration::from_millis(s.timeout_ms),
            link_tls,
            valkey: s.valkey.client()?,
            refresh: Duration::from_millis(s.lease_ttl_ms / 3),
        })
        .await
        .map_err(|_| "mailbox partition owners unreachable (Valkey)")?;
    tracing::info!(
        known = mailbox.known(),
        partitions = s.partitions,
        "send path: partition owners read"
    );
    let cluster_secret = *s.cluster_secret.resolve_key32()?;
    let router =
        songbird_router::valkey::ValkeyRouter::publisher(s.valkey.client()?, &cluster_secret)
            .await?;
    // The directory, followed like the delivery nodes follow it.
    let version = registry.directory_version().await?;
    let directory = Arc::new(songbird_send::LiveDirectory::from(
        songbird_send::Directory::from_accounts(
            registry
                .load_directory()
                .await?
                .into_iter()
                .map(|(d, a, k)| (d, k, a)),
        ),
    ));
    let follower = tokio::spawn(songbird_send::directory::follow_registry(
        Arc::clone(registry),
        Arc::clone(&directory),
        // The store generation is the delivery nodes' business; followed here only because the
        // follower updates both.
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
        version,
        Duration::from_millis(s.directory_poll_ms),
        stop.clone(),
    ));
    let (push, rx) = songbird_send::Pusher::new(metrics.push.clone());
    let pusher = tokio::spawn(songbird_send::push::run(
        Arc::clone(queue),
        rx,
        Duration::from_millis(s.push_debounce_ms),
        metrics.push.clone(),
        stop.clone(),
    ));
    let messages = Messages {
        path: Box::new(SendStack {
            directory,
            mailbox,
            router,
            push,
            metrics: metrics.send.clone(),
        }),
        limits: s.limits.limits(),
        sends_per_sec: s.sends_per_sec,
        send_burst: s.send_burst,
        rate_key: songbird_api::messages::rate_key(&cluster_secret)
            .map_err(|_| "rate-limit key derivation failed")?,
        metrics: metrics.send.clone(),
    };
    Ok((messages, vec![follower, pusher]))
}

/// Builds the application from settings (connects to every store).
///
/// # Errors
/// A store is unreachable or a secret unreadable.
async fn build(
    s: &ApiSettings,
    metrics: ApiMetrics,
    stop: &watch::Receiver<bool>,
) -> Result<(Arc<App>, Vec<tokio::task::JoinHandle<()>>), BoxError> {
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
    let queue = Arc::new(queue);
    let (messages, tasks) = match &s.send {
        Some(send) => {
            let (m, t) = build_messages(send, &registry, &queue, &metrics, stop).await?;
            (Some(m), t)
        }
        None => (None, Vec::new()),
    };
    let app = Arc::new(App {
        server_name: s.server_name.clone(),
        registry,
        s3,
        queue,
        hot,
        push_public,
        push_index_secret: *s.push_index_secret.resolve_key32()?,
        limits: s.attachments,
        metrics,
        messages,
    });
    Ok((app, tasks))
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
        let (stop_tx, stop_rx) = watch::channel(false);
        let (app, send_tasks) = build(&settings, self.metrics, &stop_rx).await?;
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
        for t in send_tasks {
            let _ = t.await;
        }
        if let Some(a) = admin {
            let _ = a.await;
        }
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    songbird_service::main::<Api>()
}
