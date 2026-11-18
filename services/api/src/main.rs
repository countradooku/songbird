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
/// What `PUT /v1/messages` enforces beyond limits: franking, the gate (requests, broadcasts and
/// the channel rate class) and group rosters.
fn send_policy(
    s: &SendSettings,
    gate: Option<(Arc<dyn songbird_send::Gate>, songbird_send::RequestLimits)>,
    registry: &Arc<songbird_accounts::Registry>,
) -> Result<songbird_send::Policy, BoxError> {
    let limits = gate
        .as_ref()
        .map_or_else(songbird_send::RequestLimits::default, |(_, l)| *l);
    Ok(songbird_send::Policy {
        franking: s
            .franking_key
            .as_ref()
            .map(|k| {
                let secret = k.resolve_key32().map_err(BoxError::from)?;
                songbird_send::Franker::from_secret(&secret)
                    .map_err(|_| BoxError::from("franking key derivation failed"))
            })
            .transpose()?,
        max_broadcast_accounts: limits.max_broadcast_accounts,
        // The channel rate class's per-node part, at the cluster's rates (D-0077).
        channels: Arc::new(songbird_send::groups::ChannelBudget::new(
            limits.channel_per_sec,
            limits.channel_burst,
        )),
        gate: gate.map(|(g, _)| g),
        rosters: Some(Arc::new(songbird_send::RegistryRosters::new(
            Arc::clone(registry),
            songbird_send::groups::ROSTER_TTL,
        ))),
    })
}

async fn build_messages(
    s: &SendSettings,
    gate: Option<(Arc<dyn songbird_send::Gate>, songbird_send::RequestLimits)>,
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
        songbird_send::Directory::from_registry(registry).await?,
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
            policy: send_policy(s, gate, registry)?,
        }),
        limits: s.limits.limits(),
        sends_per_sec: s.sends_per_sec,
        send_burst: s.send_burst,
        group_sends_per_sec: s.group_sends_per_sec,
        group_send_burst: s.group_send_burst,
        rate_key: songbird_api::messages::rate_key(&cluster_secret)
            .map_err(|_| "rate-limit key derivation failed")?,
        metrics: metrics.send.clone(),
        // MLS groups (Prompt 5): keys derived from the cluster secret, so every `api` node
        // computes the same fan-out keys; limits at their defaults (1,024 devices, 4 MiB).
        groups: Some(
            songbird_api::groups::Groups::new(&cluster_secret, songbird_groups::Limits::default())
                .ok_or("groups key derivation failed")?,
        ),
    };
    Ok((messages, vec![follower, pusher]))
}

/// Builds the application from settings (connects to every store).
///
/// # Errors
/// A store is unreachable or a secret unreadable.
/// `[api.kt]` (Prompt 3, D-0057), if configured: akd's read-only directory on its own connection.
async fn transparency(s: &ApiSettings) -> Result<Option<songbird_api::kt::Transparency>, BoxError> {
    let Some(k) = &s.kt else {
        return Ok(None);
    };
    let store = songbird_akd::SurrealStore::connect(Arc::new(
        songbird_accounts::Db::connect(s.surrealdb.config()?).await?,
    ))
    .await
    .map_err(|e| e.to_string())?;
    Ok(Some(songbird_api::kt::Transparency::new(
        k.clone(),
        &*k.secret.resolve_key32()?,
        &*k.log_key.resolve_key32()?,
        &*k.vrf_key.resolve_key32()?,
        store,
    )?))
}

/// `[api.calls]` (Prompt 7), if configured.
fn calls(
    s: &ApiSettings,
    metrics: &ApiMetrics,
) -> Result<Option<songbird_api::calls::CallsApi>, BoxError> {
    let Some(c) = &s.calls else {
        return Ok(None);
    };
    let calls = songbird_calls::Calls::from_settings(c)?;
    Ok(Some(songbird_api::calls::CallsApi {
        calls: Arc::new(calls),
        metrics: metrics.calls.clone(),
    }))
}

/// `[api.media]` (Prompt 6), if configured.
fn media(s: &ApiSettings) -> Result<Option<songbird_api::media::Media>, BoxError> {
    let Some(m) = &s.media else {
        return Ok(None);
    };
    let secret = m.secret.resolve_key32()?;
    let media = songbird_api::media::Media::new(m.budgets, m.downloads, &secret);
    let Some(g) = &m.gifs else {
        return Ok(Some(media));
    };
    // GIPHY (D-0079 §4): its key comes from the owner's account, never the repository.
    let key = g
        .api_key
        .as_ref()
        .ok_or("[api.media.gifs] api_key is required")?
        .resolve()?;
    let provider = songbird_api::gifs::Giphy::new(key.expose().trim().to_owned(), g.rating.clone());
    Ok(Some(media.with_gifs(songbird_api::gifs::Gifs::new(
        g.clone(),
        Box::new(provider),
        &secret,
    )?)))
}

/// `[api.profiles]` (Prompt 3, M5), if configured.
fn profiles(
    s: &ApiSettings,
    metrics: &ApiMetrics,
) -> Result<Option<songbird_api::profiles::Profiles>, BoxError> {
    let Some(p) = &s.profiles else {
        return Ok(None);
    };
    let cert = p
        .certificate_key
        .as_ref()
        .map(songbird_types::SecretRef::resolve_key32)
        .transpose()?;
    Ok(Some(songbird_api::profiles::Profiles::new(
        p.clone(),
        &*p.secret.resolve_key32()?,
        cert.as_deref(),
        metrics.profiles.clone(),
    )?))
}

/// `[api.requests]` (Prompt 4, D-0062), if configured: the blocks and request-policy endpoints,
/// and the gate of requests and broadcasts on `PUT /v1/messages`.
#[allow(
    clippy::type_complexity,
    reason = "the endpoints, and the gate with its broadcast limit"
)]
async fn requests(
    s: &ApiSettings,
    registry: &Arc<songbird_accounts::Registry>,
    metrics: &ApiMetrics,
) -> Result<
    (
        Option<songbird_api::requests::Requests>,
        Option<(Arc<dyn songbird_send::Gate>, songbird_send::RequestLimits)>,
    ),
    BoxError,
> {
    let Some(r) = &s.requests else {
        return Ok((None, None));
    };
    let secret = r.secret.resolve_key32()?;
    let keys = songbird_send::GateKeys::from_cluster_secret(&secret)
        .map_err(|_| BoxError::from("gate key derivation failed"))?;
    // Every node must hold the same requests secret: block rows written by one are found by all.
    if !registry
        .pin_fingerprint("requests", &keys.fingerprint())
        .await?
    {
        return Err(BoxError::from(
            "the requests secret differs from the one every other node uses (registry pin)",
        ));
    }
    let gate: Arc<dyn songbird_send::Gate> = Arc::new(songbird_send::RegistryGate::new(
        Arc::clone(registry),
        songbird_valkey::ValkeyConn::connect(s.valkey_hot.client()?).await?,
        keys.clone(),
        r.limits,
    ));
    Ok((
        Some(songbird_api::requests::Requests::new(
            keys,
            metrics.blocks.clone(),
        )),
        Some((gate, r.limits)),
    ))
}

/// `[api.reports]` (Prompt 4, D-0063), if configured: the franking keys reports are verified
/// against (`[api.send]`: current and previous), the gate's keys and the moderation key.
fn reports(
    s: &ApiSettings,
    metrics: &ApiMetrics,
) -> Result<Option<songbird_api::reports::Reports>, BoxError> {
    let (Some(r), Some(req), Some(send)) = (&s.reports, &s.requests, &s.send) else {
        return Ok(None);
    };
    let franker = |k: &songbird_types::SecretRef| -> Result<songbird_send::Franker, BoxError> {
        let secret = k.resolve_key32()?;
        songbird_send::Franker::from_secret(&secret)
            .map_err(|_| BoxError::from("franking key derivation failed"))
    };
    let current = franker(
        send.franking_key
            .as_ref()
            .ok_or("[api.reports] needs [api.send] franking_key")?,
    )?;
    let previous = send
        .previous_franking_keys
        .iter()
        .map(franker)
        .collect::<Result<Vec<_>, _>>()?;
    let secret = req.secret.resolve_key32()?;
    let keys = songbird_send::GateKeys::from_cluster_secret(&secret)
        .map_err(|_| BoxError::from("gate key derivation failed"))?;
    let mut moderation = [0u8; 32];
    hex::decode_to_slice(&r.moderation_key, &mut moderation)?;
    Ok(Some(songbird_api::reports::Reports::new(
        songbird_send::Frankers { current, previous },
        keys,
        moderation,
        r.clone(),
        metrics.reports.clone(),
    )))
}

async fn build(
    s: &ApiSettings,
    metrics: ApiMetrics,
    stop: &watch::Receiver<bool>,
) -> Result<(Arc<App>, Vec<tokio::task::JoinHandle<()>>), BoxError> {
    let db = songbird_accounts::Db::connect(s.surrealdb.config()?).await?;
    let registry = Arc::new(songbird_accounts::Registry::connect(db).await?);
    let push_store = Arc::new(match &s.push_tokens {
        Some(p) => {
            songbird_accounts::PushStore::connect(songbird_accounts::Db::connect(p.config()?).await?)
                .await?
        }
        None => songbird_accounts::PushStore::beside(&registry).await?,
    });
    // Registrations written to the registry before D-0095 move to their own database once.
    let moved = push_store.move_from_registry(&registry).await?;
    if moved > 0 {
        tracing::info!(moved, "push registrations moved to their own database");
    }
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
    let (requests, gate) = requests(s, &registry, &metrics).await?;
    let (messages, tasks) = match &s.send {
        Some(send) => {
            let (m, t) = build_messages(send, gate, &registry, &queue, &metrics, stop).await?;
            (Some(m), t)
        }
        None => (None, Vec::new()),
    };
    let registration = match &s.registration {
        Some(r) => {
            let reg = songbird_api::registration::Registration::new(
                r.clone(),
                &*r.secret.resolve_key32()?,
                metrics.registration.clone(),
            )
            .map_err(|_| "registration key derivation failed")?;
            Some(reg)
        }
        None => None,
    };
    let usernames = match &s.usernames {
        Some(u) => Some(songbird_api::usernames::Usernames::new(
            u.clone(),
            &*u.secret.resolve_key32()?,
            metrics.usernames.clone(),
        )?),
        None => None,
    };
    let (keys, devices) = match &s.keys {
        Some(k) => {
            let seed = k
                .system_key
                .as_ref()
                .map(songbird_types::SecretRef::resolve_key32)
                .transpose()?;
            let secret = k.secret.resolve_key32()?;
            (
                Some(songbird_api::keys::KeyDirectory::new(
                    k.clone(),
                    &secret,
                    seed.as_deref(),
                    metrics.keys.clone(),
                )?),
                Some(songbird_api::devices::Devices::new(
                    k.devices.clone(),
                    &k.throttle,
                    &secret,
                    seed.as_deref(),
                    metrics.devices.clone(),
                )?),
            )
        }
        None => (None, None),
    };
    let profiles = profiles(s, &metrics)?;
    let kt = transparency(s).await?;
    let reports = reports(s, &metrics)?;
    let calls = calls(s, &metrics)?;
    let app = Arc::new(App {
        reports,
        requests,
        server_name: s.server_name.clone(),
        push_store,
        registry,
        s3,
        queue,
        hot,
        push_public,
        push_index_secret: *s.push_index_secret.resolve_key32()?,
        limits: s.attachments,
        media: media(s)?,
        metrics,
        messages,
        registration,
        usernames,
        keys,
        devices,
        profiles,
        kt,
        calls,
    });
    Ok((app, tasks))
}

impl Service for Api {
    const NAME: &'static str = "api";
    type Config = ApiConfig;

    fn new(config: ApiConfig, metrics: &mut Metrics) -> Result<Self, BoxError> {
        // The registry's write-conflict retries and busy answers (D-0093).
        for (name, help, read) in songbird_accounts::METRICS {
            metrics.register_counter_fn(name, help, read)?;
        }
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
        let (app, send_tasks) = Box::pin(build(&settings, self.metrics, &stop_rx)).await?;
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
        // Group commit fan-outs a crash interrupted (Prompt 5).
        let redrive = tokio::spawn(songbird_api::groups::redrive(
            Arc::clone(&app.registry),
            Arc::clone(&app),
            stop_rx.clone(),
        ));
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
        let _ = redrive.await;
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
