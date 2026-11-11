//! Listener: accept, limit, TLS, upgrade, hand over to a session; graceful drain on shutdown.
//!
//! Overload protection (master prompt §4, connections): a per-listener token bucket limits new
//! connections per second and a cap limits open ones. Refused connections still get a
//! WebSocket close (4101) with a retry hint, so clients back off instead of hammering.

use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use songbird_mailbox::Mailbox;
use songbird_proto::CloseCode;
use songbird_router::Router;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::bucket::Bucket;
use crate::config::TlsSettings;
use crate::ws::{self, UpgradeError};
use crate::{Shared, session};

/// TLS setup failed.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The certificate chain could not be read or parsed.
    #[error("tls certificate chain: {0}")]
    Chain(String),
    /// The private key could not be read or parsed (no details: it is a secret).
    #[error("tls private key unreadable or invalid")]
    Key,
    /// rustls refused the configuration.
    #[error("tls configuration: {0}")]
    Config(String),
}

/// Builds the TLS acceptor: TLS 1.3 only, aws-lc-rs, session resumption by tickets and cache,
/// ALPN `http/1.1`.
///
/// # Errors
/// [`TlsError`].
pub fn tls_acceptor(t: &TlsSettings) -> Result<TlsAcceptor, TlsError> {
    let chain_file =
        std::fs::File::open(&t.cert_chain).map_err(|e| TlsError::Chain(e.to_string()))?;
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(BufReader::new(chain_file))
            .collect::<Result<_, _>>()
            .map_err(|e| TlsError::Chain(e.to_string()))?;
    if chain.is_empty() {
        return Err(TlsError::Chain("no certificate".into()));
    }
    let secret = t.key.resolve().map_err(|_| TlsError::Key)?;
    let key =
        PrivateKeyDer::from_pem_slice(secret.expose().as_bytes()).map_err(|_| TlsError::Key)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(64 * 1024);
    cfg.ticketer =
        rustls::crypto::aws_lc_rs::Ticketer::new().map_err(|e| TlsError::Config(e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Serves `listener` until `shutdown` turns true, then drains: stops accepting, tells every
/// session to close with 4200 within the drain window, and waits for them.
pub async fn serve<M, R>(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    shared: Arc<Shared<M, R>>,
    mut shutdown: watch::Receiver<bool>,
) where
    M: Mailbox,
    R: Router,
{
    let s = &shared.config.session;
    let mut accepts = Bucket::new(s.accepts_per_sec, s.accept_burst, std::time::Instant::now());
    let (drain_tx, drain_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    // Hourly expiry sweep: nothing undelivered outlives MAX_ENVELOPE_AGE (invariant 3). The
    // worker service takes this over with the SurrealDB store (milestone 5).
    let mut expiry = tokio::time::interval(Duration::from_secs(3600));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = expiry.tick() => {
                if shared.mailbox.expire_older_than(songbird_mailbox::MAX_ENVELOPE_AGE).await.is_err() {
                    shared.metrics.mailbox_errors.inc();
                }
            }
            _ = async { shutdown.wait_for(|d| *d).await.is_ok() } => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((tcp, _peer)) = accepted else {
                    // Out of file descriptors or similar: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let open = usize::try_from(shared.metrics.connections_open.get()).unwrap_or(0);
                let refuse = match accepts.take(std::time::Instant::now()) {
                    Err(wait) => Some(wait),
                    Ok(()) if open >= s.max_connections => Some(Duration::from_secs(5)),
                    Ok(()) => None,
                };
                tasks.spawn(connection(tcp, tls.clone(), Arc::clone(&shared), drain_rx.clone(), refuse));
            }
        }
    }
    drop(listener);
    let _ = drain_tx.send(true);
    while tasks.join_next().await.is_some() {}
}

async fn connection<M, R>(
    tcp: TcpStream,
    tls: Option<TlsAcceptor>,
    shared: Arc<Shared<M, R>>,
    drain: watch::Receiver<bool>,
    refuse: Option<Duration>,
) where
    M: Mailbox,
    R: Router,
{
    let _ = tcp.set_nodelay(true);
    let timeout = shared.config.session.handshake_timeout();
    match tls {
        None => upgraded(tcp, shared, drain, refuse).await,
        Some(acceptor) => match tokio::time::timeout(timeout, acceptor.accept(tcp)).await {
            Ok(Ok(stream)) => upgraded(stream, shared, drain, refuse).await,
            _ => {
                shared.metrics.handshake_failures.inc();
            }
        },
    }
}

async fn upgraded<S, M, R>(
    stream: S,
    shared: Arc<Shared<M, R>>,
    drain: watch::Receiver<bool>,
    refuse: Option<Duration>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
    M: Mailbox,
    R: Router,
{
    let cfg = ws::ws_config(&shared.config.session, shared.limits.max_message_bytes());
    let timeout = shared.config.session.handshake_timeout();
    let mut ws = match ws::upgrade(stream, ws::SONGBIRD, cfg, timeout).await {
        Ok(ws) => ws,
        Err(UpgradeError::Timeout | UpgradeError::Io | UpgradeError::Rejected(_)) => {
            shared.metrics.handshake_failures.inc();
            return;
        }
    };
    if let Some(wait) = refuse {
        shared.metrics.connections_refused.inc();
        let ms = u32::try_from(wait.as_millis())
            .unwrap_or(u32::MAX)
            .max(1_000);
        let reason = songbird_proto::close::retry_reason(ms);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            ws.close(CloseCode::Overloaded.code(), &reason),
        )
        .await;
        return;
    }
    shared.metrics.connections.inc();
    shared.metrics.connections_open.inc();
    session::run(ws, Arc::clone(&shared), drain).await;
    shared.metrics.connections_open.dec();
}
