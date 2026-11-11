//! The relay: outer TLS in, inner bytes out, nothing logged.
//!
//! Per connection:
//! 1. Accept TCP; over [`Limits::max_connections`](crate::config::Limits) the socket is closed.
//! 2. Complete the outer TLS handshake (the proxy's own certificate) and read the client's inner
//!    `ClientHello`, both within `handshake_timeout_secs`.
//! 3. Route by the inner SNI to an allowed upstream; unknown names are closed silently.
//! 4. Forward the buffered bytes, then copy both directions until either side closes or nothing
//!    moves for `idle_timeout_secs`.
//!
//! The inner TLS session runs end to end between the client and the Songbird server; the proxy
//! cannot read it. No addresses, host names or byte counts are logged or stored.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::config::{ProxyConfig, TlsConfig};
use crate::sni::{RECORD_HEADER_LEN, Scan, scan};

/// Pause after a failed `accept` (for example out of file descriptors) before trying again.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
/// Largest certificate chain file accepted.
const MAX_CERT_FILE: u64 = 1024 * 1024;

/// Startup errors.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Reading the certificate or key failed.
    #[error("tls material: {0}")]
    Tls(String),
    /// Configuration or secret error.
    #[error(transparent)]
    Config(#[from] songbird_types::ConfigError),
}

/// Builds the outer TLS acceptor (rustls with aws-lc-rs, TLS 1.2 and 1.3 safe defaults).
///
/// # Errors
/// [`StartError`] if the certificate or key cannot be read or do not match.
pub fn tls_acceptor(cfg: &TlsConfig) -> Result<TlsAcceptor, StartError> {
    let tls = |e: &dyn std::fmt::Display| StartError::Tls(e.to_string());
    let meta = std::fs::metadata(&cfg.cert).map_err(|e| tls(&e))?;
    if meta.len() > MAX_CERT_FILE {
        return Err(StartError::Tls("certificate file too large".into()));
    }
    let pem = std::fs::read(&cfg.cert).map_err(|e| tls(&e))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<_, _>>()
        .map_err(|e| tls(&e))?;
    if certs.is_empty() {
        return Err(StartError::Tls("no certificate in file".into()));
    }
    let key_pem = cfg.key.resolve()?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.expose().as_bytes()).map_err(|e| tls(&e))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| tls(&e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| tls(&e))?;
    // Look like an ordinary HTTPS server to a censor probing the port.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// A running relay's shared state.
pub struct Relay {
    config: ProxyConfig,
    acceptor: TlsAcceptor,
    permits: Arc<Semaphore>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Relay {
    /// A relay for `config` using `acceptor` for the outer TLS.
    #[must_use]
    pub fn new(config: ProxyConfig, acceptor: TlsAcceptor) -> Arc<Self> {
        let permits = Arc::new(Semaphore::new(config.limits.max_connections));
        Arc::new(Self {
            config,
            acceptor,
            permits,
        })
    }

    /// Accepts connections until `shutdown` completes, then waits up to `drain` for open relays.
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: impl Future<Output = ()>,
        drain: Duration,
    ) {
        tokio::pin!(shutdown);
        loop {
            let accepted = tokio::select! {
                () = &mut shutdown => break,
                a = listener.accept() => a,
            };
            let Ok((tcp, _)) = accepted else {
                // EMFILE/ENFILE/ENOBUFS persist until connections close: retrying at once would
                // spin a core and starve the tasks that free descriptors.
                tokio::select! {
                    () = &mut shutdown => break,
                    () = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                }
                continue;
            };
            let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
                continue;
            };
            let relay = Arc::clone(&self);
            tokio::spawn(async move {
                // Every failure ends the same way: the socket closes. Nothing is logged.
                let _ = relay.handle(tcp).await;
                drop(permit);
            });
        }
        drop(listener);
        let all = u32::try_from(self.config.limits.max_connections).unwrap_or(u32::MAX);
        let _ = timeout(drain, self.permits.acquire_many(all)).await;
    }

    async fn handle(&self, tcp: TcpStream) -> io::Result<()> {
        let limits = &self.config.limits;
        tcp.set_nodelay(true)?;
        let max = limits.max_client_hello_bytes;
        // Room for the hello plus worst-case record framing; bounded, not input-proportional.
        let mut buf = vec![0u8; max.saturating_mul(2).saturating_add(RECORD_HEADER_LEN)];
        let mut scratch = vec![0u8; max];

        let handshake = async {
            let mut tls = self.acceptor.accept(tcp).await?;
            let mut filled = 0usize;
            loop {
                let free = buf
                    .get_mut(filled..)
                    .filter(|b| !b.is_empty())
                    .ok_or_else(too_large)?;
                let n = tls.read(free).await?;
                if n == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                filled += n;
                let seen = buf.get(..filled).ok_or_else(too_large)?;
                match scan(seen, &mut scratch).map_err(io::Error::other)? {
                    Scan::NeedMore => {}
                    Scan::Host(host) => {
                        let upstream = self
                            .config
                            .route(host)
                            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?
                            .to_owned();
                        return Ok((tls, upstream, filled));
                    }
                }
            }
        };
        let (client, upstream, filled) = timeout(
            Duration::from_secs(limits.handshake_timeout_secs),
            handshake,
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        drop(scratch);

        let mut up = timeout(
            Duration::from_secs(limits.connect_timeout_secs),
            TcpStream::connect(upstream.as_str()),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        up.set_nodelay(true)?;
        up.write_all(buf.get(..filled).ok_or_else(too_large)?)
            .await?;
        drop(buf);

        pump(client, up, Duration::from_secs(limits.idle_timeout_secs)).await
    }
}

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "ClientHello too large")
}

/// Copies both directions until one side closes or both are idle for `idle`.
async fn pump<A, B>(a: A, b: B, idle: Duration) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let mut a = Tracked {
        inner: a,
        last: Arc::clone(&last),
        start,
    };
    let mut b = Tracked {
        inner: b,
        last: Arc::clone(&last),
        start,
    };
    let idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX);
    let watchdog = async {
        loop {
            tokio::time::sleep(idle / 4).await;
            let now = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            if now.saturating_sub(last.load(Ordering::Relaxed)) >= idle_ms {
                return;
            }
        }
    };
    tokio::select! {
        r = tokio::io::copy_bidirectional(&mut a, &mut b) => r.map(|_| ()),
        () = watchdog => Ok(()),
    }
}

/// Records the time of the last successful read on a stream.
struct Tracked<S> {
    inner: S,
    last: Arc<AtomicU64>,
    start: Instant,
}

impl<S> Tracked<S> {
    fn touch(&self) {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(now, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.touch();
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, b)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
