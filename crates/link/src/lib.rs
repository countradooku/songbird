//! Node links (D-0034): request/response between delivery nodes over TCP with mutual TLS.
//!
//! - **Who may call.** Both sides present certificates from the internal CA (D-0012), TLS 1.3
//!   only. Every component's leaf chains to that CA, so the CA alone is not enough: the client's
//!   first frame names it, the server checks the client certificate is valid for that name and
//!   that the name carries an admitted prefix. **Each admitted prefix has its own handler**
//!   ([`serve_admitting`]): delivery nodes (`delivery.`) get every mailbox operation, `api`
//!   (`api.`, D-0044) only the store of a send, and anything else is refused at the handshake.
//!   The client verifies the server's certificate for the owner's name.
//! - **Framing.** `len u32 | kind u8 | id u64 | payload`, bounded by [`MAX_FRAME`] before any
//!   allocation. Requests are multiplexed by id on one connection; the server answers each in
//!   its own task, so a slow request does not hold the others.
//! - **No identifiers in logs** (invariant 6): errors are counted and logged without peers or
//!   payloads.

pub mod devices;

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Largest frame accepted (checked before allocating).
pub const MAX_FRAME: usize = 32 << 20;

const KIND_HELLO: u8 = 0;
const KIND_REQUEST: u8 = 1;
const KIND_RESPONSE: u8 = 2;
const HEADER: usize = 1 + 8;

/// Link errors. They carry no peer names or payloads.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// Certificates, keys or the CA could not be loaded.
    #[error("link tls configuration: {0}")]
    Config(String),
    /// Connecting or the TLS handshake failed.
    #[error("link connect failed")]
    Connect,
    /// The connection broke (the request may or may not have run).
    #[error("link closed")]
    Closed,
    /// No answer in time.
    #[error("link timeout")]
    Timeout,
}

/// A request handler: the request payload in, the response payload out.
pub type Handler =
    Arc<dyn Fn(Bytes) -> Pin<Box<dyn Future<Output = Bytes> + Send>> + Send + Sync + 'static>;

/// TLS for one node: its certificate and key, the internal CA, its own name.
#[derive(Clone)]
pub struct LinkTls {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    name: String,
}

impl std::fmt::Debug for LinkTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkTls").finish_non_exhaustive()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

impl LinkTls {
    /// From PEM: this node's chain (leaf first) and key, the CA, and the name its certificate is
    /// for (`delivery.<host>.songbird.internal`).
    ///
    /// # Errors
    /// [`LinkError::Config`] (no secret material in the message).
    pub fn from_pem(chain: &[u8], key: &[u8], ca: &[u8], name: &str) -> Result<Self, LinkError> {
        let bad = |what: &str| LinkError::Config(what.to_owned());
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain)
            .collect::<Result<_, _>>()
            .map_err(|_| bad("certificate chain"))?;
        if certs.is_empty() {
            return Err(bad("certificate chain is empty"));
        }
        let key = PrivateKeyDer::from_pem_slice(key).map_err(|_| bad("private key"))?;
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(ca) {
            roots
                .add(c.map_err(|_| bad("ca"))?)
                .map_err(|_| bad("ca"))?;
        }
        let roots = Arc::new(roots);
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::clone(&roots), provider())
            .build()
            .map_err(|_| bad("client verifier"))?;
        let server = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| bad("server protocol"))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs.clone(), key.clone_key())
            .map_err(|_| bad("server certificate"))?;
        let client = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| bad("client protocol"))?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|_| bad("client certificate"))?;
        Ok(Self {
            server: Arc::new(server),
            client: Arc::new(client),
            name: name.to_owned(),
        })
    }
}

/// Counters.
#[derive(Debug, Default)]
pub struct LinkStats {
    /// Connections refused: handshake failed, or the peer's identity was not allowed.
    pub refused: AtomicU64,
    /// Requests served.
    pub served: AtomicU64,
}

/// Whether `peer` (the client certificate) is valid for `name` and `name` is allowed.
fn identity_ok(peer: &CertificateDer<'_>, name: &str, prefix: &str) -> bool {
    if !name.starts_with(prefix) || !name.ends_with(".songbird.internal") {
        return false;
    }
    let Ok(server_name) = ServerName::try_from(name) else {
        return false;
    };
    let Ok(cert) = webpki::EndEntityCert::try_from(peer) else {
        return false;
    };
    cert.verify_is_valid_for_subject_name(&server_name).is_ok()
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Option<(u8, u64, Bytes)> {
    let len = usize::try_from(r.read_u32().await.ok()?).ok()?;
    if !(HEADER..=MAX_FRAME).contains(&len) {
        return None;
    }
    let mut buf = BytesMut::zeroed(len);
    r.read_exact(&mut buf).await.ok()?;
    let kind = buf.get_u8();
    let id = buf.get_u64();
    Some((kind, id, buf.freeze()))
}

fn frame(kind: u8, id: u64, payload: &[u8]) -> Option<Bytes> {
    let len = HEADER + payload.len();
    if len > MAX_FRAME {
        return None;
    }
    let mut b = BytesMut::with_capacity(4 + len);
    b.put_u32(u32::try_from(len).ok()?);
    b.put_u8(kind);
    b.put_u64(id);
    b.put_slice(payload);
    Some(b.freeze())
}

/// One kind of peer a link server admits: certificate names starting with `prefix`, served by
/// `handler`. A handler gets requests only from peers of its own kind, so it decides what that
/// kind may ask for.
#[derive(Clone)]
pub struct Admit {
    /// Name prefix, ending with a dot (`delivery.`, `api.`).
    pub prefix: String,
    /// Handler for those peers.
    pub handler: Handler,
}

impl std::fmt::Debug for Admit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admit")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// Serves requests on `listener` until `shutdown` turns true (then open connections close too).
/// Peers must present a certificate from the CA valid for a name starting with `allowed_prefix`.
pub async fn serve(
    listener: TcpListener,
    tls: LinkTls,
    allowed_prefix: String,
    handler: Handler,
    stats: Arc<LinkStats>,
    shutdown: watch::Receiver<bool>,
) {
    let admit = vec![Admit {
        prefix: allowed_prefix,
        handler,
    }];
    serve_admitting(listener, tls, admit, stats, shutdown).await;
}

/// Like [`serve`], with one handler per kind of peer: a peer is served by the handler of the
/// first prefix its certificate's name carries, and refused if it carries none. Prefixes must
/// end with a dot, so `api.` never admits `apix.`.
pub async fn serve_admitting(
    listener: TcpListener,
    tls: LinkTls,
    admit: Vec<Admit>,
    stats: Arc<LinkStats>,
    mut shutdown: watch::Receiver<bool>,
) {
    let acceptor = TlsAcceptor::from(Arc::clone(&tls.server));
    // A prefix without its dot would admit more names than it says: drop it (fail closed).
    let admit: Arc<[Admit]> = admit
        .into_iter()
        .filter(|a| a.prefix.len() > 1 && a.prefix.ends_with('.'))
        .collect();
    loop {
        tokio::select! {
            _ = async { shutdown.wait_for(|s| *s).await.is_ok() } => return,
            accepted = listener.accept() => {
                let Ok((tcp, _)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let _ = tcp.set_nodelay(true);
                let (acceptor, admit, stats, stop) = (
                    acceptor.clone(),
                    Arc::clone(&admit),
                    Arc::clone(&stats),
                    shutdown.clone(),
                );
                tokio::spawn(async move {
                    if !serve_conn(tcp, acceptor, &admit, &stats, stop).await {
                        stats.refused.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        }
    }
}

/// One connection; false if it was refused before serving anything.
async fn serve_conn(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    admit: &[Admit],
    stats: &Arc<LinkStats>,
    mut shutdown: watch::Receiver<bool>,
) -> bool {
    let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
    else {
        return false;
    };
    let peer = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .cloned();
    let (mut rd, wr) = tokio::io::split(tls);
    let Ok(Some((KIND_HELLO, _, name))) =
        tokio::time::timeout(Duration::from_secs(10), read_frame(&mut rd)).await
    else {
        return false;
    };
    let name = String::from_utf8_lossy(&name).into_owned();
    let Some(peer) = peer else { return false };
    let Some(handler) = admit
        .iter()
        .find(|a| identity_ok(&peer, &name, &a.prefix))
        .map(|a| Arc::clone(&a.handler))
    else {
        return false;
    };
    let (out_tx, out_rx) = mpsc::channel::<Bytes>(1024);
    let writer = tokio::spawn(write_loop(wr, out_rx));
    loop {
        let next = tokio::select! {
            f = read_frame(&mut rd) => f,
            // A stopped node serves nothing more, not even on connections opened before.
            _ = async { shutdown.wait_for(|s| *s).await.is_ok() } => None,
        };
        let Some((kind, id, payload)) = next else {
            break;
        };
        if kind != KIND_REQUEST {
            break;
        }
        let (handler, out, stats) = (Arc::clone(&handler), out_tx.clone(), Arc::clone(stats));
        tokio::spawn(async move {
            let resp = handler(payload).await;
            stats.served.fetch_add(1, Ordering::Relaxed);
            if let Some(f) = frame(KIND_RESPONSE, id, &resp) {
                let _ = out.send(f).await;
            }
        });
    }
    drop(out_tx);
    let _ = writer.await;
    true
}

async fn write_loop<W: AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::Receiver<Bytes>) {
    while let Some(f) = rx.recv().await {
        if wr.write_all(&f).await.is_err() {
            return;
        }
        // Batch what is queued before flushing.
        while let Ok(more) = rx.try_recv() {
            if wr.write_all(&more).await.is_err() {
                return;
            }
        }
        if wr.flush().await.is_err() {
            return;
        }
    }
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Bytes>>>>;

struct Conn {
    out: mpsc::Sender<Bytes>,
    pending: Pending,
    /// The peer closed the connection (its reader ended): nothing sent on it is answered.
    closed: Arc<AtomicBool>,
}

/// A client link to one peer node; connects on first use and again after a failure.
pub struct LinkClient {
    addr: SocketAddr,
    peer_name: String,
    tls: LinkTls,
    next: AtomicU64,
    conn: tokio::sync::Mutex<Option<Arc<Conn>>>,
}

impl std::fmt::Debug for LinkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkClient").finish_non_exhaustive()
    }
}

impl LinkClient {
    /// A link to the node at `addr` whose certificate is for `peer_name`.
    #[must_use]
    pub fn new(addr: SocketAddr, peer_name: &str, tls: LinkTls) -> Self {
        Self {
            addr,
            peer_name: peer_name.to_owned(),
            tls,
            next: AtomicU64::new(1),
            conn: tokio::sync::Mutex::new(None),
        }
    }

    async fn connect(&self) -> Result<Arc<Conn>, LinkError> {
        let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(self.addr))
            .await
            .map_err(|_| LinkError::Connect)?
            .map_err(|_| LinkError::Connect)?;
        let _ = tcp.set_nodelay(true);
        let name = ServerName::try_from(self.peer_name.clone()).map_err(|_| LinkError::Connect)?;
        let tls = tokio::time::timeout(
            Duration::from_secs(5),
            TlsConnector::from(Arc::clone(&self.tls.client)).connect(name, tcp),
        )
        .await
        .map_err(|_| LinkError::Connect)?
        .map_err(|_| LinkError::Connect)?;
        let (mut rd, mut wr) = tokio::io::split(tls);
        let hello = frame(KIND_HELLO, 0, self.tls.name.as_bytes()).ok_or(LinkError::Connect)?;
        wr.write_all(&hello).await.map_err(|_| LinkError::Connect)?;
        wr.flush().await.map_err(|_| LinkError::Connect)?;
        let (out, out_rx) = mpsc::channel::<Bytes>(1024);
        tokio::spawn(write_loop(wr, out_rx));
        let pending: Pending = Arc::default();
        let closed = Arc::new(AtomicBool::new(false));
        let (p, gone) = (Arc::clone(&pending), Arc::clone(&closed));
        tokio::spawn(async move {
            while let Some((kind, id, payload)) = read_frame(&mut rd).await {
                if kind != KIND_RESPONSE {
                    break;
                }
                let waiter = p
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&id);
                if let Some(w) = waiter {
                    let _ = w.send(payload);
                }
            }
            // Closed: every waiter learns it (their senders drop), and nobody waits on it again.
            gone.store(true, Ordering::Release);
            p.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        });
        Ok(Arc::new(Conn {
            out,
            pending,
            closed,
        }))
    }

    async fn current(&self) -> Result<Arc<Conn>, LinkError> {
        let mut c = self.conn.lock().await;
        if let Some(conn) = c.as_ref()
            && !conn.out.is_closed()
            && !conn.closed.load(Ordering::Acquire)
        {
            return Ok(Arc::clone(conn));
        }
        let conn = self.connect().await?;
        *c = Some(Arc::clone(&conn));
        Ok(conn)
    }

    /// Sends a request and waits up to `timeout` for its response.
    ///
    /// # Errors
    /// [`LinkError`]: connect, closed (outcome unknown) or timeout (outcome unknown).
    pub async fn call(&self, payload: &[u8], timeout: Duration) -> Result<Bytes, LinkError> {
        let conn = self.current().await?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let f = frame(KIND_REQUEST, id, payload).ok_or(LinkError::Closed)?;
        let (tx, rx) = oneshot::channel();
        conn.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, tx);
        // Closed after `current` looked (the reader may have cleared the waiters already).
        if conn.closed.load(Ordering::Acquire) {
            conn.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
            *self.conn.lock().await = None;
            return Err(LinkError::Closed);
        }
        if conn.out.send(f).await.is_err() {
            *self.conn.lock().await = None;
            return Err(LinkError::Closed);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(b)) => Ok(b),
            Ok(Err(_)) => {
                *self.conn.lock().await = None;
                Err(LinkError::Closed)
            }
            Err(_) => {
                conn.pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&id);
                Err(LinkError::Timeout)
            }
        }
    }
}
