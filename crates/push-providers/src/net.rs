//! HTTP plumbing: TLS (rustls with aws-lc-rs), a small pool of multiplexed HTTP/2 connections
//! per fixed provider origin, one-shot HTTP/2 and HTTP/1.1 requests, bounded response bodies.
//!
//! Errors here carry no URL, host or token (invariant 6).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::{HeaderMap, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::ConfigError;

/// Response bodies are read up to this many bytes; a longer body is dropped unread (the status
/// alone then decides).
pub(crate) const MAX_BODY: usize = 16 * 1024;
/// Response header block bound (HTTP/2 `SETTINGS_MAX_HEADER_LIST_SIZE`, HTTP/1 read buffer).
const MAX_HEADERS: u32 = 16 * 1024;
/// HTTP/2 keep-alive: Apple asks for long-lived connections; a PING a minute finds dead ones.
const KEEPALIVE: Duration = Duration::from_secs(60);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Request body type for every client.
pub(crate) type Body = Full<Bytes>;

/// Connection settings shared by the clients.
#[derive(Clone)]
pub struct HttpConfig {
    /// Trust anchors for provider certificates ([`mozilla_roots`] in production; a test CA for
    /// the mocks).
    pub roots: Arc<RootCertStore>,
    /// TCP and TLS connection set-up bound.
    pub connect_timeout: Duration,
    /// Whole-request bound (connection, request, response and its body).
    pub request_timeout: Duration,
    /// HTTP/2 connections per provider (APNs, FCM), 1 to 16; requests are spread round-robin
    /// and multiplexed on each.
    pub connections: usize,
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConfig")
            .field("roots", &self.roots.len())
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("connections", &self.connections)
            .finish()
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            roots: mozilla_roots(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            connections: 2,
        }
    }
}

impl HttpConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=16).contains(&self.connections) {
            return Err(ConfigError::Invalid("connections must be 1 to 16"));
        }
        if self.connect_timeout.is_zero() || self.request_timeout.is_zero() {
            return Err(ConfigError::Invalid("timeouts must be positive"));
        }
        if self.roots.is_empty() {
            return Err(ConfigError::Invalid("no trust anchors"));
        }
        Ok(())
    }
}

/// Mozilla's root store (the `webpki-roots` snapshot compiled in), so the push service does not
/// depend on the container's CA bundle.
#[must_use]
pub fn mozilla_roots() -> Arc<RootCertStore> {
    Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
}

/// A rustls client configuration offering exactly `alpn`.
pub(crate) fn tls_connector(
    roots: &Arc<RootCertStore>,
    alpn: &[&[u8]],
) -> Result<TlsConnector, ConfigError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ConfigError::Invalid("TLS protocol versions"))?
        .with_root_certificates(Arc::clone(roots))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// A fixed `https` origin from configuration (`https://host[:port]`, nothing else).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Origin {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Origin {
    /// Parses a configured base URL: https, a host, an optional port, no user info, no path
    /// beyond `/`, no query.
    pub(crate) fn parse_base(url: &str) -> Result<Self, ConfigError> {
        let (origin, path) = Self::parse_url(url)?;
        if path != "/" {
            return Err(ConfigError::Invalid("base URL must be https://host[:port]"));
        }
        Ok(origin)
    }

    /// Parses a configured https URL into its origin and path (with query, if any). No user
    /// info, no fragment.
    pub(crate) fn parse_url(url: &str) -> Result<(Self, String), ConfigError> {
        let bad = ConfigError::Invalid("URL must be https://host[:port][/path]");
        if url.len() > 2048 || url.contains('#') {
            return Err(bad);
        }
        let uri: Uri = url.parse().map_err(|_| ConfigError::Invalid("URL"))?;
        if uri.scheme_str() != Some("https") {
            return Err(bad);
        }
        let auth = uri.authority().ok_or(ConfigError::Invalid("URL"))?;
        if auth.as_str().contains('@') {
            return Err(bad);
        }
        let host = auth.host().trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(bad);
        }
        let path = uri
            .path_and_query()
            .map_or_else(|| "/".to_owned(), |p| p.as_str().to_owned());
        Ok((
            Self {
                host: host.to_owned(),
                port: auth.port_u16().unwrap_or(443),
            },
            path,
        ))
    }

    /// `https://host[:port]` followed by `path` (`path` starts with `/`).
    pub(crate) fn url(&self, path: &str) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            format!("https://{host}{path}")
        } else {
            format!("https://{host}:{}{path}", self.port)
        }
    }
}

/// A transport failure. Deliberately coarse: no addresses, names or messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum NetError {
    #[error("connect failed")]
    Connect,
    #[error("TLS handshake failed")]
    Tls,
    #[error("protocol error")]
    Protocol,
    #[error("request failed")]
    Request,
    #[error("timed out")]
    Timeout,
}

/// A response with its body read up to [`MAX_BODY`].
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

async fn read(resp: Response<Incoming>) -> Reply {
    let (parts, body) = resp.into_parts();
    // Too long or broken: the status alone decides.
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body,
    }
}

async fn tls_connect(
    connector: &TlsConnector,
    tcp: TcpStream,
    host: &str,
) -> Result<TlsStream<TcpStream>, NetError> {
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(host.to_owned()).map_err(|_| NetError::Connect)?;
    connector
        .connect(name, tcp)
        .await
        .map_err(|_| NetError::Tls)
}

async fn connect_h2(
    origin: &Origin,
    connector: &TlsConnector,
    timeout: Duration,
) -> Result<http2::SendRequest<Body>, NetError> {
    let fut = async {
        let tcp = TcpStream::connect((origin.host.as_str(), origin.port))
            .await
            .map_err(|_| NetError::Connect)?;
        let tls = tls_connect(connector, tcp, &origin.host).await?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(NetError::Protocol);
        }
        let mut b = http2::Builder::new(TokioExecutor::new());
        b.timer(TokioTimer::new())
            .keep_alive_interval(KEEPALIVE)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .max_header_list_size(MAX_HEADERS);
        let (send, conn) = b
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| NetError::Protocol)?;
        tokio::spawn(async move {
            if conn.await.is_err() {
                tracing::debug!("push provider connection ended with an error");
            }
        });
        Ok(send)
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| NetError::Timeout)?
}

/// A few long-lived HTTP/2 connections to one origin. A connection that closed (GOAWAY, error,
/// failed keep-alive) is replaced on next use.
pub(crate) struct H2Pool {
    origin: Origin,
    connector: TlsConnector,
    connect_timeout: Duration,
    slots: Box<[tokio::sync::Mutex<Option<http2::SendRequest<Body>>>]>,
    next: AtomicUsize,
}

impl std::fmt::Debug for H2Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Pool")
            .field("connections", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl H2Pool {
    pub(crate) fn new(origin: Origin, cfg: &HttpConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        Ok(Self {
            origin,
            connector: tls_connector(&cfg.roots, &[b"h2"])?,
            connect_timeout: cfg.connect_timeout,
            slots: (0..cfg.connections)
                .map(|_| tokio::sync::Mutex::new(None))
                .collect(),
            next: AtomicUsize::new(0),
        })
    }

    pub(crate) fn origin(&self) -> &Origin {
        &self.origin
    }

    /// A sender on slot `i`, connecting if the slot is empty or its connection closed.
    async fn sender(&self, i: usize) -> Result<http2::SendRequest<Body>, NetError> {
        let slot = self.slots.get(i).ok_or(NetError::Connect)?;
        let mut guard = slot.lock().await;
        if let Some(s) = guard.as_ref()
            && !s.is_closed()
        {
            return Ok(s.clone());
        }
        *guard = None;
        let s = connect_h2(&self.origin, &self.connector, self.connect_timeout).await?;
        *guard = Some(s.clone());
        Ok(s)
    }

    /// Sends the request `make` builds. If the connection turned out to be closed (GOAWAY
    /// between requests), reconnects and sends once more: a duplicate wake-up is harmless.
    pub(crate) async fn send(
        &self,
        make: impl Fn() -> Option<Request<Body>>,
    ) -> Result<Reply, NetError> {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let mut last = NetError::Request;
        for _ in 0..2 {
            let mut s = self.sender(i).await?;
            if s.ready().await.is_err() {
                last = NetError::Connect;
                continue;
            }
            let req = make().ok_or(NetError::Request)?;
            match s.send_request(req).await {
                Ok(resp) => return Ok(read(resp).await),
                Err(e) if e.is_canceled() || s.is_closed() => last = NetError::Request,
                Err(_) => return Err(NetError::Request),
            }
        }
        Err(last)
    }
}

/// One request on a fresh HTTP/2 connection (the OAuth token endpoint, about once an hour).
pub(crate) async fn h2_once(
    origin: &Origin,
    connector: &TlsConnector,
    connect_timeout: Duration,
    req: Request<Body>,
) -> Result<Reply, NetError> {
    let mut s = connect_h2(origin, connector, connect_timeout).await?;
    s.ready().await.map_err(|_| NetError::Connect)?;
    let resp = s.send_request(req).await.map_err(|_| NetError::Request)?;
    Ok(read(resp).await)
}

/// One request over HTTP/1.1 on a fresh TLS connection to `addr` (already resolved and checked),
/// presenting `host` for SNI and certificate verification.
pub(crate) async fn h1_once(
    addr: SocketAddr,
    host: &str,
    connector: &TlsConnector,
    connect_timeout: Duration,
    req: Request<Body>,
) -> Result<Reply, NetError> {
    let connect = async {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|_| NetError::Connect)?;
        tls_connect(connector, tcp, host).await
    };
    let tls = tokio::time::timeout(connect_timeout, connect)
        .await
        .map_err(|_| NetError::Timeout)??;
    let mut b = http1::Builder::new();
    b.max_buf_size(usize::try_from(MAX_HEADERS).unwrap_or(16 * 1024));
    let (mut s, conn) = b
        .handshake(TokioIo::new(tls))
        .await
        .map_err(|_| NetError::Protocol)?;
    tokio::spawn(async move {
        if conn.await.is_err() {
            tracing::debug!("web push connection ended with an error");
        }
    });
    let resp = s.send_request(req).await.map_err(|_| NetError::Request)?;
    Ok(read(resp).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls() {
        assert_eq!(
            Origin::parse_base("https://api.push.apple.com").unwrap(),
            Origin {
                host: "api.push.apple.com".into(),
                port: 443
            }
        );
        let o = Origin::parse_base("https://localhost:8443/").unwrap();
        assert_eq!(o.port, 8443);
        assert_eq!(o.url("/3/device/x"), "https://localhost:8443/3/device/x");
        for bad in [
            "http://api.push.apple.com",
            "https://user@api.push.apple.com",
            "https://api.push.apple.com/path",
            "https://api.push.apple.com/?q",
            "api.push.apple.com",
            "",
        ] {
            assert!(Origin::parse_base(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn http_config_bounds() {
        let mut c = HttpConfig::default();
        assert!(c.validate().is_ok());
        c.connections = 0;
        assert!(c.validate().is_err());
        c.connections = 17;
        assert!(c.validate().is_err());
        assert!(!format!("{:?}", HttpConfig::default()).contains("TrustAnchor"));
    }
}
