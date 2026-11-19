//! The HTTP the adapters speak, behind a small trait, so the app can bring its own client and
//! tests and tools use [`HyperHttp`].
//!
//! `Debug` of a request or response shows the method, the host and the status only: headers
//! carry bearer tokens and vault secrets, URLs carry object names.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;

use crate::store::StoreError;

/// Whether `authority` (`host[:port]` or `[v6]:port`) may be reached over plain `http://`: only
/// this computer. Elsewhere, even on a home network, credentials (WebDAV's password) and signed
/// requests travel only over TLS (D-0125).
#[must_use]
pub fn plain_http_allowed(authority: &str) -> bool {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// One request.
#[derive(Clone, Default)]
pub struct Request {
    /// `GET`, `PUT`, `POST`, `DELETE`, `PATCH`, `PROPFIND`, `MKCOL`, `HEAD`.
    pub method: String,
    /// The absolute URL.
    pub url: String,
    /// Headers, in order.
    pub headers: Vec<(String, String)>,
    /// The body (empty for none).
    pub body: Vec<u8>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Request {
    /// A request without headers or body.
    #[must_use]
    pub fn new(method: &str, url: impl Into<String>) -> Self {
        Self {
            method: method.to_owned(),
            url: url.into(),
            ..Self::default()
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

/// One response.
#[derive(Clone, Default)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// Headers (names lowercase).
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Response {
    /// A header's value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the status is 2xx.
    #[must_use]
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Sends requests.
#[async_trait]
pub trait Http: Send + Sync {
    /// Sends one request and reads the whole response.
    ///
    /// # Errors
    /// [`StoreError::Unavailable`] with status 0 when there is no answer.
    async fn send(&self, req: Request) -> Result<Response, StoreError>;
}

/// Percent-encodes a path segment or query value (RFC 3986 unreserved characters kept).
#[must_use]
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{b:02X}"));
        }
    }
    out
}

struct Url<'a> {
    tls: bool,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse(url: &str) -> Result<Url<'_>, StoreError> {
    let bad = || StoreError::Protocol("url");
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(bad());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    if authority.contains('@') || authority.is_empty() {
        return Err(bad());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
            (h, p.parse::<u16>().map_err(|_| bad())?)
        }
        _ => (authority, if tls { 443 } else { 80 }),
    };
    Ok(Url {
        tls,
        host: host.trim_start_matches('[').trim_end_matches(']'),
        port,
        path,
    })
}

/// A plain hyper HTTP/1.1 client: one connection per request, rustls with the Mozilla roots
/// (and any extra roots given), bounded responses, a timeout.
#[derive(Clone)]
pub struct HyperHttp {
    tls: Arc<rustls::ClientConfig>,
    max_response: usize,
    timeout: Duration,
}

impl std::fmt::Debug for HyperHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HyperHttp").finish_non_exhaustive()
    }
}

impl HyperHttp {
    /// A client trusting the Mozilla roots and `extra` (DER certificates).
    ///
    /// # Errors
    /// [`StoreError::Protocol`] for a certificate rustls refuses.
    pub fn new(extra: &[Vec<u8>]) -> Result<Self, StoreError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for der in extra {
            roots
                .add(rustls_pki_types::CertificateDer::from(der.clone()))
                .map_err(|_| StoreError::Protocol("certificate"))?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| StoreError::Protocol("tls"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls: Arc::new(tls),
            max_response: 64 << 20,
            timeout: Duration::from_secs(120),
        })
    }

    async fn exchange<S>(
        io: S,
        req: Request,
        host_header: String,
        max: usize,
    ) -> Result<Response, StoreError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let unavailable = |_| StoreError::Unavailable { status: 0 };
        let (mut send, conn) = http1::handshake(TokioIo::new(io))
            .await
            .map_err(unavailable)?;
        let driver = tokio::spawn(conn);
        let u = parse(&req.url)?;
        let mut b = hyper::Request::builder()
            .method(req.method.as_str())
            .uri(u.path)
            .header(hyper::header::HOST, host_header);
        let has_len = req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
        for (k, v) in &req.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        if !has_len
            && (!req.body.is_empty() || matches!(req.method.as_str(), "PUT" | "POST" | "PATCH"))
        {
            b = b.header(hyper::header::CONTENT_LENGTH, req.body.len());
        }
        let r = b
            .body(Full::new(Bytes::from(req.body)))
            .map_err(|_| StoreError::Protocol("request"))?;
        let resp = send.send_request(r).await.map_err(unavailable)?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let body = Limited::new(resp.into_body(), max)
            .collect()
            .await
            .map_err(|_| StoreError::Protocol("response too large"))?
            .to_bytes()
            .to_vec();
        driver.abort();
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

#[async_trait]
impl Http for HyperHttp {
    async fn send(&self, req: Request) -> Result<Response, StoreError> {
        let u = parse(&req.url)?;
        let tls = u.tls;
        let host = u.host.to_owned();
        let port = u.port;
        let host_header = if (tls && port == 443) || (!tls && port == 80) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let max = self.max_response;
        let cfg = Arc::clone(&self.tls);
        let work = async move {
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|_| StoreError::Unavailable { status: 0 })?;
            let _ = tcp.set_nodelay(true);
            if tls {
                let name =
                    ServerName::try_from(host.clone()).map_err(|_| StoreError::Protocol("host"))?;
                let stream = tokio_rustls::TlsConnector::from(cfg)
                    .connect(name, tcp)
                    .await
                    .map_err(|_| StoreError::Unavailable { status: 0 })?;
                Self::exchange(stream, req, host_header, max).await
            } else {
                Self::exchange(tcp, req, host_header, max).await
            }
        };
        tokio::time::timeout(self.timeout, work)
            .await
            .map_err(|_| StoreError::Unavailable { status: 0 })?
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn plain_http_only_to_this_computer() {
        for ok in [
            "127.0.0.1:8080",
            "localhost",
            "LOCALHOST:1",
            "[::1]:9000",
            "127.9.9.9",
        ] {
            assert!(plain_http_allowed(ok), "{ok}");
        }
        for no in [
            "nas.local",
            "192.168.1.5:80",
            "[fe80::1]:80",
            "10.0.0.1",
            "example.com",
        ] {
            assert!(!plain_http_allowed(no), "{no}");
        }
    }

    #[test]
    fn urls_parse_strictly() {
        let u = parse("https://example.com/a/b?c=d").unwrap();
        assert!(u.tls && u.host == "example.com" && u.port == 443 && u.path == "/a/b?c=d");
        let u = parse("http://127.0.0.1:8080").unwrap();
        assert!(!u.tls && u.port == 8080 && u.path == "/");
        let u = parse("http://[::1]:9000/x").unwrap();
        assert!(u.host == "::1" && u.port == 9000);
        assert!(parse("ftp://x/").is_err());
        assert!(parse("https://user:pw@host/").is_err());
        assert!(parse("https://host:99999/").is_err());
    }

    #[test]
    fn debug_hides_headers_and_urls() {
        let r =
            Request::new("GET", "https://h/secret-object").header("authorization", "Bearer t0ken");
        let d = format!("{r:?}");
        assert!(!d.contains("t0ken") && !d.contains("secret"), "{d}");
        assert_eq!(encode("a b/ü"), "a%20b%2F%C3%BC");
    }
}
