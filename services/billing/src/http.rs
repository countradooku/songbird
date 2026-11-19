//! Billing's HTTP client to Apple, Google and Mollie: HTTP/1.1 on hyper, one connection per
//! request, rustls (aws-lc-rs) with the Mozilla roots, a timeout, bounded responses. Plain
//! `http://` only to this computer (the providers' emulators in tests).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;

/// Largest response read.
pub const MAX_RESPONSE: usize = 1 << 20;

/// Why a request got no answer (never the URL or a header: they may carry tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// A URL the client refuses (scheme, userinfo, plain HTTP elsewhere than this computer).
    #[error("url refused")]
    Url,
    /// Connection, TLS, timeout, or an oversized answer.
    #[error("unavailable")]
    Unavailable,
}

/// One response.
#[derive(Debug, Clone)]
pub struct Response {
    /// The status.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// 2xx.
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

struct Url<'a> {
    tls: bool,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse(url: &str) -> Result<Url<'_>, HttpError> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(HttpError::Url);
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(HttpError::Url);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
            (h, p.parse::<u16>().map_err(|_| HttpError::Url)?)
        }
        _ => (authority, if tls { 443 } else { 80 }),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(HttpError::Url);
    }
    let local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !tls && !local {
        return Err(HttpError::Url);
    }
    Ok(Url {
        tls,
        host,
        port,
        path,
    })
}

/// The client.
#[derive(Clone)]
pub struct Client {
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// Trusting the Mozilla roots.
    ///
    /// # Errors
    /// rustls refuses the configuration (never with its defaults).
    pub fn new(timeout: Duration) -> Result<Self, &'static str> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "tls")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls: Arc::new(tls),
            timeout,
        })
    }

    /// Sends one request and reads the whole response.
    ///
    /// # Errors
    /// [`HttpError`].
    pub async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<Response, HttpError> {
        let u = parse(url)?;
        let host_header = if (u.tls && u.port == 443) || (!u.tls && u.port == 80) {
            u.host.to_owned()
        } else {
            format!("{}:{}", u.host, u.port)
        };
        let mut b = hyper::Request::builder()
            .method(method)
            .uri(u.path)
            .header(hyper::header::HOST, host_header)
            .header(hyper::header::CONTENT_LENGTH, body.len());
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let req = b
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| HttpError::Url)?;
        let (tls, host, port) = (u.tls, u.host.to_owned(), u.port);
        let cfg = Arc::clone(&self.tls);
        let work = async move {
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|_| HttpError::Unavailable)?;
            let _ = tcp.set_nodelay(true);
            if tls {
                let name = ServerName::try_from(host).map_err(|_| HttpError::Url)?;
                let s = tokio_rustls::TlsConnector::from(cfg)
                    .connect(name, tcp)
                    .await
                    .map_err(|_| HttpError::Unavailable)?;
                exchange(s, req).await
            } else {
                exchange(tcp, req).await
            }
        };
        tokio::time::timeout(self.timeout, work)
            .await
            .map_err(|_| HttpError::Unavailable)?
    }
}

async fn exchange<S>(io: S, req: hyper::Request<Full<Bytes>>) -> Result<Response, HttpError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut send, conn) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| HttpError::Unavailable)?;
    let driver = tokio::spawn(conn);
    let resp = send
        .send_request(req)
        .await
        .map_err(|_| HttpError::Unavailable)?;
    let status = resp.status().as_u16();
    let body = Limited::new(resp.into_body(), MAX_RESPONSE)
        .collect()
        .await
        .map_err(|_| HttpError::Unavailable)?
        .to_bytes()
        .to_vec();
    driver.abort();
    Ok(Response { status, body })
}

/// Percent-encodes a path segment, query value or form value (RFC 3986 unreserved kept).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_only_to_this_computer() {
        assert!(parse("http://127.0.0.1:9/x").is_ok());
        assert!(parse("http://localhost/x").is_ok());
        assert!(parse("http://[::1]:9/x").is_ok());
        assert!(parse("https://api.mollie.com/v2/payments").is_ok());
        for bad in [
            "http://api.mollie.com/v2",
            "http://10.0.0.1/x",
            "ftp://x/y",
            "https://user@host/x",
            "https://:443/x",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(encode("a b/é"), "a%20b%2F%C3%A9");
    }
}
