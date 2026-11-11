//! The admin endpoint: `GET /metrics`, `/healthz` (liveness), `/readyz` (readiness).
//!
//! Bound to a private address (validated in `CommonConfig`). Requests are bounded: header read
//! timeout, small header buffer, few headers, a cap on concurrent connections, no request bodies
//! read. Nothing about the caller is logged.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::metrics::Metrics;

/// Most concurrent admin connections.
pub const MAX_ADMIN_CONNECTIONS: usize = 64;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BUF: usize = 8 * 1024;
const MAX_HEADERS: usize = 32;
const OPENMETRICS: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Liveness and readiness flags shared with the service.
#[derive(Debug, Default)]
pub struct Health {
    ready: AtomicBool,
}

impl Health {
    /// Marks the service ready (or not) to receive traffic.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    /// Whether the service is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

/// Serves the admin endpoint on `listener` until `shutdown` completes.
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    health: Arc<Health>,
    shutdown: impl Future<Output = ()>,
) {
    let permits = Arc::new(Semaphore::new(MAX_ADMIN_CONNECTIONS));
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_BUF)
        .max_headers(MAX_HEADERS)
        .keep_alive(false);
    let builder = Arc::new(builder);
    tokio::pin!(shutdown);
    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => return,
            a = listener.accept() => a,
        };
        let Ok((stream, _peer)) = accepted else {
            // Errors such as EMFILE persist; back off instead of spinning a core.
            tokio::select! {
                () = &mut shutdown => return,
                () = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
            }
            continue;
        };
        // Over the cap: drop the connection rather than queueing it.
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            continue;
        };
        let (metrics, health, builder) = (
            Arc::clone(&metrics),
            Arc::clone(&health),
            Arc::clone(&builder),
        );
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let r = respond(&req, &metrics, &health);
                async move { Ok::<_, Infallible>(r) }
            });
            let _ = builder.serve_connection(TokioIo::new(stream), svc).await;
            drop(permit);
        });
    }
}

fn respond(req: &Request<Incoming>, metrics: &Metrics, health: &Health) -> Response<Full<Bytes>> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return text(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
    }
    match req.uri().path() {
        "/healthz" => text(StatusCode::OK, "ok\n"),
        "/readyz" if health.is_ready() => text(StatusCode::OK, "ready\n"),
        "/readyz" => text(StatusCode::SERVICE_UNAVAILABLE, "not ready\n"),
        "/metrics" => match metrics.encode() {
            Ok(body) => {
                let mut r = Response::new(Full::new(Bytes::from(body)));
                r.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static(OPENMETRICS));
                r
            }
            Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "encode failed\n"),
        },
        _ => text(StatusCode::NOT_FOUND, "not found\n"),
    }
}

fn text(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *r.status_mut() = status;
    r.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn get(addr: std::net::SocketAddr, req: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        // The server may reset an abusive request mid-write; only the response matters.
        let _ = s.write_all(req.as_bytes()).await;
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn endpoints() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut m = Metrics::new("test", "0.0.0");
        m.register_self_metrics(None);
        let health = Arc::new(Health::default());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, Arc::new(m), Arc::clone(&health), async {
            let _ = rx.await;
        }));

        let r = get(addr, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        let r = get(addr, "GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 503"), "{r}");
        health.set_ready(true);
        let r = get(addr, "GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        let r = get(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.contains("songbird_build_info"), "{r}");
        assert!(r.contains("application/openmetrics-text"), "{r}");
        let r = get(
            addr,
            "POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 405"), "{r}");
        let r = get(addr, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 404"), "{r}");

        // Oversized headers are rejected, not buffered.
        let huge = format!(
            "GET /healthz HTTP/1.1\r\nHost: x\r\nX: {}\r\n\r\n",
            "a".repeat(64 * 1024)
        );
        let r = get(addr, &huge).await;
        assert!(r.is_empty() || r.starts_with("HTTP/1.1 431"), "{r}");

        tx.send(()).unwrap();
        server.await.unwrap();
    }
}
