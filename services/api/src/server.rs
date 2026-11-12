//! The HTTP/1.1 listener: TLS (outside development), bounded headers, a connection cap, a
//! header timeout, graceful stop.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio_rustls::TlsAcceptor;

use crate::App;

const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADERS: usize = 64;
const MAX_BUF: usize = 64 * 1024;

/// Serves until `stop` turns true.
pub async fn serve(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    app: Arc<App>,
    max_connections: usize,
    mut stop: watch::Receiver<bool>,
) {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(MAX_BUF)
        .max_headers(MAX_HEADERS);
    let builder = Arc::new(builder);
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = stop.changed() => return,
        };
        let Ok((tcp, _)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let (app, builder, tls, mut stop) = (
            Arc::clone(&app),
            Arc::clone(&builder),
            tls.clone(),
            stop.clone(),
        );
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let app = Arc::clone(&app);
                async move { Ok::<_, Infallible>(app.handle(req).await) }
            });
            if let Some(acceptor) = tls {
                let Ok(Ok(stream)) =
                    tokio::time::timeout(HEADER_TIMEOUT, acceptor.accept(tcp)).await
                else {
                    return;
                };
                drive(
                    builder.serve_connection(TokioIo::new(stream), svc),
                    &mut stop,
                )
                .await;
            } else {
                drive(builder.serve_connection(TokioIo::new(tcp), svc), &mut stop).await;
            }
            drop(permit);
        });
    }
}

/// Runs a connection; on stop, lets the request in flight finish, then closes.
async fn drive<C>(conn: C, stop: &mut watch::Receiver<bool>)
where
    C: Future + GracefulConnection,
{
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = stop.changed() => {
            conn.as_mut().graceful();
            let _ = conn.await;
        }
    }
}

/// A connection that can be told to finish.
trait GracefulConnection {
    fn graceful(self: std::pin::Pin<&mut Self>);
}

impl<I, S> GracefulConnection for hyper::server::conn::http1::Connection<I, S>
where
    S: hyper::service::HttpService<hyper::body::Incoming>,
    S::ResBody: 'static,
    <S::ResBody as hyper::body::Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    I: hyper::rt::Read + hyper::rt::Write + Unpin,
{
    fn graceful(self: std::pin::Pin<&mut Self>) {
        self.graceful_shutdown();
    }
}
