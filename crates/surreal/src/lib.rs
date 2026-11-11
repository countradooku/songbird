//! Minimal SurrealDB 4 RPC client (D-0025).
//!
//! One WebSocket per [`Client`] to `/rpc` with subprotocol `cbor`; each binary message is one
//! CBOR request `{id, method, params}` or response `{id, result | error}`
//! (`surrealdb-rpc-4.0.1/src/request.rs`, `response.rs`). Requests are pipelined: many may be in
//! flight, matched by integer `id`; one I/O task owns the socket and writes everything queued per
//! wake-up with one flush. If the connection fails, every pending request fails with
//! [`RpcError::Disconnected`] and the client is closed; the owner reconnects.
//!
//! Errors from the server can quote record IDs or values. They are kept for matching
//! ([`StatementError::message`]) but `Display` and `Debug` show only the error kind (invariant 6).
#![forbid(unsafe_code)]

pub mod cbor;

use std::collections::HashMap;
use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use futures_core::Stream as _;
use futures_sink::Sink as _;
use sockudo_ws::client::WebSocketClient;
use sockudo_ws::{Http1, Message, WebSocketStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

pub use cbor::Value;

/// Connection settings.
#[derive(Clone)]
pub struct Config {
    /// `host:port`.
    pub addr: String,
    /// Host name for the HTTP `Host` header and TLS server name.
    pub host: String,
    /// TLS client settings; `None` for plain TCP (development and CI only).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Root user.
    pub user: String,
    /// Root password.
    pub pass: String,
    /// Namespace.
    pub namespace: String,
    /// Database.
    pub database: String,
    /// Limit for connect, upgrade and each request.
    pub timeout: Duration,
    /// Largest response accepted.
    pub max_message_bytes: usize,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("addr", &self.addr)
            .field("namespace", &self.namespace)
            .field("database", &self.database)
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

/// Request failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    /// Could not connect or upgrade.
    #[error("cannot connect to SurrealDB")]
    Connect,
    /// The connection closed or failed; the request may or may not have run.
    #[error("SurrealDB connection lost")]
    Disconnected,
    /// No response within the timeout; the request may or may not have run.
    #[error("SurrealDB request timed out")]
    Timeout,
    /// A response this client cannot interpret.
    #[error("SurrealDB protocol error: {0}")]
    Protocol(&'static str),
    /// The server refused the request (`error` response).
    #[error("SurrealDB error {code}")]
    Server {
        /// JSON-RPC style code (e.g. -32009 transaction conflict).
        code: i64,
        /// Server message (may quote data: never log it).
        message: String,
    },
}

/// A statement that failed inside a `query`.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[error("SurrealDB statement failed ({kind})")]
pub struct StatementError {
    /// Error kind (`Query`, `AlreadyExists`, `Thrown`, …).
    pub kind: String,
    /// Server message (may quote data: never log it).
    pub message: String,
}

impl std::fmt::Debug for StatementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatementError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Server error code for a transaction conflict (retry the transaction).
pub const CODE_TRANSACTION_CONFLICT: i64 = -32009;

struct Request {
    method: &'static str,
    params: Value,
    reply: oneshot::Sender<Result<Value, RpcError>>,
}

/// A connected client. Cheap to clone; all clones share one connection.
#[derive(Clone)]
pub struct Client {
    tx: mpsc::Sender<Request>,
    timeout: Duration,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("closed", &self.tx.is_closed())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Client {
    /// Connects, signs in as the root user and selects the namespace and database.
    ///
    /// # Errors
    /// [`RpcError`].
    pub async fn connect(cfg: &Config) -> Result<Self, RpcError> {
        let t = cfg.timeout;
        let tcp = tokio::time::timeout(t, TcpStream::connect(&cfg.addr))
            .await
            .map_err(|_| RpcError::Connect)?
            .map_err(|_| RpcError::Connect)?;
        tcp.set_nodelay(true).map_err(|_| RpcError::Connect)?;
        let ws_cfg = sockudo_ws::Config::builder()
            .max_message_size(cfg.max_message_bytes)
            .max_frame_size(cfg.max_message_bytes)
            .auto_ping(true)
            .ping_interval(20)
            .idle_timeout(0)
            .build();
        let client = WebSocketClient::<Http1>::new(ws_cfg);
        let (tx, rx) = mpsc::channel(4096);
        if let Some(tls) = &cfg.tls {
            let name = rustls_pki_types::ServerName::try_from(cfg.host.clone())
                .map_err(|_| RpcError::Connect)?;
            let stream = tokio::time::timeout(
                t,
                tokio_rustls::TlsConnector::from(Arc::clone(tls)).connect(name, tcp),
            )
            .await
            .map_err(|_| RpcError::Connect)?
            .map_err(|_| RpcError::Connect)?;
            let (ws, hs) = tokio::time::timeout(
                t,
                client.connect_raw(stream, &cfg.host, "/rpc", Some("cbor")),
            )
            .await
            .map_err(|_| RpcError::Connect)?
            .map_err(|_| RpcError::Connect)?;
            if hs.protocol.as_deref() != Some("cbor") {
                return Err(RpcError::Connect);
            }
            tokio::spawn(io_task(ws, rx));
        } else {
            let (ws, hs) =
                tokio::time::timeout(t, client.connect_raw(tcp, &cfg.host, "/rpc", Some("cbor")))
                    .await
                    .map_err(|_| RpcError::Connect)?
                    .map_err(|_| RpcError::Connect)?;
            if hs.protocol.as_deref() != Some("cbor") {
                return Err(RpcError::Connect);
            }
            tokio::spawn(io_task(ws, rx));
        }
        let c = Self { tx, timeout: t };
        // Order matters here (the server may run concurrent requests in any order), so each
        // step waits for the previous one.
        c.call(
            "signin",
            Value::Array(vec![Value::map([
                ("user", Value::from(cfg.user.as_str())),
                ("pass", Value::from(cfg.pass.as_str())),
            ])]),
        )
        .await?;
        c.call(
            "use",
            Value::Array(vec![
                Value::from(cfg.namespace.as_str()),
                Value::from(cfg.database.as_str()),
            ]),
        )
        .await?;
        Ok(c)
    }

    /// Whether the connection is gone (reconnect).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Sends one RPC request and waits for its result.
    ///
    /// # Errors
    /// [`RpcError`].
    pub async fn call(&self, method: &'static str, params: Value) -> Result<Value, RpcError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Request {
                method,
                params,
                reply,
            })
            .await
            .map_err(|_| RpcError::Disconnected)?;
        match tokio::time::timeout(self.timeout, rx).await {
            Err(_) => Err(RpcError::Timeout),
            Ok(Err(_)) => Err(RpcError::Disconnected),
            Ok(Ok(r)) => r,
        }
    }

    /// Runs `SurrealQL` with variables; returns one result per statement.
    ///
    /// # Errors
    /// [`RpcError`] if the request as a whole failed.
    pub async fn query(
        &self,
        sql: &str,
        vars: Vec<(String, Value)>,
    ) -> Result<Vec<Result<Value, StatementError>>, RpcError> {
        let v = self
            .call(
                "query",
                Value::Array(vec![Value::from(sql), Value::Map(vars)]),
            )
            .await?;
        let Value::Array(stmts) = v else {
            return Err(RpcError::Protocol("query result is not an array"));
        };
        stmts
            .into_iter()
            .map(|mut s| {
                let status = s.get("status").and_then(Value::as_text).map(str::to_owned);
                match status.as_deref() {
                    Some("OK") => Ok(Ok(s.take("result").unwrap_or(Value::Null))),
                    Some("ERR") => Ok(Err(StatementError {
                        kind: s
                            .get("kind")
                            .and_then(Value::as_text)
                            .unwrap_or("Unknown")
                            .to_owned(),
                        message: s
                            .get("result")
                            .and_then(Value::as_text)
                            .unwrap_or("")
                            .to_owned(),
                    })),
                    _ => Err(RpcError::Protocol("statement without status")),
                }
            })
            .collect()
    }
}

/// Owns the socket: writes queued requests, reads responses, matches them by `id`.
async fn io_task<S>(mut ws: WebSocketStream<S>, mut rx: mpsc::Receiver<Request>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending: HashMap<i64, oneshot::Sender<Result<Value, RpcError>>> = HashMap::new();
    let mut next_id: i64 = 1;
    let mut buf = BytesMut::with_capacity(4096);
    let failed = loop {
        tokio::select! {
            req = rx.recv() => {
                let Some(mut req) = req else { break false };
                // Write everything queued, then flush once.
                loop {
                    let id = next_id;
                    next_id = next_id.wrapping_add(1).max(1);
                    let msg = Value::map([
                        ("id", Value::Int(id)),
                        ("method", Value::from(req.method)),
                        ("params", std::mem::replace(&mut req.params, Value::Null)),
                    ]);
                    cbor::encode(&msg, &mut buf);
                    let frame = Message::Binary(buf.split().freeze());
                    if poll_fn(|cx| Pin::new(&mut ws).poll_ready(cx)).await.is_err()
                        || Pin::new(&mut ws).start_send(frame).is_err()
                    {
                        let _ = req.reply.send(Err(RpcError::Disconnected));
                        break;
                    }
                    pending.insert(id, req.reply);
                    match rx.try_recv() {
                        Ok(r) => req = r,
                        Err(_) => break,
                    }
                }
                if poll_fn(|cx| Pin::new(&mut ws).poll_flush(cx)).await.is_err() {
                    break true;
                }
            }
            msg = poll_fn(|cx| Pin::new(&mut ws).poll_next(cx)) => match msg {
                Some(Ok(Message::Binary(b))) => {
                    let Ok(mut v) = cbor::decode(&b) else { break true };
                    // Responses without an integer id are live-query notifications: ignored.
                    let Some(id) = v.get("id").and_then(Value::as_i64) else { continue };
                    let Some(reply) = pending.remove(&id) else { continue };
                    let r = if let Some(mut e) = v.take("error") {
                        Err(RpcError::Server {
                            code: e.get("code").and_then(Value::as_i64).unwrap_or(0),
                            message: e
                                .take("message")
                                .and_then(|m| m.as_text().map(str::to_owned))
                                .unwrap_or_default(),
                        })
                    } else {
                        Ok(v.take("result").unwrap_or(Value::Null))
                    };
                    let _ = reply.send(r);
                }
                Some(Ok(_)) => {}
                _ => break true,
            },
        }
    };
    let _ = failed;
    for (_, reply) in pending.drain() {
        let _ = reply.send(Err(RpcError::Disconnected));
    }
    rx.close();
    let _ = ws.close(1000, "").await;
}
