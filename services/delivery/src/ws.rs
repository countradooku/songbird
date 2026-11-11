//! WebSocket plumbing over `sockudo-ws`: our own HTTP upgrade (so a wrong path or subprotocol
//! gets an HTTP error instead of a socket) and poll-based helpers that need no `futures-util`.

use std::future::poll_fn;
use std::pin::Pin;
use std::time::Duration;

use bytes::BytesMut;
use futures_core::Stream as _;
use futures_sink::Sink as _;
use sockudo_ws::{Message, Role, WebSocketStream, handshake};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::Instant;

use crate::config::SessionConfig;

/// Largest upgrade request accepted (the same bound `sockudo-ws` applies).
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// What an upgrade must ask for.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Required request path (`None`: any).
    pub path: Option<&'static str>,
    /// Required subprotocol among those offered (`None`: none is selected).
    pub protocol: Option<&'static str>,
}

/// The Songbird endpoint: `/v1/ws`, subprotocol `songbird.v1`.
pub const SONGBIRD: Policy = Policy {
    path: Some(songbird_proto::PATH),
    protocol: Some(songbird_proto::SUBPROTOCOL),
};

/// Why an upgrade failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeError {
    /// No complete request within the timeout.
    Timeout,
    /// The peer went away or the socket failed.
    Io,
    /// Answered with this HTTP status and closed.
    Rejected(u16),
}

/// The WebSocket settings every delivery connection uses (and the Autobahn echo server).
#[must_use]
pub fn ws_config(s: &SessionConfig, max_message: usize) -> sockudo_ws::Config {
    sockudo_ws::Config::builder()
        // Bounded before buffering (invariant 7): a frame or message over the protocol's largest
        // legal message is refused with close 1009 by the WebSocket layer.
        .max_message_size(max_message)
        .max_frame_size(max_message)
        // Ciphertext does not compress; per-connection deflate windows cost memory.
        .compression(sockudo_ws::Compression::Disabled)
        .auto_ping(true)
        .ping_interval(s.ping_interval_secs)
        .pong_timeout(s.idle_timeout_secs.saturating_sub(s.ping_interval_secs))
        .idle_timeout(s.idle_timeout_secs)
        .read_buffer_size(s.read_buffer_bytes)
        .write_buffer_size(s.write_buffer_bytes)
        .build()
}

async fn reject<S: AsyncWrite + Unpin>(stream: &mut S, status: u16) -> UpgradeError {
    let line: &[u8] = match status {
        404 => b"HTTP/1.1 404 Not Found\r\n",
        426 => b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\n",
        431 => b"HTTP/1.1 431 Request Header Fields Too Large\r\n",
        _ => b"HTTP/1.1 400 Bad Request\r\n",
    };
    let _ = stream.write_all(line).await;
    let _ = stream
        .write_all(b"Connection: close\r\nContent-Length: 0\r\n\r\n")
        .await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    UpgradeError::Rejected(status)
}

/// Reads and answers the HTTP upgrade within `timeout`, then wraps the stream.
pub async fn upgrade<S>(
    mut stream: S,
    policy: Policy,
    config: sockudo_ws::Config,
    timeout: Duration,
) -> Result<WebSocketStream<S>, UpgradeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = Instant::now() + timeout;
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(reject(&mut stream, 431).await);
        }
        // Read at most up to the limit plus one byte, so an oversized request is detected
        // without buffering more of it.
        let room = MAX_REQUEST_BYTES + 1 - buf.len();
        let mut limited = (&mut stream).take(u64::try_from(room).unwrap_or(0));
        let n = match tokio::time::timeout_at(deadline, limited.read_buf(&mut buf)).await {
            Err(_) => return Err(UpgradeError::Timeout),
            Ok(Err(_)) => return Err(UpgradeError::Io),
            Ok(Ok(n)) => n,
        };
        if n == 0 {
            return Err(UpgradeError::Io);
        }
        let (accept, selected, consumed) = match handshake::parse_request(&buf) {
            Ok(None) => continue,
            Err(sockudo_ws::Error::InvalidHttp("request too large")) => {
                return Err(reject(&mut stream, 431).await);
            }
            Err(sockudo_ws::Error::HandshakeFailed("unsupported WebSocket version")) => {
                return Err(reject(&mut stream, 426).await);
            }
            Err(_) => return Err(reject(&mut stream, 400).await),
            Ok(Some((req, consumed))) => {
                if policy.path.is_some_and(|p| req.path.as_ref() != p) {
                    return Err(reject(&mut stream, 404).await);
                }
                let selected = match policy.protocol {
                    None => None,
                    Some(want) => {
                        let offered = req.protocol.unwrap_or("");
                        if !offered.split(',').any(|p| p.trim() == want) {
                            return Err(reject(&mut stream, 400).await);
                        }
                        Some(want)
                    }
                };
                // Extensions are never negotiated (no permessage-deflate).
                (handshake::generate_accept_key(req.key), selected, consumed)
            }
        };
        let response = handshake::build_response(&accept, selected, None);
        let write = async {
            stream.write_all(&response).await?;
            stream.flush().await
        };
        match tokio::time::timeout_at(deadline, write).await {
            Ok(Ok(())) => {}
            Err(_) => return Err(UpgradeError::Timeout),
            Ok(Err(_)) => return Err(UpgradeError::Io),
        }
        let leftover = (consumed < buf.len()).then(|| buf.split_off(consumed).freeze());
        return Ok(WebSocketStream::from_raw_with_leftover(
            stream,
            Role::Server,
            config,
            leftover,
        ));
    }
}

/// Next message; cancel-safe (state lives in the stream).
pub async fn next<S>(ws: &mut WebSocketStream<S>) -> Option<sockudo_ws::Result<Message>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|cx| Pin::new(&mut *ws).poll_next(cx)).await
}

/// Queues a message; writes only when the coalescing buffer is past its high-water mark.
pub async fn feed<S>(ws: &mut WebSocketStream<S>, msg: Message) -> sockudo_ws::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|cx| Pin::new(&mut *ws).poll_ready(cx)).await?;
    Pin::new(&mut *ws).start_send(msg)
}

/// Writes everything queued (one vectored write when possible).
pub async fn flush<S>(ws: &mut WebSocketStream<S>) -> sockudo_ws::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|cx| Pin::new(&mut *ws).poll_flush(cx)).await
}
