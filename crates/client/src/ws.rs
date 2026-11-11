//! Thin async helpers over `sockudo-ws`'s `Stream` and `Sink` implementations, so neither the
//! client nor the server needs `futures-util`.

use std::future::poll_fn;
use std::pin::Pin;

use futures_core::Stream as _;
use futures_sink::Sink as _;
use sockudo_ws::{Message, WebSocketStream};
use tokio::io::{AsyncRead, AsyncWrite};

/// Next message, or `None` once the stream ended. Cancel-safe: the state lives in the stream.
pub(crate) async fn next<S>(ws: &mut WebSocketStream<S>) -> Option<sockudo_ws::Result<Message>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|cx| Pin::new(&mut *ws).poll_next(cx)).await
}

/// Queues a message without flushing (batched with whatever follows until [`flush`]).
pub(crate) async fn feed<S>(ws: &mut WebSocketStream<S>, msg: Message) -> sockudo_ws::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|cx| Pin::new(&mut *ws).poll_ready(cx)).await?;
    Pin::new(&mut *ws).start_send(msg)
}

/// Writes everything queued.
pub(crate) async fn flush<S>(ws: &mut WebSocketStream<S>) -> sockudo_ws::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    poll_fn(|cx| Pin::new(&mut *ws).poll_flush(cx)).await
}
