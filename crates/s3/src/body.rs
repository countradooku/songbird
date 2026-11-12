//! Request and response bodies.

use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use hyper::body::{Body, Frame, Incoming, SizeHint};

use crate::{Error, Inner, Pooled};

/// Why an upload body stopped (shared with the caller, which sees only hyper's error).
pub(crate) const BODY_OK: u8 = 0;
pub(crate) const BODY_MISMATCH: u8 = 1;
pub(crate) const BODY_SOURCE: u8 = 2;

/// An upload body failure. Carries nothing from the source stream.
#[derive(Debug)]
pub(crate) struct BodyError;

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upload body aborted")
    }
}

impl std::error::Error for BodyError {}

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, ()>> + Send>>;

/// Adapts a caller's stream, dropping its error values (they could carry anything).
struct DropErr<S>(S);

impl<S, E> Stream for DropErr<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    type Item = Result<Bytes, ()>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0)
            .poll_next(cx)
            .map(|o| o.map(|r| r.map_err(|_| ())))
    }
}

/// A body that yields exactly `remaining` bytes, or fails: more bytes from the source, or an end
/// before `remaining` reaches zero, abort the request (so the connection is dropped and the
/// server never sees a complete body).
///
/// hyper stops polling a body once it has written `Content-Length` bytes, so the chunk that
/// completes the length is held back until the source has confirmed its end.
pub(crate) struct ExactBody {
    stream: ByteStream,
    remaining: u64,
    held: Option<Bytes>,
    done: bool,
    state: Arc<AtomicU8>,
}

impl ExactBody {
    pub(crate) fn new<S, E>(stream: S, length: u64, state: Arc<AtomicU8>) -> Self
    where
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: 'static,
    {
        Self {
            stream: Box::pin(DropErr(Box::pin(stream))),
            remaining: length,
            held: None,
            done: false,
            state,
        }
    }

    fn fail(&mut self, why: u8) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.state.store(why, Ordering::Relaxed);
        self.done = true;
        self.held = None;
        Poll::Ready(Some(Err(BodyError)))
    }

    fn poll_exact(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        loop {
            if self.done {
                return Poll::Ready(None);
            }
            let next = match self.stream.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(n) => n,
            };
            match next {
                None => {
                    if self.remaining > 0 {
                        return self.fail(BODY_MISMATCH);
                    }
                    self.done = true;
                    return Poll::Ready(self.held.take().map(|b| Ok(Frame::data(b))));
                }
                Some(Err(())) => return self.fail(BODY_SOURCE),
                Some(Ok(chunk)) if chunk.is_empty() => {}
                Some(Ok(chunk)) => {
                    let len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                    if self.held.is_some() || len > self.remaining {
                        return self.fail(BODY_MISMATCH);
                    }
                    self.remaining -= len;
                    if self.remaining == 0 {
                        self.held = Some(chunk);
                    } else {
                        return Poll::Ready(Some(Ok(Frame::data(chunk))));
                    }
                }
            }
        }
    }

    /// For a zero length: confirms the source is empty before anything is sent.
    pub(crate) async fn confirm_empty(&mut self) -> Result<(), u8> {
        match std::future::poll_fn(|cx| self.poll_exact(cx)).await {
            None => Ok(()),
            Some(_) => Err(self.state.load(Ordering::Relaxed)),
        }
    }
}

/// Every request body this client sends.
pub(crate) enum ReqBody {
    Empty,
    Full(Option<Bytes>),
    Exact(ExactBody),
}

impl Body for ReqBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match self.get_mut() {
            Self::Empty => Poll::Ready(None),
            Self::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Self::Exact(e) => e.poll_exact(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full(b) => b.is_none(),
            Self::Exact(e) => e.done,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::Full(b) => SizeHint::with_exact(
                b.as_ref()
                    .map_or(0, |b| u64::try_from(b.len()).unwrap_or(u64::MAX)),
            ),
            Self::Exact(e) => SizeHint::with_exact(
                e.remaining
                    + e.held
                        .as_ref()
                        .map_or(0, |b| u64::try_from(b.len()).unwrap_or(u64::MAX)),
            ),
        }
    }
}

/// A streaming object body (from [`Client::get_object`](crate::Client::get_object)).
///
/// Yields exactly the response's `Content-Length` bytes. Each chunk must arrive within the
/// client's request timeout. The connection goes back to the pool only when the body has been
/// read to its end; dropping it early closes the connection.
pub struct ObjectBody {
    incoming: Incoming,
    remaining: u64,
    conn: Option<Pooled>,
    inner: Arc<Inner>,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
    finished: bool,
}

impl std::fmt::Debug for ObjectBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectBody")
            .field("remaining", &self.remaining)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl ObjectBody {
    pub(crate) fn new(incoming: Incoming, length: u64, conn: Pooled, inner: Arc<Inner>) -> Self {
        let idle = inner.request_timeout;
        Self {
            incoming,
            remaining: length,
            conn: Some(conn),
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
            finished: length == 0,
        }
        .released_if_finished()
    }

    fn released_if_finished(mut self) -> Self {
        if self.finished
            && self.incoming.is_end_stream()
            && let Some(c) = self.conn.take()
        {
            self.inner.release(c);
        }
        self
    }

    /// Bytes still to come.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// The next chunk, `None` at the end.
    pub async fn chunk(&mut self) -> Option<Result<Bytes, Error>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    fn fail(&mut self, e: Error) -> Poll<Option<Result<Bytes, Error>>> {
        self.finished = true;
        self.conn = None;
        Poll::Ready(Some(Err(e)))
    }
}

impl Stream for ObjectBody {
    type Item = Result<Bytes, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if this.finished && this.conn.is_none() {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.incoming).poll_frame(cx) {
                Poll::Pending => {
                    if this.sleep.as_mut().poll(cx).is_ready() {
                        return this.fail(Error::Timeout);
                    }
                    return Poll::Pending;
                }
                Poll::Ready(None) => {
                    if this.remaining != 0 {
                        return this.fail(Error::Protocol("object body ended early"));
                    }
                    this.finished = true;
                    if let Some(c) = this.conn.take() {
                        this.inner.release(c);
                    }
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(_))) => return this.fail(Error::Transport),
                Poll::Ready(Some(Ok(frame))) => {
                    let Ok(data) = frame.into_data() else {
                        continue; // trailers: ignored
                    };
                    let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    if len > this.remaining {
                        return this.fail(Error::Protocol("object body longer than announced"));
                    }
                    this.remaining -= len;
                    let deadline = tokio::time::Instant::now() + this.idle;
                    this.sleep.as_mut().reset(deadline);
                    if this.remaining == 0 && this.incoming.is_end_stream() {
                        this.finished = true;
                        if let Some(c) = this.conn.take() {
                            this.inner.release(c);
                        }
                    }
                    if data.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(data)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    struct Chunks(VecDeque<Result<Bytes, ()>>);

    impl Stream for Chunks {
        type Item = Result<Bytes, ()>;
        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    fn run(length: u64, chunks: &[&'static [u8]], fail_at_end: bool) -> (Vec<u8>, bool, u8) {
        let mut items: VecDeque<_> = chunks.iter().map(|c| Ok(Bytes::from_static(c))).collect();
        if fail_at_end {
            items.push_back(Err(()));
        }
        let state = Arc::new(AtomicU8::new(BODY_OK));
        let mut body = ReqBody::Exact(ExactBody::new(Chunks(items), length, Arc::clone(&state)));
        assert_eq!(body.size_hint().exact(), Some(length));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut out = Vec::new();
        let mut failed = false;
        while let Poll::Ready(Some(r)) = Pin::new(&mut body).poll_frame(&mut cx) {
            let Ok(f) = r else {
                failed = true;
                break;
            };
            out.extend_from_slice(&f.into_data().unwrap_or_default());
        }
        if !failed {
            assert!(body.is_end_stream());
        }
        (out, failed, state.load(Ordering::Relaxed))
    }

    #[test]
    fn exact_length_passes() {
        assert_eq!(
            run(6, &[b"ab", b"", b"cd", b"ef"], false),
            (b"abcdef".to_vec(), false, BODY_OK)
        );
        assert_eq!(
            run(2, &[b"ab", b""], false),
            (b"ab".to_vec(), false, BODY_OK)
        );
    }

    #[test]
    fn longer_or_shorter_fails_before_the_last_byte() {
        // Too long inside a chunk: nothing of that chunk is sent.
        let (out, failed, st) = run(3, &[b"ab", b"cd"], false);
        assert_eq!(
            (out.as_slice(), failed, st),
            (&b"ab"[..], true, BODY_MISMATCH)
        );
        // Too long after the length was complete: the completing chunk is held back.
        let (out, failed, st) = run(2, &[b"ab", b"c"], false);
        assert_eq!(
            (out.as_slice(), failed, st),
            (&b""[..], true, BODY_MISMATCH)
        );
        // Too short.
        let (out, failed, st) = run(5, &[b"ab", b"cd"], false);
        assert_eq!(
            (out.as_slice(), failed, st),
            (&b"abcd"[..], true, BODY_MISMATCH)
        );
        // Source error after the full length: still refused.
        let (_, failed, st) = run(2, &[b"ab"], true);
        assert_eq!((failed, st), (true, BODY_SOURCE));
    }
}
