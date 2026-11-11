//! One device connection, from `Hello` to close (master prompt §5, `delivery`).
//!
//! ```text
//! Hello ─▶ Auth (≤ auth timeout) ─▶ verify ─▶ attach (claim the device, replace older)
//!       ─▶ AuthOk ─▶ drain mailbox after last_acked_seq ─▶ live loop
//! ```
//!
//! The live loop waits on, in priority order: shutdown drain, router signals (replaced, lagged),
//! inbound frames, stored-envelope notifications, ephemeral events and the safety sweep. Every
//! wake-up writes everything it produced and flushes once.
//!
//! Hot-path rules applied here:
//! - Store before acknowledge (invariant 1): `SendResult` is written only after
//!   `Mailbox::store_batch` returned; routing happens after that.
//! - The router never blocks on this session (bounded inbox, lag flag); this session never
//!   blocks on anyone else. A socket write that makes no progress for `write_timeout` closes the
//!   connection with 4100 (invariant 5); the device catches up from the mailbox on reconnect.
//! - No device ID, IP or content in logs (invariant 6): only codes and counts are logged.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use sockudo_ws::{Message, WebSocketStream};
use songbird_mailbox::{Mailbox, MailboxError, NewEnvelope};
use songbird_proto::frame::{self, RejectReason, SendFrame, SendStatus};
use songbird_proto::{ClientFrame, CloseCode, NONCE_LEN, PROTOCOL_VERSION, ServerFrame, control};
use songbird_router::{InboxSizes, Live, Routed, Router};
use songbird_types::DeviceId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::Shared;
use crate::bucket::Bucket;
use crate::ordering::{Cursor, LiveAction};
use crate::ws;

/// Most live notifications written per wake-up before flushing, so one busy device cannot
/// starve its own inbound frames.
const LIVE_BATCH: usize = 64;
/// Retry hint for clients closed because the store is unavailable or they were too slow.
const RETRY_MS: u32 = 1_000;

/// Why the session ended (for metrics and the close frame).
enum Exit {
    /// Close with this code (and retry hint when relevant).
    Close(CloseCode, Option<u32>),
    /// The peer closed or the socket failed; nothing more to send.
    Gone,
}

type Res<T = ()> = Result<T, Exit>;

/// Runs one upgraded connection to completion.
pub async fn run<S, M, R>(
    mut ws: WebSocketStream<S>,
    shared: Arc<Shared<M, R>>,
    drain: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
    M: Mailbox,
    R: Router,
{
    let exit = match authenticate(&mut ws, &shared).await {
        Err(e) => e,
        Ok((device, last_acked)) => {
            let sizes = InboxSizes {
                live: shared.config.session.live_inbox,
                ephemeral: shared.config.session.ephemeral_inbox,
            };
            let inbox = shared.router.attach(device, sizes).await;
            let conn = inbox.conn;
            shared.metrics.auth_ok.inc();
            let mut s = Session {
                device,
                cursor: Cursor::new(last_acked),
                buf: BytesMut::with_capacity(1024),
                shared: Arc::clone(&shared),
                sends: Bucket::new(
                    shared.config.session.sends_per_sec,
                    shared.config.session.send_burst,
                    std::time::Instant::now(),
                ),
                frames: Bucket::new(
                    shared.config.session.frames_per_sec,
                    shared.config.session.frame_burst,
                    std::time::Instant::now(),
                ),
                ephemerals: Bucket::new(
                    shared.config.session.ephemeral_per_sec,
                    shared.config.session.ephemeral_burst,
                    std::time::Instant::now(),
                ),
                needs_drain: false,
            };
            let e = s.live(&mut ws, inbox, drain).await;
            shared.router.detach(&device, conn).await;
            e
        }
    };
    if let Exit::Close(code, retry) = exit {
        count_close(&shared, code);
        let reason = retry
            .map(songbird_proto::close::retry_reason)
            .unwrap_or_default();
        // Bounded by the WebSocket close timeout; a stuck peer cannot hold the task.
        let _ = tokio::time::timeout(Duration::from_secs(2), ws.close(code.code(), &reason)).await;
    }
}

fn count_close<M: Mailbox, R: Router>(shared: &Shared<M, R>, code: CloseCode) {
    let m = &shared.metrics;
    match code {
        CloseCode::AuthFailed => m.auth_failures.inc(),
        CloseCode::AuthTimeout => m.auth_timeouts.inc(),
        CloseCode::Replaced => m.replaced.inc(),
        CloseCode::SlowConsumer => m.slow_consumers.inc(),
        CloseCode::ProtocolError | CloseCode::UnsupportedVersion => m.protocol_errors.inc(),
        CloseCode::RateLimited => m.rate_limited.inc(),
        _ => 0,
    };
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

async fn write_frame<S>(ws: &mut WebSocketStream<S>, f: &ServerFrame, timeout: Duration) -> Res
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = f.to_bytes();
    let w = async {
        ws::feed(ws, Message::Binary(bytes)).await?;
        ws::flush(ws).await
    };
    match tokio::time::timeout(timeout, w).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(Exit::Gone),
        Err(_) => Err(Exit::Close(CloseCode::SlowConsumer, Some(RETRY_MS))),
    }
}

/// `Hello`, then a valid `Auth` within the timeout. Returns the device and its last ACK.
async fn authenticate<S, M, R>(
    ws: &mut WebSocketStream<S>,
    shared: &Shared<M, R>,
) -> Res<(DeviceId, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    M: Mailbox,
    R: Router,
{
    let cfg = &shared.config;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Exit::Close(CloseCode::Unavailable, Some(RETRY_MS)))?;
    let store_generation = shared
        .mailbox
        .store_generation()
        .await
        .map_err(|_| Exit::Close(CloseCode::Unavailable, Some(RETRY_MS)))?;
    let hello = ServerFrame::Hello(control::Hello {
        nonce: nonce.to_vec(),
        server_time_ms: now_ms(),
        protocol_versions: vec![PROTOCOL_VERSION],
        store_generation,
        server_name: cfg.server_name.clone(),
    });
    write_frame(ws, &hello, cfg.session.write_timeout()).await?;

    let deadline = Instant::now() + cfg.session.auth_timeout();
    let auth = loop {
        match tokio::time::timeout_at(deadline, ws::next(ws)).await {
            Err(_) => return Err(Exit::Close(CloseCode::AuthTimeout, None)),
            Ok(Some(Ok(Message::Binary(b)))) => match ClientFrame::decode(&b, &shared.limits) {
                Ok(ClientFrame::Auth(a)) => break a,
                _ => return Err(Exit::Close(CloseCode::ProtocolError, None)),
            },
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Ok(Message::Text(_)))) => {
                return Err(Exit::Close(CloseCode::ProtocolError, None));
            }
            Ok(_) => return Err(Exit::Gone),
        }
    };
    let device = match auth.validate() {
        Ok(d) => d,
        Err(songbird_proto::FrameError::Control("auth.protocol_version unsupported")) => {
            return Err(Exit::Close(CloseCode::UnsupportedVersion, None));
        }
        Err(_) => return Err(Exit::Close(CloseCode::ProtocolError, None)),
    };
    let transcript =
        songbird_proto::auth::transcript(&cfg.server_name, &nonce, &device, PROTOCOL_VERSION)
            .map_err(|_| Exit::Close(CloseCode::Unavailable, Some(RETRY_MS)))?;
    if !shared
        .directory
        .verify(&device, &transcript, &auth.signature)
    {
        return Err(Exit::Close(CloseCode::AuthFailed, None));
    }
    // The device holds everything up to `last_acked_seq`: treat it as an ACK, so a reconnect
    // after a lost ACK frame still deletes (invariant 3).
    if auth.last_acked_seq > 0 {
        match shared.mailbox.ack_up_to(&device, auth.last_acked_seq).await {
            Ok(n) => {
                shared.metrics.acked.inc_by(n);
            }
            Err(_) => {
                shared.metrics.mailbox_errors.inc();
            }
        }
    }
    let ok = ServerFrame::AuthOk(control::AuthOk {
        store_generation,
        resume_after_seq: auth.last_acked_seq,
    });
    write_frame(ws, &ok, cfg.session.write_timeout()).await?;
    Ok((device, auth.last_acked_seq))
}

struct Session<M, R> {
    device: DeviceId,
    cursor: Cursor,
    /// Reused encode buffer: frames are split off it, so its capacity is recycled once the
    /// socket released the previous frames.
    buf: BytesMut,
    shared: Arc<Shared<M, R>>,
    sends: Bucket,
    frames: Bucket,
    ephemerals: Bucket,
    /// A drain failed (store unavailable) and must be retried.
    needs_drain: bool,
}

impl<M: Mailbox, R: Router> Session<M, R> {
    fn safety_sweep_deadline(&self) -> Instant {
        let base = self.shared.config.session.safety_sweep_secs;
        let base = if self.needs_drain { 1 } else { base };
        // ±20 % jitter so sessions that connected together do not sweep together.
        let jitter = f64::from(getrandom::u32().unwrap_or(0)) / f64::from(u32::MAX);
        let secs = Duration::from_secs(base).as_secs_f64() * (0.8 + 0.4 * jitter);
        Instant::now() + Duration::try_from_secs_f64(secs).unwrap_or(Duration::from_secs(base))
    }

    async fn live<S>(
        &mut self,
        ws: &mut WebSocketStream<S>,
        mut inbox: songbird_router::Inbox,
        mut drain: watch::Receiver<bool>,
    ) -> Exit
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Attached above, so the first drain cannot miss an envelope stored meanwhile.
        if let Err(e) = self.drain(ws).await {
            return e;
        }
        let mut sweep_at = self.safety_sweep_deadline();
        let write_timeout = self.shared.config.session.write_timeout();
        loop {
            let step: Res = tokio::select! {
                biased;
                draining = async { drain.wait_for(|d| *d).await.is_ok() } => {
                    // Deploy drain: close at a random point in the window so clients do not
                    // reconnect all at once.
                    if draining {
                        let window = self.shared.config.session.drain_window_ms;
                        let at = u64::from(getrandom::u32().unwrap_or(0)) % window.max(1);
                        tokio::time::sleep(Duration::from_millis(at)).await;
                    }
                    return Exit::Close(CloseCode::Draining, None);
                }
                () = inbox.signals.notified() => {
                    if inbox.signals.is_replaced() {
                        return Exit::Close(CloseCode::Replaced, None);
                    }
                    if inbox.signals.take_lagged() {
                        self.shared.metrics.routes_lagged.inc();
                        self.drain(ws).await
                    } else {
                        Ok(())
                    }
                }
                msg = ws::next(ws) => match msg {
                    Some(Ok(Message::Binary(b))) => self.on_frame(ws, &b).await,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(()),
                    Some(Ok(Message::Text(_))) => Err(Exit::Close(CloseCode::ProtocolError, None)),
                    Some(Err(e)) if e.is_protocol_error() || matches!(
                        e,
                        sockudo_ws::Error::MessageTooLarge | sockudo_ws::Error::FrameTooLarge
                    ) => {
                        // The WebSocket layer already failed the connection.
                        self.shared.metrics.protocol_errors.inc();
                        Err(Exit::Gone)
                    }
                    // Peer close, transport error, or idle/heartbeat timeout: the stream has
                    // already answered or ended the connection.
                    _ => Err(Exit::Gone),
                },
                Some(first) = inbox.live.recv() => {
                    self.on_live(ws, first, &mut inbox.live, write_timeout).await
                }
                Some(payload) = inbox.ephemeral.recv() => {
                    self.buf.reserve(1 + payload.len());
                    ServerFrame::Ephemeral { payload }.encode(&mut self.buf);
                    let b = self.buf.split().freeze();
                    self.send_now(ws, b, write_timeout).await
                }
                () = tokio::time::sleep_until(sweep_at) => {
                    sweep_at = self.safety_sweep_deadline();
                    self.drain(ws).await
                }
            };
            if let Err(e) = step {
                return e;
            }
            if self.needs_drain {
                sweep_at = sweep_at.min(self.safety_sweep_deadline());
            }
        }
    }

    /// Writes up to [`LIVE_BATCH`] queued notifications, then flushes once; a gap switches to a
    /// mailbox drain.
    async fn on_live<S>(
        &mut self,
        ws: &mut WebSocketStream<S>,
        first: Live,
        rx: &mut tokio::sync::mpsc::Receiver<Live>,
        write_timeout: Duration,
    ) -> Res
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut n = 0;
        let mut next = Some(first);
        while let Some(l) = next {
            match self.cursor.on_live(l.seq) {
                LiveAction::Send => {
                    self.queue_deliver(ws, l.seq, &l.envelope).await?;
                    self.shared.metrics.delivered_live.inc();
                }
                LiveAction::Duplicate => {
                    self.shared.metrics.live_duplicates.inc();
                }
                // Everything queued is in the mailbox too; the drain sends it in order.
                LiveAction::Gap => return self.drain(ws).await,
            }
            n += 1;
            next = if n < LIVE_BATCH {
                rx.try_recv().ok()
            } else {
                None
            };
        }
        self.flush(ws, write_timeout).await
    }

    /// Queues a `Deliver` frame (written at the next flush or when the buffer fills).
    async fn queue_deliver<S>(
        &mut self,
        ws: &mut WebSocketStream<S>,
        seq: u64,
        envelope: &[u8],
    ) -> Res
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // One copy of the envelope into the frame; milestone 3 removes it (zero-allocation
        // delivery) once the frame header can be written as a separate vectored segment.
        frame::encode_deliver(&mut self.buf, seq, envelope);
        let b = self.buf.split().freeze();
        let timeout = self.shared.config.session.write_timeout();
        match tokio::time::timeout(timeout, ws::feed(ws, Message::Binary(b))).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Exit::Gone),
            Err(_) => Err(Exit::Close(CloseCode::SlowConsumer, Some(RETRY_MS))),
        }
    }

    async fn flush<S>(&mut self, ws: &mut WebSocketStream<S>, timeout: Duration) -> Res
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match tokio::time::timeout(timeout, ws::flush(ws)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Exit::Gone),
            Err(_) => Err(Exit::Close(CloseCode::SlowConsumer, Some(RETRY_MS))),
        }
    }

    async fn send_now<S>(&mut self, ws: &mut WebSocketStream<S>, b: Bytes, timeout: Duration) -> Res
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let w = async {
            ws::feed(ws, Message::Binary(b)).await?;
            ws::flush(ws).await
        };
        match tokio::time::timeout(timeout, w).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Exit::Gone),
            Err(_) => Err(Exit::Close(CloseCode::SlowConsumer, Some(RETRY_MS))),
        }
    }

    /// Sends everything in the mailbox after the cursor, page by page.
    async fn drain<S>(&mut self, ws: &mut WebSocketStream<S>) -> Res
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.shared.metrics.drains.inc();
        let page = self.shared.config.session.drain_page;
        let timeout = self.shared.config.session.write_timeout();
        loop {
            let Ok(batch) = self
                .shared
                .mailbox
                .fetch_after(&self.device, self.cursor.last_sent(), page)
                .await
            else {
                // Keep the socket open; retry on a short timer ("SurrealDB unavailable" row of
                // the failure matrix).
                self.shared.metrics.mailbox_errors.inc();
                self.needs_drain = true;
                return Ok(());
            };
            let n = batch.len();
            for s in batch {
                if self.cursor.on_drained(s.seq) {
                    self.queue_deliver(ws, s.seq, &s.envelope).await?;
                    self.shared.metrics.delivered_drained.inc();
                }
            }
            self.flush(ws, timeout).await?;
            if n < page {
                self.needs_drain = false;
                return Ok(());
            }
        }
    }

    async fn on_frame<S>(&mut self, ws: &mut WebSocketStream<S>, b: &Bytes) -> Res
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let now = std::time::Instant::now();
        if let Err(wait) = self.frames.take(now) {
            let ms = u32::try_from(wait.as_millis())
                .unwrap_or(u32::MAX)
                .max(RETRY_MS);
            return Err(Exit::Close(CloseCode::RateLimited, Some(ms)));
        }
        let frame = ClientFrame::decode(b, &self.shared.limits)
            .map_err(|_| Exit::Close(CloseCode::ProtocolError, None))?;
        match frame {
            ClientFrame::Send(s) => self.on_send(ws, s, now).await,
            ClientFrame::Ack { up_to_seq } => {
                if !self.cursor.ack_allowed(up_to_seq) {
                    return Err(Exit::Close(CloseCode::ProtocolError, None));
                }
                // Milestone 2 batches ACK deletes per core every 50–100 ms.
                match self.shared.mailbox.ack_up_to(&self.device, up_to_seq).await {
                    Ok(n) => {
                        self.shared.metrics.acked.inc_by(n);
                    }
                    Err(_) => {
                        // Not fatal: the next ACK or reconnect (Auth.last_acked_seq) repeats it.
                        self.shared.metrics.mailbox_errors.inc();
                    }
                }
                Ok(())
            }
            ClientFrame::Ephemeral { to, payload } => {
                let m = &self.shared.metrics;
                if self.ephemerals.take(now).is_err() {
                    m.ephemeral_dropped.inc();
                } else if self.shared.router.route_ephemeral(&to, payload).await == Routed::Queued {
                    m.ephemeral_routed.inc();
                } else {
                    m.ephemeral_dropped.inc();
                }
                Ok(())
            }
            ClientFrame::Auth(_) => Err(Exit::Close(CloseCode::ProtocolError, None)),
        }
    }

    async fn reply<S>(
        &mut self,
        ws: &mut WebSocketStream<S>,
        req_id: u32,
        status: SendStatus,
    ) -> Res
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !matches!(status, SendStatus::Accepted) {
            self.shared.metrics.sends_rejected.inc();
        }
        ServerFrame::SendResult { req_id, status }.encode(&mut self.buf);
        let b = self.buf.split().freeze();
        let t = self.shared.config.session.write_timeout();
        self.send_now(ws, b, t).await
    }

    async fn on_send<S>(
        &mut self,
        ws: &mut WebSocketStream<S>,
        s: SendFrame,
        now: std::time::Instant,
    ) -> Res
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let reject = |reason, retry_after_ms| SendStatus::Rejected {
            reason,
            retry_after_ms,
        };
        if let Err(wait) = self.sends.take(now) {
            let ms = u32::try_from(wait.as_millis()).unwrap_or(u32::MAX).max(1);
            return self
                .reply(ws, s.req_id, reject(RejectReason::RateLimited, ms))
                .await;
        }
        let dir = &self.shared.directory;
        if s.recipients.iter().any(|r| !dir.contains(&r.device)) {
            return self
                .reply(ws, s.req_id, reject(RejectReason::UnknownRecipient, 0))
                .await;
        }
        // Bounded by max_recipients (checked by the decoder).
        let mut seen = HashSet::with_capacity(s.recipients.len());
        if !s.recipients.iter().all(|r| seen.insert(r.device)) {
            return self
                .reply(ws, s.req_id, reject(RejectReason::DuplicateRecipient, 0))
                .await;
        }
        let items: Vec<NewEnvelope> = s
            .recipients
            .iter()
            .map(|r| NewEnvelope {
                device: r.device,
                envelope: r.envelope.clone(),
            })
            .collect();
        // Invariant 1: store first; only then acknowledge and route.
        let outcome = match self
            .shared
            .mailbox
            .store_batch(Some(s.idempotency_key), &items)
            .await
        {
            Ok(o) => o,
            Err(MailboxError::Full | MailboxError::Unavailable) => {
                self.shared.metrics.mailbox_errors.inc();
                return self
                    .reply(ws, s.req_id, reject(RejectReason::Unavailable, RETRY_MS))
                    .await;
            }
        };
        let m = &self.shared.metrics;
        if outcome.replayed {
            m.sends_replayed.inc();
        } else {
            m.sends_accepted.inc();
            m.envelopes_stored
                .inc_by(u64::try_from(items.len()).unwrap_or(u64::MAX));
        }
        frame::encode_send_accepted(&mut self.buf, s.req_id);
        let ack = self.buf.split().freeze();
        let t = self.shared.config.session.write_timeout();
        match tokio::time::timeout(t, ws::feed(ws, Message::Binary(ack))).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(Exit::Gone),
            Err(_) => return Err(Exit::Close(CloseCode::SlowConsumer, Some(RETRY_MS))),
        }
        // Route even a replayed send: if the original route was lost (crash between store and
        // route), this retry delivers it now instead of at the next safety sweep; a duplicate
        // is dropped by the recipient session's cursor.
        for (r, seq) in s.recipients.into_iter().zip(outcome.seqs) {
            let live = Live {
                seq,
                envelope: r.envelope,
            };
            match self.shared.router.route(&r.device, live).await {
                Routed::Queued => {}
                Routed::Lagged => {
                    m.routes_lagged.inc();
                }
                // Milestone 5 queues a push job here.
                Routed::Offline => {
                    m.routes_offline.inc();
                }
            }
        }
        self.flush(ws, t).await
    }
}
