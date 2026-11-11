//! Songbird delivery client (master prompt §5, `client`).
//!
//! One background task per device runs the connection state machine:
//!
//! ```text
//! Connecting ──Hello/Auth/AuthOk──▶ Connected ──close/error──▶ Unavailable ──backoff──▶ Connecting
//!      │                                  │
//!      └────────── 4000–4099 close ───────┴──▶ Failed (stop; the app must act)
//! ```
//!
//! - **Authentication:** signs the transcript of `songbird_proto::auth` with the device key, for
//!   the server name from *this* configuration (never the one the server announces).
//! - **Backoff:** exponential with full jitter, never shorter than the server's retry hint;
//!   `42xx` closes reconnect after a short jitter only.
//! - **Exactly once to the app:** deliveries with a `seq` at or below the last one handed to the
//!   app are dropped (they arrive again after a reconnect until the app's ACK reaches the server).
//! - **ACKs:** cumulative, sent only for what the app confirmed it stored durably
//!   ([`Client::ack`]), coalesced for `ack_delay`.
//! - **Store generation:** reported in [`Event::StoreGenerationChanged`] when it grows; the app
//!   then resends every message without a delivery receipt (`PROTOCOL.md` §3.6).
#![forbid(unsafe_code)]

mod backoff;
mod key;
mod ws;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use sockudo_ws::client::WebSocketClient;
use sockudo_ws::{Http1, Message, WebSocketStream};
use songbird_proto::close::{self, Reconnect};
use songbird_proto::frame::{Recipient, SendFrame, SendStatus};
use songbird_proto::{ClientFrame, CloseCode, Limits, PROTOCOL_VERSION, ServerFrame, control};
use songbird_types::DeviceId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

pub use backoff::{Backoff, BackoffConfig};
pub use key::{DeviceKey, KeyError};

/// Client settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// `host:port` to connect to.
    pub addr: String,
    /// The endpoint's public name: signed during authentication, sent as `Host`, used for TLS.
    pub server_name: String,
    /// TLS settings; `None` for plain TCP (development and tests only).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Frame limits (must match the server's).
    pub limits: Limits,
    /// Reconnect backoff.
    pub backoff: BackoffConfig,
    /// How long to coalesce ACKs.
    pub ack_delay: Duration,
    /// Limit for TCP connect, TLS, upgrade and each authentication step.
    pub handshake_timeout: Duration,
    /// Events buffered for the app; when full, the client stops reading the socket (the server
    /// then treats it as a slow consumer).
    pub event_capacity: usize,
    /// Reported in `Auth.client_version`.
    pub client_version: String,
}

impl ClientConfig {
    /// Defaults for a plain-TCP endpoint.
    #[must_use]
    pub fn new(addr: impl Into<String>, server_name: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            server_name: server_name.into(),
            tls: None,
            limits: Limits::DEFAULT,
            backoff: BackoffConfig::default(),
            ack_delay: Duration::from_millis(10),
            handshake_timeout: Duration::from_secs(10),
            event_capacity: 1024,
            client_version: concat!("songbird-client/", env!("CARGO_PKG_VERSION")).into(),
        }
    }
}

/// What the app persists between runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResumeState {
    /// Highest `seq` the app stored durably and acknowledged.
    pub acked_seq: u64,
    /// Last store generation seen (0: never connected).
    pub store_generation: u64,
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Connecting or authenticating.
    Connecting,
    /// Authenticated; deliveries flow.
    Connected,
    /// Waiting to reconnect.
    Unavailable,
    /// Stopped after a do-not-reconnect close; the app must act.
    Failed,
}

/// Events for the app.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Authenticated.
    Connected {
        /// Current store generation.
        store_generation: u64,
        /// Delivery resumes after this `seq`.
        resume_after_seq: u64,
    },
    /// A new envelope, exactly once and in `seq` order. Store it, then call [`Client::ack`].
    Deliver {
        /// Its sequence number.
        seq: u64,
        /// Opaque ciphertext.
        envelope: Bytes,
    },
    /// An ephemeral event (never stored).
    Ephemeral {
        /// Opaque payload.
        payload: Bytes,
    },
    /// The server's data was restored from a backup: resend unreceipted messages.
    StoreGenerationChanged {
        /// Generation before.
        previous: u64,
        /// Generation now.
        current: u64,
    },
    /// The connection ended; a reconnect follows after `retry_in`.
    Disconnected {
        /// Close code, if the server sent one.
        code: Option<u16>,
        /// Wait before the next attempt.
        retry_in: Duration,
    },
    /// The server closed with a do-not-reconnect code; the client stopped.
    Failed {
        /// The close code.
        code: u16,
    },
}

/// Errors returned to the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// No authenticated connection right now; retry with the same idempotency key.
    #[error("not connected")]
    NotConnected,
    /// The connection dropped before the result arrived; retry with the same idempotency key.
    #[error("disconnected before the result")]
    Disconnected,
    /// The client task has stopped.
    #[error("client stopped")]
    Stopped,
}

enum Command {
    Send {
        idempotency_key: [u8; 16],
        recipients: Vec<Recipient>,
        reply: oneshot::Sender<Result<SendStatus, ClientError>>,
    },
    Ephemeral {
        to: DeviceId,
        payload: Bytes,
    },
    Ack(u64),
    /// Drop the socket without a close frame (tests and chaos runs).
    Abort,
    Close,
}

/// Handle to a running client. Dropping it stops the client.
#[derive(Debug)]
pub struct Client {
    cmds: mpsc::Sender<Command>,
    state: watch::Receiver<State>,
}

impl Client {
    /// Starts the client task on the current Tokio runtime. Returns the handle and the event
    /// stream.
    #[must_use]
    pub fn start(
        cfg: ClientConfig,
        key: DeviceKey,
        resume: ResumeState,
    ) -> (Self, mpsc::Receiver<Event>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (ev_tx, ev_rx) = mpsc::channel(cfg.event_capacity.max(1));
        let (state_tx, state_rx) = watch::channel(State::Connecting);
        let task = Task {
            backoff: Backoff::new(cfg.backoff),
            cfg,
            key,
            cmds: cmd_rx,
            events: ev_tx,
            state: state_tx,
            acked: resume.acked_seq,
            sent_ack: resume.acked_seq,
            delivered: resume.acked_seq,
            store_generation: resume.store_generation,
            next_req: 1,
            pending: HashMap::new(),
            buf: BytesMut::with_capacity(1024),
            channel_binding: songbird_proto::auth::NO_CHANNEL_BINDING,
        };
        tokio::spawn(task.run());
        (
            Self {
                cmds: cmd_tx,
                state: state_rx,
            },
            ev_rx,
        )
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> State {
        *self.state.borrow()
    }

    /// Waits until the state is `want` (or the client stopped).
    pub async fn wait_for(&mut self, want: State) -> State {
        match self
            .state
            .wait_for(|s| *s == want || *s == State::Failed)
            .await
        {
            Ok(s) => *s,
            Err(_) => State::Failed,
        }
    }

    /// Sends envelopes and waits for the server's result.
    ///
    /// # Errors
    /// [`ClientError`]: not connected, disconnected before the result, or stopped. Retry with
    /// the same `idempotency_key`: the server stores a retried send once.
    pub async fn send(
        &self,
        idempotency_key: [u8; 16],
        recipients: Vec<Recipient>,
    ) -> Result<SendStatus, ClientError> {
        let (reply, rx) = oneshot::channel();
        self.cmds
            .send(Command::Send {
                idempotency_key,
                recipients,
                reply,
            })
            .await
            .map_err(|_| ClientError::Stopped)?;
        rx.await.map_err(|_| ClientError::Stopped)?
    }

    /// Sends an ephemeral event (best effort: dropped if not connected).
    ///
    /// # Errors
    /// [`ClientError::Stopped`].
    pub async fn ephemeral(&self, to: DeviceId, payload: Bytes) -> Result<(), ClientError> {
        self.cmds
            .send(Command::Ephemeral { to, payload })
            .await
            .map_err(|_| ClientError::Stopped)
    }

    /// Confirms that everything up to `seq` is stored durably on the device.
    ///
    /// # Errors
    /// [`ClientError::Stopped`].
    pub async fn ack(&self, seq: u64) -> Result<(), ClientError> {
        self.cmds
            .send(Command::Ack(seq))
            .await
            .map_err(|_| ClientError::Stopped)
    }

    /// Drops the current socket without a close frame, as a network failure would.
    ///
    /// # Errors
    /// [`ClientError::Stopped`].
    pub async fn abort_connection(&self) -> Result<(), ClientError> {
        self.cmds
            .send(Command::Abort)
            .await
            .map_err(|_| ClientError::Stopped)
    }

    /// Closes the connection cleanly and stops the client.
    pub async fn close(self) {
        let _ = self.cmds.send(Command::Close).await;
        let mut state = self.state;
        let _ = state.wait_for(|s| *s == State::Failed).await;
    }
}

enum Outcome {
    /// The server closed with this code and reason.
    Closed(u16, String),
    /// Transport error, timeout or protocol failure.
    Error,
    /// The app asked to stop.
    Shutdown,
}

struct Task {
    cfg: ClientConfig,
    key: DeviceKey,
    backoff: Backoff,
    cmds: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    state: watch::Sender<State>,
    /// Highest `seq` the app confirmed durable.
    acked: u64,
    /// Highest ACK sent on the current connection.
    sent_ack: u64,
    /// Highest `seq` handed to the app.
    delivered: u64,
    store_generation: u64,
    next_req: u32,
    pending: HashMap<u32, oneshot::Sender<Result<SendStatus, ClientError>>>,
    buf: BytesMut,
    /// TLS exporter of the current connection (zeros without TLS).
    channel_binding: [u8; songbird_proto::auth::CHANNEL_BINDING_LEN],
}

enum Conn {
    Plain(Box<WebSocketStream<TcpStream>>),
    Tls(Box<WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>>),
}

impl Task {
    async fn run(mut self) {
        loop {
            self.state.send_replace(State::Connecting);
            let outcome = match self.connect().await {
                Ok(Conn::Plain(ws)) => self.session(*ws).await,
                Ok(Conn::Tls(ws)) => self.session(*ws).await,
                Err(()) => Outcome::Error,
            };
            for (_, reply) in self.pending.drain() {
                let _ = reply.send(Err(ClientError::Disconnected));
            }
            let (code, wait) = match outcome {
                Outcome::Shutdown => break,
                Outcome::Error => (None, self.backoff.next(None)),
                Outcome::Closed(code, reason) => match CloseCode::reconnect(code) {
                    Reconnect::Never => {
                        let _ = self.events.send(Event::Failed { code }).await;
                        break;
                    }
                    Reconnect::Now => (Some(code), Backoff::now_jitter()),
                    Reconnect::Backoff => {
                        let hint = close::parse_retry(&reason)
                            .map(|ms| Duration::from_millis(u64::from(ms)));
                        (Some(code), self.backoff.next(hint))
                    }
                },
            };
            self.state.send_replace(State::Unavailable);
            if self
                .events
                .send(Event::Disconnected {
                    code,
                    retry_in: wait,
                })
                .await
                .is_err()
                || !self.idle(wait).await
            {
                break;
            }
        }
        self.state.send_replace(State::Failed);
    }

    /// Waits `wait` while answering commands; `false` if the app asked to stop.
    async fn idle(&mut self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => return true,
                cmd = self.cmds.recv() => match cmd {
                    None | Some(Command::Close) => return false,
                    Some(Command::Send { reply, .. }) => {
                        let _ = reply.send(Err(ClientError::NotConnected));
                    }
                    Some(Command::Ack(seq)) => self.record_ack(seq),
                    Some(Command::Ephemeral { .. } | Command::Abort) => {}
                },
            }
        }
    }

    fn record_ack(&mut self, seq: u64) {
        // Never acknowledge beyond what was handed to the app.
        self.acked = self.acked.max(seq.min(self.delivered));
    }

    fn ws_config(&self) -> sockudo_ws::Config {
        let max = self.cfg.limits.max_message_bytes();
        sockudo_ws::Config::builder()
            .max_message_size(max)
            .max_frame_size(max)
            // The server pings every 25 s; the client only answers (saves mobile radio wake-ups)
            // and gives up after 90 s of silence.
            .auto_ping(false)
            .idle_timeout(90)
            .build()
    }

    async fn connect(&mut self) -> Result<Conn, ()> {
        let t = self.cfg.handshake_timeout;
        let tcp = tokio::time::timeout(t, TcpStream::connect(&self.cfg.addr))
            .await
            .map_err(drop)?
            .map_err(drop)?;
        tcp.set_nodelay(true).map_err(drop)?;
        let client = WebSocketClient::<Http1>::new(self.ws_config());
        let host = self.cfg.server_name.clone();
        self.channel_binding = songbird_proto::auth::NO_CHANNEL_BINDING;
        let proto = Some(songbird_proto::SUBPROTOCOL);
        if let Some(tls) = &self.cfg.tls {
            let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(drop)?;
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
            let stream = tokio::time::timeout(t, connector.connect(name, tcp))
                .await
                .map_err(drop)?
                .map_err(drop)?;
            // RFC 9266 tls-exporter, signed during authentication (D-0018).
            self.channel_binding = stream
                .get_ref()
                .1
                .export_keying_material(
                    [0u8; songbird_proto::auth::CHANNEL_BINDING_LEN],
                    songbird_proto::auth::EXPORTER_LABEL,
                    None,
                )
                .map_err(drop)?;
            let (ws, hs) = tokio::time::timeout(
                t,
                client.connect_raw(stream, &host, songbird_proto::PATH, proto),
            )
            .await
            .map_err(drop)?
            .map_err(drop)?;
            check_protocol(hs.protocol.as_deref())?;
            Ok(Conn::Tls(Box::new(ws)))
        } else {
            let (ws, hs) = tokio::time::timeout(
                t,
                client.connect_raw(tcp, &host, songbird_proto::PATH, proto),
            )
            .await
            .map_err(drop)?
            .map_err(drop)?;
            check_protocol(hs.protocol.as_deref())?;
            Ok(Conn::Plain(Box::new(ws)))
        }
    }

    fn encode(&mut self, f: &ClientFrame) -> Bytes {
        f.encode(&mut self.buf);
        self.buf.split().freeze()
    }

    async fn write<S>(&mut self, ws: &mut WebSocketStream<S>, f: &ClientFrame) -> Result<(), ()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let b = self.encode(f);
        ws::feed(ws, Message::Binary(b)).await.map_err(drop)?;
        ws::flush(ws).await.map_err(drop)
    }

    /// Reads the next server frame within the handshake timeout.
    async fn read_frame<S>(&self, ws: &mut WebSocketStream<S>) -> Result<ServerFrame, Outcome>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let deadline = Instant::now() + self.cfg.handshake_timeout;
        loop {
            let msg = tokio::time::timeout_at(deadline, ws::next(ws))
                .await
                .map_err(|_| Outcome::Error)?;
            match msg {
                Some(Ok(Message::Binary(b))) => {
                    return ServerFrame::decode(&b, &self.cfg.limits).map_err(|_| Outcome::Error);
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(r)) | Err(sockudo_ws::Error::Closed(r))) => {
                    return Err(closed(r));
                }
                _ => return Err(Outcome::Error),
            }
        }
    }

    async fn authenticate<S>(&mut self, ws: &mut WebSocketStream<S>) -> Result<(), Outcome>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let ServerFrame::Hello(hello) = self.read_frame(ws).await? else {
            return Err(Outcome::Error);
        };
        if !hello.protocol_versions.contains(&PROTOCOL_VERSION) {
            return Err(Outcome::Closed(
                CloseCode::UnsupportedVersion.code(),
                String::new(),
            ));
        }
        // A restore from backup: the server's mailboxes and `seq` counters are from the backup,
        // so `seq`s already seen here may be reused for new envelopes. Start over from 0; the app
        // drops repeats by the message ID inside each envelope (PROTOCOL.md §3.6).
        let restored = self.store_generation != 0 && hello.store_generation > self.store_generation;
        if restored {
            self.acked = 0;
            self.sent_ack = 0;
            self.delivered = 0;
        }
        let device = self.key.device();
        let transcript = songbird_proto::auth::transcript(
            &self.cfg.server_name,
            &hello.nonce,
            &device,
            PROTOCOL_VERSION,
            &self.channel_binding,
        )
        .map_err(|_| Outcome::Error)?;
        let auth = ClientFrame::Auth(control::Auth {
            device_id: device.as_bytes().to_vec(),
            signature: self.key.sign(&transcript).to_vec(),
            last_acked_seq: self.acked,
            client_version: self.cfg.client_version.clone(),
            protocol_version: PROTOCOL_VERSION,
        });
        self.write(ws, &auth).await.map_err(|()| Outcome::Error)?;
        self.sent_ack = self.acked;
        let ok = loop {
            match self.read_frame(ws).await? {
                ServerFrame::AuthOk(ok) => break ok,
                // An `Error` frame precedes the close; the close carries the decision.
                ServerFrame::Error(_) => {}
                _ => return Err(Outcome::Error),
            }
        };
        if restored {
            let _ = self
                .events
                .send(Event::StoreGenerationChanged {
                    previous: self.store_generation,
                    current: ok.store_generation,
                })
                .await;
        }
        self.store_generation = ok.store_generation;
        Ok(())
    }

    async fn session<S>(&mut self, mut ws: WebSocketStream<S>) -> Outcome
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if let Err(o) = self.authenticate(&mut ws).await {
            return o;
        }
        self.backoff.reset();
        self.state.send_replace(State::Connected);
        if self
            .events
            .send(Event::Connected {
                store_generation: self.store_generation,
                resume_after_seq: self.acked,
            })
            .await
            .is_err()
        {
            return Outcome::Shutdown;
        }
        let mut ack_deadline: Option<Instant> = None;
        loop {
            let ack_timer = async {
                match ack_deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                msg = ws::next(&mut ws) => match msg {
                    Some(Ok(Message::Binary(b))) => {
                        if let Err(o) = self.on_frame(&b).await {
                            return o;
                        }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Close(r)) | Err(sockudo_ws::Error::Closed(r))) => {
                        return closed(r);
                    }
                    _ => return Outcome::Error,
                },
                cmd = self.cmds.recv() => {
                    let r = match cmd {
                        None | Some(Command::Close) => {
                            // Flush a coalesced ACK first, so a clean close never leaves
                            // stored envelopes to be redelivered on the next connection.
                            if self.acked > self.sent_ack {
                                let up_to_seq = self.acked;
                                let _ = self.write(&mut ws, &ClientFrame::Ack { up_to_seq }).await;
                            }
                            let _ = ws.close(1000, "").await;
                            return Outcome::Shutdown;
                        }
                        Some(Command::Abort) => return Outcome::Error,
                        Some(Command::Ack(seq)) => {
                            self.record_ack(seq);
                            if self.acked > self.sent_ack && ack_deadline.is_none() {
                                ack_deadline = Some(Instant::now() + self.cfg.ack_delay);
                            }
                            Ok(())
                        }
                        Some(Command::Ephemeral { to, payload }) => {
                            self.write(&mut ws, &ClientFrame::Ephemeral { to, payload }).await
                        }
                        Some(Command::Send { idempotency_key, recipients, reply }) => {
                            let req_id = self.next_req;
                            self.next_req = self.next_req.wrapping_add(1);
                            self.pending.insert(req_id, reply);
                            let f = ClientFrame::Send(SendFrame { req_id, idempotency_key, recipients });
                            self.write(&mut ws, &f).await
                        }
                    };
                    if r.is_err() {
                        return Outcome::Error;
                    }
                }
                () = ack_timer => {
                    ack_deadline = None;
                    let up_to_seq = self.acked;
                    if self.write(&mut ws, &ClientFrame::Ack { up_to_seq }).await.is_err() {
                        return Outcome::Error;
                    }
                    self.sent_ack = up_to_seq;
                }
            }
        }
    }

    async fn on_frame(&mut self, b: &Bytes) -> Result<(), Outcome> {
        match ServerFrame::decode(b, &self.cfg.limits).map_err(|_| Outcome::Error)? {
            ServerFrame::Deliver { seq, envelope } => {
                // Already handed to the app (redelivered after a reconnect before the ACK
                // landed): drop, so the app sees each seq exactly once.
                if seq <= self.delivered {
                    return Ok(());
                }
                self.delivered = seq;
                self.events
                    .send(Event::Deliver { seq, envelope })
                    .await
                    .map_err(|_| Outcome::Shutdown)
            }
            ServerFrame::SendResult { req_id, status } => {
                if let Some(reply) = self.pending.remove(&req_id) {
                    let _ = reply.send(Ok(status));
                }
                Ok(())
            }
            ServerFrame::Ephemeral { payload } => {
                // Ephemeral events never block the connection: dropped if the app is behind.
                let _ = self.events.try_send(Event::Ephemeral { payload });
                Ok(())
            }
            ServerFrame::Error(_) => Ok(()),
            ServerFrame::Hello(_) | ServerFrame::AuthOk(_) => Err(Outcome::Error),
        }
    }
}

fn check_protocol(p: Option<&str>) -> Result<(), ()> {
    if p == Some(songbird_proto::SUBPROTOCOL) {
        Ok(())
    } else {
        Err(())
    }
}

fn closed(r: Option<sockudo_ws::error::CloseReason>) -> Outcome {
    r.map_or(Outcome::Error, |r| Outcome::Closed(r.code, r.reason))
}
