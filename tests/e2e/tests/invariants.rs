//! One named test per invariant (constitution §Invariants; master prompt §1), plus the security
//! and degraded-mode behaviour of the delivery service. Real client, real server, loopback TCP.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests"
)]

use std::collections::HashSet;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use futures_core::Stream as _;
use futures_sink::Sink as _;
use sockudo_ws::client::WebSocketClient;
use sockudo_ws::{Http1, Message, WebSocketStream};
use songbird_client::{ClientConfig, Event, ResumeState};
use songbird_e2e::{SERVER_NAME, key, next_delivery, next_event, start, start_with, to};
use songbird_mailbox::memory::MemoryMailbox;
use songbird_mailbox::{Mailbox, MailboxError, NewEnvelope, StoreOutcome, Stored};
use songbird_proto::frame::{RejectReason, SendStatus};
use songbird_proto::{ClientFrame, CloseCode, Limits, ServerFrame, control};
use songbird_types::DeviceId;
use tokio::net::TcpStream;

// ---------------------------------------------------------------- raw protocol helpers

type Raw = WebSocketStream<TcpStream>;

async fn raw_connect(addr: std::net::SocketAddr) -> Raw {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (ws, hs) = WebSocketClient::<Http1>::new(sockudo_ws::Config::default())
        .connect_raw(
            tcp,
            SERVER_NAME,
            songbird_proto::PATH,
            Some(songbird_proto::SUBPROTOCOL),
        )
        .await
        .unwrap();
    assert_eq!(hs.protocol.as_deref(), Some(songbird_proto::SUBPROTOCOL));
    ws
}

async fn raw_next(ws: &mut Raw) -> Option<Message> {
    tokio::time::timeout(
        Duration::from_secs(5),
        poll_fn(|cx| Pin::new(&mut *ws).poll_next(cx)),
    )
    .await
    .expect("raw read timeout")
    .and_then(Result::ok)
}

async fn raw_send(ws: &mut Raw, b: Bytes) {
    poll_fn(|cx| Pin::new(&mut *ws).poll_ready(cx))
        .await
        .unwrap();
    Pin::new(&mut *ws).start_send(Message::Binary(b)).unwrap();
    poll_fn(|cx| Pin::new(&mut *ws).poll_flush(cx))
        .await
        .unwrap();
}

async fn raw_hello(ws: &mut Raw) -> control::Hello {
    match raw_next(ws).await {
        Some(Message::Binary(b)) => match ServerFrame::decode(&b, &Limits::DEFAULT).unwrap() {
            ServerFrame::Hello(h) => h,
            other => panic!("expected Hello, got {other:?}"),
        },
        other => panic!("expected Hello, got {other:?}"),
    }
}

/// Reads until the server's close frame and returns its code.
async fn raw_close_code(ws: &mut Raw) -> u16 {
    loop {
        match raw_next(ws).await {
            Some(Message::Close(r)) => return r.map_or(1005, |r| r.code),
            Some(_) => {}
            None => return 1006,
        }
    }
}

fn auth_frame(
    key: &songbird_client::DeviceKey,
    server_name: &str,
    nonce: &[u8],
    last_acked_seq: u64,
) -> Bytes {
    let t = songbird_proto::auth::transcript(
        server_name,
        nonce,
        &key.device(),
        1,
        &songbird_proto::auth::NO_CHANNEL_BINDING,
    )
    .unwrap();
    ClientFrame::Auth(control::Auth {
        device_id: key.device().as_bytes().to_vec(),
        signature: key.sign(&t).to_vec(),
        last_acked_seq,
        client_version: "raw-test".into(),
        protocol_version: 1,
    })
    .to_bytes()
}

async fn raw_authenticated(s: &songbird_e2e::TestServer<impl Mailbox>, i: usize) -> Raw {
    let mut ws = raw_connect(s.addr).await;
    let hello = raw_hello(&mut ws).await;
    raw_send(&mut ws, auth_frame(&s.key(i), SERVER_NAME, &hello.nonce, 0)).await;
    match raw_next(&mut ws).await {
        Some(Message::Binary(b)) => assert!(matches!(
            ServerFrame::decode(&b, &Limits::DEFAULT).unwrap(),
            ServerFrame::AuthOk(_)
        )),
        other => panic!("expected AuthOk, got {other:?}"),
    }
    ws
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------- invariants

/// Invariant 1: an envelope is stored before the sender is told "accepted", and survives the
/// recipient being offline.
#[tokio::test]
async fn inv1_store_before_acknowledge() {
    let s = start(2, |_| {}).await;
    let (alice, _a) = s.connect(0).await;
    let bob = s.device(1);
    let r = alice.send(key(), vec![to(bob, "hello")]).await.unwrap();
    assert_eq!(r, SendStatus::Accepted);
    // Accepted implies stored: the mailbox holds it although Bob never connected.
    assert_eq!(s.shared.mailbox.pending(&bob), 1);
    assert_eq!(s.shared.metrics.routes_offline.get(), 1);
    let (_b, mut bev) = s.connect(1).await;
    let (seq, env) = next_delivery(&mut bev).await;
    assert_eq!((seq, env.as_ref()), (1, b"hello".as_ref()));
    s.stop().await;
}

/// Invariant 2: per device, strictly increasing seq, no gaps, no duplicates delivered to the
/// app — with concurrent senders, live and drained delivery mixed, and a dropped connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inv2_per_device_order_without_gaps_or_duplicates() {
    const SENDERS: usize = 4;
    const PER_SENDER: usize = 150;
    let s = Arc::new(start(SENDERS + 1, |c| c.session.live_inbox = 8).await);
    let rx = s.device(SENDERS);
    let (recv, mut ev) = s.connect(SENDERS).await;
    let mut tasks = Vec::new();
    for i in 0..SENDERS {
        let s = Arc::clone(&s);
        tasks.push(tokio::spawn(async move {
            let (c, _ev) = s.connect(i).await;
            for n in 0..PER_SENDER {
                let body = format!("{i}:{n}");
                let k = key();
                // Retry with the same idempotency key until accepted.
                loop {
                    match c.send(k, vec![to(rx, body.clone())]).await {
                        Ok(SendStatus::Accepted) => break,
                        Ok(SendStatus::Rejected { retry_after_ms, .. }) => {
                            tokio::time::sleep(Duration::from_millis(u64::from(retry_after_ms)))
                                .await;
                        }
                        _ => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                }
            }
        }));
    }
    let total = SENDERS * PER_SENDER;
    let mut seen = HashSet::new();
    let mut last = 0u64;
    let mut aborted = false;
    while seen.len() < total {
        match tokio::time::timeout(Duration::from_secs(10), ev.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Event::Deliver { seq, envelope } => {
                assert_eq!(seq, last + 1, "gap or reorder at the app");
                last = seq;
                assert!(seen.insert(envelope), "duplicate message at the app");
                // Acknowledge only part of what arrived, then drop the connection once: the
                // unacknowledged tail is redelivered by the server and must be deduplicated.
                if seq % 2 == 0 {
                    recv.ack(seq - 1).await.unwrap();
                }
                if seq == 100 && !aborted {
                    aborted = true;
                    recv.abort_connection().await.unwrap();
                }
            }
            Event::Connected { .. } | Event::Disconnected { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert!(aborted);
    assert_eq!(last, u64::try_from(total).unwrap());
    // Lag happened (inbox of 8), so drains were exercised too.
    assert!(s.shared.metrics.delivered_drained.get() > 0);
}

/// Invariant 3: delete on ACK; an ACK beyond what was sent is a protocol violation; expiry
/// removes old envelopes.
#[tokio::test]
async fn inv3_delete_on_ack_and_expiry() {
    let s = start(2, |_| {}).await;
    let (alice, _a) = s.connect(0).await;
    let bob = s.device(1);
    for i in 0..5 {
        alice
            .send(key(), vec![to(bob, format!("m{i}"))])
            .await
            .unwrap();
    }
    let (b, mut bev) = s.connect(1).await;
    for want in 1..=5 {
        assert_eq!(next_delivery(&mut bev).await.0, want);
    }
    b.ack(3).await.unwrap();
    wait_until("ack to delete", || s.shared.mailbox.pending(&bob) == 2).await;
    b.ack(5).await.unwrap();
    wait_until("ack to delete", || s.shared.mailbox.pending(&bob) == 0).await;
    assert_eq!(s.shared.metrics.acked.get(), 5);

    // ACK beyond what this connection sent: closed with 4003.
    let mut raw = raw_authenticated(&s, 1).await;
    raw_send(&mut raw, ClientFrame::Ack { up_to_seq: 99 }.to_bytes()).await;
    assert_eq!(
        raw_close_code(&mut raw).await,
        CloseCode::ProtocolError.code()
    );

    // Expiry (the server sweeps hourly with MAX_ENVELOPE_AGE = 30 days).
    alice.send(key(), vec![to(bob, "old")]).await.unwrap();
    assert_eq!(
        s.shared
            .mailbox
            .expire_older_than(Duration::ZERO)
            .await
            .unwrap(),
        1
    );
    assert_eq!(s.shared.mailbox.pending(&bob), 0);
    assert_eq!(
        songbird_mailbox::MAX_ENVELOPE_AGE,
        Duration::from_secs(30 * 24 * 3600)
    );
    s.stop().await;
}

/// Invariant 4: one live connection per device: a second connection replaces the first, which
/// is closed with 4001 and does not reconnect.
#[tokio::test]
async fn inv4_one_live_connection_per_device() {
    let s = start(2, |_| {}).await;
    let (_first, mut ev1) = s.connect(1).await;
    let (_second, mut ev2) = s.connect(1).await;
    loop {
        match next_event(&mut ev1).await {
            Event::Failed { code } => {
                assert_eq!(code, CloseCode::Replaced.code());
                break;
            }
            Event::Disconnected { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    let (alice, _a) = s.connect(0).await;
    alice.send(key(), vec![to(s.device(1), "x")]).await.unwrap();
    assert_eq!(next_delivery(&mut ev2).await.0, 1);
    assert_eq!(s.shared.router.attached(), 2);
    assert_eq!(s.shared.metrics.replaced.get(), 1);
    s.stop().await;
}

/// Invariant 5: a client that stops reading is disconnected as a slow consumer (4100) and
/// meanwhile nobody else is slowed; it catches up from the mailbox after reconnecting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inv5_slow_client_never_slows_anyone_else() {
    let s = start(3, |c| {
        c.session.write_timeout_ms = 300;
        c.session.sends_per_sec = 10_000;
        c.session.send_burst = 10_000;
        c.session.frames_per_sec = 10_000;
        c.session.frame_burst = 10_000;
    })
    .await;
    // Device 1 authenticates, then never reads again.
    let _stuck = raw_authenticated(&s, 1).await;
    let (alice, _a) = s.connect(0).await;
    let (_carol, mut cev) = s.connect(2).await;
    let big = Bytes::from(vec![7u8; 60 * 1024]);
    let mut worst = Duration::ZERO;
    for i in 0..400u32 {
        let t0 = Instant::now();
        alice
            .send(key(), vec![to(s.device(1), big.clone())])
            .await
            .unwrap();
        if i % 20 == 0 {
            // Carol's messages keep flowing promptly while device 1 is stuck.
            let t1 = Instant::now();
            alice
                .send(key(), vec![to(s.device(2), "ping")])
                .await
                .unwrap();
            next_delivery(&mut cev).await;
            worst = worst.max(t1.elapsed());
        }
        let _ = t0;
        if s.shared.metrics.slow_consumers.get() > 0 {
            break;
        }
    }
    wait_until("slow consumer close", || {
        s.shared.metrics.slow_consumers.get() == 1
    })
    .await;
    assert!(
        worst < Duration::from_millis(250),
        "carol was slowed: {worst:?}"
    );
    // Device 1 reconnects and gets everything that was stored for it, in order.
    let stored = u64::try_from(s.shared.mailbox.pending(&s.device(1))).unwrap();
    assert!(stored > 0);
    let (b, mut bev) = s.connect(1).await;
    for want in 1..=stored {
        assert_eq!(next_delivery(&mut bev).await.0, want);
        // Acknowledge as an app does; the un-acked window (D-0020) pauses delivery otherwise.
        b.ack(want).await.unwrap();
    }
    s.stop().await;
}

/// Invariant 6: no device IDs, content or addresses in logs, and only aggregate metrics.
#[test]
fn inv6_no_identifiers_in_logs_or_metrics() {
    use std::io::Write;
    #[derive(Clone, Default)]
    struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let writer = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (ids, metrics) = rt.block_on(async {
        let s = start(2, |_| {}).await;
        let (a, _ae) = s.connect(0).await;
        let (_b, mut be) = s.connect(1).await;
        a.send(key(), vec![to(s.device(1), "secret-content")])
            .await
            .unwrap();
        next_delivery(&mut be).await;
        let ids = [s.device(0), s.device(1)];
        let mut m = songbird_service::telemetry::Metrics::new("delivery", "test");
        s.shared.metrics.register(&mut m).unwrap();
        let text = m.encode().unwrap();
        s.stop().await;
        (ids, text)
    });
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    for id in ids {
        assert!(!logs.contains(&id.to_hex_unredacted()), "device id in logs");
        assert!(
            !metrics.contains(&id.to_hex_unredacted()),
            "device id in metrics"
        );
    }
    assert!(!logs.contains("secret-content"));
    assert!(!logs.contains("127.0.0.1"), "address in logs");
    assert_eq!(
        songbird_service::telemetry::metrics::audit_exposition(&metrics),
        Vec::<String>::new()
    );
    assert!(metrics.contains("songbird_delivery_envelopes_stored_total 1"));
}

/// Invariant 7: every input is bounded and validated before allocation proportional to it.
#[tokio::test]
async fn inv7_bounded_and_validated_input() {
    let s = start(2, |c| c.session.auth_timeout_ms = 300).await;

    // A frame over the largest legal message: the WebSocket layer refuses it from its header,
    // before buffering the payload, and fails the connection (RFC 6455 §7.1.7: TCP closed
    // without a close frame, seen as 1006).
    let mut ws = raw_authenticated(&s, 0).await;
    let huge = Bytes::from(vec![0x02u8; Limits::DEFAULT.max_message_bytes() + 1]);
    raw_send(&mut ws, huge).await;
    assert_eq!(raw_close_code(&mut ws).await, 1006);
    wait_until("protocol error counted", || {
        s.shared.metrics.protocol_errors.get() == 1
    })
    .await;

    // A send claiming more recipients than allowed: protocol violation.
    let mut ws = raw_authenticated(&s, 0).await;
    let mut b = BytesMut::new();
    b.put_u8(songbird_proto::frame::ty::SEND);
    b.put_u32(1);
    b.put_slice(&[0; 16]);
    b.put_u16(u16::MAX);
    raw_send(&mut ws, b.freeze()).await;
    assert_eq!(
        raw_close_code(&mut ws).await,
        CloseCode::ProtocolError.code()
    );

    // Garbage and text frames: protocol violation.
    let mut ws = raw_authenticated(&s, 0).await;
    raw_send(&mut ws, Bytes::from_static(&[0x7f, 1, 2, 3])).await;
    assert_eq!(
        raw_close_code(&mut ws).await,
        CloseCode::ProtocolError.code()
    );

    // No Auth within the timeout: 4102.
    let mut ws = raw_connect(s.addr).await;
    raw_hello(&mut ws).await;
    assert_eq!(raw_close_code(&mut ws).await, CloseCode::AuthTimeout.code());

    // Oversized, wrong-path and wrong-subprotocol upgrades get HTTP errors, not sockets.
    for (req, want) in [
        (
            format!("GET /v1/ws HTTP/1.1\r\nHost: x\r\nX-Pad: {}\r\n\r\n", "a".repeat(9000)),
            "431",
        ),
        (
            "GET /other HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: songbird.v1\r\n\r\n".to_owned(),
            "404",
        ),
        (
            "GET /v1/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_owned(),
            "400",
        ),
    ] {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut tcp = TcpStream::connect(s.addr).await.unwrap();
        let _ = tcp.write_all(req.as_bytes()).await;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut out)).await;
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with(&format!("HTTP/1.1 {want}")), "{want}: {text}");
    }
    s.stop().await;
}

/// A mailbox whose store can be switched off, for the degraded-mode test.
struct Flaky {
    inner: MemoryMailbox,
    down: AtomicBool,
}

impl Mailbox for Flaky {
    fn store_batch(
        &self,
        k: Option<[u8; 16]>,
        items: &[NewEnvelope],
    ) -> impl Future<Output = Result<StoreOutcome, MailboxError>> + Send {
        // The in-memory store works eagerly, so only call it while up.
        let r = if self.down.load(Ordering::SeqCst) {
            Err(MailboxError::Unavailable)
        } else {
            self.inner.store_now_for_tests(k, items)
        };
        std::future::ready(r)
    }
    fn fetch_after(
        &self,
        d: &DeviceId,
        after: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Stored>, MailboxError>> + Send {
        self.inner.fetch_after(d, after, limit)
    }
    fn ack_up_to(
        &self,
        d: &DeviceId,
        up: u64,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        self.inner.ack_up_to(d, up)
    }
    fn expire_older_than(
        &self,
        age: Duration,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        self.inner.expire_older_than(age)
    }
    fn store_generation(&self) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        self.inner.store_generation()
    }
}

/// Invariant 8 (degraded modes are explicit): with the store unavailable, sends are rejected
/// with a retryable error and sockets stay open; a retry with the same key succeeds once it
/// recovers, and the idempotency key stores it once.
#[tokio::test]
async fn inv8_store_unavailable_rejects_retryably_and_keeps_sockets() {
    let flaky = Flaky {
        inner: MemoryMailbox::new(100, 1),
        down: AtomicBool::new(true),
    };
    let s = start_with(flaky, 2, |_| {}).await;
    let (alice, _a) = s.connect(0).await;
    let (_b, mut bev) = s.connect(1).await;
    let k = key();
    let r = alice.send(k, vec![to(s.device(1), "x")]).await.unwrap();
    assert_eq!(
        r,
        SendStatus::Rejected {
            reason: RejectReason::Unavailable,
            retry_after_ms: 1000
        }
    );
    assert!(RejectReason::Unavailable.is_retryable());
    assert_eq!(alice.state(), songbird_client::State::Connected);
    s.shared.mailbox.down.store(false, Ordering::SeqCst);
    assert_eq!(
        alice.send(k, vec![to(s.device(1), "x")]).await.unwrap(),
        SendStatus::Accepted
    );
    assert_eq!(
        alice.send(k, vec![to(s.device(1), "x")]).await.unwrap(),
        SendStatus::Accepted
    );
    assert_eq!(next_delivery(&mut bev).await.0, 1);
    assert_eq!(
        s.shared.mailbox.inner.pending(&s.device(1)),
        1,
        "stored once"
    );
    assert_eq!(s.shared.metrics.sends_replayed.get(), 1);
    s.stop().await;
}

/// Invariant 9: authorization is checked on the server for every request.
#[tokio::test]
async fn inv9_server_side_authorization() {
    let s = start(2, |_| {}).await;
    let stranger = songbird_client::DeviceKey::generate(DeviceId::random().unwrap())
        .unwrap()
        .0;

    // Unknown device, signature over another server name, and a replayed signature all fail
    // with the same code (no device-existence oracle).
    let mut ws = raw_connect(s.addr).await;
    let h = raw_hello(&mut ws).await;
    raw_send(&mut ws, auth_frame(&stranger, SERVER_NAME, &h.nonce, 0)).await;
    assert_eq!(raw_close_code(&mut ws).await, CloseCode::AuthFailed.code());

    let mut ws = raw_connect(s.addr).await;
    let h = raw_hello(&mut ws).await;
    raw_send(&mut ws, auth_frame(&s.key(0), "other.example", &h.nonce, 0)).await;
    assert_eq!(raw_close_code(&mut ws).await, CloseCode::AuthFailed.code());

    let mut ws = raw_connect(s.addr).await;
    let old = raw_hello(&mut ws).await;
    drop(ws);
    let mut ws = raw_connect(s.addr).await;
    let _fresh = raw_hello(&mut ws).await;
    raw_send(&mut ws, auth_frame(&s.key(0), SERVER_NAME, &old.nonce, 0)).await;
    assert_eq!(raw_close_code(&mut ws).await, CloseCode::AuthFailed.code());

    // A client given a wrong key stops (4000 range: never reconnect).
    let wrong = songbird_client::DeviceKey::from_seed(s.device(0), &[9; 32]).unwrap();
    let (_c, mut ev) =
        songbird_client::Client::start(s.client_config(), wrong, ResumeState::default());
    loop {
        match next_event(&mut ev).await {
            Event::Failed { code } => {
                assert_eq!(code, CloseCode::AuthFailed.code());
                break;
            }
            Event::Disconnected { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    // Sends to unknown or duplicate recipients are refused and store nothing.
    let (alice, _a) = s.connect(0).await;
    let r = alice
        .send(key(), vec![to(stranger.device(), "x")])
        .await
        .unwrap();
    assert!(matches!(
        r,
        SendStatus::Rejected {
            reason: RejectReason::UnknownRecipient,
            ..
        }
    ));
    let r = alice
        .send(key(), vec![to(s.device(1), "x"), to(s.device(1), "y")])
        .await
        .unwrap();
    assert!(matches!(
        r,
        SendStatus::Rejected {
            reason: RejectReason::DuplicateRecipient,
            ..
        }
    ));
    assert_eq!(s.shared.mailbox.total_pending(), 0);
    assert!(s.shared.metrics.auth_failures.get() >= 4);
    s.stop().await;
}

// ---------------------------------------------------------------- lifecycle

/// Graceful drain: on shutdown every session closes with 4200 within the window and clients
/// treat it as "reconnect now".
#[tokio::test]
async fn graceful_drain_closes_with_4200() {
    let s = start(1, |c| c.session.drain_window_ms = 200).await;
    let (_c, mut ev) = s.connect(0).await;
    let t0 = Instant::now();
    s.stop().await;
    match next_event(&mut ev).await {
        Event::Disconnected { code, retry_in } => {
            assert_eq!(code, Some(CloseCode::Draining.code()));
            assert!(retry_in <= Duration::from_millis(500));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(t0.elapsed() < Duration::from_secs(3));
}

/// Overload: beyond the accept rate, connections are closed with 4101 and a retry hint.
#[tokio::test]
async fn accept_rate_limit_closes_with_retry_hint() {
    let s = start(1, |c| {
        c.session.accepts_per_sec = 1;
        c.session.accept_burst = 1;
    })
    .await;
    let mut first = raw_connect(s.addr).await;
    raw_hello(&mut first).await;
    let mut second = raw_connect(s.addr).await;
    loop {
        match raw_next(&mut second).await {
            Some(Message::Close(Some(r))) => {
                assert_eq!(r.code, CloseCode::Overloaded.code());
                assert!(songbird_proto::close::parse_retry(&r.reason).unwrap() >= 1000);
                break;
            }
            Some(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(s.shared.metrics.connections_refused.get(), 1);
    s.stop().await;
}

/// Ephemeral events reach a connected device and are never stored.
#[tokio::test]
async fn ephemeral_events_are_relayed_and_never_stored() {
    let s = start(2, |_| {}).await;
    let (a, _ae) = s.connect(0).await;
    let (_b, mut be) = s.connect(1).await;
    a.ephemeral(s.device(1), Bytes::from_static(b"typing"))
        .await
        .unwrap();
    match next_event(&mut be).await {
        Event::Ephemeral { payload } => assert_eq!(payload.as_ref(), b"typing"),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(s.shared.mailbox.total_pending(), 0);
    s.stop().await;
}

/// TLS 1.3 end to end with a certificate from a test CA.
#[tokio::test]
async fn tls_connection_works() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = rcgen::CertificateParams::new(vec![SERVER_NAME.to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let chain = dir.path().join("chain.pem");
    let keyf = dir.path().join("key.pem");
    std::fs::write(&chain, leaf.pem()).unwrap();
    std::fs::write(&keyf, leaf_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keyf, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let s = start(2, |c| {
        c.tls = Some(songbird_delivery::config::TlsSettings {
            cert_chain: chain.clone(),
            key: songbird_types::SecretRef::File(keyf.clone()),
        });
    })
    .await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut cfg: ClientConfig = s.client_config();
    cfg.tls = Some(Arc::new(tls));
    let (a, _ae) = s.connect_with(0, cfg.clone(), ResumeState::default()).await;
    let (_b, mut be) = s.connect_with(1, cfg, ResumeState::default()).await;
    a.send(key(), vec![to(s.device(1), "over tls")])
        .await
        .unwrap();
    assert_eq!(next_delivery(&mut be).await.1.as_ref(), b"over tls");

    // Channel binding (D-0018): a valid signature that does not cover *this* TLS session's
    // exporter, as a relaying man in the middle would obtain from the device over its own TLS
    // session, is refused with 4000.
    let tls = cfg_tls_for_raw(&s, &ca);
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from(SERVER_NAME).unwrap();
    let stream = tokio_rustls::TlsConnector::from(tls)
        .connect(name, tcp)
        .await
        .unwrap();
    let (mut ws, _) = WebSocketClient::<Http1>::new(sockudo_ws::Config::default())
        .connect_raw(
            stream,
            SERVER_NAME,
            songbird_proto::PATH,
            Some(songbird_proto::SUBPROTOCOL),
        )
        .await
        .unwrap();
    let hello = loop {
        match poll_fn(|cx| Pin::new(&mut ws).poll_next(cx)).await {
            Some(Ok(Message::Binary(b))) => {
                if let ServerFrame::Hello(h) = ServerFrame::decode(&b, &Limits::DEFAULT).unwrap() {
                    break h;
                }
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    };
    let unbound = auth_frame(&s.key(0), SERVER_NAME, &hello.nonce, 0);
    poll_fn(|cx| Pin::new(&mut ws).poll_ready(cx))
        .await
        .unwrap();
    Pin::new(&mut ws)
        .start_send(Message::Binary(unbound))
        .unwrap();
    poll_fn(|cx| Pin::new(&mut ws).poll_flush(cx))
        .await
        .unwrap();
    let code = loop {
        match tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| Pin::new(&mut ws).poll_next(cx)),
        )
        .await
        .unwrap()
        {
            Some(Ok(Message::Close(r))) => break r.map_or(1005, |r| r.code),
            Some(Ok(_)) => {}
            _ => break 1006,
        }
    };
    assert_eq!(code, CloseCode::AuthFailed.code());
    s.stop().await;
}

fn cfg_tls_for_raw<M: Mailbox>(
    _s: &songbird_e2e::TestServer<M>,
    ca: &rcgen::Certificate,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

/// After a restore (store generation grew), the client resumes from `seq` 0 instead of its old
/// resume point, so reused `seq`s are not dropped, and it tells the app to resend.
#[tokio::test]
async fn store_generation_change_resets_resume_point() {
    let s = start_with(MemoryMailbox::new(100, 2), 2, |_| {}).await;
    let (alice, _a) = s.connect(0).await;
    alice
        .send(key(), vec![to(s.device(1), "after restore")])
        .await
        .unwrap();
    // Device 1 had acknowledged up to 50 before the restore, under generation 1.
    let resume = ResumeState {
        acked_seq: 50,
        store_generation: 1,
    };
    let (_b, mut ev) = songbird_client::Client::start(s.client_config(), s.key(1), resume);
    let mut changed = false;
    loop {
        match next_event(&mut ev).await {
            Event::StoreGenerationChanged { previous, current } => {
                assert_eq!((previous, current), (1, 2));
                changed = true;
            }
            Event::Connected {
                resume_after_seq, ..
            } => assert_eq!(resume_after_seq, 0),
            Event::Deliver { seq, envelope } => {
                assert_eq!((seq, envelope.as_ref()), (1, b"after restore".as_ref()));
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(changed);
    s.stop().await;
}

/// D-0020: at most `max_unacked` envelopes are in flight per connection; delivery pauses at the
/// limit and resumes, in order, when the device acknowledges.
#[tokio::test]
async fn unacked_window_bounds_in_flight() {
    let s = start(2, |c| {
        c.session.max_unacked = 8;
        c.session.sends_per_sec = 1_000;
        c.session.send_burst = 1_000;
    })
    .await;
    let (alice, _a) = s.connect(0).await;
    let (bob, mut bev) = s.connect(1).await;
    for i in 0..20 {
        alice
            .send(key(), vec![to(s.device(1), format!("m{i}"))])
            .await
            .unwrap();
    }
    for want in 1..=8 {
        assert_eq!(next_delivery(&mut bev).await.0, want);
    }
    // Nothing more while nothing is acknowledged.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), bev.recv())
            .await
            .is_err()
    );
    assert!(s.shared.metrics.window_full.get() >= 1);
    bob.ack(8).await.unwrap();
    for want in 9..=16 {
        assert_eq!(next_delivery(&mut bev).await.0, want);
    }
    bob.ack(16).await.unwrap();
    for want in 17..=20 {
        assert_eq!(next_delivery(&mut bev).await.0, want);
    }
    s.stop().await;
}
