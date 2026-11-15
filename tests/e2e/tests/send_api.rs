//! `PUT /v1/messages` and system frames (D-0037, D-0044): `api` and `delivery` in one process,
//! sharing one mailbox and router through the `songbird-send` library, against the real registry
//! (SurrealDB: device keys) and `valkey-hot` (nonces, the send rate). The mailbox is Iggy when
//! `SONGBIRD_TEST_IGGY` is set (the compose CI job), else in memory. Runs when
//! `SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`) and `SONGBIRD_TEST_VALKEY` are set; with
//! `SONGBIRD_REQUIRE_STACK=1` a missing one fails instead of skipping.
//!
//! The store over node links from a send-only `api` (the deployed path) is
//! `a_send_only_node_stores_on_the_owners_and_may_do_nothing_else` in `crates/mailbox`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use bytes::Bytes;
use songbird_accounts::{Db, Registry};
use songbird_api::client::ApiClient;
use songbird_api::messages::{Messages, SendStack};
use songbird_api::{ApiMetrics, App};
use songbird_client::{Client, ClientConfig, DeviceKey, ResumeState, State};
use songbird_delivery::{DeliveryMetrics, Directory, Shared, server};
use songbird_e2e::{SERVER_NAME, key, next_delivery, settings, test_mailbox, to};
use songbird_mailbox::{AnyMailbox, Mailbox as _};
use songbird_proto::frame::{Recipient, RejectReason, SendFrame, SendStatus};
use songbird_proto::system::{self, DeviceListChanged, Kind, SystemFrame};
use songbird_proto::{ClientFrame, Limits};
use songbird_router::LocalRouter;
use songbird_send::system::SystemSigner;
use songbird_types::{AccountId, DeviceId, Secret};
use tokio::sync::{mpsc, watch};

const API: &str = "api.test";

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

/// A device: its ID and key seed.
struct Dev {
    id: DeviceId,
    seed: [u8; 32],
}

impl Dev {
    fn new() -> Self {
        let id = DeviceId::random().unwrap();
        let (_, seed) = DeviceKey::generate(id).unwrap();
        Self { id, seed }
    }
    fn key(&self) -> DeviceKey {
        DeviceKey::from_seed(self.id, &self.seed).unwrap()
    }
    fn api(&self, s: &Stack) -> ApiClient {
        ApiClient::new(
            s.api_addr,
            API,
            self.id,
            Ed25519KeyPair::from_seed_unchecked(&self.seed).unwrap(),
        )
    }
}

/// Alice (one device) and Bob (two devices), `delivery` and `api` sharing mailbox and router.
struct Stack {
    alice: Dev,
    bob1: Dev,
    bob2: Dev,
    shared: Arc<Shared<Arc<AnyMailbox>, Arc<LocalRouter>>>,
    app: Arc<App>,
    ws_addr: std::net::SocketAddr,
    api_addr: std::net::SocketAddr,
    /// Push wake-ups from `api`'s send path (the batcher to the job queue is M5's, tested there).
    pushes: mpsc::Receiver<DeviceId>,
    _stop: watch::Sender<bool>,
}

fn random32() -> [u8; 32] {
    let mut k = [0u8; 32];
    aws_lc_rs::rand::fill(&mut k).unwrap();
    k
}

async fn stack(limits: Limits, sends_per_sec: u32, send_burst: u32) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("send_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    let (alice, bob1, bob2) = (Dev::new(), Dev::new(), Dev::new());
    registry
        .create_account(
            &AccountId::random().unwrap(),
            &[(alice.id, alice.key().public_key())],
        )
        .await
        .unwrap();
    registry
        .create_account(
            &AccountId::random().unwrap(),
            &[
                (bob1.id, bob1.key().public_key()),
                (bob2.id, bob2.key().public_key()),
            ],
        )
        .await
        .unwrap();
    let rows = registry.load_directory().await.unwrap();

    // delivery.
    let mailbox = Arc::new(test_mailbox().await);
    let router = Arc::new(LocalRouter::new());
    let mut cfg = settings();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let ws_addr = listener.local_addr().unwrap();
    let shared = Arc::new(Shared::new(
        cfg,
        Directory::from_accounts(rows.into_iter().map(|(d, a, k)| (d, k, a))),
        Arc::clone(&mailbox),
        Arc::clone(&router),
        DeliveryMetrics::default(),
    ));
    let (stop, stop_rx) = watch::channel(false);
    tokio::spawn(server::serve(
        listener,
        None,
        Arc::clone(&shared),
        stop_rx.clone(),
    ));

    // api, on the same directory, mailbox and router.
    let metrics = ApiMetrics::default();
    let (push, pushes) = songbird_send::Pusher::new(metrics.push.clone());
    let hot_client = redis::Client::open(hot.as_str()).unwrap();
    let messages = Messages {
        path: Box::new(SendStack {
            directory: Arc::clone(&shared.directory),
            mailbox: Arc::clone(&mailbox),
            router: Arc::clone(&router),
            push,
            metrics: metrics.send.clone(),
        }),
        limits,
        sends_per_sec,
        send_burst,
        rate_key: songbird_api::messages::rate_key(&random32()).unwrap(),
        metrics: metrics.send.clone(),
    };
    let app = Arc::new(App {
        server_name: API.into(),
        registry,
        // Unused by these tests (attachments and deletion are M5's).
        s3: songbird_s3::Client::new(songbird_s3::Config::new(
            "127.0.0.1:9".into(),
            "unused".into(),
            Secret::new("unused".into()),
            Secret::new("unused-secret".into()),
        ))
        .unwrap(),
        queue: Arc::new(
            songbird_jobs::Queue::connect(
                hot_client.clone(),
                &[3; 32],
                songbird_jobs::QueueConfig::new("send-api-test".into()),
            )
            .await
            .unwrap(),
        ),
        hot: songbird_valkey::ValkeyConn::connect(hot_client)
            .await
            .unwrap(),
        push_public: [0; 32],
        push_index_secret: [9; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        metrics,
        messages: Some(messages),
        registration: None,
        usernames: None,
    });
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    tokio::spawn(songbird_api::server::serve(
        api_listener,
        None,
        Arc::clone(&app),
        64,
        stop_rx,
    ));
    Some(Stack {
        alice,
        bob1,
        bob2,
        shared,
        app,
        ws_addr,
        api_addr,
        pushes,
        _stop: stop,
    })
}

async fn default_stack() -> Option<Stack> {
    stack(Limits::DEFAULT, 50, 200).await
}

fn frame(k: [u8; 16], recipients: Vec<Recipient>) -> SendFrame {
    SendFrame::per_device(42, k, recipients)
}

/// A WebSocket client for `d` on the stack's delivery server.
async fn connect(s: &Stack, d: &Dev) -> (Client, mpsc::Receiver<songbird_client::Event>) {
    let mut c = ClientConfig::new(s.ws_addr.to_string(), SERVER_NAME);
    c.backoff.initial = Duration::from_millis(20);
    let (mut client, events) = Client::start(c, d.key(), ResumeState::default());
    client.wait_for(State::Connected).await;
    (client, events)
}

/// Raw HTTP on a new connection; the status line's code.
async fn raw_status(s: &Stack, request: &[u8]) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut tcp = tokio::net::TcpStream::connect(s.api_addr).await.unwrap();
    tcp.write_all(request).await.unwrap();
    let mut out = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut out))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&out[..n])
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_messages_is_signed_and_authenticated_before_the_body_is_read() {
    let Some(s) = default_stack().await else {
        return;
    };
    let send = frame(key(), vec![to(s.bob1.id, "hi"), to(s.bob2.id, "hi")]);
    let body = ClientFrame::Send(send.clone()).to_bytes();
    let alice = s.alice.api(&s);
    // Signed by a known device: accepted, the answer is the WebSocket's `SendResult`.
    assert_eq!(
        alice.put_message(&send).await.unwrap(),
        (200, Some((42, SendStatus::Accepted)))
    );
    let fresh = || frame(key(), vec![to(s.bob1.id, "x"), to(s.bob2.id, "x")]);
    let failures = s.app.metrics.auth_failures.get();

    // No signature.
    let req = hyper::Request::builder()
        .method("PUT")
        .uri("/v1/messages")
        .header("host", API);
    assert_eq!(alice.raw(req, body.clone()).await.unwrap().0, 401);
    // The body swapped after signing (same length): the digest no longer matches.
    let signed = ClientFrame::Send(fresh()).to_bytes();
    let (authz, hash) = alice.sign("PUT", "/v1/messages", Some(&signed));
    let mut swapped = ClientFrame::Send(fresh()).to_bytes().to_vec();
    swapped[5] ^= 1; // inside the idempotency key: still a valid frame
    let req = hyper::Request::builder()
        .method("PUT")
        .uri("/v1/messages")
        .header("host", API)
        .header(songbird_api::auth::AUTHORIZATION, &authz)
        .header(songbird_api::auth::CONTENT_SHA256, hash.clone().unwrap());
    assert_eq!(alice.raw(req, Bytes::from(swapped)).await.unwrap().0, 401);
    // Replayed: the same signed request twice; the second is refused (single-use nonce).
    let (authz, hash) = alice.sign("PUT", "/v1/messages", Some(&signed));
    let replay = || {
        hyper::Request::builder()
            .method("PUT")
            .uri("/v1/messages")
            .header("host", API)
            .header(songbird_api::auth::AUTHORIZATION, &authz)
            .header(songbird_api::auth::CONTENT_SHA256, hash.clone().unwrap())
    };
    assert_eq!(alice.raw(replay(), signed.clone()).await.unwrap().0, 200);
    assert_eq!(alice.raw(replay(), signed.clone()).await.unwrap().0, 401);
    // Signed for another path.
    let (authz, hash) = alice.sign("PUT", "/v1/push", Some(&signed));
    let req = hyper::Request::builder()
        .method("PUT")
        .uri("/v1/messages")
        .header("host", API)
        .header(songbird_api::auth::AUTHORIZATION, authz)
        .header(songbird_api::auth::CONTENT_SHA256, hash.unwrap());
    assert_eq!(alice.raw(req, signed.clone()).await.unwrap().0, 401);
    // A device the registry does not know.
    let stranger = Dev::new().api(&s);
    assert_eq!(stranger.put_message(&fresh()).await.unwrap().0, 401);
    assert!(s.app.metrics.auth_failures.get() >= failures + 4);
    // No length (chunked) and an over-limit length: refused before anything is read or checked.
    let chunked = format!(
        "PUT /v1/messages HTTP/1.1\r\nhost: {API}\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n"
    );
    assert_eq!(raw_status(&s, chunked.as_bytes()).await, "411");
    let huge = format!(
        "PUT /v1/messages HTTP/1.1\r\nhost: {API}\r\ncontent-length: {}\r\n\r\n",
        Limits::DEFAULT.max_send_bytes + 1
    );
    assert_eq!(raw_status(&s, huge.as_bytes()).await, "413");
    // Only the two accepted sends were stored (Bob's devices each hold two).
    assert_eq!(s.shared.mailbox.count_pending(&s.bob1.id).await.unwrap(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_messages_holds_the_send_frame_to_the_websocket_limits_and_rate() {
    let limits = Limits {
        max_envelope_bytes: 1024,
        max_recipients: 4,
        ..Limits::DEFAULT
    };
    let Some(s) = stack(limits, 1, 3).await else {
        return;
    };
    let alice = s.alice.api(&s);
    let ok = || frame(key(), vec![to(s.bob1.id, "x"), to(s.bob2.id, "x")]);
    // Not a `Send` frame: 400.
    let ack = ClientFrame::Ack { up_to_seq: 1 }.to_bytes();
    assert_eq!(
        alice
            .send("PUT", "/v1/messages", Some(&ack))
            .await
            .unwrap()
            .0,
        400
    );
    // An envelope over the limit, and more recipients than allowed: the decoder refuses, 400.
    let big = frame(
        key(),
        vec![to(s.bob1.id, vec![0u8; 1025]), to(s.bob2.id, "x")],
    );
    assert_eq!(alice.put_message(&big).await.unwrap().0, 400);
    let many = frame(
        key(),
        (0..5)
            .map(|_| to(DeviceId::random().unwrap(), "x"))
            .collect(),
    );
    assert_eq!(alice.put_message(&many).await.unwrap().0, 400);
    // The send path's own refusals come back as `SendResult`s, as over the WebSocket. (The
    // three below each take a token of the burst.)
    let mismatch = alice
        .put_message(&frame(key(), vec![to(s.bob1.id, "x")]))
        .await
        .unwrap();
    assert!(matches!(
        mismatch,
        (200, Some((42, SendStatus::DeviceMismatch(ref m)))) if m.missing.len() == 1
    ));
    let mut forged = system::MAGIC.to_vec();
    forged.extend_from_slice(&[0; 90]);
    let reserved = alice
        .put_message(&frame(
            key(),
            vec![to(s.bob1.id, forged.clone()), to(s.bob2.id, forged)],
        ))
        .await
        .unwrap();
    assert_eq!(
        reserved,
        (
            200,
            Some((
                42,
                SendStatus::Rejected {
                    reason: RejectReason::ReservedEnvelope,
                    retry_after_ms: 0
                }
            ))
        )
    );
    assert_eq!(
        alice.put_message(&ok()).await.unwrap().1.unwrap().1,
        SendStatus::Accepted
    );
    // The burst (3) is spent: rate limited with a hint (one token a second), nothing stored.
    match alice.put_message(&ok()).await.unwrap() {
        (
            200,
            Some((
                42,
                SendStatus::Rejected {
                    reason: RejectReason::RateLimited,
                    retry_after_ms,
                },
            )),
        ) => assert!((1..=1000).contains(&retry_after_ms), "{retry_after_ms}"),
        other => panic!("not rate limited: {other:?}"),
    }
    assert_eq!(s.shared.mailbox.count_pending(&s.bob1.id).await.unwrap(), 1);
    // Another device has its own bucket.
    let bob = s.bob1.api(&s);
    assert_eq!(
        bob.put_message(&frame(key(), vec![to(s.alice.id, "x"), to(s.bob2.id, "x")]))
            .await
            .unwrap()
            .1
            .unwrap()
            .1,
        SendStatus::Accepted
    );
    // A second later the device may send again.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        alice.put_message(&ok()).await.unwrap().1.unwrap().1,
        SendStatus::Accepted
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_retried_over_the_websocket_after_http_is_stored_once() {
    let Some(s) = default_stack().await else {
        return;
    };
    let alice_api = s.alice.api(&s);
    let (alice_ws, _alice_events) = connect(&s, &s.alice).await;
    // HTTP first, then the same send (same idempotency key) over the WebSocket: a replay.
    let k1 = key();
    let recipients = || vec![to(s.bob1.id, "one"), to(s.bob2.id, "one")];
    assert_eq!(
        alice_api
            .put_message(&frame(k1, recipients()))
            .await
            .unwrap(),
        (200, Some((42, SendStatus::Accepted)))
    );
    assert_eq!(
        alice_ws.send(k1, recipients()).await.unwrap(),
        SendStatus::Accepted
    );
    assert_eq!(s.shared.metrics.sends_replayed.get(), 1);
    // The WebSocket first, then HTTP: a replay too.
    let k2 = key();
    let recipients2 = || vec![to(s.bob1.id, "two"), to(s.bob2.id, "two")];
    assert_eq!(
        alice_ws.send(k2, recipients2()).await.unwrap(),
        SendStatus::Accepted
    );
    assert_eq!(
        alice_api
            .put_message(&frame(k2, recipients2()))
            .await
            .unwrap(),
        (200, Some((42, SendStatus::Accepted)))
    );
    assert_eq!(s.app.metrics.send.sends_replayed.get(), 1);
    assert_eq!(s.app.metrics.send.sends_accepted.get(), 1);
    // Bob's device receives each message once, in order.
    let (_bob, mut bob_events) = connect(&s, &s.bob1).await;
    assert_eq!(
        next_delivery(&mut bob_events).await,
        (1, Bytes::from("one"))
    );
    assert_eq!(
        next_delivery(&mut bob_events).await,
        (2, Bytes::from("two"))
    );
    assert_eq!(s.shared.mailbox.count_pending(&s.bob2.id).await.unwrap(), 2);
    // The same key for other recipients: refused, over HTTP as over the WebSocket.
    let conflict = alice_api
        .put_message(&frame(
            k1,
            vec![to(s.bob1.id, "x"), to(s.bob2.id, "x"), to(s.alice.id, "x")],
        ))
        .await
        .unwrap();
    assert!(matches!(
        conflict,
        (
            200,
            Some((
                42,
                SendStatus::Rejected {
                    reason: RejectReason::IdempotencyConflict,
                    ..
                }
            ))
        )
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offline_recipient_of_an_http_send_gets_a_push_wake_up() {
    let Some(mut s) = default_stack().await else {
        return;
    };
    let bob = s.bob1.api(&s);
    // Alice has no session: stored, then a wake-up for her device (none for Bob's own other
    // device, which is online).
    let (_bob2, mut bob2_events) = connect(&s, &s.bob2).await;
    assert_eq!(
        bob.put_message(&frame(
            key(),
            vec![to(s.alice.id, "wake"), to(s.bob2.id, "sync")]
        ))
        .await
        .unwrap()
        .1
        .unwrap()
        .1,
        SendStatus::Accepted
    );
    let woken = tokio::time::timeout(Duration::from_secs(5), s.pushes.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(woken, s.alice.id);
    assert_eq!(s.app.metrics.send.routes_offline.get(), 1);
    // Bob's online device got it live, routed from `api` through the same router.
    assert_eq!(next_delivery(&mut bob2_events).await.1, Bytes::from("sync"));
    assert!(s.pushes.try_recv().is_err());
    // Alice connects and finds it waiting (stored before the 200).
    let (_alice, mut alice_events) = connect(&s, &s.alice).await;
    assert_eq!(
        next_delivery(&mut alice_events).await,
        (1, Bytes::from("wake"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_system_notice_reaches_the_device_signed_and_a_forged_one_never_does() {
    let Some(s) = default_stack().await else {
        return;
    };
    let signer = SystemSigner::from_seed(&[0x51; 32]).unwrap();
    let (bob, mut bob_events) = connect(&s, &s.bob1).await;
    // The server tells Bob's device that Alice's device list changed: signed, stored, delivered.
    let body = DeviceListChanged {
        account: AccountId::from_bytes([0xA1; 16]),
    }
    .encode();
    s.shared
        .send_path()
        .send_system(
            &signer,
            &[s.bob1.id],
            Kind::DeviceListChanged,
            &body,
            [7; 16],
        )
        .await
        .unwrap();
    let (seq, envelope) = next_delivery(&mut bob_events).await;
    assert_eq!(seq, 1);
    let notice = SystemFrame::decode(&envelope).unwrap();
    assert_eq!(notice.frame.device, s.bob1.id);
    assert_eq!(
        DeviceListChanged::decode(&notice.frame.body)
            .unwrap()
            .account,
        AccountId::from_bytes([0xA1; 16])
    );
    UnparsedPublicKey::new(&ED25519, signer.public_key())
        .verify(&notice.message(), &notice.signature)
        .unwrap();
    // A user cannot send one, over either transport.
    let mut forged = system::MAGIC.to_vec();
    forged.extend_from_slice(&[0; 120]);
    let st = bob
        .send(key(), vec![to(s.alice.id, forged.clone())])
        .await
        .unwrap();
    assert!(matches!(
        st,
        SendStatus::Rejected {
            reason: RejectReason::ReservedEnvelope,
            ..
        }
    ));
    let via_http = s
        .bob1
        .api(&s)
        .put_message(&frame(key(), vec![to(s.alice.id, forged)]))
        .await
        .unwrap();
    assert!(matches!(
        via_http,
        (
            200,
            Some((
                _,
                SendStatus::Rejected {
                    reason: RejectReason::ReservedEnvelope,
                    ..
                }
            ))
        )
    ));
    assert_eq!(
        s.shared.mailbox.count_pending(&s.alice.id).await.unwrap(),
        0
    );
}
