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
    clippy::many_single_char_names,
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
/// The system key's seed in these tests.
const SYSTEM_SEED: [u8; 32] = [0x51; 32];
/// The sender-certificate key's seed in these tests.
const CERT_SEED: [u8; 32] = [0x52; 32];

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
        // Generous: CI's shared SurrealDB also serves the prekey gate's 400 concurrent claims.
        timeout: Duration::from_secs(30),
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
        // The key directory, with the system key, so a device low on prekeys is told (M3).
        keys: Some(
            songbird_api::keys::KeyDirectory::new(
                songbird_api::config::KeySettings {
                    secret: songbird_types::SecretRef::Env("UNUSED".into()),
                    system_key: None,
                    max_stored: 20,
                    refill_below: 3,
                    throttle: songbird_api::config::KeyThrottle::default(),
                    devices: songbird_api::config::DeviceSettings::default(),
                },
                &random32(),
                Some(&SYSTEM_SEED),
                songbird_api::keys::KeyMetrics::default(),
            )
            .unwrap(),
        ),
        // Devices (M4), with the system key, so a link and a new list are announced.
        // Profiles and sealed sender (M5), the flag on.
        kt: None,
        profiles: Some(
            songbird_api::profiles::Profiles::new(
                songbird_api::config::ProfileSettings {
                    secret: songbird_types::SecretRef::Env("UNUSED".into()),
                    certificate_key: None,
                    sealed_sender: true,
                    certificate_hours: 24,
                    fetches_per_hour: 600,
                    fetch_burst: 120,
                    sealed_per_hour: 3_600,
                    sealed_per_account_hour: 3_600,
                    sealed_burst: 200,
                    ipv4_prefix: 24,
                    ipv6_prefix: 48,
                },
                &random32(),
                Some(&CERT_SEED),
                songbird_api::profiles::ProfileMetrics::default(),
            )
            .unwrap(),
        ),
        devices: Some(
            songbird_api::devices::Devices::new(
                songbird_api::config::DeviceSettings {
                    token_burst: 50,
                    ..songbird_api::config::DeviceSettings::default()
                },
                &songbird_api::config::KeyThrottle::default(),
                &random32(),
                Some(&SYSTEM_SEED),
                songbird_api::devices::DeviceMetrics::default(),
            )
            .unwrap(),
        ),
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

/// A device whose one-time prekeys run low is told once, with a notice signed by the system key
/// (Prompt 3, M3, D-0050), and not again within the hour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_low_on_prekeys_is_told_once() {
    use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_1024};
    use songbird_keys::xeddsa::Signer;
    use songbird_proto::keys::{self as wire, OneTimeEc, SignedEc, SignedKem, Upload};
    use songbird_proto::system::PrekeysLow;

    let Some(s) = default_stack().await else {
        return;
    };
    let ec = |seed: &[u8; 32]| {
        let mut k = [0u8; wire::EC_LEN];
        k[0] = wire::TYPE_X25519;
        k[1..].copy_from_slice(&Signer::new(seed).public());
        k
    };
    let identity = Signer::new(&random32());
    let kem = |id: u32| {
        let dk = DecapsulationKey::generate(&ML_KEM_1024).unwrap();
        let mut key = [0u8; wire::KEM_LEN];
        key[0] = wire::TYPE_ML_KEM_1024;
        key[1..].copy_from_slice(
            dk.encapsulation_key()
                .unwrap()
                .key_bytes()
                .unwrap()
                .as_ref(),
        );
        SignedKem {
            id,
            sig: identity.sign(&key, &[7; 64]),
            key: Box::new(key),
        }
    };
    let spk = ec(&random32());
    let mut ik = [0u8; wire::EC_LEN];
    ik[0] = wire::TYPE_X25519;
    ik[1..].copy_from_slice(&identity.public());
    let upload = Upload {
        identity: Some(ik),
        signed: Some(SignedEc {
            id: 1,
            key: spk,
            sig: identity.sign(&spk, &[3; 64]),
        }),
        last_resort: Some(kem(2)),
        one_time_ec: (10..14)
            .map(|id| OneTimeEc {
                id,
                key: ec(&random32()),
            })
            .collect(),
        one_time_kem: (10..14).map(kem).collect(),
    };
    let alice_api = s.alice.api(&s);
    assert_eq!(
        alice_api
            .send("PUT", "/v1/keys", Some(&upload.encode()))
            .await
            .unwrap()
            .0,
        204
    );
    let (_alice, mut alice_events) = connect(&s, &s.alice).await;
    let alice_account = s
        .app
        .registry
        .device(&s.alice.id)
        .await
        .unwrap()
        .unwrap()
        .account;
    let body = format!(r#"{{"account":"{}"}}"#, alice_account.to_hex_unredacted());
    let bob_api = s.bob1.api(&s);
    // 4 -> 3 (not below 3), then 3 -> 2: the notice.
    for _ in 0..2 {
        assert_eq!(
            bob_api
                .send("POST", "/v1/keys/fetch", Some(body.as_bytes()))
                .await
                .unwrap()
                .0,
            200
        );
    }
    let (_, envelope) = next_delivery(&mut alice_events).await;
    let notice = SystemFrame::decode(&envelope).unwrap();
    assert_eq!(notice.frame.kind, Kind::PrekeysLow);
    assert_eq!(notice.frame.device, s.alice.id);
    assert_eq!(
        PrekeysLow::decode(&notice.frame.body).unwrap(),
        PrekeysLow { ec: 2, kem: 2 }
    );
    let signer = SystemSigner::from_seed(&SYSTEM_SEED).unwrap();
    UnparsedPublicKey::new(&ED25519, signer.public_key())
        .verify(&notice.message(), &notice.signature)
        .unwrap();
    // Another fetch (2 -> 1) within the hour: no second notice.
    bob_api
        .send("POST", "/v1/keys/fetch", Some(body.as_bytes()))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), alice_events.recv())
            .await
            .is_err(),
        "a second notice within the hour"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_linked_device_is_announced_and_joins_the_send_check_only_once_listed() {
    use songbird_keys::xeddsa::Signer;
    use songbird_proto::devices::{
        self as wire, DeviceList, IDENTITY_LEN, LINK_AUTH_CONTEXT, LINK_IDENTITY_CONTEXT,
        LinkRequest, ListedDevice,
    };

    let Some(s) = default_stack().await else {
        return;
    };
    let reg = &s.app.registry;
    let reload = || async {
        s.shared
            .directory
            .store(Directory::from_registry(reg).await.unwrap());
    };
    let pk = |k: &Ed25519KeyPair| -> [u8; 32] {
        use aws_lc_rs::signature::KeyPair as _;
        k.public_key().as_ref().try_into().unwrap()
    };
    let ec = |sgn: &Signer| {
        let mut k = [0u8; IDENTITY_LEN];
        k[0] = 5;
        k[1..].copy_from_slice(&sgn.public());
        k
    };
    // Carol registers (an account identity key) and uploads her device identity key.
    let carol = Dev::new();
    let account_key = Ed25519KeyPair::generate().unwrap();
    let carol_identity = Signer::new(&random32());
    let account = AccountId::random().unwrap();
    reg.register(
        &songbird_accounts::NewAccount {
            account,
            identity: pk(&account_key),
            device: carol.id,
            auth_key: carol.key().public_key(),
            allowance: 0,
        },
        None,
    )
    .await
    .unwrap();
    reg.put_keys(
        &carol.id,
        &songbird_accounts::KeysUpdate {
            identity: Some(ec(&carol_identity)),
            signed: Some(vec![1]),
            last_resort: Some(vec![2]),
            ..songbird_accounts::KeysUpdate::default()
        },
        10,
    )
    .await
    .unwrap();
    reload().await;
    let (_carol_ws, mut carol_events) = connect(&s, &carol).await;
    let carol_api = carol.api(&s);

    // Carol's primary asks for a link token; the new device links (the QR channel itself is
    // `services/api` `devices_live`).
    let (st, b) = carol_api
        .send("POST", "/v1/devices/link-token", None)
        .await
        .unwrap();
    assert_eq!(st, 200);
    let t: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let token: [u8; 32] = hex::decode(t["token"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let new_id = DeviceId::parse_hex(t["device"].as_str().unwrap()).unwrap();
    let new = Dev {
        id: new_id,
        seed: DeviceKey::generate(new_id).unwrap().1,
    };
    let new_identity = Signer::new(&random32());
    let mut r = LinkRequest {
        token,
        device: new.id,
        auth_key: new.key().public_key(),
        identity_key: ec(&new_identity),
        auth_sig: [0; 64],
        identity_sig: [0; 64],
        confirm: [0; 32],
        factor: songbird_proto::devices::Factor::None,
    };
    let tr = |c, r: &LinkRequest| {
        wire::link_transcript(c, API, &r.token, &r.device, &r.auth_key, &r.identity_key).unwrap()
    };
    let auth = Ed25519KeyPair::from_seed_unchecked(&new.seed).unwrap();
    let sig = auth.sign(&tr(LINK_AUTH_CONTEXT, &r));
    r.auth_sig.copy_from_slice(sig.as_ref());
    r.identity_sig = new_identity.sign(&tr(LINK_IDENTITY_CONTEXT, &r), &[1; 64]);
    let (st, _) = songbird_api::client::unsigned(
        s.api_addr,
        API,
        "POST",
        "/v1/devices/link",
        Some(&r.encode()),
    )
    .await
    .unwrap();
    assert_eq!(st, 200);

    // Carol's primary is told, by a notice signed by the system key.
    let (_, envelope) = next_delivery(&mut carol_events).await;
    let notice = SystemFrame::decode(&envelope).unwrap();
    assert_eq!(notice.frame.kind, Kind::DeviceListChanged);
    assert_eq!(notice.frame.device, carol.id);
    assert_eq!(
        DeviceListChanged::decode(&notice.frame.body)
            .unwrap()
            .account,
        account
    );
    let signer = SystemSigner::from_seed(&SYSTEM_SEED).unwrap();
    UnparsedPublicKey::new(&ED25519, signer.public_key())
        .verify(&notice.message(), &notice.signature)
        .unwrap();

    // Delivery reloads its directory (the follower does this on the version bump). The new
    // device authenticates, but while pending no sender is asked to encrypt to it, and a send
    // to it is refused.
    reload().await;
    let (_new_ws, _new_events) = connect(&s, &new).await;
    let alice_api = s.alice.api(&s);
    assert_eq!(
        alice_api
            .put_message(&frame(key(), vec![to(carol.id, "hi")]))
            .await
            .unwrap(),
        (200, Some((42, SendStatus::Accepted)))
    );
    match alice_api
        .put_message(&frame(key(), vec![to(carol.id, "hi"), to(new.id, "hi")]))
        .await
        .unwrap()
    {
        (200, Some((_, SendStatus::DeviceMismatch(m)))) => {
            assert_eq!(m.extra, vec![new.id.as_bytes().to_vec()]);
            assert_eq!(m.missing, Vec::<Vec<u8>>::new());
        }
        other => panic!("expected a device mismatch, got {other:?}"),
    }

    // Carol signs a list naming both; from now on a send that leaves the new device out is
    // stale, and the sender is told which device is missing.
    let mut list = DeviceList {
        account,
        list_version: 1,
        issued_ms: 0,
        devices: vec![
            ListedDevice {
                device: carol.id,
                auth_key: carol.key().public_key(),
                identity_key: ec(&carol_identity),
                primary: true,
            },
            ListedDevice {
                device: new.id,
                auth_key: new.key().public_key(),
                identity_key: ec(&new_identity),
                primary: false,
            },
        ],
        signature: [0; 64],
    };
    let sig = account_key.sign(&list.signed_bytes());
    list.signature.copy_from_slice(sig.as_ref());
    assert_eq!(
        carol_api
            .send("PUT", "/v1/devices/list", Some(&list.encode()))
            .await
            .unwrap()
            .0,
        204
    );
    reload().await;
    match alice_api
        .put_message(&frame(key(), vec![to(carol.id, "hi")]))
        .await
        .unwrap()
    {
        (200, Some((_, SendStatus::DeviceMismatch(m)))) => {
            assert_eq!(m.missing, vec![new.id.as_bytes().to_vec()]);
        }
        other => panic!("expected a device mismatch, got {other:?}"),
    }
    assert_eq!(
        alice_api
            .put_message(&frame(key(), vec![to(carol.id, "hi"), to(new.id, "hi")]))
            .await
            .unwrap(),
        (200, Some((42, SendStatus::Accepted)))
    );
}

/// Prompt 3, M5 (D-0054): encrypted profiles with growing versions; sender certificates; sealed
/// sends authorized by the recipients' access keys, with no device signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profiles_certificates_and_sealed_sends() {
    use songbird_keys::sealed::{access_key, combine};
    use songbird_proto::profile::{ProfileUpload, SenderCertificate};

    let Some(s) = default_stack().await else {
        return;
    };
    let reg = &s.app.registry;
    let (alice_api, bob_api) = (s.alice.api(&s), s.bob1.api(&s));
    let bob_account = reg.device(&s.bob1.id).await.unwrap().unwrap().account;
    let alice_account = reg.device(&s.alice.id).await.unwrap().unwrap().account;
    // Bob publishes his encrypted profile with the access key derived from his profile key.
    let bob_key = access_key(&[0xB0; 32]);
    let put = |v: u64, open: bool, key: [u8; 16]| {
        ProfileUpload {
            profile_version: v,
            access_key: key,
            open,
            blob: vec![0xAA; 300],
        }
        .encode()
    };
    assert_eq!(
        bob_api
            .send("PUT", "/v1/profile", Some(&put(1, false, bob_key)))
            .await
            .unwrap()
            .0,
        204
    );
    let (st, b) = bob_api
        .send("PUT", "/v1/profile", Some(&put(1, false, bob_key)))
        .await
        .unwrap();
    assert_eq!(
        (st, b.as_ref()),
        (409, br#"{"error":"version"}"#.as_slice())
    );
    assert_eq!(
        bob_api
            .send("PUT", "/v1/profile", Some(&put(2, false, bob_key)))
            .await
            .unwrap()
            .0,
        204
    );
    let body = format!(r#"{{"account":"{}"}}"#, bob_account.to_hex_unredacted());
    let (st, b) = alice_api
        .send("POST", "/v1/profile/fetch", Some(body.as_bytes()))
        .await
        .unwrap();
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["version"], 2);
    assert_eq!(v["profile"].as_str().unwrap(), hex::encode([0xAA; 300]));
    // A sender certificate needs the device's identity key, then names the device, signed.
    assert_eq!(
        alice_api
            .send("GET", "/v1/certificate", None)
            .await
            .unwrap()
            .0,
        409
    );
    let mut ik = [7u8; 33];
    ik[0] = 5;
    reg.put_keys(
        &s.alice.id,
        &songbird_accounts::KeysUpdate {
            identity: Some(ik),
            signed: Some(vec![1]),
            last_resort: Some(vec![2]),
            ..songbird_accounts::KeysUpdate::default()
        },
        10,
    )
    .await
    .unwrap();
    let (st, b) = alice_api
        .send("GET", "/v1/certificate", None)
        .await
        .unwrap();
    assert_eq!(st, 200);
    let cert = SenderCertificate::decode(&b).unwrap();
    let cert_key = Ed25519KeyPair::from_seed_unchecked(&CERT_SEED).unwrap();
    let public: [u8; 32] = {
        use aws_lc_rs::signature::KeyPair as _;
        cert_key.public_key().as_ref().try_into().unwrap()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let now = u64::try_from(now).unwrap();
    assert!(songbird_api::profiles::certificate_valid(
        &cert, &public, now
    ));
    assert_eq!(
        (cert.account, cert.device, cert.identity_key),
        (alice_account, s.alice.id, ik)
    );
    assert!(cert.expires_ms <= now + 24 * 3_600_000);

    // Sealed sends: no device signature, only the access key.
    let sealed = |devices: Vec<DeviceId>, key: Option<[u8; 16]>| {
        let api = &alice_api;
        async move {
            let frame = frame(
                key_rand(),
                devices.iter().map(|d| to(*d, "sealed")).collect(),
            );
            let body = ClientFrame::Send(frame).to_bytes();
            let mut b = hyper::Request::builder()
                .method("PUT")
                .uri("/v1/messages/sealed")
                .header("host", API)
                .header("content-length", body.len());
            if let Some(k) = key {
                b = b.header("unidentified-access-key", hex::encode(k));
            }
            let (st, reply) = api.raw(b, body).await.unwrap();
            let status = match songbird_proto::ServerFrame::decode(&reply, &Limits::DEFAULT) {
                Ok(songbird_proto::ServerFrame::SendResult { status, .. }) => Some(status),
                _ => None,
            };
            (st, status)
        }
    };
    let bob_devices = vec![s.bob1.id, s.bob2.id];
    assert_eq!(
        sealed(bob_devices.clone(), Some(bob_key)).await,
        (200, Some(SendStatus::Accepted))
    );
    assert_eq!(
        sealed(bob_devices.clone(), Some(access_key(&[0xB1; 32])))
            .await
            .0,
        401
    );
    assert_eq!(sealed(bob_devices.clone(), None).await.0, 401);
    // Bob's device receives it from its mailbox like any message.
    let (_bob, mut bob_events) = connect(&s, &s.bob1).await;
    assert_eq!(
        next_delivery(&mut bob_events).await.1,
        Bytes::from("sealed")
    );
    // Alice has no profile and is not open: refused; once open, anyone may send sealed.
    assert_eq!(sealed(vec![s.alice.id], Some([0; 16])).await.0, 401);
    assert_eq!(
        alice_api
            .send(
                "PUT",
                "/v1/profile",
                Some(&put(1, true, access_key(&[0xA0; 32])))
            )
            .await
            .unwrap()
            .0,
        204
    );
    assert_eq!(
        sealed(vec![s.alice.id], None).await,
        (200, Some(SendStatus::Accepted))
    );
    // Several accounts: the XOR of the closed ones' keys.
    let both = vec![s.alice.id, s.bob1.id, s.bob2.id];
    assert_eq!(
        sealed(both.clone(), Some(combine([&bob_key]))).await,
        (200, Some(SendStatus::Accepted))
    );
    // The device-list check still applies (Bob's second device left out).
    assert!(matches!(
        sealed(vec![s.bob1.id], Some(bob_key)).await,
        (200, Some(SendStatus::DeviceMismatch(_)))
    ));

    // The flag off: no certificates, no sealed sends.
    let off = songbird_api::profiles::Profiles::new(
        songbird_api::config::ProfileSettings {
            secret: songbird_types::SecretRef::Env("UNUSED".into()),
            certificate_key: None,
            sealed_sender: false,
            certificate_hours: 24,
            fetches_per_hour: 600,
            fetch_burst: 120,
            sealed_per_hour: 3_600,
            sealed_per_account_hour: 3_600,
            sealed_burst: 200,
            ipv4_prefix: 24,
            ipv6_prefix: 48,
        },
        &random32(),
        Some(&CERT_SEED),
        songbird_api::profiles::ProfileMetrics::default(),
    )
    .unwrap();
    assert_eq!(
        off.certificate(reg, &alice_account, &s.alice.id).await,
        songbird_api::profiles::Outcome::NotFound
    );
    assert_eq!(
        off.sealed_send(
            reg,
            &s.app.hot,
            None,
            "127.0.0.1".parse().unwrap(),
            Some(bob_key),
            Bytes::new()
        )
        .await,
        songbird_api::profiles::Outcome::NotFound
    );
}

fn key_rand() -> [u8; 16] {
    let mut k = [0u8; 16];
    aws_lc_rs::rand::fill(&mut k).unwrap();
    k
}
