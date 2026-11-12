//! Milestone 5 gate (D-0036), against the real stores. Runs when the whole compose stack is
//! configured (`SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`), `SONGBIRD_TEST_VALKEY`,
//! `SONGBIRD_TEST_VALKEY_JOBS`, `SONGBIRD_TEST_RUSTFS` (+ `_ACCESS_KEY`, `_SECRET_KEY`), and Iggy
//! for the mailbox when `SONGBIRD_TEST_IGGY` is set); with `SONGBIRD_REQUIRE_STACK=1` a missing
//! one fails instead of skipping.
//!
//! - `account_deletion_is_verified_across_every_store`: an account with messages waiting, a live
//!   session, a push registration, a pending upload and a finished attachment is deleted through
//!   `api`; the `worker` job runs; then every store is inspected directly.
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

use aws_lc_rs::signature::Ed25519KeyPair;
use bytes::Bytes;
use songbird_accounts::{Db, Registry, push_index};
use songbird_api::client::ApiClient;
use songbird_api::{ApiMetrics, App};
use songbird_client::{DeviceKey, Event, ResumeState};
use songbird_delivery::{DeliveryMetrics, Directory, Shared, server};
use songbird_e2e::{SERVER_NAME, key, next_delivery, settings, test_mailbox, to};
use songbird_jobs::{ObjectKey, Outcome, Queue, QueueConfig, Stream, Work};
use songbird_mailbox::Mailbox as _;
use songbird_proto::frame::SendStatus;
use songbird_router::LocalRouter;
use songbird_types::{AccountId, DeviceId, Secret};
use songbird_worker::{DeliveryLink, Worker, WorkerMetrics};

const API: &str = "api.test";
const PUSH_INDEX: [u8; 32] = [0x21; 32];
const JOBS_SECRET: [u8; 32] = [0x22; 32];

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

struct Env {
    surreal: String,
    hot: String,
    jobs: String,
    s3: String,
}

fn stack_env() -> Option<Env> {
    Some(Env {
        surreal: env("SONGBIRD_TEST_SURREALDB")?,
        hot: env("SONGBIRD_TEST_VALKEY")?,
        jobs: env("SONGBIRD_TEST_VALKEY_JOBS")?,
        s3: env("SONGBIRD_TEST_RUSTFS")?,
    })
}

async fn registry(e: &Env) -> Arc<Registry> {
    let db = Db::connect(songbird_surreal::Config {
        addr: e.surreal.clone(),
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("gate_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    Arc::new(Registry::connect(db).await.unwrap())
}

fn s3(e: &Env) -> songbird_s3::Client {
    songbird_s3::Client::new(songbird_s3::Config::new(
        e.s3.clone(),
        "songbird-gate".into(),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_ACCESS_KEY").unwrap()),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_SECRET_KEY").unwrap()),
    ))
    .unwrap()
}

async fn queue(e: &Env, name: &str) -> Arc<Queue> {
    let q = Queue::connect(
        redis::Client::open(e.jobs.as_str()).unwrap(),
        &JOBS_SECRET,
        QueueConfig::new(name.into()),
    )
    .await
    .unwrap();
    q.ensure_groups(&Stream::ALL).await.unwrap();
    Arc::new(q)
}

/// A device with its key: registered in the registry under `account`.
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
    fn api(&self, addr: std::net::SocketAddr) -> ApiClient {
        ApiClient::new(
            addr,
            API,
            self.id,
            Ed25519KeyPair::from_seed_unchecked(&self.seed).unwrap(),
        )
    }
}

/// Every key and value in a Valkey instance, rendered (streams, sorted sets, strings).
async fn valkey_dump(url: &str) -> Vec<u8> {
    let client = redis::Client::open(url).unwrap();
    let mut c = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<Vec<u8>> = redis::cmd("KEYS")
        .arg("*")
        .query_async(&mut c)
        .await
        .unwrap();
    let mut out = Vec::new();
    for k in keys {
        out.extend_from_slice(&k);
        let t: String = redis::cmd("TYPE")
            .arg(&k)
            .query_async(&mut c)
            .await
            .unwrap();
        let mut cmd = match t.as_str() {
            "stream" => redis::cmd("XRANGE"),
            "zset" => redis::cmd("ZRANGE"),
            "string" => redis::cmd("GET"),
            _ => continue,
        };
        cmd.arg(&k);
        match t.as_str() {
            "stream" => {
                cmd.arg("-").arg("+");
            }
            "zset" => {
                cmd.arg(0).arg(-1);
            }
            _ => {}
        }
        let v: redis::Value = cmd.query_async(&mut c).await.unwrap();
        out.extend_from_slice(format!("{v:?}").as_bytes());
    }
    out
}

fn contains_id(hay: &[u8], id: &[u8; 16]) -> bool {
    let hex = hex::encode(id);
    hay.windows(16).any(|w| w == id) || hay.windows(32).any(|w| w == hex.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_deletion_is_verified_across_every_store() {
    let Some(e) = stack_env() else { return };
    let registry = registry(&e).await;
    let s3 = s3(&e);
    s3.create_bucket().await.unwrap();

    // Alice: two devices; Bob: one.
    let (alice, bob) = (AccountId::random().unwrap(), AccountId::random().unwrap());
    let (a1, a2, b1) = (Dev::new(), Dev::new(), Dev::new());
    registry
        .create_account(
            &alice,
            &[
                (a1.id, a1.key().public_key()),
                (a2.id, a2.key().public_key()),
            ],
        )
        .await
        .unwrap();
    registry
        .create_account(&bob, &[(b1.id, b1.key().public_key())])
        .await
        .unwrap();

    // Delivery, its directory followed from the registry.
    let rows = registry.load_directory().await.unwrap();
    let mut cfg = settings();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(Shared::new(
        cfg,
        Directory::from_accounts(rows.into_iter().map(|(d, a, k)| (d, k, a))),
        test_mailbox().await,
        LocalRouter::new(),
        DeliveryMetrics::default(),
    ));
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(server::serve(
        listener,
        None,
        Arc::clone(&shared),
        stop_rx.clone(),
    ));
    tokio::spawn(songbird_delivery::directory::follow_registry(
        Arc::clone(&registry),
        Arc::clone(&shared.directory),
        registry.directory_version().await.unwrap(),
        Duration::from_millis(100),
        stop_rx.clone(),
    ));

    // api.
    let (_, push_public) = songbird_accounts::push_token::key_pair(&[0x23; 32]).unwrap();
    let app = Arc::new(App {
        server_name: API.into(),
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue: queue(&e, "gate-api").await,
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(e.hot.as_str()).unwrap())
            .await
            .unwrap(),
        push_public,
        push_index_secret: PUSH_INDEX,
        limits: songbird_api::config::AttachmentLimits::default(),
        metrics: ApiMetrics::default(),
    });
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    tokio::spawn(songbird_api::server::serve(
        api_listener,
        None,
        Arc::clone(&app),
        64,
        stop_rx.clone(),
    ));

    let client_cfg = || {
        let mut c = songbird_client::ClientConfig::new(addr.to_string(), SERVER_NAME);
        c.backoff.initial = Duration::from_millis(20);
        c.backoff.max = Duration::from_millis(200);
        c
    };
    // Bob writes to Alice's two devices while both are offline; then a1 connects and reads
    // one; a2 never connects (its message stays pending).
    let (mut bob_c, _bev) =
        songbird_client::Client::start(client_cfg(), b1.key(), ResumeState::default());
    bob_c.wait_for(songbird_client::State::Connected).await;
    for _ in 0..3 {
        let r = bob_c
            .send(
                key(),
                vec![to(a1.id, "MARK-for-a1"), to(a2.id, "MARK-for-a2")],
            )
            .await
            .unwrap();
        assert_eq!(r, SendStatus::Accepted);
    }
    let (mut a1_c, mut a1_ev) =
        songbird_client::Client::start(client_cfg(), a1.key(), ResumeState::default());
    a1_c.wait_for(songbird_client::State::Connected).await;
    assert_eq!(&next_delivery(&mut a1_ev).await.1[..], b"MARK-for-a1");
    assert!(shared.mailbox.knows(&a2.id).await.unwrap());

    // Alice registers push, starts an upload she never finishes, and sends an attachment.
    let api = a1.api(api_addr);
    assert_eq!(
        api.send("PUT", "/v1/push", Some(br#"{"fcm":{"token":"alice-fcm"}}"#))
            .await
            .unwrap()
            .0,
        204
    );
    let grant = |r: (u16, Bytes)| {
        assert_eq!(r.0, 201);
        let v: serde_json::Value = serde_json::from_slice(&r.1).unwrap();
        ObjectKey::parse_hex(v["id"].as_str().unwrap()).unwrap()
    };
    let pending = grant(
        api.send(
            "POST",
            "/v1/attachments",
            Some(br#"{"size":64,"fetches":1}"#),
        )
        .await
        .unwrap(),
    );
    // A partial object of the pending upload (as a crashed upload could leave behind).
    s3.put_object_bytes(
        &songbird_api::object_name(&pending),
        Bytes::from_static(&[1; 32]),
    )
    .await
    .unwrap();
    let sent = grant(
        api.send(
            "POST",
            "/v1/attachments",
            Some(br#"{"size":16,"fetches":1}"#),
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        api.upload(
            &format!("/v1/attachments/{}", sent.to_hex_unredacted()),
            Bytes::from_static(&[2; 16])
        )
        .await
        .unwrap()
        .0,
        201
    );
    // Bob registers push too: his data must survive.
    assert_eq!(
        b1.api(api_addr)
            .send("PUT", "/v1/push", Some(br#"{"fcm":{"token":"bob-fcm"}}"#))
            .await
            .unwrap()
            .0,
        204
    );

    // Alice deletes her account.
    assert_eq!(
        api.send("DELETE", "/v1/account", None).await.unwrap().0,
        202
    );

    // The worker runs the deletion job (delivery reached in process; the node link with
    // mutual TLS is covered by crates/link's tests).
    let worker = Worker {
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue: queue(&e, "gate-worker").await,
        delivery: DeliveryLink::Direct(songbird_delivery::internal::handler(Arc::clone(&shared))),
        push_index_secret: PUSH_INDEX,
        propagation: Duration::from_millis(400),
        metrics: WorkerMetrics::default(),
    };
    let mut done = false;
    for _ in 0..100 {
        for d in worker.queue.read(Stream::Deletion, 16).await.unwrap() {
            let mine = d.job.work == (Work::DeleteAccount { account: alice });
            let outcome = if mine {
                worker.handle(d.job.clone()).await
            } else {
                Outcome::Done
            };
            worker.queue.finish(&d, outcome).await.unwrap();
            if mine {
                assert_eq!(outcome, Outcome::Done, "deletion verified");
                done = true;
            }
        }
        if done {
            break;
        }
    }
    assert!(done, "deletion job ran");
    assert_eq!(worker.metrics.deletions_verified.get(), 1);

    // ---- Every store, inspected directly ----
    // SurrealDB: no account, device, push or grant row of Alice.
    let index: Vec<[u8; 32]> = [a1.id, a2.id]
        .iter()
        .map(|d| push_index(&PUSH_INDEX, d))
        .collect();
    let r = registry
        .remnants(&alice, &[a1.id, a2.id], &index)
        .await
        .unwrap();
    assert!(r.is_empty(), "{r:?}");
    assert!(registry.device(&a1.id).await.unwrap().is_none());
    assert!(registry.grant(&pending).await.unwrap().is_none());
    // Mailbox (Iggy in CI): nothing pending, no counters, for either device.
    for d in [a1.id, a2.id] {
        assert!(!shared.mailbox.knows(&d).await.unwrap());
        assert_eq!(shared.mailbox.count_pending(&d).await.unwrap(), 0);
    }
    // RustFS: the pending upload's object is gone.
    assert!(
        s3.head_object(&songbird_api::object_name(&pending))
            .await
            .unwrap()
            .is_none()
    );
    // Valkey (jobs and hot): no device or account ID in any key or value, raw or hex.
    for url in [&e.jobs, &e.hot] {
        let dump = valkey_dump(url).await;
        for id in [a1.id.as_bytes(), a2.id.as_bytes(), alice.as_bytes()] {
            assert!(!contains_id(&dump, id), "an identifier in Valkey");
        }
    }
    // Delivery: the live session was closed and the device can no longer authenticate.
    let mut closed = false;
    for _ in 0..100 {
        if let Ok(Some(Event::Disconnected { .. }) | None) =
            tokio::time::timeout(Duration::from_millis(50), a1_ev.recv()).await
        {
            closed = true;
            break;
        }
    }
    assert!(closed, "session closed");
    assert!(!shared.directory.load().contains(&a1.id));
    // Sends to Alice's devices are refused as unknown now.
    let r = bob_c.send(key(), vec![to(a1.id, "late")]).await.unwrap();
    assert!(matches!(r, SendStatus::DeviceMismatch(_)), "{r:?}");
    // Bob is untouched.
    assert!(registry.device(&b1.id).await.unwrap().is_some());
    assert!(
        registry
            .push_token(&push_index(&PUSH_INDEX, &b1.id))
            .await
            .unwrap()
            .is_some()
    );
    // The finished attachment is not linked to Alice by design: it stays for its recipient
    // until fetched or 30 days (threat model row), and opens for any device that has its ID.
    assert!(registry.attachment(&sent).await.unwrap().is_some());

    let _ = stop.send(true);
}
