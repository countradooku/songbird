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
    s3_bucket(e, "songbird-gate")
}

const JOURNAL_KEY: [u8; 32] = [0x6a; 32];

fn s3_bucket(e: &Env, bucket: &str) -> songbird_s3::Client {
    songbird_s3::Client::new(songbird_s3::Config::new(
        e.s3.clone(),
        bucket.into(),
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
        Arc::clone(&shared.generation),
        registry.directory_version().await.unwrap(),
        Duration::from_millis(100),
        stop_rx.clone(),
    ));

    // api.
    let (_, push_public) = songbird_accounts::push_token::key_pair(&[0x23; 32]).unwrap();
    let app = Arc::new(App {
        requests: None,
        reports: None,
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
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        kt: None,
        profiles: None,
        devices: None,
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
    // The deletion journal (D-0041) in a write-once bucket standing in for the backup bucket.
    let journal_s3 = s3_bucket(&e, "songbird-gate-journal");
    journal_s3.create_bucket_locked().await.unwrap();
    let worker = Worker {
        block_keys: None,
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue: queue(&e, "gate-worker").await,
        delivery: DeliveryLink::Direct(songbird_delivery::internal::handler(Arc::clone(&shared))),
        push_index_secret: PUSH_INDEX,
        journal: Some(songbird_worker::Journal {
            s3: journal_s3.clone(),
            key: JOURNAL_KEY,
        }),
        propagation: Duration::from_millis(400),
        kt: None,
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

    // The deletion journal holds Alice's tombstone (so a restore deletes her again), named by a
    // keyed tag: neither her account ID nor her devices', raw or hex.
    let tag = songbird_accounts::journal::tag(&JOURNAL_KEY, &alice);
    let listed = journal_s3
        .list_objects_v2(songbird_accounts::journal::PREFIX, None, 1000)
        .await
        .unwrap();
    assert!(
        listed
            .objects
            .iter()
            .any(|o| songbird_accounts::journal::parse_tombstone(&o.key) == Some(tag)),
        "a tombstone for the deleted account"
    );
    for o in &listed.objects {
        for id in [a1.id.as_bytes(), a2.id.as_bytes(), alice.as_bytes()] {
            assert!(
                !contains_id(o.key.as_bytes(), id),
                "an identifier in a tombstone"
            );
        }
    }

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

/// Prompt 3, M4 (D-0052): a removed device is deleted from every store as an account is, and
/// nothing of its account's other device goes with it. Alice's second device has messages
/// waiting, a live session, a push registration and an unfinished upload; it removes itself
/// through `api`; the worker's `DeleteDevices` job runs; then every store is inspected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_removal_is_verified_across_every_store_and_spares_the_rest() {
    let Some(e) = stack_env() else { return };
    let registry = registry(&e).await;
    let s3 = s3(&e);
    s3.create_bucket().await.unwrap();
    let (alice, bob) = (AccountId::random().unwrap(), AccountId::random().unwrap());
    let (a1, a2, b1) = (Dev::new(), Dev::new(), Dev::new());
    // a1 is the primary (the first device), a2 a linked device.
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
    // Alice lets anyone write to her (Prompt 4: otherwise Bob needs her access key or a
    // request; this test is about deletion).
    registry
        .put_profile(&alice, 1, b"profile", &[0xA1; 16], true)
        .await
        .unwrap();
    let mut cfg = settings();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(Shared::new(
        cfg,
        Directory::from_registry(&registry).await.unwrap(),
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
        Arc::clone(&shared.generation),
        registry.directory_version().await.unwrap(),
        Duration::from_millis(100),
        stop_rx.clone(),
    ));
    let (_, push_public) = songbird_accounts::push_token::key_pair(&[0x23; 32]).unwrap();
    let app = Arc::new(App {
        requests: None,
        reports: None,
        server_name: API.into(),
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue: queue(&e, "gate-devices-api").await,
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(e.hot.as_str()).unwrap())
            .await
            .unwrap(),
        push_public,
        push_index_secret: PUSH_INDEX,
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        kt: None,
        profiles: None,
        devices: Some(
            songbird_api::devices::Devices::new(
                songbird_api::config::DeviceSettings::default(),
                &songbird_api::config::KeyThrottle::default(),
                &[0x24; 32],
                None,
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
        stop_rx.clone(),
    ));
    let client_cfg = || {
        let mut c = songbird_client::ClientConfig::new(addr.to_string(), SERVER_NAME);
        c.backoff.initial = Duration::from_millis(20);
        c.backoff.max = Duration::from_millis(200);
        c
    };
    // Bob writes to both of Alice's devices; a2 is connected and reads one; both register push;
    // a2 starts an upload it never finishes.
    let (mut bob_c, _bev) =
        songbird_client::Client::start(client_cfg(), b1.key(), ResumeState::default());
    bob_c.wait_for(songbird_client::State::Connected).await;
    let (mut a2_c, mut a2_ev) =
        songbird_client::Client::start(client_cfg(), a2.key(), ResumeState::default());
    a2_c.wait_for(songbird_client::State::Connected).await;
    for _ in 0..3 {
        let r = bob_c
            .send(key(), vec![to(a1.id, "MARK-a1"), to(a2.id, "MARK-a2")])
            .await
            .unwrap();
        assert_eq!(r, SendStatus::Accepted);
    }
    assert_eq!(&next_delivery(&mut a2_ev).await.1[..], b"MARK-a2");
    for d in [&a1, &a2] {
        assert_eq!(
            d.api(api_addr)
                .send("PUT", "/v1/push", Some(br#"{"fcm":{"token":"t"}}"#))
                .await
                .unwrap()
                .0,
            204
        );
    }
    let api2 = a2.api(api_addr);
    let (st, b) = api2
        .send(
            "POST",
            "/v1/attachments",
            Some(br#"{"size":64,"fetches":1}"#),
        )
        .await
        .unwrap();
    assert_eq!(st, 201);
    let pending = ObjectKey::parse_hex(
        serde_json::from_slice::<serde_json::Value>(&b).unwrap()["id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    s3.put_object_bytes(
        &songbird_api::object_name(&pending),
        Bytes::from_static(&[1; 32]),
    )
    .await
    .unwrap();

    // a2 removes itself; the primary cannot.
    assert_eq!(
        a1.api(api_addr)
            .send("DELETE", "/v1/devices/self", None)
            .await
            .unwrap()
            .0,
        409
    );
    assert_eq!(
        api2.send("DELETE", "/v1/devices/self", None)
            .await
            .unwrap()
            .0,
        204
    );

    // The worker runs the job.
    let worker = Worker {
        block_keys: None,
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue: queue(&e, "gate-devices-worker").await,
        delivery: DeliveryLink::Direct(songbird_delivery::internal::handler(Arc::clone(&shared))),
        push_index_secret: PUSH_INDEX,
        journal: None,
        propagation: Duration::from_millis(400),
        kt: None,
        metrics: WorkerMetrics::default(),
    };
    let mut done = false;
    for _ in 0..100 {
        for d in app.queue.read(Stream::Deletion, 16).await.unwrap() {
            let mine = d.job.work == (Work::DeleteDevices { account: alice });
            let outcome = if mine {
                worker.handle(d.job.clone()).await
            } else {
                Outcome::Done
            };
            app.queue.finish(&d, outcome).await.unwrap();
            if mine {
                assert_eq!(outcome, Outcome::Done, "device deletion verified");
                done = true;
            }
        }
        if done {
            break;
        }
    }
    assert!(done, "device deletion job ran");
    assert_eq!(worker.metrics.devices_deleted.get(), 1);

    // a2 is gone from every store.
    assert!(registry.device(&a2.id).await.unwrap().is_none());
    assert_eq!(registry.device_remnants(&[a2.id]).await.unwrap(), 0);
    assert!(
        registry
            .push_token(&push_index(&PUSH_INDEX, &a2.id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(registry.grant(&pending).await.unwrap().is_none());
    assert!(
        s3.head_object(&songbird_api::object_name(&pending))
            .await
            .unwrap()
            .is_none()
    );
    assert!(!shared.mailbox.knows(&a2.id).await.unwrap());
    assert_eq!(shared.mailbox.count_pending(&a2.id).await.unwrap(), 0);
    let mut closed = false;
    for _ in 0..100 {
        if let Ok(Some(Event::Disconnected { .. }) | None) =
            tokio::time::timeout(Duration::from_millis(50), a2_ev.recv()).await
        {
            closed = true;
            break;
        }
    }
    assert!(closed, "session closed");
    assert!(!shared.directory.load().contains(&a2.id));
    // a1 and its account are untouched: row, push registration, waiting messages.
    let row = registry.device(&a1.id).await.unwrap().unwrap();
    assert!(!row.disabled);
    assert_eq!(row.account, alice);
    assert!(
        registry
            .push_token(&push_index(&PUSH_INDEX, &a1.id))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(shared.mailbox.count_pending(&a1.id).await.unwrap(), 3);
    // Sends now name a1 alone; a2 is refused as unknown.
    let r = bob_c
        .send(key(), vec![to(a1.id, "x"), to(a2.id, "x")])
        .await
        .unwrap();
    assert!(matches!(r, SendStatus::DeviceMismatch(_)), "{r:?}");
    assert_eq!(
        bob_c.send(key(), vec![to(a1.id, "x")]).await.unwrap(),
        SendStatus::Accepted
    );
    let _ = stop.send(true);
}

/// Gate: an offline device receives a push end to end. Bob writes to Alice's phone while it is
/// offline: delivery stores the messages, finds no session, queues a sealed push job (one per
/// burst); the push service opens Alice's sealed registration and wakes the phone through
/// (mock) APNs with the constant, identifier-free alert. The phone connects and reads every
/// message from its mailbox. While it is online, no push is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offline_device_receives_a_push_end_to_end() {
    use songbird_push_providers::apns::{Apns, ApnsConfig};
    use songbird_push_providers::test_support::{MockServer, TestCa, p256_pkcs8};

    let Some(e) = stack_env() else { return };
    let registry = registry(&e).await;
    let s3 = s3(&e);
    s3.create_bucket().await.unwrap();
    let (alice, bob) = (AccountId::random().unwrap(), AccountId::random().unwrap());
    let (a1, b1) = (Dev::new(), Dev::new());
    registry
        .create_account(&alice, &[(a1.id, a1.key().public_key())])
        .await
        .unwrap();
    registry
        .create_account(&bob, &[(b1.id, b1.key().public_key())])
        .await
        .unwrap();

    // Delivery with push jobs.
    let rows = registry.load_directory().await.unwrap();
    let mut cfg = settings();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = DeliveryMetrics::default();
    let (pusher, rx) = songbird_delivery::Pusher::new(metrics.push());
    let shared = Arc::new(
        Shared::new(
            cfg,
            Directory::from_accounts(rows.into_iter().map(|(d, a, k)| (d, k, a))),
            test_mailbox().await,
            LocalRouter::new(),
            metrics.clone(),
        )
        .with_push(pusher),
    );
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(server::serve(
        listener,
        None,
        Arc::clone(&shared),
        stop_rx.clone(),
    ));
    tokio::spawn(songbird_delivery::push::run(
        queue(&e, "gate-delivery").await,
        rx,
        Duration::from_secs(5),
        metrics.push(),
        stop_rx.clone(),
    ));

    // api: Alice registers her APNs token (sealed to the push service's key).
    let push_key = [0x24; 32];
    let (_, push_public) = songbird_accounts::push_token::key_pair(&push_key).unwrap();
    let app = Arc::new(App {
        requests: None,
        reports: None,
        server_name: API.into(),
        registry: Arc::clone(&registry),
        s3,
        queue: queue(&e, "gate-api").await,
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(e.hot.as_str()).unwrap())
            .await
            .unwrap(),
        push_public,
        push_index_secret: PUSH_INDEX,
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        kt: None,
        profiles: None,
        devices: None,
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
    let token = [0xa7u8; 32];
    let body = format!(r#"{{"apns":{{"token":"{}"}}}}"#, hex::encode(token));
    assert_eq!(
        a1.api(api_addr)
            .send("PUT", "/v1/push", Some(body.as_bytes()))
            .await
            .unwrap()
            .0,
        204
    );

    // The push service, against mock APNs.
    let ca = TestCa::new();
    let apns_mock = MockServer::apns(&ca).await;
    let mut apns_cfg = ApnsConfig::new("TEAM123456", "KEYID12345", "eu.songbird.app");
    apns_cfg.base_url = apns_mock.url();
    apns_cfg.http = ca.http_config();
    let handler = songbird_push::Handler::new(
        Arc::clone(&registry),
        &PUSH_INDEX,
        &push_key,
        songbird_push::Providers {
            apns: Some(Apns::with_pkcs8_der(apns_cfg, &p256_pkcs8()).unwrap()),
            ..songbird_push::Providers::default()
        },
        Duration::from_secs(1),
        songbird_push::PushMetrics::default(),
    )
    .unwrap();
    let running = songbird_push::spawn(
        queue(&e, "gate-push").await,
        Arc::new(handler),
        songbird_jobs::ConsumeConfig {
            housekeeping: Duration::from_millis(50),
            ..songbird_jobs::ConsumeConfig::default()
        },
    );

    // Bob writes three messages to Alice's offline phone.
    let client_cfg = || {
        let mut c = songbird_client::ClientConfig::new(addr.to_string(), SERVER_NAME);
        c.backoff.initial = Duration::from_millis(20);
        c.backoff.max = Duration::from_millis(200);
        c
    };
    let (mut bob_c, _bev) =
        songbird_client::Client::start(client_cfg(), b1.key(), ResumeState::default());
    bob_c.wait_for(songbird_client::State::Connected).await;
    for i in 0..3 {
        let r = bob_c
            .send(key(), vec![to(a1.id, format!("hello-{i}"))])
            .await
            .unwrap();
        assert_eq!(r, SendStatus::Accepted);
    }
    // One wake-up for the burst, with the constant alert and nothing of the device.
    let mut woke = false;
    for _ in 0..200 {
        if !apns_mock.requests().is_empty() {
            woke = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(woke, "no push reached APNs");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reqs = apns_mock.requests();
    assert_eq!(reqs.len(), 1, "one push per burst");
    let r = &reqs[0];
    assert_eq!(r.path, format!("/3/device/{}", hex::encode(token)));
    assert_eq!(r.header("apns-push-type"), Some("alert"));
    assert_eq!(
        r.body,
        br#"{"aps":{"alert":{"body":"New message","title":"Songbird"},"mutable-content":1}}"#
    );
    let seen: Vec<u8> = r
        .headers
        .iter()
        .flat_map(|(k, v)| [k.as_bytes(), v.as_bytes()].concat())
        .chain(r.body.iter().copied())
        .chain(r.path.bytes())
        .collect();
    for id in [a1.id.as_bytes(), b1.id.as_bytes(), alice.as_bytes()] {
        assert!(!contains_id(&seen, id), "an identifier reached APNs");
    }

    // The phone wakes, connects, and reads every message from its mailbox, in order.
    let (mut a1_c, mut a1_ev) =
        songbird_client::Client::start(client_cfg(), a1.key(), ResumeState::default());
    a1_c.wait_for(songbird_client::State::Connected).await;
    for i in 0..3u64 {
        let (seq, env) = next_delivery(&mut a1_ev).await;
        assert_eq!(seq, i + 1);
        assert_eq!(&env[..], format!("hello-{i}").as_bytes());
    }
    // Online: messages go straight to the session, no push.
    let before = metrics.push_jobs.get();
    bob_c.send(key(), vec![to(a1.id, "live")]).await.unwrap();
    assert_eq!(&next_delivery(&mut a1_ev).await.1[..], b"live");
    assert_eq!(metrics.push_jobs.get(), before);
    assert_eq!(apns_mock.requests().len(), 1);

    running.stop().await;
    let _ = stop.send(true);
}

/// Numbers for the M5 report (ignored by default; `cargo test -p songbird-e2e --test gate_m5
/// --release -- --ignored --nocapture m5_numbers`): job queue round trip, push job to provider,
/// attachment upload and download through `api`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark"]
#[allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::as_conversions,
    clippy::many_single_char_names,
    reason = "benchmark output"
)]
async fn m5_numbers() {
    use songbird_jobs::{ConsumeConfig, Job};
    use std::time::Instant;

    let Some(e) = stack_env() else { return };
    let pct = |v: &mut Vec<Duration>, p: f64| {
        v.sort();
        v[((v.len() as f64 - 1.0) * p) as usize]
    };

    // 1. Job queue: enqueue 20,000 push jobs in batches of 256, consume them.
    let q = queue(&e, "bench").await;
    let n = 20_000usize;
    let t = Instant::now();
    for chunk in (0..n).collect::<Vec<_>>().chunks(256) {
        let jobs: Vec<Job> = chunk
            .iter()
            .map(|_| {
                Job::new(Work::Push {
                    device: DeviceId::random().unwrap(),
                    call: false,
                })
                .unwrap()
            })
            .collect();
        q.enqueue(&jobs).await.unwrap();
    }
    let enq = t.elapsed();
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let d2 = Arc::clone(&done);
    let t = Instant::now();
    let c = tokio::spawn(songbird_jobs::consume(
        Arc::clone(&q),
        Stream::Push,
        ConsumeConfig {
            batch: 256,
            concurrency: 256,
            ..ConsumeConfig::default()
        },
        move |_| {
            d2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            async { Outcome::Done }
        },
        stop_rx,
    ));
    while done.load(std::sync::atomic::Ordering::Relaxed) < n {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let cons = t.elapsed();
    let _ = stop_tx.send(true);
    c.await.unwrap();
    println!(
        "jobs: enqueue {:.0}/s (batches of 256), consume+ack+delete {:.0}/s",
        n as f64 / enq.as_secs_f64(),
        n as f64 / cons.as_secs_f64()
    );

    // 2. Attachments through api: 1 MiB and 16 MiB, upload and download.
    let registry = registry(&e).await;
    let s3 = s3(&e);
    s3.create_bucket().await.unwrap();
    let dev = Dev::new();
    registry
        .create_account(
            &AccountId::random().unwrap(),
            &[(dev.id, dev.key().public_key())],
        )
        .await
        .unwrap();
    let (_, push_public) = songbird_accounts::push_token::key_pair(&[0x24; 32]).unwrap();
    let app = Arc::new(App {
        requests: None,
        reports: None,
        server_name: API.into(),
        registry: Arc::clone(&registry),
        s3,
        queue: Arc::clone(&q),
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(e.hot.as_str()).unwrap())
            .await
            .unwrap(),
        push_public,
        push_index_secret: PUSH_INDEX,
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        kt: None,
        profiles: None,
        devices: None,
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = l.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(songbird_api::server::serve(
        l,
        None,
        Arc::clone(&app),
        256,
        rx,
    ));
    let api = dev.api(api_addr);
    for (size, rounds) in [(1usize << 20, 40usize), (16 << 20, 10)] {
        let (mut up, mut down) = (Vec::new(), Vec::new());
        let body = Bytes::from(vec![0x5a; size]);
        for _ in 0..rounds {
            let g = api
                .send(
                    "POST",
                    "/v1/attachments",
                    Some(format!(r#"{{"size":{size},"fetches":1}}"#).as_bytes()),
                )
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&g.1).unwrap();
            let path = format!("/v1/attachments/{}", v["id"].as_str().unwrap());
            let t = Instant::now();
            assert_eq!(api.upload(&path, body.clone()).await.unwrap().0, 201);
            up.push(t.elapsed());
            let t = Instant::now();
            let (st, got) = api.send("GET", &path, None).await.unwrap();
            assert_eq!((st, got.len()), (200, size));
            down.push(t.elapsed());
        }
        let mib = size as f64 / f64::from(1u32 << 20);
        println!(
            "attachments {mib:.0} MiB x{rounds}: upload p50 {:?} p99 {:?} ({:.0} MiB/s at p50); download p50 {:?} p99 {:?} ({:.0} MiB/s at p50)",
            pct(&mut up, 0.5),
            pct(&mut up, 0.99),
            mib / pct(&mut up, 0.5).as_secs_f64(),
            pct(&mut down, 0.5),
            pct(&mut down, 0.99),
            mib / pct(&mut down, 0.5).as_secs_f64(),
        );
    }
    let _ = stop.send(true);
}
