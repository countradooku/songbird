//! `api` against real stores: SurrealDB, `valkey-hot`, `valkey-jobs` and `RustFS`. Runs when
//! `SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`), `SONGBIRD_TEST_VALKEY`,
//! `SONGBIRD_TEST_VALKEY_JOBS` and `SONGBIRD_TEST_RUSTFS` (+ `_ACCESS_KEY`, `_SECRET_KEY`) are set;
//! with `SONGBIRD_REQUIRE_STACK=1` a missing one fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use songbird_accounts::push_token::{self, Registration};
use songbird_accounts::{Db, Registry, push_index};
use songbird_api::client::{ApiClient, unsigned_full};
use songbird_api::{ApiMetrics, App};
use songbird_jobs::{ObjectKey, Queue, QueueConfig, Stream, Work};
use songbird_types::{AccountId, DeviceId, Secret};

const SERVER: &str = "api.test";

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

struct Stack {
    app: Arc<App>,
    addr: std::net::SocketAddr,
    push_private: aws_lc_rs::agreement::PrivateKey,
    stop: tokio::sync::watch::Sender<bool>,
}

async fn stack() -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let jobs = env("SONGBIRD_TEST_VALKEY_JOBS")?;
    let s3 = env("SONGBIRD_TEST_RUSTFS")?;
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("api_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    let s3 = songbird_s3::Client::new(songbird_s3::Config::new(
        s3,
        "songbird-api-test".into(),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_ACCESS_KEY").unwrap()),
        Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_SECRET_KEY").unwrap()),
    ))
    .unwrap();
    s3.create_bucket().await.unwrap();
    let queue = Queue::connect(
        redis::Client::open(jobs).unwrap(),
        &[3; 32],
        QueueConfig::new("api-test".into()),
    )
    .await
    .unwrap();
    queue.ensure_groups(&Stream::ALL).await.unwrap();
    let hot = songbird_valkey::ValkeyConn::connect(redis::Client::open(hot).unwrap())
        .await
        .unwrap();
    let (push_private, push_public) = push_token::key_pair(&[0x77; 32]).unwrap();
    let app = Arc::new(App {
        plans: songbird_api::plans::Plans::default(),
        requests: None,
        reports: None,
        support: None,
        calls: None,
        server_name: SERVER.into(),
        push_store: Arc::new(
            songbird_accounts::PushStore::beside(&registry)
                .await
                .unwrap(),
        ),
        registry,
        s3,
        queue: Arc::new(queue),
        hot,
        push_public,
        push_index_secret: [9; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        media: Some(songbird_api::media::Media::new(
            songbird_api::config::MediaBudgets::default(),
            songbird_api::config::MediaDownloads::default(),
            &[5; 32],
        )),
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        storage: None,
        vault: None,
        kt: None,
        profiles: None,
        devices: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(songbird_api::server::serve(
        listener,
        None,
        Arc::clone(&app),
        64,
        rx,
    ));
    Some(Stack {
        app,
        addr,
        push_private,
        stop,
    })
}

/// A new account with one device; returns its client.
async fn device(s: &Stack) -> (AccountId, DeviceId, ApiClient) {
    let mut seed = [0u8; 32];
    aws_lc_rs::rand::fill(&mut seed).unwrap();
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.public_key().as_ref());
    let (a, d) = (AccountId::random().unwrap(), DeviceId::random().unwrap());
    s.app.registry.create_account(&a, &[(d, pk)]).await.unwrap();
    (a, d, ApiClient::new(s.addr, SERVER, d, kp))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_registration_is_sealed_and_requests_are_authenticated() {
    let Some(s) = stack().await else { return };
    let (_, d, c) = device(&s).await;
    let body = br#"{"fcm":{"token":"fcm-registration-token-123"}}"#;
    assert_eq!(c.send("PUT", "/v1/push", Some(body)).await.unwrap().0, 204);
    let index = push_index(&[9; 32], &d);
    let sealed = s.app.push_store.get(&index).await.unwrap().unwrap();
    // The database holds no trace of the token; only the push key opens it, on this row only.
    assert!(!sealed.windows(9).any(|w| w == b"fcm-regis"));
    assert_eq!(
        push_token::open(&s.push_private, &index, &sealed).unwrap(),
        Registration::Fcm {
            token: "fcm-registration-token-123".into()
        }
    );
    // Refused: replayed nonce, wrong path, body not matching its digest, unknown device,
    // malformed registration.
    let (authz, hash) = c.sign("PUT", "/v1/push", Some(body));
    let req = || {
        hyper::Request::builder()
            .method("PUT")
            .uri("/v1/push")
            .header("authorization", authz.clone())
            .header("x-songbird-content-sha256", hash.clone().unwrap())
    };
    assert_eq!(c.raw(req(), Bytes::from_static(body)).await.unwrap().0, 204);
    assert_eq!(
        c.raw(req(), Bytes::from_static(body)).await.unwrap().0,
        401,
        "replay"
    );
    let other = hyper::Request::builder()
        .method("PUT")
        .uri("/v1/account")
        .header("authorization", c.sign("PUT", "/v1/push", None).0);
    assert_eq!(c.raw(other, Bytes::new()).await.unwrap().0, 404);
    let swapped = hyper::Request::builder()
        .method("PUT")
        .uri("/v1/push")
        .header("authorization", c.sign("PUT", "/v1/push", Some(body)).0)
        .header("x-songbird-content-sha256", hash.clone().unwrap());
    assert_eq!(
        c.raw(swapped, Bytes::from_static(br#"{"fcm":{"token":"x"}}"#))
            .await
            .unwrap()
            .0,
        401
    );
    let stranger = ApiClient::new(
        s.addr,
        SERVER,
        DeviceId::random().unwrap(),
        Ed25519KeyPair::from_seed_unchecked(&[5; 32]).unwrap(),
    );
    assert_eq!(
        stranger
            .send("PUT", "/v1/push", Some(body))
            .await
            .unwrap()
            .0,
        401
    );
    assert_eq!(
        c.send("PUT", "/v1/push", Some(br#"{"fcm":{"token":""}}"#))
            .await
            .unwrap()
            .0,
        400
    );
    assert_eq!(c.send("DELETE", "/v1/push", None).await.unwrap().0, 204);
    assert!(s.app.push_store.get(&index).await.unwrap().is_none());
    let _ = s.stop.send(true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attachments_upload_exactly_and_go_after_the_last_fetch() {
    let Some(s) = stack().await else { return };
    let (_, _, up) = device(&s).await;
    let (_, _, down) = device(&s).await;
    let r = up
        .send(
            "POST",
            "/v1/attachments",
            Some(br#"{"size":4145,"fetches":2}"#),
        )
        .await
        .unwrap();
    assert_eq!(r.0, 201);
    let v: serde_json::Value = serde_json::from_slice(&r.1).unwrap();
    let id = v["id"].as_str().unwrap().to_owned();
    let path = format!("/v1/attachments/{id}");
    let object = ObjectKey::parse_hex(&id).unwrap();
    // Only the granted device, only the granted size.
    assert_eq!(
        down.upload(&path, Bytes::from(vec![1; 4145]))
            .await
            .unwrap()
            .0,
        404
    );
    assert_eq!(
        up.upload(&path, Bytes::from(vec![1; 4144]))
            .await
            .unwrap()
            .0,
        400
    );
    assert_eq!(
        up.upload(&path, Bytes::from(vec![7; 4145]))
            .await
            .unwrap()
            .0,
        201
    );
    assert_eq!(
        up.upload(&path, Bytes::from(vec![7; 4145]))
            .await
            .unwrap()
            .0,
        404,
        "used"
    );
    // The record holds no uploader.
    assert!(s.app.registry.grant(&object).await.unwrap().is_none());
    let depth = s.app.queue.depth(Stream::Cleanup).await.unwrap();
    // Downloads go by capability (Prompt 6, D-0082): a 303 to a signed URL; each device then
    // confirms its fetch, and the last confirmation deletes.
    for left in [1u32, 0] {
        let (st, h, _) = unsigned_full(s.addr, SERVER, "GET", &path, &[])
            .await
            .unwrap();
        assert_eq!(st, 303);
        let url = h["location"].to_str().unwrap().to_owned();
        let (st, _, body) = unsigned_full(s.addr, SERVER, "GET", &url, &[])
            .await
            .unwrap();
        assert_eq!(st, 200);
        assert_eq!(body.len(), 4145);
        assert!(body.iter().all(|b| *b == 7));
        let fetched = format!("{path}/fetched");
        // Two recipient devices, two source addresses (one source counts once, D-0084).
        let source = if left == 1 { 1 } else { 2 };
        let (st, _, _) = songbird_api::client::unsigned_from(
            s.addr,
            [127, 0, 0, source].into(),
            SERVER,
            "POST",
            &fetched,
        )
        .await
        .unwrap();
        assert_eq!(st, 204);
        let a = s.app.registry.attachment(&object).await.unwrap();
        assert_eq!(a.map_or(0, |a| a.left), left);
    }
    assert_eq!(
        down.send("GET", &path, None).await.unwrap().0,
        404,
        "fetched out"
    );
    // The last fetch queued the object's deletion.
    let mut queued = false;
    for _ in 0..100 {
        if s.app.queue.depth(Stream::Cleanup).await.unwrap() > depth {
            queued = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(queued);
    // Bounds.
    for bad in [
        &br#"{"size":0,"fetches":1}"#[..],
        br#"{"size":4145,"fetches":0}"#,
        br#"{"size":999999999999,"fetches":1}"#,
        br#"{"size":1,"fetches":1,"x":1}"#,
    ] {
        assert_eq!(
            up.send("POST", "/v1/attachments", Some(bad))
                .await
                .unwrap()
                .0,
            400
        );
    }
    assert_eq!(
        up.send("GET", "/v1/attachments/zz", None).await.unwrap().0,
        404
    );
    let _ = s.stop.send(true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_deletion_disables_devices_and_queues_the_job() {
    let Some(s) = stack().await else { return };
    let (a, d, c) = device(&s).await;
    assert_eq!(c.send("DELETE", "/v1/account", None).await.unwrap().0, 202);
    assert!(s.app.registry.device(&d).await.unwrap().unwrap().disabled);
    // Disabled devices cannot sign requests any more.
    assert_eq!(c.send("DELETE", "/v1/push", None).await.unwrap().0, 401);
    // The job reached the deletion stream (relayed from the outbox).
    let mut found = false;
    for _ in 0..50 {
        for dl in s.app.queue.read(Stream::Deletion, 64).await.unwrap() {
            if dl.job.work == (Work::DeleteAccount { account: a }) {
                found = true;
            }
            s.app
                .queue
                .finish(&dl, songbird_jobs::Outcome::Done)
                .await
                .unwrap();
        }
        if found {
            break;
        }
    }
    assert!(found);
    let _ = s.stop.send(true);
}
