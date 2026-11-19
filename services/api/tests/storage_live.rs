//! The record store (Prompt 9, M1) against real stores: SurrealDB, `valkey-hot`, `valkey-jobs`
//! and `RustFS`. Devices run `songbird_sync` replicas over HTTP against a real `api`. Runs when
//! the `SONGBIRD_TEST_*` variables are set (see `api_live.rs`); with `SONGBIRD_REQUIRE_STACK=1`
//! a missing one fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use songbird_accounts::push_token;
use songbird_accounts::{Db, Registry};
use songbird_api::client::ApiClient;
use songbird_api::config::StorageSettings;
use songbird_api::{ApiMetrics, App};
use songbird_jobs::{Queue, QueueConfig, Stream};
use songbird_proto::storage::{self, Head, ID_LEN, Ids, Record, Write};
use songbird_sync::{Remote, Replica, StorageKey, SyncError, WriteOutcome, rotate, sync};
use songbird_types::{AccountId, DeviceId, Secret, SecretRef};

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
    _stop: tokio::sync::watch::Sender<bool>,
}

fn settings(max_records: u32) -> StorageSettings {
    StorageSettings {
        // Not read: the test passes the secret's bytes directly.
        secret: SecretRef::Env("SONGBIRD_UNUSED".into()),
        max_records,
        max_bytes: 16 * 1024 * 1024,
        max_objects: 2,
        writes_per_hour: 3_600_000,
        write_burst: 100_000,
        record_units_per_hour: 3_600_000,
        record_units_burst: 1_000_000,
        reads_per_hour: 3_600_000,
        read_burst: 100_000,
    }
}

async fn stack(max_records: u32) -> Option<Stack> {
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
        database: format!(
            "storage_{}",
            DeviceId::random().unwrap().to_hex_unredacted()
        ),
        timeout: Duration::from_secs(10),
        max_message_bytes: 64 << 20,
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
        QueueConfig::new("storage-test".into()),
    )
    .await
    .unwrap();
    queue.ensure_groups(&Stream::ALL).await.unwrap();
    let hot = songbird_valkey::ValkeyConn::connect(redis::Client::open(hot).unwrap())
        .await
        .unwrap();
    let (_, push_public) = push_token::key_pair(&[0x77; 32]).unwrap();
    let st = settings(max_records);
    let secret = [0x11u8; 32];
    let app = Arc::new(App {
        requests: None,
        reports: None,
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
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys: None,
        storage: Some(
            songbird_api::storage::Storage::new(
                st,
                &secret,
                songbird_api::storage::StorageMetrics::default(),
            )
            .unwrap(),
        ),
        kt: None,
        vault: None,
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
        _stop: stop,
    })
}

fn key_pair() -> (Ed25519KeyPair, [u8; 32]) {
    let mut seed = [0u8; 32];
    aws_lc_rs::rand::fill(&mut seed).unwrap();
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.public_key().as_ref());
    (kp, pk)
}

/// A new account with `n` listed devices; their clients.
async fn account(s: &Stack, n: usize) -> (AccountId, Vec<ApiClient>) {
    let a = AccountId::random().unwrap();
    let mut keys = Vec::new();
    let mut clients = Vec::new();
    for _ in 0..n {
        let (kp, pk) = key_pair();
        let d = DeviceId::random().unwrap();
        keys.push((d, pk));
        clients.push(ApiClient::new(s.addr, SERVER, d, kp));
    }
    s.app.registry.create_account(&a, &keys).await.unwrap();
    (a, clients)
}

/// The store over HTTP, as an app sees it.
struct Http<'a>(&'a ApiClient);

impl Remote for Http<'_> {
    async fn head(&self) -> Result<Head, SyncError> {
        {
            let (st, b) = self
                .0
                .send("GET", "/v1/storage", None)
                .await
                .map_err(|_| SyncError::Remote)?;
            if st != 200 {
                return Err(SyncError::Remote);
            }
            Head::decode(&b).map_err(|_| SyncError::Remote)
        }
    }
    async fn ids(&self) -> Result<Ids, SyncError> {
        {
            let (st, b) = self
                .0
                .send("GET", "/v1/storage/ids", None)
                .await
                .map_err(|_| SyncError::Remote)?;
            if st != 200 {
                return Err(SyncError::Remote);
            }
            Ids::decode(&b).map_err(|_| SyncError::Remote)
        }
    }
    async fn read(&self, ids: &[[u8; ID_LEN]]) -> Result<Vec<Record>, SyncError> {
        let body = storage::encode_read(ids);
        {
            let body = body.map_err(|_| SyncError::Malformed)?;
            let (st, b) = self
                .0
                .send("POST", "/v1/storage/read", Some(&body))
                .await
                .map_err(|_| SyncError::Remote)?;
            if st != 200 {
                return Err(SyncError::Remote);
            }
            storage::decode_records(&b).map_err(|_| SyncError::Remote)
        }
    }
    async fn write(&self, w: &Write) -> Result<WriteOutcome, SyncError> {
        let body = w.encode();
        {
            let (st, b) = self
                .0
                .send("PUT", "/v1/storage", Some(&body))
                .await
                .map_err(|_| SyncError::Remote)?;
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
            match (st, v["error"].as_str()) {
                (200, _) => Ok(WriteOutcome::Applied(v["version"].as_u64().unwrap_or(0))),
                (409, Some("version")) => {
                    Ok(WriteOutcome::Conflict(v["version"].as_u64().unwrap_or(0)))
                }
                (409, Some("full")) => Ok(WriteOutcome::Full),
                _ => Err(SyncError::Remote),
            }
        }
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_converge_through_the_real_store_and_concurrent_writers_never_lose_an_edit() {
    let Some(s) = stack(10_000).await else { return };
    let (_, c) = account(&s, 3).await;
    let key = StorageKey::generate().unwrap();
    let mut a = Replica::new(key.clone(), [1; 16]);
    let mut b = Replica::new(key.clone(), [2; 16]);
    a.set("s/theme", b"dark".to_vec(), now_ms()).unwrap();
    a.set("c/ab/mute", b"until:9".to_vec(), now_ms()).unwrap();
    sync(&mut a, &Http(&c[0]), now_ms()).await.unwrap();
    let changed = sync(&mut b, &Http(&c[1]), now_ms()).await.unwrap();
    assert_eq!(changed, vec!["c/ab/mute".to_owned(), "s/theme".to_owned()]);
    assert_eq!(b.get("s/theme"), Some(&b"dark"[..]));

    // Eight devices write different keys at once, each through its own HTTP client: every
    // compare-and-swap that loses retries, and no edit is lost.
    let c2 = Arc::new(c);
    let mut handles = Vec::new();
    for i in 0..8u8 {
        let c2 = Arc::clone(&c2);
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            let mut r = Replica::new(key, [10 + i; 16]);
            r.set(&format!("k/{i:02}"), vec![i], now_ms()).unwrap();
            let client = &c2[usize::from(i % 3)];
            let mut tries = 0;
            loop {
                match sync(&mut r, &Http(client), now_ms()).await {
                    Ok(_) => break,
                    Err(SyncError::Busy) if tries < 5 => tries += 1,
                    Err(e) => panic!("{e}"),
                }
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    sync(&mut a, &Http(&c2[0]), now_ms()).await.unwrap();
    for i in 0..8u8 {
        assert_eq!(a.get(&format!("k/{i:02}")), Some(&[i][..]), "edit {i}");
    }
    assert_eq!(a.get("s/theme"), Some(&b"dark"[..]));

    // A key rotation rewrites the store; the other device needs the new key.
    let new = StorageKey::generate().unwrap();
    rotate(&mut a, &Http(&c2[0]), new.clone(), now_ms())
        .await
        .unwrap();
    assert_eq!(
        sync(&mut b, &Http(&c2[1]), now_ms()).await,
        Err(SyncError::KeyChanged)
    );
    b.set_key(new);
    sync(&mut b, &Http(&c2[1]), now_ms()).await.unwrap();
    assert_eq!(b.entries(), a.entries());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_server_checks_versions_lengths_caps_accounts_and_pending_devices() {
    let Some(s) = stack(4).await else { return };
    let (a, c) = account(&s, 1).await;
    let (_, other) = account(&s, 1).await;
    let key = StorageKey::generate().unwrap();
    let mut r = Replica::new(key, [1; 16]);
    for i in 0..4 {
        r.set(&format!("s/{i}"), vec![i], now_ms()).unwrap();
    }
    sync(&mut r, &Http(&c[0]), now_ms()).await.unwrap();
    // A fifth record passes the cap of four.
    r.set("s/5", vec![5], now_ms()).unwrap();
    assert_eq!(
        sync(&mut r, &Http(&c[0]), now_ms()).await,
        Err(SyncError::Full)
    );
    // A stale version is refused with the current one.
    let head = Head::decode(&c[0].send("GET", "/v1/storage", None).await.unwrap().1).unwrap();
    let stale = Write {
        expected: head.version - 1,
        manifest: vec![0; 76],
        deletes: Vec::new(),
        inserts: Vec::new(),
    };
    let (st, b) = c[0]
        .send("PUT", "/v1/storage", Some(&stale.encode()))
        .await
        .unwrap();
    assert_eq!(st, 409);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["version"].as_u64(), Some(head.version));
    // A record whose length is not a padded one is refused before the database.
    let mut bad = stale.encode();
    bad[1..9].copy_from_slice(&head.version.to_be_bytes());
    let mut w = Write::decode(&bad).unwrap();
    w.inserts.push(Record {
        id: [7; ID_LEN],
        blob: vec![0; 300],
    });
    assert_eq!(
        c[0].send("PUT", "/v1/storage", Some(&w.encode()))
            .await
            .unwrap()
            .0,
        400
    );
    // Another account sees its own empty store, and cannot read this account's records by ID.
    let ids = Ids::decode(&c[0].send("GET", "/v1/storage/ids", None).await.unwrap().1).unwrap();
    assert_eq!(ids.ids.len(), 4);
    let (st, b) = other[0]
        .send(
            "POST",
            "/v1/storage/read",
            Some(&storage::encode_read(&ids.ids).unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(st, 200);
    assert_eq!(storage::decode_records(&b).unwrap().len(), 0);
    let head = Head::decode(&other[0].send("GET", "/v1/storage", None).await.unwrap().1).unwrap();
    assert_eq!((head.version, head.manifest.len()), (0, 0));
    // A pending device reads and writes nothing (D-0052).
    let (kp, pk) = key_pair();
    let pending = DeviceId::random().unwrap();
    s.app
        .registry
        .db()
        .exec(
            "CREATE device:[$d] SET account = $a, key = $k, disabled = false, pending = true,
               at = time::now();",
            vec![
                (
                    "d".into(),
                    songbird_surreal::Value::Bytes(Bytes::copy_from_slice(pending.as_bytes())),
                ),
                (
                    "a".into(),
                    songbird_surreal::Value::Bytes(Bytes::copy_from_slice(a.as_bytes())),
                ),
                (
                    "k".into(),
                    songbird_surreal::Value::Bytes(Bytes::copy_from_slice(&pk)),
                ),
            ],
        )
        .await
        .unwrap();
    let p = ApiClient::new(s.addr, SERVER, pending, kp);
    assert_eq!(p.send("GET", "/v1/storage", None).await.unwrap().0, 403);
    // The export reports the store's size, never its contents.
    let export = s.app.registry.export(&a, None).await.unwrap();
    assert_eq!(export["settings_store"]["records"].as_u64(), Some(4));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn objects_are_the_accounts_own_and_deletion_leaves_nothing() {
    let Some(s) = stack(10_000).await else { return };
    let (a, c) = account(&s, 1).await;
    let (_, other) = account(&s, 1).await;
    let blob = vec![0x42; 100_000];
    let (st, b) = c[0]
        .send("PUT", "/v1/storage/object", Some(&blob))
        .await
        .unwrap();
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let id = v["object"].as_str().unwrap().to_owned();
    let path = format!("/v1/storage/object/{id}");
    let (st, got) = c[0].send("GET", &path, None).await.unwrap();
    assert_eq!((st, got.len()), (200, blob.len()));
    assert_eq!(other[0].send("GET", &path, None).await.unwrap().0, 404);
    assert_eq!(other[0].send("DELETE", &path, None).await.unwrap().0, 404);
    // The cap (two in this stack).
    assert_eq!(
        c[0].send("PUT", "/v1/storage/object", Some(&blob))
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        c[0].send("PUT", "/v1/storage/object", Some(&blob))
            .await
            .unwrap()
            .0,
        409
    );
    assert_eq!(c[0].send("DELETE", &path, None).await.unwrap().0, 204);
    assert_eq!(c[0].send("GET", &path, None).await.unwrap().0, 404);
    // Records and the remaining object go with the account's rows.
    let mut r = Replica::new(StorageKey::generate().unwrap(), [1; 16]);
    r.set("s/theme", b"dark".to_vec(), now_ms()).unwrap();
    sync(&mut r, &Http(&c[0]), now_ms()).await.unwrap();
    let objects = s.app.registry.storage_objects_of(&a).await.unwrap();
    assert_eq!(objects.len(), 1);
    s.app.registry.delete_account_rows(&a).await.unwrap();
    let left = s.app.registry.remnants(&a, &[]).await.unwrap();
    assert_eq!(left.storage, 0);
}

/// Read and write latency on the compose stack (M1's numbers; `--nocapture` prints them).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn store_latency() {
    let Some(s) = stack(10_000).await else { return };
    let (_, c) = account(&s, 1).await;
    let mut r = Replica::new(StorageKey::generate().unwrap(), [1; 16]);
    // A realistic store: 300 settings and per-chat records, 200 contacts.
    for i in 0..300 {
        r.set(&format!("s/{i}"), vec![1; 8], now_ms()).unwrap();
    }
    for i in 0..200 {
        r.set(&format!("k/{i:032}"), vec![2; 200], now_ms())
            .unwrap();
    }
    let t = Instant::now();
    sync(&mut r, &Http(&c[0]), now_ms()).await.unwrap();
    let first = t.elapsed();
    let mut writes = Vec::new();
    for i in 0..200 {
        r.set("s/theme", vec![i], now_ms()).unwrap();
        let t = Instant::now();
        sync(&mut r, &Http(&c[0]), now_ms()).await.unwrap();
        writes.push(t.elapsed());
    }
    let mut heads = Vec::new();
    for _ in 0..200 {
        let t = Instant::now();
        sync(&mut r, &Http(&c[0]), now_ms()).await.unwrap();
        heads.push(t.elapsed());
    }
    let mut fresh_reads = Vec::new();
    for i in 0..20u8 {
        let mut f = Replica::new(r.key().clone(), [i; 16]);
        let t = Instant::now();
        sync(&mut f, &Http(&c[0]), now_ms()).await.unwrap();
        fresh_reads.push(t.elapsed());
        assert_eq!(f.entries().len(), 501);
    }
    let pct = |v: &mut Vec<Duration>, p: f64| {
        v.sort();
        v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
    };
    println!(
        "storage: first write of 500 records {first:?}; one-record sync p50 {:?} p99 {:?}; \
         unchanged sync p50 {:?} p99 {:?}; fresh device (501 records) p50 {:?} p99 {:?}",
        pct(&mut writes, 0.5),
        pct(&mut writes, 0.99),
        pct(&mut heads, 0.5),
        pct(&mut heads, 0.99),
        pct(&mut fresh_reads, 0.5),
        pct(&mut fresh_reads, 0.99),
    );
}
