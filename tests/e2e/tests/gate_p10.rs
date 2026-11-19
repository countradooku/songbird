//! Prompt 10's gate items for the Songbird vault (M2, D-0121), against a real `api`, SurrealDB,
//! `valkey-hot` and `RustFS`:
//!
//! - the vault adapter passes the conformance suite every adapter passes;
//! - a brand-new device holding only the recovery key finds and restores the backup;
//! - only the owning account's primary writes; another account or a linked device cannot;
//! - an unknown vault and a wrong secret get the same 404, and misses are throttled per range;
//! - the quota holds; deleting the account (or turning backups off) leaves no row and no object;
//! - chunk put and get and the manifest swap are timed (p50, p99).
//!
//! Runs when the `SONGBIRD_TEST_*` variables are set; with `SONGBIRD_REQUIRE_STACK=1` a missing
//! one fails instead of skipping.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::many_single_char_names,
    clippy::unnested_or_patterns,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::large_futures,
    clippy::assert_is_empty,
    reason = "tests"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use songbird_accounts::{Db, Registry};
use songbird_api::client::ApiClient;
use songbird_api::config::VaultSettings;
use songbird_api::{ApiMetrics, App};
use songbird_backup_format::reader::MemoryStaging;
use songbird_backup_format::synth::{self, Shape};
use songbird_backup_format::{BackupKeys, ChunkName, OsRng, RecoveryKey, object};
use songbird_backup_storage::conformance::{self, Plan};
use songbird_backup_storage::http::HyperHttp;
use songbird_backup_storage::run::{self, Options};
use songbird_backup_storage::vault::{Signer, VaultStore};
use songbird_backup_storage::{BackupStore, StoreError};
use songbird_jobs::{Queue, QueueConfig, Stream};
use songbird_types::{AccountId, DeviceId, Secret, SecretRef};
use songbird_worker::{DeliveryLink, Worker, WorkerMetrics};

const SERVER: &str = "api.gatep10.test";

fn env(name: &str) -> Option<String> {
    let v = std::env::var(name).ok();
    assert!(
        v.is_some() || std::env::var("SONGBIRD_REQUIRE_STACK").is_err(),
        "SONGBIRD_REQUIRE_STACK is set but {name} is not"
    );
    v
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).unwrap();
    b
}

fn settings(quota_bytes: u64) -> VaultSettings {
    VaultSettings {
        secret: SecretRef::Env("SONGBIRD_UNUSED".into()),
        bucket: String::new(),
        quota_bytes,
        quota_chunks: 100_000,
        max_vaults: 2,
        max_manifest: 16 << 20,
        reads_per_hour: 3_600_000,
        read_burst: 100_000,
        writes_per_hour: 3_600_000,
        write_burst: 100_000,
        misses_per_hour: 60,
        miss_burst: 20,
        ipv4_prefix: 24,
        ipv6_prefix: 48,
    }
}

struct Stack {
    app: Arc<App>,
    worker: Worker,
    vault_s3: songbird_s3::Client,
    api: String,
    _stop: tokio::sync::watch::Sender<bool>,
}

async fn stack(quota_bytes: u64) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let jobs = env("SONGBIRD_TEST_VALKEY_JOBS")?;
    let s3_addr = env("SONGBIRD_TEST_RUSTFS")?;
    let registry = Arc::new(
        Registry::connect(
            Db::connect(songbird_surreal::Config {
                addr: surreal,
                host: "localhost".into(),
                tls: None,
                user: std::env::var("SONGBIRD_TEST_SURREALDB_USER")
                    .unwrap_or_else(|_| "root".into()),
                pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
                namespace: "test".into(),
                database: format!(
                    "gatep10_{}",
                    DeviceId::random().unwrap().to_hex_unredacted()
                ),
                timeout: Duration::from_secs(30),
                max_message_bytes: 64 << 20,
            })
            .await
            .unwrap(),
        )
        .await
        .unwrap(),
    );
    let bucket = |name: String| {
        let mut cfg = songbird_s3::Config::new(
            s3_addr.clone(),
            name,
            Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_ACCESS_KEY").unwrap()),
            Secret::new(std::env::var("SONGBIRD_TEST_RUSTFS_SECRET_KEY").unwrap()),
        );
        cfg.max_connections = 64;
        songbird_s3::Client::new(cfg).unwrap()
    };
    let s3 = bucket("songbird-gatep10".into());
    s3.create_bucket().await.unwrap();
    // A bucket per run: the deletion checks list it.
    let vault_s3 = bucket(format!("p10v-{}", &hex::encode(rand32())[..12]));
    vault_s3.create_bucket().await.unwrap();
    let hot_conn = || async {
        songbird_valkey::ValkeyConn::connect(redis::Client::open(hot.as_str()).unwrap())
            .await
            .unwrap()
    };
    let queue = Queue::connect(
        redis::Client::open(jobs.as_str()).unwrap(),
        &[0x10; 32],
        QueueConfig::new(format!("gate-p10-{}", &hex::encode(rand32())[..8])),
    )
    .await
    .unwrap();
    queue.ensure_groups(&Stream::ALL).await.unwrap();
    let queue = Arc::new(queue);
    let metrics = ApiMetrics::default();
    let vault = songbird_api::vault::Vault::new(
        settings(quota_bytes),
        &rand32(),
        vault_s3.clone(),
        metrics.vault.clone(),
    )
    .unwrap();
    let app = Arc::new(App {
        calls: None,
        reports: None,
        requests: None,
        server_name: SERVER.into(),
        push_store: Arc::new(
            songbird_accounts::PushStore::beside(&registry)
                .await
                .unwrap(),
        ),
        registry: Arc::clone(&registry),
        s3: s3.clone(),
        queue: Arc::clone(&queue),
        hot: hot_conn().await,
        push_public: [0; 32],
        push_index_secret: [0x31; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        messages: None,
        metrics,
        registration: None,
        usernames: None,
        keys: None,
        devices: None,
        profiles: None,
        storage: None,
        vault: Some(vault),
        kt: None,
    });
    let worker = Worker {
        block_keys: None,
        vault_s3: Some(vault_s3.clone()),
        push_store: Arc::new(
            songbird_accounts::PushStore::beside(&registry)
                .await
                .unwrap(),
        ),
        registry,
        s3,
        queue,
        // A stand-in for delivery: forgetting succeeds, and no device is known.
        delivery: DeliveryLink::Direct(Arc::new(|b: Bytes| {
            Box::pin(async move {
                use songbird_link::devices::{DeviceRequest, encode_response};
                let r = match DeviceRequest::decode(&b) {
                    Some(DeviceRequest::Known(ds)) => Ok(vec![false; ds.len()]),
                    _ => Ok(Vec::new()),
                };
                Bytes::from(encode_response(&r))
            })
        })),
        push_index_secret: [0x31; 32],
        journal: None,
        propagation: Duration::from_millis(10),
        kt: None,
        metrics: WorkerMetrics::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(songbird_api::server::serve(
        listener,
        None,
        Arc::clone(&app),
        256,
        rx,
    ));
    Some(Stack {
        app,
        worker,
        vault_s3,
        api: format!("http://{addr}"),
        _stop: stop,
    })
}

/// A device of an account, signing as `ApiClient` does.
struct Device {
    account: AccountId,
    client: Arc<ApiClient>,
}

struct DeviceSigner(Arc<ApiClient>);

impl Signer for DeviceSigner {
    fn sign(&self, method: &str, path: &str, body: Option<&[u8]>) -> (String, Option<String>) {
        self.0.sign(method, path, body)
    }
}

fn key_pair() -> (Ed25519KeyPair, [u8; 32]) {
    let kp = Ed25519KeyPair::from_seed_unchecked(&rand32()).unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.public_key().as_ref());
    (kp, pk)
}

/// An account with a primary and `linked` more devices (all listed).
async fn account(s: &Stack, linked: usize) -> Vec<Device> {
    let a = AccountId::random().unwrap();
    let mut keys = vec![];
    let mut pairs = vec![];
    for _ in 0..=linked {
        let (kp, pk) = key_pair();
        let d = DeviceId::random().unwrap();
        keys.push((d, pk));
        pairs.push((d, kp));
    }
    s.app.registry.create_account(&a, &keys).await.unwrap();
    let addr: SocketAddr = s.api.trim_start_matches("http://").parse().unwrap();
    pairs
        .into_iter()
        .map(|(d, kp)| Device {
            account: a,
            client: Arc::new(ApiClient::new(addr, SERVER, d, kp)),
        })
        .collect()
}

fn http() -> Arc<HyperHttp> {
    Arc::new(HyperHttp::new(&[]).unwrap())
}

fn store(s: &Stack, keys: &BackupKeys, d: Option<&Device>) -> Arc<dyn BackupStore> {
    Arc::new(VaultStore::new(
        http(),
        s.api.clone(),
        keys,
        d.map(|d| Arc::new(DeviceSigner(Arc::clone(&d.client))) as Arc<dyn Signer>),
    ))
}

fn new_keys() -> Arc<BackupKeys> {
    Arc::new(RecoveryKey::generate(&mut OsRng).unwrap().derive().unwrap())
}

const SHAPE: Shape = Shape {
    seed: 77,
    chats: 8,
    messages_per_chat: 150,
    media_every: 25,
    media_sizes: &[4_000, 1_300_000],
    contacts: 10,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_vault_passes_the_conformance_suite() {
    let Some(s) = stack(5 << 30).await else {
        return;
    };
    let owner = account(&s, 0).await;
    let keys = new_keys();
    let r = conformance::run(
        store(&s, &keys, Some(&owner[0])),
        Arc::clone(&keys),
        Plan::default(),
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    println!("vault conformance: {:?}", r.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_new_device_with_only_the_recovery_key_restores_and_others_cannot_write() {
    let Some(s) = stack(5 << 30).await else {
        return;
    };
    let owner = account(&s, 1).await;
    let key = RecoveryKey::generate(&mut OsRng).unwrap();
    let keys = Arc::new(key.derive().unwrap());
    let primary = store(&s, &keys, Some(&owner[0]));
    let done = run::backup(
        Arc::clone(&primary),
        Arc::clone(&keys),
        None,
        Options::default(),
        |w| synth::write(w, &SHAPE, 0).map(|_| ()),
    )
    .await
    .unwrap();

    // A brand-new device: it types the key, derives everything, and reads without an account.
    let typed = RecoveryKey::parse(&key.display().to_lowercase().replace('-', " ")).unwrap();
    let fresh_keys = Arc::new(typed.derive().unwrap());
    let fresh = store(&s, &fresh_keys, None);
    let r = run::restore(
        Arc::clone(&fresh),
        Arc::clone(&fresh_keys),
        None,
        MemoryStaging::default(),
        8,
    )
    .await
    .unwrap();
    assert_eq!(r.opened.generation, done.seen.generation);
    let b =
        songbird_backup_format::reader::Backup::new(&fresh_keys, &r.opened.manifest, &r.staging);
    let first = b.records().next().unwrap().unwrap();
    assert!(matches!(
        first.body,
        Some(songbird_backup_format::schema::record::Body::Account(_))
    ));

    // Without a signature nothing is written.
    let (n, o) = chunk(&fresh_keys);
    assert!(matches!(
        fresh.put(&n, o.clone()).await,
        Err(StoreError::Unauthorized)
    ));
    // A linked device of the owner: 403 primary.
    let linked = store(&s, &keys, Some(&owner[1]));
    assert!(matches!(
        linked.put(&n, o.clone()).await,
        Err(StoreError::Unauthorized)
    ));
    assert!(matches!(
        linked.destroy().await,
        Err(StoreError::Unauthorized)
    ));
    // Another account's primary holding the secret: 403 owner.
    let other = account(&s, 0).await;
    let stranger = store(&s, &keys, Some(&other[0]));
    assert!(matches!(
        stranger.put(&n, o).await,
        Err(StoreError::Unauthorized)
    ));
    assert!(matches!(
        stranger
            .swap_manifest(
                done.seen.generation,
                manifest_of(&keys, done.seen.generation + 1)
            )
            .await,
        Err(StoreError::Unauthorized)
    ));
    // Nothing changed.
    let again = run::current(fresh.as_ref(), &fresh_keys, Some(done.seen))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.hash, done.seen.hash);
}

fn chunk(keys: &BackupKeys) -> (ChunkName, Vec<u8>) {
    let p = rand32();
    let n = object::chunk_name(keys, &p);
    let o = object::seal_chunk(keys, &n, &p, &mut OsRng).unwrap();
    (n, o)
}

fn manifest_of(keys: &BackupKeys, generation: u64) -> Vec<u8> {
    let m = songbird_backup_format::schema::Manifest {
        format_version: 1,
        min_reader_version: 1,
        streams: vec![songbird_backup_format::schema::Stream {
            kind: songbird_backup_format::schema::StreamKind::Records.into(),
            sha256: object::manifest_hash(&[]).to_vec(),
            ..Default::default()
        }],
        ..Default::default()
    };
    object::seal_manifest(keys, generation, &m, &mut OsRng).unwrap()
}

/// GETs a vault path with the given credentials; the status.
async fn probe(s: &Stack, id: [u8; 32], access: [u8; 32]) -> (u16, Duration) {
    let req =
        songbird_backup_storage::http::Request::new("GET", format!("{}/v1/vault/manifest", s.api))
            .header(songbird_proto::vault::VAULT_HEADER, hex::encode(id))
            .header(songbird_proto::vault::ACCESS_HEADER, hex::encode(access));
    let t = Instant::now();
    let r = songbird_backup_storage::http::Http::send(http().as_ref(), req)
        .await
        .unwrap();
    (r.status, t.elapsed())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_vault_and_a_wrong_secret_look_the_same_and_misses_are_throttled() {
    let Some(s) = stack(5 << 30).await else {
        return;
    };
    let owner = account(&s, 0).await;
    let keys = new_keys();
    store(&s, &keys, Some(&owner[0])).open().await.unwrap();
    assert_eq!(probe(&s, keys.vault_id, *keys.vault_access).await.0, 204);
    let mut wrong = *keys.vault_access;
    wrong[0] ^= 1;
    let (a, _) = probe(&s, keys.vault_id, wrong).await;
    let (b, _) = probe(&s, rand32(), rand32()).await;
    assert_eq!((a, b), (404, 404));
    // The range's miss budget (burst 20) runs out; then even the right secret waits.
    let mut statuses = vec![];
    for _ in 0..30 {
        statuses.push(probe(&s, rand32(), rand32()).await.0);
    }
    assert!(statuses.contains(&429), "{statuses:?}");
    assert_eq!(probe(&s, keys.vault_id, *keys.vault_access).await.0, 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_quota_holds() {
    // 2 MiB: a few chunks fit, then the vault is full.
    let Some(s) = stack(2 << 20).await else {
        return;
    };
    let owner = account(&s, 0).await;
    let keys = new_keys();
    let st = store(&s, &keys, Some(&owner[0]));
    st.open().await.unwrap();
    let mut full = false;
    for _ in 0..8 {
        let p = vec![1u8; 400_000];
        let mut q = p.clone();
        q[0] = rand32()[0];
        q[1] = rand32()[1];
        let n = object::chunk_name(&keys, &q);
        let o = object::seal_chunk(&keys, &n, &q, &mut OsRng).unwrap();
        match st.put(&n, o).await {
            Ok(()) => {}
            Err(StoreError::Full) => {
                full = true;
                break;
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(full, "the quota never refused");
    let vault = VaultStore::new(http(), s.api.clone(), &keys, None);
    let (_, bytes, _, quota, _) = vault.stats().await.unwrap();
    assert!(bytes <= quota, "{bytes} > {quota}");
    // A shape the vault does not take: refused before it counts.
    let r = st.put(&ChunkName([3; 32]), vec![0; 2048]).await;
    assert!(
        matches!(
            r,
            Err(StoreError::Unavailable { status: 400 }) | Err(StoreError::Protocol(_))
        ),
        "{r:?}"
    );
}

async fn objects(s: &Stack) -> usize {
    s.vault_s3
        .list_objects_v2("", None, 1000)
        .await
        .unwrap()
        .objects
        .len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turning_backups_off_and_deleting_the_account_leave_nothing() {
    let Some(s) = stack(5 << 30).await else {
        return;
    };
    let owner = account(&s, 0).await;
    let k1 = new_keys();
    let k2 = new_keys();
    for k in [&k1, &k2] {
        run::backup(
            store(&s, k, Some(&owner[0])),
            Arc::clone(k),
            None,
            Options::default(),
            |w| synth::write(w, &SHAPE, 0).map(|_| ()),
        )
        .await
        .unwrap();
    }
    // At most two vaults per account.
    let k3 = new_keys();
    assert!(store(&s, &k3, Some(&owner[0])).open().await.is_err());
    assert!(objects(&s).await > 10);

    // Turned off: gone at once for every request; the sweep deletes its objects.
    store(&s, &k1, Some(&owner[0])).destroy().await.unwrap();
    assert_eq!(probe(&s, k1.vault_id, *k1.vault_access).await.0, 404);
    s.worker.sweep().await;
    let vk1 = s.app.vault.as_ref().unwrap().vault_key(&k1.vault_id);
    assert!(s.app.registry.vault(&vk1).await.unwrap().is_none());
    let left = s
        .vault_s3
        .list_objects_v2(&hex::encode(vk1), None, 10)
        .await
        .unwrap();
    assert!(left.objects.is_empty());
    assert!(s.app.registry.vaults_gone(10).await.unwrap().is_empty());
    assert!(objects(&s).await > 0);
    // The same key opens a new, empty vault at once.
    let again = store(&s, &k1, Some(&owner[0]));
    again.open().await.unwrap();
    assert!(again.list().await.unwrap().is_empty() && again.manifest().await.unwrap().is_none());
    again.destroy().await.unwrap();
    s.worker.sweep().await;

    // The account is deleted: its other vault goes with it.
    let (st, _) = owner[0]
        .client
        .send("DELETE", "/v1/account", None)
        .await
        .unwrap();
    assert_eq!(st, 202);
    s.worker.delete_account(&owner[0].account).await.unwrap();
    assert_eq!(objects(&s).await, 0);
    let vk2 = s.app.vault.as_ref().unwrap().vault_key(&k2.vault_id);
    assert!(s.app.registry.vault(&vk2).await.unwrap().is_none());
    assert!(
        s.app
            .registry
            .vaults_of(&owner[0].account)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(probe(&s, k2.vault_id, *k2.vault_access).await.0, 404);
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(f64::total_cmp);
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn vault_latency() {
    let Some(s) = stack(5 << 30).await else {
        return;
    };
    let owner = account(&s, 0).await;
    let keys = new_keys();
    let st = store(&s, &keys, Some(&owner[0]));
    st.open().await.unwrap();
    let mut put = vec![];
    let mut get = vec![];
    let mut names = vec![];
    for _ in 0..200 {
        let mut p = vec![0u8; 2 << 20];
        aws_lc_rs::rand::fill(&mut p).unwrap();
        let n = object::chunk_name(&keys, &p);
        let o = object::seal_chunk(&keys, &n, &p, &mut OsRng).unwrap();
        let t = Instant::now();
        st.put(&n, o).await.unwrap();
        put.push(t.elapsed().as_secs_f64() * 1e3);
        names.push(n);
    }
    for n in &names {
        let t = Instant::now();
        st.get(n).await.unwrap();
        get.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let mut swap = vec![];
    for g in 0..200u64 {
        let m = manifest_of(&keys, g + 1);
        let t = Instant::now();
        st.swap_manifest(g, m).await.unwrap();
        swap.push(t.elapsed().as_secs_f64() * 1e3);
    }
    println!(
        "vault, 2 MiB chunks, 200 each: put p50 {:.1} ms p99 {:.1} ms; get p50 {:.1} ms p99 {:.1} ms; manifest swap p50 {:.1} ms p99 {:.1} ms",
        pct(&mut put, 0.5),
        pct(&mut put, 0.99),
        pct(&mut get, 0.5),
        pct(&mut get, 0.99),
        pct(&mut swap, 0.5),
        pct(&mut swap, 0.99)
    );
}

/// Prompt 10's gate: the incremental cost on a large simulated history, on the vault (compose
/// `RustFS`, SurrealDB, Valkey; `api` in process). The same history as
/// `songbird-backup-storage`'s `incremental_cost_in_memory`.
///
/// `cargo test --release -p songbird-e2e --test gate_p10 incremental_cost -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a measurement: about 1.7 GB into the compose RustFS"]
async fn incremental_cost_on_the_vault() {
    let Some(s) = stack(1 << 40).await else {
        return;
    };
    let owner = account(&s, 0).await;
    let keys = new_keys();
    let large = Shape {
        seed: 1_000_000,
        chats: 2_000,
        messages_per_chat: 501,
        media_every: 50,
        media_sizes: &[20_000, 60_000, 200_000],
        contacts: 500,
    };
    let steps = conformance::incremental_cost(
        store(&s, &keys, Some(&owner[0])),
        Arc::clone(&keys),
        large,
        1,
        25,
    )
    .await
    .unwrap();
    println!(
        "vault: step | new chunks | new MB | reused chunks | deleted | plaintext MB | seconds"
    );
    for st in &steps {
        println!(
            "{} | {} | {:.1} | {} | {} | {:.0} | {:.1}",
            st.what,
            st.new_chunks,
            st.new_bytes as f64 / 1e6,
            st.reused_chunks,
            st.deleted,
            st.plaintext as f64 / 1e6,
            st.seconds
        );
    }
    let vault = VaultStore::new(http(), s.api.clone(), &keys, None);
    let (generation, bytes, chunks, _, _) = vault.stats().await.unwrap();
    println!(
        "vault after: generation {generation}, {:.1} MB in {chunks} chunks",
        bytes as f64 / 1e6
    );
}
