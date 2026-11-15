//! The key directory over HTTP against SurrealDB and `valkey-hot` (Prompt 3, M3, D-0050). Runs
//! when `SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`) and `SONGBIRD_TEST_VALKEY` are set; with
//! `SONGBIRD_REQUIRE_STACK=1` a missing one fails instead of skipping.
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

use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_1024};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use songbird_accounts::{Db, Registry};
use songbird_api::client::ApiClient;
use songbird_api::config::{KeySettings, KeyThrottle};
use songbird_api::keys::{KeyDirectory, KeyMetrics};
use songbird_api::{ApiMetrics, App};
use songbird_jobs::{Queue, QueueConfig};
use songbird_keys::xeddsa::{Signer, verify};
use songbird_proto::keys::{self as wire, OneTimeEc, SignedEc, SignedKem, Upload, decode_bundles};
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

fn settings(throttle: KeyThrottle) -> KeySettings {
    KeySettings {
        secret: SecretRef::Env("UNUSED".into()),
        system_key: None,
        max_stored: 20,
        refill_below: 3,
        throttle,
    }
}

async fn stack(k: Option<KeySettings>) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("keys_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).unwrap();
    let keys = k.map(|k| KeyDirectory::new(k, &secret, None, KeyMetrics::default()).unwrap());
    let app = Arc::new(App {
        server_name: SERVER.into(),
        registry,
        s3: songbird_s3::Client::new(songbird_s3::Config::new(
            "127.0.0.1:9".into(),
            "unused".into(),
            Secret::new("unused".into()),
            Secret::new("unused-secret".into()),
        ))
        .unwrap(),
        queue: Arc::new(
            Queue::connect(
                redis::Client::open(hot.clone()).unwrap(),
                &[3; 32],
                QueueConfig::new("keys-test".into()),
            )
            .await
            .unwrap(),
        ),
        hot: songbird_valkey::ValkeyConn::connect(redis::Client::open(hot).unwrap())
            .await
            .unwrap(),
        push_public: [0; 32],
        push_index_secret: [9; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames: None,
        keys,
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

/// A device of a new account.
async fn person(s: &Stack) -> (AccountId, DeviceId, ApiClient) {
    let kp = Ed25519KeyPair::generate().unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.public_key().as_ref());
    let (a, d) = (AccountId::random().unwrap(), DeviceId::random().unwrap());
    s.app.registry.create_account(&a, &[(d, pk)]).await.unwrap();
    (a, d, ApiClient::new(s.addr, SERVER, d, kp))
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn ec_key(s: &Signer) -> [u8; wire::EC_LEN] {
    let mut k = [0u8; wire::EC_LEN];
    k[0] = wire::TYPE_X25519;
    k[1..].copy_from_slice(&s.public());
    k
}

fn kem(id: u32, identity: &Signer) -> SignedKem {
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
}

/// A complete first upload with `n` one-time keys of each kind, IDs from `first`.
fn upload(identity: &Signer, first: u32, n: u32) -> Upload {
    let spk = ec_key(&Signer::new(&rand32()));
    Upload {
        identity: Some(ec_key(identity)),
        signed: Some(SignedEc {
            id: 1,
            key: spk,
            sig: identity.sign(&spk, &[3; 64]),
        }),
        last_resort: Some(kem(2, identity)),
        one_time_ec: (first..first + n)
            .map(|id| OneTimeEc {
                id,
                key: ec_key(&Signer::new(&rand32())),
            })
            .collect(),
        one_time_kem: (first..first + n).map(|id| kem(id, identity)).collect(),
    }
}

async fn put(c: &ApiClient, u: &Upload) -> (u16, String) {
    let (s, b) = c.send("PUT", "/v1/keys", Some(&u.encode())).await.unwrap();
    (s, String::from_utf8_lossy(&b).into_owned())
}

async fn counts(c: &ApiClient) -> (u64, u64) {
    let (s, b) = c.send("GET", "/v1/keys", None).await.unwrap();
    assert_eq!(s, 200);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    (v["ec"].as_u64().unwrap(), v["kem"].as_u64().unwrap())
}

async fn fetch(c: &ApiClient, account: &AccountId) -> (u16, Vec<wire::Bundle>) {
    let body = format!(r#"{{"account":"{}"}}"#, account.to_hex_unredacted());
    let (s, b) = c
        .send("POST", "/v1/keys/fetch", Some(body.as_bytes()))
        .await
        .unwrap();
    let bundles = if s == 200 {
        decode_bundles(&b).unwrap()
    } else {
        Vec::new()
    };
    (s, bundles)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uploads_are_verified_and_fetches_hand_out_each_one_time_key_once() {
    let Some(s) = stack(Some(settings(KeyThrottle::default()))).await else {
        return;
    };
    let (alice, _, alice_c) = person(&s).await;
    let (_, _, bob_c) = person(&s).await;
    let identity = Signer::new(&rand32());
    // Before any upload Alice has no bundle.
    assert_eq!(fetch(&bob_c, &alice).await.0, 404);
    assert_eq!(put(&alice_c, &upload(&identity, 10, 3)).await.0, 204);
    assert_eq!(counts(&alice_c).await, (3, 3));
    let mut seen = std::collections::HashSet::new();
    for left in [2, 1, 0] {
        let (st, b) = fetch(&bob_c, &alice).await;
        assert_eq!(st, 200);
        assert_eq!(b.len(), 1);
        let b = &b[0];
        // What a client checks before PQXDH: both signatures by the identity key.
        let ik: [u8; 32] = b.identity[1..].try_into().unwrap();
        assert_eq!(ik, identity.public());
        assert!(verify(&ik, &b.signed.key, &b.signed.sig));
        assert!(verify(&ik, b.kem.key.as_slice(), &b.kem.sig));
        assert!(b.kem_one_time);
        let one_time = b.one_time_ec.as_ref().unwrap();
        assert!(seen.insert(one_time.id), "a one-time key handed out twice");
        assert_eq!(counts(&alice_c).await, (left, left));
    }
    // None left: the last-resort ML-KEM key, no one-time X25519 key.
    let (_, b) = fetch(&bob_c, &alice).await;
    assert!(b[0].one_time_ec.is_none() && !b[0].kem_one_time);
    assert_eq!(b[0].kem.id, 2);
    // Alice fetching her own (only) device gets nothing.
    assert_eq!(fetch(&alice_c, &alice).await.0, 404);
    // Refill with one-time keys only (the identity is known).
    let more = Upload {
        one_time_ec: vec![OneTimeEc {
            id: 50,
            key: ec_key(&Signer::new(&rand32())),
        }],
        ..Upload::default()
    };
    assert_eq!(put(&alice_c, &more).await.0, 204);
    assert_eq!(counts(&alice_c).await, (1, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_keys_signatures_identity_changes_and_overflow_are_refused() {
    let Some(s) = stack(Some(settings(KeyThrottle::default()))).await else {
        return;
    };
    let (_, _, c) = person(&s).await;
    let identity = Signer::new(&rand32());
    // Incomplete first upload; malformed body.
    let mut u = upload(&identity, 0, 1);
    u.identity = None;
    assert_eq!(put(&c, &u).await, (400, r#"{"error":"incomplete"}"#.into()));
    assert_eq!(
        c.send("PUT", "/v1/keys", Some(&[1, 2, 3])).await.unwrap().0,
        400
    );
    // A signature by another key.
    let mut u = upload(&identity, 0, 1);
    u.one_time_kem = vec![kem(0, &Signer::new(&rand32()))];
    assert_eq!(put(&c, &u).await, (400, r#"{"error":"signature"}"#.into()));
    // Nothing was stored by the refusals.
    assert_eq!(counts(&c).await, (0, 0));
    assert_eq!(put(&c, &upload(&identity, 0, 5)).await.0, 204);
    // Another identity key.
    assert_eq!(
        put(&c, &upload(&Signer::new(&rand32()), 100, 1)).await,
        (409, r#"{"error":"identity"}"#.into())
    );
    // A duplicate ID; beyond the store's bound (20).
    assert_eq!(
        put(&c, &upload(&identity, 4, 1)).await,
        (409, r#"{"error":"duplicate"}"#.into())
    );
    assert_eq!(
        put(&c, &upload(&identity, 200, 16)).await,
        (409, r#"{"error":"full"}"#.into())
    );
    assert_eq!(counts(&c).await, (5, 5));
    // Unsigned requests are refused.
    let stranger = ApiClient::new(
        s.addr,
        SERVER,
        DeviceId::random().unwrap(),
        Ed25519KeyPair::generate().unwrap(),
    );
    assert_eq!(stranger.send("GET", "/v1/keys", None).await.unwrap().0, 401);
}

/// Draining is limited: past the target's one-time budget (here 2), fetches still answer, with
/// the last-resort key only, and the one-time keys stay for later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_targets_one_time_keys_cannot_be_drained_and_fetchers_are_throttled() {
    let throttle = KeyThrottle {
        target_one_time_burst: 2,
        target_one_time_per_hour: 1,
        fetch_burst: 4,
        fetches_per_hour: 1,
        ..KeyThrottle::default()
    };
    let Some(s) = stack(Some(settings(throttle))).await else {
        return;
    };
    let (alice, _, alice_c) = person(&s).await;
    let (_, _, mallory) = person(&s).await;
    put(&alice_c, &upload(&Signer::new(&rand32()), 0, 10)).await;
    let mut one_time = 0;
    for _ in 0..4 {
        let (st, b) = fetch(&mallory, &alice).await;
        assert_eq!(st, 200);
        one_time += usize::from(b[0].kem_one_time);
    }
    assert_eq!(one_time, 2, "only the budget's worth of one-time keys");
    assert_eq!(counts(&alice_c).await, (8, 8));
    // The fetcher's own budget (4) is spent.
    assert_eq!(fetch(&mallory, &alice).await.0, 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_settings_nothing_is_served() {
    let Some(s) = stack(None).await else { return };
    let (alice, _, c) = person(&s).await;
    assert_eq!(fetch(&c, &alice).await.0, 503);
    assert_eq!(c.send("GET", "/v1/keys", None).await.unwrap().0, 503);
}

// ----- M3b: MLS KeyPackages -----

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A KeyPackage for `device`, valid now (or `expired`), single use or last resort.
fn key_package(device: &DeviceId, last_resort: bool, expired: bool) -> Vec<u8> {
    let signer = Ed25519KeyPair::generate().unwrap();
    let (init, enc) = (
        Signer::new(&rand32()).public(),
        Signer::new(&rand32()).public(),
    );
    let now = now_secs();
    let (nb, na) = if expired {
        (now - 7_200, now - 3_600)
    } else {
        (now - 60, now + 30 * 86_400)
    };
    songbird_keys::mls::encode(
        &songbird_keys::mls::Params {
            cipher_suite: 0x0001,
            init_key: &init,
            encryption_key: &enc,
            identity: device.as_bytes(),
            not_before: nb,
            not_after: na,
            last_resort,
        },
        &signer,
    )
}

async fn put_kps(c: &ApiClient, packages: &[Vec<u8>]) -> (u16, String) {
    let refs: Vec<&[u8]> = packages.iter().map(Vec::as_slice).collect();
    let body = wire::encode_key_packages(&refs);
    let (s, b) = c.send("PUT", "/v1/keypackages", Some(&body)).await.unwrap();
    (s, String::from_utf8_lossy(&b).into_owned())
}

async fn fetch_kps(c: &ApiClient, account: &AccountId) -> (u16, Vec<wire::KeyPackageBundle>) {
    let body = format!(r#"{{"account":"{}"}}"#, account.to_hex_unredacted());
    let (s, b) = c
        .send("POST", "/v1/keypackages/fetch", Some(body.as_bytes()))
        .await
        .unwrap();
    let bundles = if s == 200 {
        wire::decode_key_package_bundles(&b).unwrap()
    } else {
        Vec::new()
    };
    (s, bundles)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_packages_are_bound_to_their_device_and_served_once() {
    let Some(s) = stack(Some(settings(KeyThrottle::default()))).await else {
        return;
    };
    let (alice, alice_dev, alice_c) = person(&s).await;
    let (_, _, bob_c) = person(&s).await;
    assert_eq!(fetch_kps(&bob_c, &alice).await.0, 404);
    let packages: Vec<_> = (0..3)
        .map(|_| key_package(&alice_dev, false, false))
        .collect();
    let mut upload = packages.clone();
    upload.push(key_package(&alice_dev, true, false));
    assert_eq!(put_kps(&alice_c, &upload).await.0, 204);
    let (st, b) = alice_c.send("GET", "/v1/keypackages", None).await.unwrap();
    assert_eq!(st, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&b).unwrap(),
        serde_json::json!({ "single_use": 3, "last_resort": true })
    );
    let mut seen = std::collections::HashSet::new();
    for _ in 0..3 {
        let (st, b) = fetch_kps(&bob_c, &alice).await;
        assert_eq!(st, 200);
        assert!(b[0].one_time);
        // What a client checks before adding Alice's device to a group (here, our own checks).
        songbird_keys::mls::check(&b[0].package, alice_dev.as_bytes(), now_secs()).unwrap();
        assert!(
            seen.insert(b[0].package.clone()),
            "a KeyPackage handed out twice"
        );
    }
    let (_, b) = fetch_kps(&bob_c, &alice).await;
    assert!(
        !b[0].one_time,
        "the last-resort package once single use runs out"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_packages_for_another_device_or_out_of_date_are_refused() {
    let Some(s) = stack(Some(settings(KeyThrottle::default()))).await else {
        return;
    };
    let (_, dev, c) = person(&s).await;
    let other = DeviceId::random().unwrap();
    let cases = [
        (
            vec![key_package(&other, false, false)],
            r#"{"error":"identity"}"#,
        ),
        (
            vec![key_package(&dev, false, true)],
            r#"{"error":"lifetime"}"#,
        ),
        (
            vec![
                key_package(&dev, true, false),
                key_package(&dev, true, false),
            ],
            r#"{"error":"last resort"}"#,
        ),
    ];
    for (upload, want) in cases {
        assert_eq!(put_kps(&c, &upload).await, (400, want.to_owned()));
    }
    let one = key_package(&dev, false, false);
    assert_eq!(
        put_kps(&c, &[one.clone(), one.clone()]).await,
        (400, r#"{"error":"duplicate"}"#.into())
    );
    assert_eq!(put_kps(&c, std::slice::from_ref(&one)).await.0, 204);
    assert_eq!(
        put_kps(&c, std::slice::from_ref(&one)).await,
        (409, r#"{"error":"duplicate"}"#.into())
    );
    // A tampered package (its last signature byte).
    let mut bad = key_package(&dev, false, false);
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        put_kps(&c, &[bad]).await,
        (400, r#"{"error":"signature"}"#.into())
    );
    assert_eq!(
        c.send("PUT", "/v1/keypackages", Some(&[1, 0]))
            .await
            .unwrap()
            .0,
        400
    );
}
