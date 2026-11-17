//! Usernames, the username key and links over HTTP against SurrealDB and `valkey-hot` (Prompt 3,
//! M2, D-0049). Runs when `SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`) and
//! `SONGBIRD_TEST_VALKEY` are set; with `SONGBIRD_REQUIRE_STACK=1` a missing one fails instead of
//! skipping. Every test has its own database and secret, so throttle records never meet.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use songbird_accounts::{Db, Registry};
use songbird_api::client::ApiClient;
use songbird_api::config::{KeyCost, UsernameSettings, UsernameThrottle};
use songbird_api::usernames::{UsernameMetrics, Usernames};
use songbird_api::{ApiMetrics, App};
use songbird_jobs::{Queue, QueueConfig};
use songbird_keys::username::Username;
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

fn settings(key: KeyCost, throttle: UsernameThrottle) -> UsernameSettings {
    UsernameSettings {
        secret: SecretRef::Env("UNUSED".into()),
        reserved: vec!["songbird_ops".into()],
        max_concurrent_key_checks: 2,
        key,
        throttle,
    }
}

/// Cheap Argon2id so most tests run fast; the timing test uses the real defaults.
const CHEAP: KeyCost = KeyCost {
    memory_kib: 8,
    iterations: 1,
};

async fn stack(u: Option<UsernameSettings>) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("uname_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    let s3 = songbird_s3::Client::new(songbird_s3::Config::new(
        "127.0.0.1:9".into(),
        "unused".into(),
        Secret::new("unused".into()),
        Secret::new("unused-secret".into()),
    ))
    .unwrap();
    let queue = Queue::connect(
        redis::Client::open(hot.clone()).unwrap(),
        &[3; 32],
        QueueConfig::new("uname-test".into()),
    )
    .await
    .unwrap();
    let hot = songbird_valkey::ValkeyConn::connect(redis::Client::open(hot).unwrap())
        .await
        .unwrap();
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).unwrap();
    let usernames = u.map(|u| Usernames::new(u, &secret, UsernameMetrics::default()).unwrap());
    let app = Arc::new(App {
        requests: None,
        reports: None,
        server_name: SERVER.into(),
        registry,
        s3,
        queue: Arc::new(queue),
        hot,
        push_public: [0; 32],
        push_index_secret: [9; 32],
        limits: songbird_api::config::AttachmentLimits::default(),
        media: None,
        metrics: ApiMetrics::default(),
        messages: None,
        registration: None,
        usernames,
        keys: None,
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
        _stop: stop,
    })
}

/// A new account with one device.
async fn person(s: &Stack) -> (AccountId, ApiClient) {
    let kp = Ed25519KeyPair::generate().unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.public_key().as_ref());
    let (a, d) = (AccountId::random().unwrap(), DeviceId::random().unwrap());
    s.app.registry.create_account(&a, &[(d, pk)]).await.unwrap();
    (a, ApiClient::new(s.addr, SERVER, d, kp))
}

fn claim_body(name: &str) -> Vec<u8> {
    let u = Username::parse(name).unwrap();
    let mut r = [0u8; 32];
    getrandom::fill(&mut r).unwrap();
    let mut b = u.hash().to_vec();
    b.extend_from_slice(&u.proof(&r));
    b
}

fn lookup_body(name: &str, key: Option<&str>) -> Vec<u8> {
    let h = hex::encode(Username::parse(name).unwrap().hash());
    match key {
        Some(k) => format!(r#"{{"hash":"{h}","key":"{k}"}}"#),
        None => format!(r#"{{"hash":"{h}"}}"#),
    }
    .into_bytes()
}

async fn lookup(c: &ApiClient, name: &str, key: Option<&str>) -> (u16, Option<String>) {
    let (status, body) = c
        .send("POST", "/v1/username/lookup", Some(&lookup_body(name, key)))
        .await
        .unwrap();
    let account = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["account"].as_str().map(str::to_owned));
    (status, account)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unique_claims_reserved_names_proofs_and_holds() {
    // Bob makes many claim attempts here; the change budget is tested on its own below.
    let throttle = UsernameThrottle {
        change_burst: 100,
        ..UsernameThrottle::default()
    };
    let Some(s) = stack(Some(settings(CHEAP, throttle))).await else {
        return;
    };
    let (alice_id, alice) = person(&s).await;
    let (_, bob) = person(&s).await;
    assert_eq!(
        alice
            .send("PUT", "/v1/username", Some(&claim_body("Radu")))
            .await
            .unwrap()
            .0,
        204
    );
    // Found by exact match, in any case; nobody else may claim it.
    let want = Some(alice_id.to_hex_unredacted());
    assert_eq!(lookup(&bob, "radu", None).await, (200, want.clone()));
    assert_eq!(lookup(&bob, "RADU", None).await, (200, want.clone()));
    assert_eq!(lookup(&bob, "rad", None).await.0, 404);
    let taken = bob
        .send("PUT", "/v1/username", Some(&claim_body("radu")))
        .await
        .unwrap();
    assert_eq!((taken.0, &taken.1[..]), (409, &br#"{"error":"taken"}"#[..]));
    // Reserved names (built in, and from configuration) answer the same.
    for name in ["admin", "Support", "songbird_ops"] {
        let r = bob
            .send("PUT", "/v1/username", Some(&claim_body(name)))
            .await
            .unwrap();
        assert_eq!(r.0, 409, "{name}");
    }
    // A claim without a valid proof: someone else's hash with a proof for another name, a
    // short body, a random point.
    let mut forged = Username::parse("mallory").unwrap().hash().to_vec();
    forged.extend_from_slice(&claim_body("eve")[32..]);
    assert_eq!(
        bob.send("PUT", "/v1/username", Some(&forged))
            .await
            .unwrap(),
        (400, bytes::Bytes::from_static(br#"{"error":"proof"}"#))
    );
    assert_eq!(
        bob.send("PUT", "/v1/username", Some(&[1; 40]))
            .await
            .unwrap()
            .0,
        400
    );
    // Alice changes: the old name is held, found by nobody and claimable by nobody.
    assert_eq!(
        alice
            .send("PUT", "/v1/username", Some(&claim_body("radu.d")))
            .await
            .unwrap()
            .0,
        204
    );
    assert_eq!(lookup(&bob, "radu", None).await.0, 404);
    assert_eq!(
        bob.send("PUT", "/v1/username", Some(&claim_body("radu")))
            .await
            .unwrap()
            .0,
        409
    );
    assert_eq!(lookup(&bob, "radu.d", None).await, (200, want));
    // Release: not found.
    assert_eq!(
        alice.send("DELETE", "/v1/username", None).await.unwrap().0,
        204
    );
    assert_eq!(lookup(&bob, "radu.d", None).await.0, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_username_key_answers_not_found_to_strangers_without_it() {
    let throttle = UsernameThrottle {
        key_failure_burst: 4,
        key_failures_per_hour: 1,
        ..UsernameThrottle::default()
    };
    let Some(s) = stack(Some(settings(CHEAP, throttle))).await else {
        return;
    };
    let (alice_id, alice) = person(&s).await;
    let (_, bob) = person(&s).await;
    alice
        .send("PUT", "/v1/username", Some(&claim_body("alice")))
        .await
        .unwrap();
    assert_eq!(
        alice
            .send("PUT", "/v1/username/key", Some(br#"{"key":"482916"}"#))
            .await
            .unwrap()
            .0,
        204
    );
    let m = &s.app.usernames.as_ref().unwrap().metrics;
    let checks = || m.key_checks.get();
    let want = Some(alice_id.to_hex_unredacted());
    // Without the key: exactly like a username that does not exist, and no key check either way.
    let before = checks();
    assert_eq!(lookup(&bob, "alice", None).await, (404, None));
    assert_eq!(lookup(&bob, "nobody_here", None).await, (404, None));
    assert_eq!(checks(), before);
    // With a key: one check whatever the case (wrong key, unknown username, right key).
    assert_eq!(lookup(&bob, "alice", Some("111111")).await, (404, None));
    assert_eq!(
        lookup(&bob, "nobody_here", Some("111111")).await,
        (404, None)
    );
    assert_eq!(
        lookup(&bob, "alice", Some("482916")).await,
        (200, want.clone())
    );
    assert_eq!(checks(), before + 3);
    // A key of the wrong shape is a client error, not a guess.
    assert_eq!(lookup(&bob, "alice", Some("12")).await.0, 400);
    // Guesses are limited per username across everyone: once the budget is spent (burst 4, one
    // spent above), even the right key finds nothing.
    let (_, carol) = person(&s).await;
    for k in ["000001", "000002", "000003"] {
        assert_eq!(lookup(&carol, "alice", Some(k)).await.0, 404);
    }
    assert_eq!(lookup(&carol, "alice", Some("482916")).await.0, 404);
    // Removing the key makes the username findable again without one.
    alice
        .send("DELETE", "/v1/username/key", None)
        .await
        .unwrap();
    assert_eq!(lookup(&bob, "alice", None).await, (200, want));
    // Shapes refused when setting a key.
    for bad in [
        &br#"{"key":"123"}"#[..],
        br#"{"key":"12345678901"}"#,
        br#"{"key":"12a456"}"#,
    ] {
        assert_eq!(
            alice
                .send("PUT", "/v1/username/key", Some(bad))
                .await
                .unwrap()
                .0,
            400
        );
    }
}

/// The keyed path costs the same whether the username exists or not (one Argon2id run at the
/// production cost dominates): mean times within a factor of 1.5 over 15 lookups each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keyed_lookups_take_the_same_time_whether_or_not_the_username_exists() {
    let throttle = UsernameThrottle {
        key_failure_burst: 1_000,
        lookup_burst: 1_000,
        range_lookup_burst: 1_000,
        ..UsernameThrottle::default()
    };
    let Some(s) = stack(Some(settings(KeyCost::default(), throttle))).await else {
        return;
    };
    let (_, alice) = person(&s).await;
    let (_, bob) = person(&s).await;
    alice
        .send("PUT", "/v1/username", Some(&claim_body("timing_target")))
        .await
        .unwrap();
    alice
        .send("PUT", "/v1/username/key", Some(br#"{"key":"55555555"}"#))
        .await
        .unwrap();
    let mean = |name: &'static str| {
        let bob = &bob;
        async move {
            let mut total = Duration::ZERO;
            for _ in 0..15 {
                let t = Instant::now();
                assert_eq!(lookup(bob, name, Some("12345678")).await.0, 404);
                total += t.elapsed();
            }
            total.as_secs_f64() / 15.0
        }
    };
    // Warm up, then alternate.
    let _ = mean("timing_target").await;
    let existing = mean("timing_target").await;
    let absent = mean("no_such_user").await;
    let ratio = existing / absent;
    println!("keyed lookup mean: existing {existing:.4} s, absent {absent:.4} s, ratio {ratio:.3}");
    assert!((1.0 / 1.5..=1.5).contains(&ratio), "ratio {ratio}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn links_reset_and_need_a_username() {
    let Some(s) = stack(Some(settings(CHEAP, UsernameThrottle::default()))).await else {
        return;
    };
    let (_, alice) = person(&s).await;
    let (_, bob) = person(&s).await;
    let no = alice
        .send("PUT", "/v1/username/link", Some(b"ciphertext"))
        .await
        .unwrap();
    assert_eq!((no.0, &no.1[..]), (409, &br#"{"error":"no username"}"#[..]));
    alice
        .send("PUT", "/v1/username", Some(&claim_body("linked")))
        .await
        .unwrap();
    let handle = |b: &[u8]| {
        serde_json::from_slice::<serde_json::Value>(b).unwrap()["handle"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (st, b) = alice
        .send("PUT", "/v1/username/link", Some(b"first-ciphertext"))
        .await
        .unwrap();
    assert_eq!(st, 200);
    let first = handle(&b);
    let get = |h: String| {
        let bob = &bob;
        async move {
            bob.send("GET", &format!("/v1/username/link/{h}"), None)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        get(first.clone()).await,
        (200, bytes::Bytes::from_static(b"first-ciphertext"))
    );
    // A reset: a new handle; the old one is gone.
    let (_, b) = alice
        .send("PUT", "/v1/username/link", Some(b"second"))
        .await
        .unwrap();
    let second = handle(&b);
    assert_ne!(first, second);
    assert_eq!(get(first).await.0, 404);
    assert_eq!(get(second.clone()).await.0, 200);
    // Bounded size; a malformed handle; deletion.
    assert_eq!(
        alice
            .send("PUT", "/v1/username/link", Some(&[0; 257]))
            .await
            .unwrap()
            .0,
        400
    );
    assert_eq!(get("zz".into()).await.0, 404);
    alice
        .send("DELETE", "/v1/username/link", None)
        .await
        .unwrap();
    assert_eq!(get(second).await.0, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookups_and_claims_are_throttled() {
    let throttle = UsernameThrottle {
        lookup_burst: 3,
        lookups_per_hour: 1,
        change_burst: 2,
        changes_per_hour: 1,
        ..UsernameThrottle::default()
    };
    let Some(s) = stack(Some(settings(CHEAP, throttle))).await else {
        return;
    };
    let (_, alice) = person(&s).await;
    for _ in 0..3 {
        assert_eq!(lookup(&alice, "someone", None).await.0, 404);
    }
    assert_eq!(lookup(&alice, "someone", None).await.0, 429);
    // Claims: every attempt counts, taken or not.
    for name in ["first_name", "second_name"] {
        assert_eq!(
            alice
                .send("PUT", "/v1/username", Some(&claim_body(name)))
                .await
                .unwrap()
                .0,
            204
        );
    }
    assert_eq!(
        alice
            .send("PUT", "/v1/username", Some(&claim_body("third_name")))
            .await
            .unwrap()
            .0,
        429
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_settings_or_a_signature_nothing_is_served() {
    let Some(s) = stack(None).await else { return };
    let (_, alice) = person(&s).await;
    assert_eq!(lookup(&alice, "anyone", None).await.0, 503);
    let Some(s) = stack(Some(settings(CHEAP, UsernameThrottle::default()))).await else {
        return;
    };
    let stranger = ApiClient::new(
        s.addr,
        SERVER,
        DeviceId::random().unwrap(),
        Ed25519KeyPair::generate().unwrap(),
    );
    assert_eq!(lookup(&stranger, "anyone", None).await.0, 401);
}

/// Prompt 3, M4 (D-0052): a pending device (linked, not yet in a signed list) changes nothing
/// account-wide, but may look up; only the primary deletes the account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_device_changes_nothing_account_wide_and_only_the_primary_deletes() {
    let Some(s) = stack(Some(settings(CHEAP, UsernameThrottle::default()))).await else {
        return;
    };
    // The primary (first device) and a device linked through a token: pending.
    let kp = Ed25519KeyPair::generate().unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(kp.public_key().as_ref());
    let (a, primary) = (AccountId::random().unwrap(), DeviceId::random().unwrap());
    s.app
        .registry
        .create_account(&a, &[(primary, pk)])
        .await
        .unwrap();
    let primary_c = ApiClient::new(s.addr, SERVER, primary, kp);
    let linked = DeviceId::random().unwrap();
    let mut token = [0u8; 32];
    getrandom::fill(&mut token).unwrap();
    s.app
        .registry
        .create_link_token(&primary, &token, &linked, Duration::from_secs(60), 6)
        .await
        .unwrap();
    let lkp = Ed25519KeyPair::generate().unwrap();
    let mut lpk = [0u8; 32];
    lpk.copy_from_slice(lkp.public_key().as_ref());
    let mut ik = [7u8; 33];
    ik[0] = 5;
    s.app
        .registry
        .link_device(&token, &linked, &lpk, &ik, &[0; 32], 6)
        .await
        .unwrap();
    let linked_c = ApiClient::new(s.addr, SERVER, linked, lkp);
    let refused = |r: (u16, bytes::Bytes)| {
        assert_eq!(
            (r.0, r.1.as_ref()),
            (403, br#"{"error":"pending"}"#.as_slice())
        );
    };
    refused(
        linked_c
            .send("PUT", "/v1/username", Some(&claim_body("Pendingclaim")))
            .await
            .unwrap(),
    );
    refused(linked_c.send("DELETE", "/v1/username", None).await.unwrap());
    refused(
        linked_c
            .send("DELETE", "/v1/username/key", None)
            .await
            .unwrap(),
    );
    refused(
        linked_c
            .send("DELETE", "/v1/username/link", None)
            .await
            .unwrap(),
    );
    // Lookups are not changes.
    assert_eq!(lookup(&linked_c, "Nobodyhere", None).await.0, 404);
    // Account deletion: never from a linked device; the primary can.
    let (st, b) = linked_c.send("DELETE", "/v1/account", None).await.unwrap();
    assert_eq!(
        (st, b.as_ref()),
        (403, br#"{"error":"primary"}"#.as_slice())
    );
    assert!(
        !s.app
            .registry
            .device(&primary)
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
    assert_eq!(
        primary_c
            .send("DELETE", "/v1/account", None)
            .await
            .unwrap()
            .0,
        202
    );
    assert!(
        s.app
            .registry
            .device(&linked)
            .await
            .unwrap()
            .unwrap()
            .disabled
    );
}
