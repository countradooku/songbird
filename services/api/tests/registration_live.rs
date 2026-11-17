//! Registration and invites over HTTP against SurrealDB and `valkey-hot` (Prompt 3, M1, D-0048).
//! Runs when `SONGBIRD_TEST_SURREALDB` (+ `_USER`, `_PASS`) and `SONGBIRD_TEST_VALKEY` are set;
//! with `SONGBIRD_REQUIRE_STACK=1` a missing one fails instead of skipping. Every test has its own
//! database and its own registration secret, so their throttle records never meet.
//!
//! The invite gate of Prompt 3 (D-0038): valid, expired, reused and guessed codes; quota limits;
//! invite-only mode switched off.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use songbird_accounts::{Db, Registry, invite_hash};
use songbird_api::client::{ApiClient, Registered, Registrar};
use songbird_api::config::{PowSettings, RegistrationSettings, ThrottleSettings};
use songbird_api::registration::{Registration, RegistrationMetrics};
use songbird_api::{ApiMetrics, App};
use songbird_jobs::{Queue, QueueConfig};
use songbird_proto::registration::{INVITE_LEN, invite};
use songbird_types::{AccountId, DeviceId, Secret, SecretRef};

const SERVER: &str = "api.test";

/// Cheap work so the tests run fast; the real defaults are measured in D-0048.
const CHEAP: PowSettings = PowSettings {
    memory_kib: 8,
    iterations: 1,
    bits: 2,
    solutions: 2,
};

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

fn settings(invite_only: bool, allowance: u32, throttle: ThrottleSettings) -> RegistrationSettings {
    RegistrationSettings {
        secret: SecretRef::Env("UNUSED".into()),
        invite_only,
        allowance,
        invite_ttl_days: 7,
        challenge_ttl_secs: 600,
        max_concurrent_verifications: 2,
        pow: CHEAP,
        throttle,
    }
}

async fn stack(reg: RegistrationSettings) -> Option<Stack> {
    stack_with(Some(reg)).await
}

async fn stack_with(reg: Option<RegistrationSettings>) -> Option<Stack> {
    let surreal = env("SONGBIRD_TEST_SURREALDB")?;
    let hot = env("SONGBIRD_TEST_VALKEY")?;
    let db = Db::connect(songbird_surreal::Config {
        addr: surreal,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").unwrap(),
        namespace: "test".into(),
        database: format!("reg_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    })
    .await
    .unwrap();
    let registry = Arc::new(Registry::connect(db).await.unwrap());
    // Registration needs neither the object store nor the job queue; both are constructed
    // without connecting (the queue against valkey-hot, never used here).
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
        QueueConfig::new("reg-test".into()),
    )
    .await
    .unwrap();
    let hot = songbird_valkey::ValkeyConn::connect(redis::Client::open(hot).unwrap())
        .await
        .unwrap();
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).unwrap();
    let registration =
        reg.map(|r| Registration::new(r, &secret, RegistrationMetrics::default()).unwrap());
    let app = Arc::new(App {
        requests: None,
        reports: None,
        calls: None,
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
        registration,
        usernames: None,
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

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::generate().unwrap()
}

/// An operator's code (`songbird-admin invites create`).
async fn admin_code(s: &Stack, uses: u32, ttl: Duration) -> [u8; INVITE_LEN] {
    let mut c = [0u8; INVITE_LEN];
    getrandom::fill(&mut c).unwrap();
    s.app
        .registry
        .create_invites(&[invite_hash(&c)], uses, ttl)
        .await
        .unwrap();
    c
}

fn registrar(s: &Stack) -> Registrar {
    Registrar::new(s.addr, SERVER)
}

async fn register(s: &Stack, invite: Option<[u8; INVITE_LEN]>) -> Registered {
    registrar(s).register(&key(), &key(), invite).await.unwrap()
}

fn refused(r: &Registered) -> (u16, String) {
    match r {
        Registered::Refused((status, body)) => {
            (*status, String::from_utf8_lossy(body).into_owned())
        }
        Registered::Ok { .. } => panic!("registered"),
    }
}

/// Registers and returns a signed client for the new device.
async fn new_device(s: &Stack, invite: Option<[u8; INVITE_LEN]>) -> (AccountId, ApiClient) {
    let (identity, auth) = (key(), key());
    let mut auth_pk = [0u8; 32];
    auth_pk.copy_from_slice(auth.public_key().as_ref());
    match registrar(s)
        .register(&identity, &auth, invite)
        .await
        .unwrap()
    {
        Registered::Ok { account, device } => {
            let row = s.app.registry.device(&device).await.unwrap().unwrap();
            assert_eq!(
                (row.account, row.key, row.disabled),
                (account, auth_pk, false)
            );
            let mut id_pk = [0u8; 32];
            id_pk.copy_from_slice(identity.public_key().as_ref());
            assert_eq!(
                s.app.registry.identity_key(&account).await.unwrap(),
                Some(id_pk)
            );
            (account, ApiClient::new(s.addr, SERVER, device, auth))
        }
        Registered::Refused(r) => panic!("refused {r:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_codes_valid_expired_reused_and_guessed() {
    let Some(s) = stack(settings(true, 5, ThrottleSettings::default())).await else {
        return;
    };
    // Valid: registers, and the new device can sign requests at once.
    let code = admin_code(&s, 1, Duration::from_secs(3600)).await;
    let (_, client) = new_device(&s, Some(code)).await;
    let (status, body) = client.send("GET", "/v1/invites", None).await.unwrap();
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["allowance"], 5);
    assert_eq!(v["invite_only"], true);

    // Reused, expired, guessed and missing: one answer for the first three.
    let reused = refused(&register(&s, Some(code)).await);
    let short = admin_code(&s, 1, Duration::from_secs(1)).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let expired = refused(&register(&s, Some(short)).await);
    let mut guess = [0u8; INVITE_LEN];
    getrandom::fill(&mut guess).unwrap();
    let guessed = refused(&register(&s, Some(guess)).await);
    let expected = (403, r#"{"error":"invite"}"#.to_owned());
    assert_eq!(reused, expected);
    assert_eq!(expired, expected);
    assert_eq!(guessed, expected);
    assert_eq!(refused(&register(&s, None).await), expected);
    // Nothing was created by the refusals: one account in the database.
    let n = s
        .app
        .registry
        .db()
        .query1("SELECT VALUE count() FROM account GROUP ALL;", Vec::new())
        .await
        .unwrap();
    assert_eq!(
        n.into_array().unwrap()[0].as_i64(),
        Some(1),
        "one account only"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guessing_codes_is_throttled_before_any_work() {
    let throttle = ThrottleSettings {
        invite_failure_burst: 2,
        invite_failures_per_hour: 1,
        ..ThrottleSettings::default()
    };
    let Some(s) = stack(settings(true, 5, throttle)).await else {
        return;
    };
    let guess = || {
        let mut g = [0u8; INVITE_LEN];
        getrandom::fill(&mut g).unwrap();
        Some(g)
    };
    // The burst of refused codes (each one paid for with a solved challenge)...
    for _ in 0..2 {
        assert_eq!(refused(&register(&s, guess()).await).0, 403);
    }
    // ...then the range waits, and is told how long, before its challenge is even checked.
    let (status, _) = refused(&register(&s, guess()).await);
    assert_eq!(status, 429);
    let r = registrar(&s);
    let (_, ch) = r.challenge().await.unwrap();
    let c = songbird_pow::decode(&ch).unwrap();
    // An unsolved request: refused by the throttle, not the work.
    let req = r.request(&c.bytes, vec![0, 1], guess(), &key(), &key());
    let (status, _) = r.submit(req.encode()).await.unwrap();
    assert_eq!(status, 429);
    // A valid code is held up too: the throttle is per range, not per code.
    let code = admin_code(&s, 1, Duration::from_secs(3600)).await;
    assert_eq!(refused(&register(&s, Some(code)).await).0, 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_invites_spend_a_quota_and_can_be_revoked() {
    let Some(s) = stack(settings(true, 2, ThrottleSettings::default())).await else {
        return;
    };
    let first = admin_code(&s, 1, Duration::from_secs(3600)).await;
    let (_, inviter) = new_device(&s, Some(first)).await;
    let mut codes = Vec::new();
    for _ in 0..2 {
        let (status, body) = inviter
            .send("POST", "/v1/invites", Some(br#"{"ttl_days":30}"#))
            .await
            .unwrap();
        assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Capped at the configured lifetime (7 days).
        assert_eq!(v["expires_in_secs"], 7 * 86_400);
        codes.push(invite::parse(v["code"].as_str().unwrap()).unwrap());
    }
    // The quota is spent.
    let (status, body) = inviter.send("POST", "/v1/invites", None).await.unwrap();
    assert_eq!((status, &body[..]), (403, &br#"{"error":"allowance"}"#[..]));
    // One code is used; the other revoked, and refused afterwards.
    new_device(&s, Some(codes[0])).await;
    let revoke = format!(r#"{{"code":"{}"}}"#, invite::format(&codes[1]));
    let (status, _) = inviter
        .send("DELETE", "/v1/invites", Some(revoke.as_bytes()))
        .await
        .unwrap();
    assert_eq!(status, 204);
    assert_eq!(refused(&register(&s, Some(codes[1])).await).0, 403);
    // Revoking again (or a code that never existed) gives the same answer.
    let (status, _) = inviter
        .send("DELETE", "/v1/invites", Some(revoke.as_bytes()))
        .await
        .unwrap();
    assert_eq!(status, 204);
    // An unsigned invite request is refused.
    let anonymous = ApiClient::new(s.addr, SERVER, DeviceId::random().unwrap(), key());
    assert_eq!(
        anonymous.send("POST", "/v1/invites", None).await.unwrap().0,
        401
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invite_only_mode_switched_off() {
    let Some(s) = stack(settings(false, 0, ThrottleSettings::default())).await else {
        return;
    };
    let (_, client) = new_device(&s, None).await;
    // A code, even a made-up one, is ignored: nothing to consume.
    new_device(&s, Some([7; INVITE_LEN])).await;
    let v: serde_json::Value =
        serde_json::from_slice(&client.send("GET", "/v1/invites", None).await.unwrap().1).unwrap();
    assert_eq!(
        (v["allowance"].as_u64(), v["invite_only"].as_bool()),
        (Some(0), Some(false))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn challenges_are_authenticated_single_use_and_must_be_solved() {
    let Some(s) = stack(settings(false, 0, ThrottleSettings::default())).await else {
        return;
    };
    let r = registrar(&s);
    let fresh = || async {
        let (status, body) = r.challenge().await.unwrap();
        assert_eq!(status, 200);
        songbird_pow::decode(&body).unwrap()
    };
    let challenge = r#"{"error":"challenge"}"#;
    // Solved and submitted twice: the second is a replay.
    let c = fresh().await;
    let sol = songbird_pow::solve(&c).unwrap().unwrap();
    let body = r.request(&c.bytes, sol, None, &key(), &key()).encode();
    assert_eq!(r.submit(body.clone()).await.unwrap().0, 201);
    let (status, b) = r.submit(body).await.unwrap();
    assert_eq!((status, &b[..]), (403, challenge.as_bytes()));
    // Wrong solutions burn the challenge too: a corrected retry needs a new one.
    let c = fresh().await;
    let good = songbird_pow::solve(&c).unwrap().unwrap();
    let bad = (0..u32::MAX)
        .filter(|&n| !songbird_pow::meets(&songbird_pow::evaluate(&c, n).unwrap(), c.params.bits))
        .take(2)
        .collect::<Vec<_>>();
    let (status, _) = r
        .submit(r.request(&c.bytes, bad, None, &key(), &key()).encode())
        .await
        .unwrap();
    assert_eq!(status, 403);
    let (status, _) = r
        .submit(r.request(&c.bytes, good, None, &key(), &key()).encode())
        .await
        .unwrap();
    assert_eq!(status, 403);
    // A challenge this deployment did not issue (one byte changed) is refused.
    let c = fresh().await;
    let mut forged = c.bytes;
    forged[2] ^= 1;
    let (status, _) = r
        .submit(
            r.request(&forged, vec![0, 1], None, &key(), &key())
                .encode(),
        )
        .await
        .unwrap();
    assert_eq!(status, 403);
    // Bodies: without a length, too long, or not a request.
    let raw = |len: Option<usize>, body: Vec<u8>| {
        let mut b = hyper::Request::builder()
            .method("POST")
            .uri("/v1/registration")
            .header("host", SERVER);
        if let Some(l) = len {
            b = b.header("content-length", l);
        }
        (b, Bytes::from(body))
    };
    let client = ApiClient::new(s.addr, SERVER, DeviceId::random().unwrap(), key());
    let (b, body) = raw(None, Vec::new());
    assert_eq!(client.raw(b, body).await.unwrap().0, 411);
    let (b, body) = raw(Some(4_096), vec![0; 4_096]);
    assert_eq!(client.raw(b, body).await.unwrap().0, 413);
    let (b, body) = raw(Some(3), vec![1, 2, 3]);
    assert_eq!(client.raw(b, body).await.unwrap().0, 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_must_be_distinct_honest_and_signed_for_this_server() {
    let Some(s) = stack(settings(false, 0, ThrottleSettings::default())).await else {
        return;
    };
    let r = registrar(&s);
    let solved = || async {
        let (_, body) = r.challenge().await.unwrap();
        let c = songbird_pow::decode(&body).unwrap();
        let sol = songbird_pow::solve(&c).unwrap().unwrap();
        (c, sol)
    };
    let keys = r#"{"error":"keys"}"#.as_bytes();
    // One key for both roles.
    let (c, sol) = solved().await;
    let k = key();
    let (status, b) = r
        .submit(r.request(&c.bytes, sol, None, &k, &k).encode())
        .await
        .unwrap();
    assert_eq!((status, &b[..]), (400, keys));
    // The identity point as identity key, with a "signature" that verifies under it for any
    // message (R = sB): refused by the point check (`songbird-keys`).
    let (c, sol) = solved().await;
    let mut req = r.request(&c.bytes, sol, None, &key(), &key());
    req.identity_key = [0; 32];
    req.identity_key[0] = 1;
    let (status, b) = r.submit(req.encode()).await.unwrap();
    assert_eq!((status, &b[..]), (400, keys));
    // Signatures swapped between the roles.
    let (c, sol) = solved().await;
    let mut req = r.request(&c.bytes, sol, None, &key(), &key());
    std::mem::swap(&mut req.identity_sig, &mut req.auth_sig);
    assert_eq!(r.submit(req.encode()).await.unwrap().0, 400);
    // Signed for another server.
    let (c, sol) = solved().await;
    let other = Registrar::new(s.addr, "api.elsewhere");
    let req = other.request(&c.bytes, sol, None, &key(), &key());
    assert_eq!(r.submit(req.encode()).await.unwrap().0, 400);
    // None of these spent the challenge's single use on a wasted Argon2id run: the keys are
    // checked first. (The refusals above happened before the nonce was burnt, so the honest
    // request with the last challenge still succeeds.)
    let req = r.request(
        &c.bytes,
        songbird_pow::solve(&c).unwrap().unwrap(),
        None,
        &key(),
        &key(),
    );
    assert_eq!(r.submit(req.encode()).await.unwrap().0, 201);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn challenges_and_registrations_are_throttled_per_range() {
    let throttle = ThrottleSettings {
        challenge_burst: 3,
        challenges_per_hour: 1,
        registration_burst: 2,
        registrations_per_hour: 1,
        ..ThrottleSettings::default()
    };
    let Some(s) = stack(settings(false, 0, throttle)).await else {
        return;
    };
    let r = registrar(&s);
    let mut challenges = Vec::new();
    for _ in 0..3 {
        let (status, body) = r.challenge().await.unwrap();
        assert_eq!(status, 200);
        challenges.push(songbird_pow::decode(&body).unwrap());
    }
    let req = hyper::Request::builder()
        .method("POST")
        .uri("/v1/registration/challenge")
        .header("host", SERVER)
        .header("content-length", 0);
    let client = ApiClient::new(s.addr, SERVER, DeviceId::random().unwrap(), key());
    let (status, _) = client.raw(req, Bytes::new()).await.unwrap();
    assert_eq!(status, 429);
    // Registrations: two, then the range waits.
    for c in &challenges[..2] {
        let sol = songbird_pow::solve(c).unwrap().unwrap();
        let (status, _) = r
            .submit(r.request(&c.bytes, sol, None, &key(), &key()).encode())
            .await
            .unwrap();
        assert_eq!(status, 201);
    }
    let c = &challenges[2];
    let sol = songbird_pow::solve(c).unwrap().unwrap();
    let (status, _) = r
        .submit(r.request(&c.bytes, sol, None, &key(), &key()).encode())
        .await
        .unwrap();
    assert_eq!(status, 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_registration_settings_the_endpoints_are_unavailable() {
    let Some(s) = stack_with(None).await else {
        return;
    };
    let r = registrar(&s);
    assert_eq!(r.challenge().await.unwrap().0, 503);
    assert_eq!(r.submit(vec![1]).await.unwrap().0, 503);
    let client = ApiClient::new(s.addr, SERVER, DeviceId::random().unwrap(), key());
    assert_eq!(
        client.send("GET", "/v1/invites", None).await.unwrap().0,
        503
    );
}
