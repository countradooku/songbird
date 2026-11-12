//! The push service's gate test: sealed registrations in a real SurrealDB, jobs on a real
//! `valkey-jobs`, the service's consumer in-process, and mock APNs, FCM and Web Push providers.
//!
//! Runs when `SONGBIRD_TEST_VALKEY_JOBS` (a `redis://` URL with credentials) and
//! `SONGBIRD_TEST_SURREALDB` (`host:port`, with `SONGBIRD_TEST_SURREALDB_PASS`) are set; with
//! `SONGBIRD_REQUIRE_VALKEY=1` or `SONGBIRD_REQUIRE_SURREALDB=1` a missing server fails instead
//! of skipping. It wipes the push stream, so it must not run beside `crates/jobs`'s live tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use songbird_accounts::push_token::{self, Registration};
use songbird_accounts::{Db, Registry, push_index};
use songbird_jobs::queue::DEAD_KEY;
use songbird_jobs::{ConsumeConfig, Job, Queue, QueueConfig, Stream, Work};
use songbird_push::{Handler, Kind, Providers, PushMetrics};
use songbird_push_providers::apns::{Apns, ApnsConfig};
use songbird_push_providers::fcm::{Fcm, FcmConfig, ServiceAccount};
use songbird_push_providers::test_support::{
    Behaviour, MockServer, RecordedRequest, TestCa, TestSubscription, p256_pkcs8, rsa_pkcs8,
};
use songbird_push_providers::webpush::{PLAINTEXT, WebPush, WebPushConfig};
use songbird_types::DeviceId;

struct Env {
    valkey: String,
    registry: Arc<Registry>,
}

async fn env() -> Option<Env> {
    let valkey = std::env::var("SONGBIRD_TEST_VALKEY_JOBS").ok();
    let surreal = std::env::var("SONGBIRD_TEST_SURREALDB").ok();
    assert!(
        valkey.is_some() || std::env::var("SONGBIRD_REQUIRE_VALKEY").is_err(),
        "SONGBIRD_REQUIRE_VALKEY is set but SONGBIRD_TEST_VALKEY_JOBS is not"
    );
    assert!(
        surreal.is_some() || std::env::var("SONGBIRD_REQUIRE_SURREALDB").is_err(),
        "SONGBIRD_REQUIRE_SURREALDB is set but SONGBIRD_TEST_SURREALDB is not"
    );
    let (valkey, addr) = (valkey?, surreal?);
    let cfg = songbird_surreal::Config {
        addr,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").expect("SONGBIRD_TEST_SURREALDB_PASS"),
        namespace: "test".into(),
        database: format!("push_{}", DeviceId::random().unwrap().to_hex_unredacted()),
        timeout: Duration::from_secs(5),
        max_message_bytes: 16 << 20,
    };
    let registry = Arc::new(
        Registry::connect(Db::connect(cfg).await.unwrap())
            .await
            .unwrap(),
    );
    Some(Env { valkey, registry })
}

async fn wipe(url: &str) {
    let client = redis::Client::open(url).unwrap();
    let mut c = client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis::cmd("DEL")
        .arg(&[Stream::Push.key(), Stream::Push.delayed_key(), DEAD_KEY])
        .query_async(&mut c)
        .await
        .unwrap();
}

async fn eventually(what: &str, mut ok: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !ok().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct Device {
    id: DeviceId,
    index: [u8; 32],
}

fn job(d: &Device, call: bool) -> Job {
    Job::new(Work::Push { device: d.id, call }).unwrap()
}

fn for_token<'a>(reqs: &'a [RecordedRequest], token: &str) -> Vec<&'a RecordedRequest> {
    reqs.iter()
        .filter(|r| String::from_utf8_lossy(&r.body).contains(token))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines, reason = "one end-to-end scenario, in phases")]
async fn offline_devices_get_one_constant_wake_up() {
    let Some(env) = env().await else { return };
    wipe(&env.valkey).await;

    // Keys: the push service's X25519 key (registrations are sealed to its public half) and the
    // push-index secret.
    let mut push_key = [0u8; 32];
    aws_lc_rs::rand::fill(&mut push_key).unwrap();
    let (_, push_public) = push_token::key_pair(&push_key).unwrap();
    let mut index_secret = [0u8; 32];
    aws_lc_rs::rand::fill(&mut index_secret).unwrap();

    let register = async |reg: Option<Registration>| {
        let id = DeviceId::random().unwrap();
        let index = push_index(&index_secret, &id);
        if let Some(reg) = reg {
            let sealed = push_token::seal(&push_public, &index, &reg).unwrap();
            env.registry.put_push_token(&index, &sealed).await.unwrap();
        }
        Device { id, index }
    };

    let fcm_token = "fcm-registration:token_A-1";
    let retry_token = "fcm-registration:token_R-2";
    let sub = TestSubscription::generate();

    // Mock providers.
    let ca = TestCa::new();
    let apns_mock = MockServer::apns(&ca).await;
    let fcm_mock = MockServer::fcm(&ca).await;
    let web_mock = MockServer::web_push(&ca).await;

    let apple = register(Some(Registration::Apns {
        token: vec![0xa1; 32],
        voip: Some(vec![0xb2; 32]),
    }))
    .await;
    let android = register(Some(Registration::Fcm {
        token: fcm_token.into(),
    }))
    .await;
    let unified = register(Some(Registration::WebPush {
        endpoint: format!("{}/up/opaque", web_mock.url()),
        p256dh: sub.p256dh,
        auth: sub.auth,
    }))
    .await;
    let gone = register(Some(Registration::Apns {
        token: vec![0xc3; 32],
        voip: None,
    }))
    .await;
    let flaky = register(Some(Registration::Fcm {
        token: retry_token.into(),
    }))
    .await;
    let nobody = register(None).await;

    let mut apns_cfg = ApnsConfig::new("TEAM123456", "KEYID12345", "eu.songbird.app");
    apns_cfg.base_url = apns_mock.url();
    apns_cfg.http = ca.http_config();
    let account = ServiceAccount::with_pkcs8_der(
        "songbird-test",
        "push@songbird-test.iam.gserviceaccount.com",
        &format!("{}/token", fcm_mock.url()),
        &rsa_pkcs8(),
    )
    .unwrap();
    let fcm_cfg = FcmConfig {
        base_url: fcm_mock.url(),
        http: ca.http_config(),
        ..FcmConfig::default()
    };
    let mut web_cfg = WebPushConfig::new("mailto:ops@songbird.example");
    web_cfg.http = ca.http_config();
    web_cfg.allow_insecure_for_tests = true;
    let providers = Providers {
        apns: Some(Apns::with_pkcs8_der(apns_cfg, &p256_pkcs8()).unwrap()),
        fcm: Some(Fcm::new(&fcm_cfg, account).unwrap()),
        webpush: Some(WebPush::with_pkcs8_der(web_cfg, &p256_pkcs8()).unwrap()),
    };

    let metrics = PushMetrics::default();
    let handler = Handler::new(
        Arc::clone(&env.registry),
        &index_secret,
        &push_key,
        providers,
        Duration::from_secs(1),
        metrics.clone(),
    )
    .unwrap();
    let mut qcfg = QueueConfig::new("push-test".into());
    qcfg.backoff_base = Duration::from_millis(50);
    qcfg.backoff_max = Duration::from_millis(200);
    let client = redis::Client::open(env.valkey.as_str()).unwrap();
    let queue = Arc::new(Queue::connect(client, &[9; 32], qcfg).await.unwrap());
    queue.ensure_groups(&[Stream::Push]).await.unwrap();
    let running = songbird_push::spawn(
        Arc::clone(&queue),
        Arc::new(handler),
        ConsumeConfig {
            housekeeping: Duration::from_millis(50),
            ..ConsumeConfig::default()
        },
    );

    // 1. A burst per device becomes exactly one push each.
    let mut burst = Vec::new();
    for _ in 0..5 {
        burst.extend([
            job(&apple, false),
            job(&android, false),
            job(&unified, false),
        ]);
    }
    queue.enqueue(&burst).await.unwrap();
    eventually("one push per provider", async || {
        apns_mock.requests().len() == 1
            && fcm_mock.requests().len() == 1
            && web_mock.requests().len() == 1
    })
    .await;
    eventually("the burst handled", async || {
        [Kind::Apns, Kind::Fcm, Kind::WebPush]
            .iter()
            .all(|k| metrics.count(*k, "debounced") == 4)
    })
    .await;
    assert_eq!(apns_mock.requests().len(), 1);
    assert_eq!(fcm_mock.requests().len(), 1);
    assert_eq!(web_mock.requests().len(), 1);
    // Constant content.
    let a = &apns_mock.requests()[0];
    assert_eq!(a.path, format!("/3/device/{}", hex::encode([0xa1; 32])));
    assert_eq!(a.header("apns-push-type"), Some("alert"));
    assert_eq!(
        a.body,
        br#"{"aps":{"alert":{"body":"New message","title":"Songbird"},"mutable-content":1}}"#
    );
    let f = &fcm_mock.requests()[0];
    assert_eq!(
        f.body,
        format!(
            r#"{{"message":{{"android":{{"collapse_key":"sb","priority":"HIGH","ttl":"86400s"}},"token":"{fcm_token}"}}}}"#
        )
        .as_bytes()
    );
    let w = &web_mock.requests()[0];
    assert_eq!(w.path, "/up/opaque");
    assert_eq!(sub.decrypt(&w.body).unwrap(), PLAINTEXT);

    // 2. A call goes to the VoIP token (debounced apart from messages).
    queue.enqueue(&[job(&apple, true)]).await.unwrap();
    eventually("the VoIP push", async || apns_mock.requests().len() == 2).await;
    let v = &apns_mock.requests()[1];
    assert_eq!(v.path, format!("/3/device/{}", hex::encode([0xb2; 32])));
    assert_eq!(v.header("apns-push-type"), Some("voip"));
    assert_eq!(v.body, b"{}");

    // 3. An unregistered token is deleted.
    apns_mock.push(Behaviour::Unregistered);
    queue.enqueue(&[job(&gone, false)]).await.unwrap();
    eventually("the unregistered token deleted", async || {
        env.registry
            .push_token(&gone.index)
            .await
            .unwrap()
            .is_none()
    })
    .await;
    assert_eq!(metrics.count(Kind::Apns, "unregistered"), 1);
    // The other registrations stay.
    assert!(
        env.registry
            .push_token(&apple.index)
            .await
            .unwrap()
            .is_some()
    );

    // 4. A provider outage (503) is retried and the push arrives later.
    fcm_mock.push(Behaviour::Unavailable);
    queue.enqueue(&[job(&flaky, false)]).await.unwrap();
    eventually("the retried push", async || {
        for_token(&fcm_mock.requests(), retry_token).len() == 2
    })
    .await;
    eventually("the retry delivered", async || {
        metrics.count(Kind::Fcm, "sent") == 2
    })
    .await;
    assert_eq!(metrics.count(Kind::Fcm, "retried"), 1);

    // 5. A device without a registration: done, nothing sent.
    let before = apns_mock.requests().len() + fcm_mock.requests().len() + web_mock.requests().len();
    queue.enqueue(&[job(&nobody, false)]).await.unwrap();
    eventually("the job without registration", async || {
        metrics.no_registration.get() == 1
    })
    .await;
    assert_eq!(
        apns_mock.requests().len() + fcm_mock.requests().len() + web_mock.requests().len(),
        before
    );

    // Nothing of a device ID (or its push index) reaches any provider.
    let mut seen = Vec::new();
    for r in apns_mock
        .requests()
        .iter()
        .chain(fcm_mock.requests().iter())
        .chain(fcm_mock.token_requests().iter())
        .chain(web_mock.requests().iter())
    {
        seen.extend_from_slice(r.path.as_bytes());
        for (k, v) in &r.headers {
            seen.extend_from_slice(k.as_bytes());
            seen.extend_from_slice(v.as_bytes());
        }
        seen.extend_from_slice(&r.body);
    }
    let seen_lower = String::from_utf8_lossy(&seen).to_ascii_lowercase();
    for d in [&apple, &android, &unified, &gone, &flaky, &nobody] {
        let raw = d.id.as_bytes();
        assert!(!seen.windows(raw.len()).any(|w| w == raw));
        assert!(!seen.windows(32).any(|w| w == d.index));
        assert!(!seen_lower.contains(&d.id.to_hex_unredacted().to_ascii_lowercase()));
        assert!(!seen_lower.contains(&hex::encode(d.index)));
        let b64 = songbird_push_providers::b64::encode_url(raw);
        assert!(!String::from_utf8_lossy(&seen).contains(&b64));
    }

    assert_eq!(queue.dead_letters().await.unwrap(), 0);
    running.stop().await;
}
