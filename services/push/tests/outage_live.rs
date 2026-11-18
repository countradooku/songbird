//! Prompt 8, M2 (D-0096): provider outages and recovery, a crashed consumer, and the numbers
//! (pushes per second, p99 from enqueue to the provider's answer), on a real `valkey-jobs` and
//! SurrealDB with mock providers over TLS and HTTP/2.
//!
//! Every outage test ends the same way: once the provider is back, **every device that was due
//! a wake-up gets one**, without an operator, and nothing is dead-lettered. (Messages are never
//! here: they wait in the mailbox, which `tests/e2e/tests/gate_p08.rs` checks end to end.)
//!
//! Runs like `push_live.rs` (same variables); the tests share the job streams, so CI runs this
//! crate with `-j 1`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    reason = "tests"
)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use songbird_accounts::push_token::{self, Registration};
use songbird_accounts::{Db, PushStore, push_index};
use songbird_jobs::queue::DEAD_KEY;
use songbird_jobs::{ConsumeConfig, Job, Queue, QueueConfig, Stream, Work};
use songbird_push::{Handler, Kind, Providers, PushMetrics};
use songbird_push_providers::BreakerConfig;
use songbird_push_providers::apns::{Apns, ApnsConfig};
use songbird_push_providers::fcm::{Fcm, FcmConfig, ServiceAccount};
use songbird_push_providers::test_support::{
    Behaviour, MockServer, RecordedRequest, TestCa, p256_pkcs8, rsa_pkcs8,
};
use songbird_types::DeviceId;

const INDEX_SECRET: [u8; 32] = [0x1d; 32];
const PUSH_KEY: [u8; 32] = [0x2e; 32];

struct Env {
    valkey: String,
    store: Arc<PushStore>,
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
        database: format!(
            "pushout_{}",
            DeviceId::random().unwrap().to_hex_unredacted()
        ),
        timeout: Duration::from_secs(10),
        max_message_bytes: 16 << 20,
    };
    let store = Arc::new(
        PushStore::connect(Db::connect(cfg).await.unwrap())
            .await
            .unwrap(),
    );
    wipe(&valkey).await;
    Some(Env { valkey, store })
}

async fn wipe(url: &str) {
    let client = redis::Client::open(url).unwrap();
    let mut c = client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis::cmd("DEL")
        .arg(&[
            Stream::Push.key(),
            Stream::Push.delayed_key(),
            Stream::Ring.key(),
            Stream::Ring.delayed_key(),
            DEAD_KEY,
        ])
        .query_async(&mut c)
        .await
        .unwrap();
}

async fn eventually(what: &str, secs: u64, mut ok: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !ok().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `n` devices registered with FCM (token `fcm-<i>`) or APNs (token `[i; 32]`-ish), sealed to
/// the push key, written in parallel.
async fn register(store: &PushStore, n: usize, apns: bool) -> Vec<(DeviceId, String)> {
    let (_, public) = push_token::key_pair(&PUSH_KEY).unwrap();
    let mut out = Vec::with_capacity(n);
    let mut rows = Vec::with_capacity(n);
    for i in 0..n {
        let d = DeviceId::random().unwrap();
        let (reg, needle) = if apns {
            let mut t = [0u8; 32];
            t[..8].copy_from_slice(&(i as u64).to_be_bytes());
            t[8..24].copy_from_slice(d.as_bytes());
            (
                Registration::Apns {
                    token: t.to_vec(),
                    voip: None,
                },
                hex::encode(t),
            )
        } else {
            let t = format!("fcm-{i}-{}", d.to_hex_unredacted());
            (Registration::Fcm { token: t.clone() }, t)
        };
        let index = push_index(&INDEX_SECRET, &d);
        rows.push((index, push_token::seal(&public, &index, &reg).unwrap()));
        out.push((d, needle));
    }
    for chunk in rows.chunks(64) {
        let puts = chunk.iter().map(|(i, s)| store.put(i, s));
        for r in futures_join_all(puts).await {
            r.unwrap();
        }
    }
    out
}

async fn futures_join_all<F: Future>(fs: impl Iterator<Item = F>) -> Vec<F::Output> {
    let mut set = Vec::new();
    for f in fs {
        set.push(f);
    }
    let mut out = Vec::with_capacity(set.len());
    for f in set {
        out.push(f.await);
    }
    out
}

struct Rig {
    apns: MockServer,
    fcm: MockServer,
    queue: Arc<Queue>,
    handler: Arc<Handler>,
    metrics: PushMetrics,
}

async fn rig(env: &Env, timeout: Duration, breaker: BreakerConfig, visibility: Duration) -> Rig {
    let ca = TestCa::new();
    let apns_mock = MockServer::apns(&ca).await;
    let fcm_mock = MockServer::fcm(&ca).await;
    let mut http = ca.http_config();
    http.request_timeout = timeout;
    http.connections = 4;
    let mut apns_cfg = ApnsConfig::new("TEAM123456", "KEYID12345", "eu.songbird.app");
    apns_cfg.base_url = apns_mock.url();
    apns_cfg.http = http.clone();
    apns_cfg.breaker = breaker;
    let account = ServiceAccount::with_pkcs8_der(
        "songbird-test",
        "push@songbird-test.iam.gserviceaccount.com",
        &format!("{}/token", fcm_mock.url()),
        &rsa_pkcs8(),
    )
    .unwrap();
    let fcm_cfg = FcmConfig {
        base_url: fcm_mock.url(),
        http,
        breaker,
        ..FcmConfig::default()
    };
    let providers = Providers {
        apns: Some(Apns::with_pkcs8_der(apns_cfg, &p256_pkcs8()).unwrap()),
        fcm: Some(Fcm::new(&fcm_cfg, account).unwrap()),
        webpush: None,
    };
    let metrics = PushMetrics::default();
    let handler = Handler::new(
        Arc::clone(&env.store),
        &INDEX_SECRET,
        &PUSH_KEY,
        providers,
        // No debounce: these tests count one push per device and job.
        Duration::ZERO,
        metrics.clone(),
    )
    .unwrap();
    let mut qcfg = QueueConfig::new(format!("push-out-{}", hex::encode([0u8; 2])));
    qcfg.backoff_base = Duration::from_millis(100);
    qcfg.backoff_max = Duration::from_millis(800);
    qcfg.max_attempts = 40;
    qcfg.visibility = visibility;
    let client = redis::Client::open(env.valkey.as_str()).unwrap();
    let queue = Arc::new(Queue::connect(client, &[9; 32], qcfg).await.unwrap());
    queue
        .ensure_groups(&[Stream::Push, Stream::Ring])
        .await
        .unwrap();
    Rig {
        apns: apns_mock,
        fcm: fcm_mock,
        queue,
        handler: Arc::new(handler),
        metrics,
    }
}

fn consumer() -> ConsumeConfig {
    ConsumeConfig {
        housekeeping: Duration::from_millis(50),
        ..ConsumeConfig::default()
    }
}

fn jobs(devices: &[(DeviceId, String)]) -> Vec<Job> {
    devices
        .iter()
        .map(|(d, _)| Job::new(Work::Push { device: *d }).unwrap())
        .collect()
}

/// Devices whose token appears in a request answered after `from` (index into the requests).
fn reached(reqs: &[RecordedRequest], from: usize, devices: &[(DeviceId, String)]) -> usize {
    let seen: Vec<String> = reqs[from..]
        .iter()
        .map(|r| format!("{}{}", r.path, String::from_utf8_lossy(&r.body)))
        .collect();
    devices
        .iter()
        .filter(|(_, needle)| seen.iter().any(|s| s.contains(needle.as_str())))
        .count()
}

fn breaker() -> BreakerConfig {
    BreakerConfig {
        failures: 5,
        window: Duration::from_secs(30),
        cooldown: Duration::from_millis(500),
    }
}

/// FCM answers 503 to everything for 3 s. The breaker opens, jobs wait in the retry set with
/// backoff, and once FCM is back every device is woken; nothing is dead-lettered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_provider_outage_ends_with_every_device_woken() {
    let Some(env) = env().await else { return };
    let r = rig(
        &env,
        Duration::from_secs(2),
        breaker(),
        Duration::from_secs(30),
    )
    .await;
    let devices = register(&env.store, 200, false).await;
    r.fcm.outage(Behaviour::Unavailable);
    let running = songbird_push::spawn(
        Arc::clone(&r.queue),
        Arc::clone(&r.handler),
        consumer(),
        consumer(),
    );
    r.queue.enqueue(&jobs(&devices)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(r.metrics.count(Kind::Fcm, "sent"), 0);
    let failed_requests = r.fcm.requests().len();
    // The breaker kept the outage cheap: far fewer requests than jobs × retries.
    assert!(
        failed_requests < 200 * 4,
        "{failed_requests} requests during the outage"
    );
    let from = r.fcm.requests().len();
    r.fcm.recover();
    let t = Instant::now();
    eventually("every device woken after the outage", 60, async || {
        reached(&r.fcm.requests(), from, &devices) == devices.len()
    })
    .await;
    println!(
        "FCM 503 for 3 s: {failed_requests} requests refused, all 200 woken {:?} after recovery",
        t.elapsed()
    );
    assert_eq!(r.queue.dead_letters().await.unwrap(), 0);
    running.stop().await;
}

/// APNs black-holed (accepts, never answers) for 3 s: each request costs the 300 ms timeout
/// until the breaker opens; after recovery every device is woken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_black_holed_provider_ends_with_every_device_woken() {
    let Some(env) = env().await else { return };
    let r = rig(
        &env,
        Duration::from_millis(300),
        breaker(),
        Duration::from_secs(30),
    )
    .await;
    let devices = register(&env.store, 100, true).await;
    r.apns.outage(Behaviour::Hang);
    let running = songbird_push::spawn(
        Arc::clone(&r.queue),
        Arc::clone(&r.handler),
        consumer(),
        consumer(),
    );
    r.queue.enqueue(&jobs(&devices)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(r.metrics.count(Kind::Apns, "sent"), 0);
    assert!(r.breaker_is_open(), "the breaker did not open");
    let from = r.apns.requests().len();
    r.apns.recover();
    eventually("every device woken after the black hole", 60, async || {
        reached(&r.apns.requests(), from, &devices) == devices.len()
    })
    .await;
    assert_eq!(r.queue.dead_letters().await.unwrap(), 0);
    running.stop().await;
}

/// FCM rate-limits with `retry-after: 1`: the retry waits at least that long, then delivers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limiting_is_honoured_then_delivered() {
    let Some(env) = env().await else { return };
    let r = rig(
        &env,
        Duration::from_secs(2),
        breaker(),
        Duration::from_secs(30),
    )
    .await;
    let devices = register(&env.store, 1, false).await;
    r.fcm.push(Behaviour::RateLimited {
        retry_after: Some(1),
    });
    let running = songbird_push::spawn(
        Arc::clone(&r.queue),
        Arc::clone(&r.handler),
        consumer(),
        consumer(),
    );
    r.queue.enqueue(&jobs(&devices)).await.unwrap();
    eventually("delivered after the rate limit", 20, async || {
        r.metrics.count(Kind::Fcm, "sent") == 1
    })
    .await;
    let reqs = r.fcm.requests();
    assert_eq!(reqs.len(), 2);
    let gap = reqs[1].at.duration_since(reqs[0].at);
    assert!(gap >= Duration::from_millis(950), "retried after {gap:?}");
    running.stop().await;
}

/// The push service dies mid-burst (its runtime dropped, jobs in hand never finished). A new
/// instance reclaims what the dead one held after the visibility timeout: every device is woken
/// (some twice: a push may have left just before the crash), nothing is lost.
#[test]
fn a_crashed_push_service_loses_no_wake_up() {
    let main = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let Some(env) = main.block_on(env()) else {
        return;
    };
    let r = main.block_on(rig(
        &env,
        Duration::from_secs(2),
        breaker(),
        Duration::from_secs(2),
    ));
    let devices = main.block_on(register(&env.store, 300, false));
    // Slow answers so jobs are in hand when the service dies.
    r.fcm.outage(Behaviour::Slow(Duration::from_millis(400)));
    main.block_on(r.queue.enqueue(&jobs(&devices))).unwrap();
    // First instance: its own runtime, dropped after half a second (a crash, no shutdown).
    let doomed = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    {
        let _g = doomed.enter();
        let _running = songbird_push::spawn(
            Arc::clone(&r.queue),
            Arc::clone(&r.handler),
            consumer(),
            consumer(),
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    doomed.shutdown_background();
    let before = r.fcm.requests().len();
    assert!(
        before > 0 && before < devices.len(),
        "{before} sent before the crash"
    );
    r.fcm.recover();
    // A new instance (another consumer name in the same group).
    main.block_on(async {
        let running = songbird_push::spawn(
            Arc::clone(&r.queue),
            Arc::clone(&r.handler),
            consumer(),
            consumer(),
        );
        eventually("every device woken after the crash", 60, async || {
            reached(&r.fcm.requests(), 0, &devices) == devices.len()
        })
        .await;
        let total = r.fcm.requests().len();
        println!(
            "crash after {before} of 300 pushes: all woken, {} pushed twice",
            total - devices.len()
        );
        assert_eq!(r.queue.dead_letters().await.unwrap(), 0);
        running.stop().await;
    });
}

/// The M2 numbers (ignored by default): `cargo nextest run -p songbird-push --release
/// --run-ignored only --no-capture m2_numbers`. Pushes per second and the time from enqueue to
/// the mock provider's having the request, over TLS and HTTP/2 on loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark: run in release, see the doc comment"]
async fn m2_numbers() {
    let Some(env) = env().await else { return };
    let n: usize = std::env::var("SONGBIRD_M2_PUSHES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let r = rig(
        &env,
        Duration::from_secs(5),
        breaker(),
        Duration::from_secs(30),
    )
    .await;
    let devices = register(&env.store, n, true).await;
    let running = songbird_push::spawn(
        Arc::clone(&r.queue),
        Arc::clone(&r.handler),
        ConsumeConfig {
            batch: 256,
            concurrency: 256,
            ..consumer()
        },
        consumer(),
    );
    let all = jobs(&devices);
    let start = Instant::now();
    let mut enqueued_at = Vec::with_capacity(n);
    for chunk in all.chunks(256) {
        r.queue.enqueue(chunk).await.unwrap();
        let t = Instant::now();
        enqueued_at.extend(std::iter::repeat_n(t, chunk.len()));
    }
    eventually("every push sent", 300, async || r.apns.request_count() >= n).await;
    let elapsed = start.elapsed();
    let reqs = r.apns.requests();
    let by_token: std::collections::HashMap<String, Instant> = reqs
        .iter()
        .map(|q| (q.path.trim_start_matches("/3/device/").to_owned(), q.at))
        .collect();
    let mut lat: Vec<Duration> = devices
        .iter()
        .zip(&enqueued_at)
        .map(|((_, tok), t0)| by_token[tok].duration_since(*t0))
        .collect();
    lat.sort();
    let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)];
    println!(
        "M2: {n} pushes in {elapsed:?}: {:.0}/s; enqueue→provider p50 {:?} p99 {:?} max {:?}",
        n as f64 / elapsed.as_secs_f64(),
        pct(0.50),
        pct(0.99),
        lat[lat.len() - 1]
    );
    let distinct: HashSet<&str> = reqs.iter().map(|q| q.path.as_str()).collect();
    assert_eq!(distinct.len(), n);

    // Steady load without a backlog: 1,000 wake-ups/s for 5 s, one job at a time, each timed
    // from its own enqueue to the provider's having it.
    let before = r.apns.request_count();
    let steady: Vec<Job> = jobs(&devices[..5_000]);
    let mut sent_at = Vec::with_capacity(steady.len());
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    for j in &steady {
        tick.tick().await;
        sent_at.push(Instant::now());
        r.queue.enqueue(std::slice::from_ref(j)).await.unwrap();
    }
    eventually("the steady load sent", 60, async || {
        r.apns.request_count() >= before + steady.len()
    })
    .await;
    let reqs = r.apns.requests();
    let at: std::collections::HashMap<String, Instant> = reqs[before..]
        .iter()
        .map(|q| (q.path.trim_start_matches("/3/device/").to_owned(), q.at))
        .collect();
    let mut lat: Vec<Duration> = devices[..5_000]
        .iter()
        .zip(&sent_at)
        .map(|((_, tok), t0)| at[tok].duration_since(*t0))
        .collect();
    lat.sort();
    let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)];
    println!(
        "M2 steady 1,000/s: enqueue→provider p50 {:?} p99 {:?} max {:?}",
        pct(0.50),
        pct(0.99),
        lat[lat.len() - 1]
    );
    running.stop().await;
}

impl Rig {
    /// The breaker is internal to the provider; an open one answers without the network, so
    /// while jobs keep being retried the request count grows by at most one probe per cooldown.
    fn breaker_is_open(&self) -> bool {
        let before = self.apns.requests().len();
        std::thread::sleep(Duration::from_millis(400));
        self.apns.requests().len() <= before + 1
    }
}
