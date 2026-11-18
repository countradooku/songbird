//! The job queue against a real Valkey. Runs when `SONGBIRD_TEST_VALKEY_JOBS` (a `redis://` URL
//! with credentials) is set; with `SONGBIRD_REQUIRE_VALKEY=1` a missing server fails instead of
//! skipping. Stream names are fixed, so the tests run one at a time and start from empty
//! streams.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use songbird_jobs::queue::DEAD_KEY;
use songbird_jobs::{
    ConsumeConfig, Job, Outbox, Outcome, Queue, QueueConfig, Stream, Work, consume, relay,
};
use songbird_types::{AccountId, DeviceId, JobId};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn url() -> Option<String> {
    let url = std::env::var("SONGBIRD_TEST_VALKEY_JOBS").ok();
    assert!(
        url.is_some() || std::env::var("SONGBIRD_REQUIRE_VALKEY").is_err(),
        "SONGBIRD_REQUIRE_VALKEY is set but SONGBIRD_TEST_VALKEY_JOBS is not"
    );
    url
}

async fn wipe(url: &str) {
    let client = redis::Client::open(url).unwrap();
    let mut c = client.get_multiplexed_async_connection().await.unwrap();
    let mut keys = vec![DEAD_KEY.to_owned()];
    for s in Stream::ALL {
        keys.push(s.key().to_owned());
        keys.push(s.delayed_key().to_owned());
    }
    let _: () = redis::cmd("DEL")
        .arg(&keys)
        .query_async(&mut c)
        .await
        .unwrap();
}

async fn queue(url: &str, consumer: &str, tweak: impl FnOnce(&mut QueueConfig)) -> Queue {
    let mut cfg = QueueConfig::new(consumer.to_owned());
    tweak(&mut cfg);
    let q = Queue::connect(redis::Client::open(url).unwrap(), &[5; 32], cfg)
        .await
        .unwrap();
    q.ensure_groups(&Stream::ALL).await.unwrap();
    q
}

fn push(b: u8) -> Job {
    Job::new(Work::Push {
        device: DeviceId::from_bytes([b; 16]),
    })
    .unwrap()
}

/// Raw bytes Valkey holds for every key: no device ID appears in them.
async fn raw_dump(url: &str) -> Vec<u8> {
    let client = redis::Client::open(url).unwrap();
    let mut c = client.get_multiplexed_async_connection().await.unwrap();
    let mut out = Vec::new();
    for s in Stream::ALL {
        let v: redis::Value = redis::cmd("XRANGE")
            .arg(s.key())
            .arg("-")
            .arg("+")
            .query_async(&mut c)
            .await
            .unwrap();
        out.extend_from_slice(format!("{v:?}").as_bytes());
    }
    out
}

#[tokio::test]
async fn jobs_are_sealed_delivered_once_and_deleted_when_done() {
    let Some(url) = url() else { return };
    let _g = SERIAL.lock().await;
    wipe(&url).await;
    let q = queue(&url, "t1", |_| {}).await;
    let jobs: Vec<Job> = (1..=20).map(push).collect();
    q.enqueue(&jobs).await.unwrap();
    assert_eq!(q.depth(Stream::Push).await.unwrap(), 20);
    // Valkey holds no device ID (hex or the debug rendering of raw bytes).
    let dump = raw_dump(&url).await;
    for b in 1..=20u8 {
        let hex = DeviceId::from_bytes([b; 16]).to_hex_unredacted();
        assert!(!dump.windows(hex.len()).any(|w| w == hex.as_bytes()));
        assert!(!dump.windows(16).any(|w| w == [b; 16]));
    }
    let mut got = Vec::new();
    while got.len() < 20 {
        let batch = q.read(Stream::Push, 8).await.unwrap();
        assert!(!batch.is_empty());
        for d in batch {
            q.finish(&d, Outcome::Done).await.unwrap();
            got.push(d.job);
        }
    }
    got.sort_by_key(|j| j.id.as_bytes().to_vec());
    let mut want = jobs.clone();
    want.sort_by_key(|j| j.id.as_bytes().to_vec());
    assert_eq!(got, want);
    assert!(q.read(Stream::Push, 8).await.unwrap().is_empty());
    // Finished jobs are deleted, not only acknowledged.
    assert_eq!(q.depth(Stream::Push).await.unwrap(), 0);
}

#[tokio::test]
async fn failed_jobs_come_back_after_backoff_then_go_to_dead_letters() {
    let Some(url) = url() else { return };
    let _g = SERIAL.lock().await;
    wipe(&url).await;
    let q = queue(&url, "t2", |c| {
        c.max_attempts = 3;
        c.backoff_base = Duration::from_millis(20);
        c.backoff_max = Duration::from_millis(40);
    })
    .await;
    let job = push(9);
    q.enqueue(std::slice::from_ref(&job)).await.unwrap();
    let mut attempts = Vec::new();
    for _ in 0..200 {
        q.promote(Stream::Push).await.unwrap();
        for d in q.read(Stream::Push, 8).await.unwrap() {
            assert_eq!(d.job.id, job.id);
            attempts.push(d.job.attempt);
            q.finish(&d, Outcome::Retry(None)).await.unwrap();
        }
        if q.dead_letters().await.unwrap() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(attempts, vec![0, 1, 2]);
    assert_eq!(q.dead_letters().await.unwrap(), 1);
    assert_eq!(q.depth(Stream::Push).await.unwrap(), 0);
    assert_eq!(q.stats().dead.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_dead_consumers_jobs_are_reclaimed_and_poison_jobs_dead_lettered() {
    let Some(url) = url() else { return };
    let _g = SERIAL.lock().await;
    wipe(&url).await;
    let crashed = queue(&url, "crashed", |_| {}).await;
    let rescuer = queue(&url, "rescuer", |c| {
        c.visibility = Duration::from_millis(50);
        c.max_deliveries = 3;
    })
    .await;
    let job = Job::new(Work::DeleteAccount {
        account: AccountId::from_bytes([3; 16]),
    })
    .unwrap();
    crashed.enqueue(std::slice::from_ref(&job)).await.unwrap();
    // Taken, never finished.
    assert_eq!(crashed.read(Stream::Deletion, 1).await.unwrap().len(), 1);
    tokio::time::sleep(Duration::from_millis(80)).await;
    let back = rescuer.reclaim(Stream::Deletion, 8).await.unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].job, job);
    // It keeps crashing its consumers: after three deliveries it is dead-lettered.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(rescuer.reclaim(Stream::Deletion, 8).await.unwrap().len(), 1);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        rescuer
            .reclaim(Stream::Deletion, 8)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(rescuer.dead_letters().await.unwrap(), 1);
    assert_eq!(rescuer.depth(Stream::Deletion).await.unwrap(), 0);
}

#[tokio::test]
async fn garbage_in_a_stream_is_dead_lettered_not_run() {
    let Some(url) = url() else { return };
    let _g = SERIAL.lock().await;
    wipe(&url).await;
    let q = queue(&url, "t4", |_| {}).await;
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut c = client.get_multiplexed_async_connection().await.unwrap();
    let _: String = redis::cmd("XADD")
        .arg(Stream::Cleanup.key())
        .arg("*")
        .arg("s")
        .arg(b"not a sealed job".as_slice())
        .query_async(&mut c)
        .await
        .unwrap();
    // A job sealed for another stream does not open on this one either.
    let other = Queue::connect(client, &[6; 32], QueueConfig::new("x".into()))
        .await
        .unwrap();
    other.enqueue(&[push(1)]).await.unwrap();
    assert!(q.read(Stream::Cleanup, 8).await.unwrap().is_empty());
    assert!(q.read(Stream::Push, 8).await.unwrap().is_empty());
    assert_eq!(q.dead_letters().await.unwrap(), 2);
    assert_eq!(q.stats().unopenable.load(Ordering::Relaxed), 2);
}

#[derive(Default)]
struct MemOutbox(std::sync::Mutex<Vec<Job>>);

impl Outbox for MemOutbox {
    fn take(&self, limit: usize) -> impl Future<Output = Result<Vec<Job>, String>> + Send {
        let jobs = self.0.lock().unwrap().iter().take(limit).cloned().collect();
        std::future::ready(Ok(jobs))
    }
    fn remove(&self, ids: &[JobId]) -> impl Future<Output = Result<(), String>> + Send {
        self.0.lock().unwrap().retain(|j| !ids.contains(&j.id));
        std::future::ready(Ok(()))
    }
}

#[tokio::test]
async fn the_relay_empties_the_outbox_and_the_consumer_runs_every_job() {
    let Some(url) = url() else { return };
    let _g = SERIAL.lock().await;
    wipe(&url).await;
    let q = Arc::new(queue(&url, "t5", |c| c.backoff_base = Duration::from_millis(10)).await);
    let outbox = MemOutbox::default();
    for b in 0..600u16 {
        let mut a = [0u8; 16];
        a[..2].copy_from_slice(&b.to_be_bytes());
        outbox.0.lock().unwrap().push(
            Job::new(Work::DeleteAccount {
                account: AccountId::from_bytes(a),
            })
            .unwrap(),
        );
    }
    assert_eq!(relay(&outbox, &q).await.unwrap(), 600);
    assert!(outbox.0.lock().unwrap().is_empty());
    let runs = Arc::new(AtomicU32::new(0));
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    let r = Arc::clone(&runs);
    // Every job fails once, then succeeds: all 600 finish, each run twice.
    let consumer = tokio::spawn(consume(
        Arc::clone(&q),
        Stream::Deletion,
        ConsumeConfig {
            housekeeping: Duration::from_millis(20),
            ..ConsumeConfig::default()
        },
        move |job: Job| {
            let r = Arc::clone(&r);
            async move {
                r.fetch_add(1, Ordering::Relaxed);
                if job.attempt == 0 {
                    Outcome::Retry(Some(Duration::from_millis(5)))
                } else {
                    Outcome::Done
                }
            }
        },
        stop,
    ));
    for _ in 0..500 {
        if runs.load(Ordering::Relaxed) >= 1200 && q.depth(Stream::Deletion).await.unwrap() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop_tx.send(true).unwrap();
    consumer.await.unwrap();
    assert_eq!(runs.load(Ordering::Relaxed), 1200);
    assert_eq!(q.depth(Stream::Deletion).await.unwrap(), 0);
    assert_eq!(q.dead_letters().await.unwrap(), 0);
}
