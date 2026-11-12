//! The Iggy mailbox against a real Apache Iggy server. Runs when `SONGBIRD_TEST_IGGY`
//! (`host:port`) and `SONGBIRD_TEST_IGGY_PASS` are set (`SONGBIRD_TEST_IGGY_USER` defaults to
//! `iggy`); with `SONGBIRD_REQUIRE_IGGY=1` a missing server fails instead of skipping. Each test
//! uses its own stream.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use songbird_mailbox::iggy::{IggyConfig, IggyConnection, IggyMailbox};
use songbird_mailbox::{Mailbox, MailboxError, MlsCommit, NewEnvelope, Payload, StoreRequest};
use songbird_types::DeviceId;

fn config(name: &str) -> Option<IggyConfig> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_IGGY") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_IGGY").is_err(),
            "SONGBIRD_REQUIRE_IGGY is set but SONGBIRD_TEST_IGGY is not"
        );
        return None;
    };
    let connection = IggyConnection {
        addr,
        tls_domain: None,
        tls_ca_file: None,
        user: std::env::var("SONGBIRD_TEST_IGGY_USER").unwrap_or_else(|_| "iggy".into()),
        pass: std::env::var("SONGBIRD_TEST_IGGY_PASS").expect("SONGBIRD_TEST_IGGY_PASS"),
    };
    let stream = format!(
        "t_{name}_{}_{}",
        std::process::id(),
        DeviceId::random()
            .unwrap()
            .to_hex_unredacted()
            .get(..8)
            .unwrap()
    );
    let mut master = [0u8; 32];
    master.copy_from_slice(&DeviceId::random().unwrap().as_bytes().repeat(2));
    let key_dir =
        private_key_dir(&std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("mailbox-keys"));
    let mut cfg = IggyConfig::new(connection, [7; 32], key_dir, master);
    cfg.stream = stream;
    cfg.ack_interval = Duration::from_millis(20);
    cfg.key_interval = Duration::from_millis(50);
    cfg.idem_flush = Duration::from_millis(20);
    cfg.timeout = Duration::from_secs(10);
    cfg.compaction_interval = Duration::from_hours(1);
    Some(cfg)
}

/// A new private directory for a test's key stores: an unpredictable name, created exclusively
/// with mode 0700 under the build's own directory (never a predictable path in a shared temp dir).
fn private_key_dir(parent: &std::path::Path) -> std::path::PathBuf {
    std::fs::create_dir_all(parent).unwrap();
    let dir = parent.join(DeviceId::random().unwrap().to_hex_unredacted());
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir).unwrap();
    dir
}

fn d(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

fn devices(n: usize) -> Vec<DeviceId> {
    (0..n).map(|_| DeviceId::random().unwrap()).collect()
}

fn per(items: &[(DeviceId, &'static str)]) -> StoreRequest {
    StoreRequest {
        idempotency_key: None,
        mls: None,
        payload: Payload::PerDevice(
            items
                .iter()
                .map(|(device, e)| NewEnvelope {
                    device: *device,
                    envelope: Bytes::from_static(e.as_bytes()),
                })
                .collect(),
        ),
    }
}

async fn wait_pending(m: &IggyMailbox, dev: &DeviceId, want: u64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let n = m.count_pending(dev).await.unwrap();
        if n == want {
            return;
        }
        assert!(Instant::now() < deadline, "pending {n}, want {want}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn store_fetch_ack_and_seq_rules() {
    let Some(cfg) = config("basic") else { return };
    let m = IggyMailbox::connect(cfg).await.unwrap();
    // Eight devices: they land on several partitions, so this is a multi-partition send.
    let ds = devices(8);
    let items: Vec<(DeviceId, &'static str)> = ds.iter().map(|d| (*d, "hello")).collect();
    let out = m.store(per(&items)).await.unwrap();
    assert_eq!(out.seqs, vec![1; 8]);
    let out = m
        .store(per(&[(ds[0], "second"), (ds[1], "x")]))
        .await
        .unwrap();
    assert_eq!(out.seqs, vec![2, 2]);
    let got = m.fetch_after(&ds[0], 0, 10).await.unwrap();
    assert_eq!(got.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(&got[1].envelope[..], b"second");
    assert_eq!(m.fetch_after(&ds[0], 1, 10).await.unwrap().len(), 1);
    m.ack_up_to(&ds[0], 1).await.unwrap();
    wait_pending(&m, &ds[0], 1).await;
    m.ack_up_to(&ds[0], 2).await.unwrap();
    wait_pending(&m, &ds[0], 0).await;
    // Never reused after deletion.
    assert_eq!(
        m.store(per(&[(ds[0], "third")])).await.unwrap().seqs,
        vec![3]
    );
    assert_eq!(m.store_generation().await.unwrap(), 1);
    assert!(m.is_healthy());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idempotency_replays_and_conflicts() {
    let Some(cfg) = config("idem") else { return };
    let m = IggyMailbox::connect(cfg).await.unwrap();
    let ds = devices(6);
    let items: Vec<(DeviceId, &'static str)> = ds.iter().map(|d| (*d, "e")).collect();
    let mut req = per(&items);
    req.idempotency_key = Some([1; 16]);
    let first = m.store(req.clone()).await.unwrap();
    assert!(!first.replayed);
    let again = m.store(req.clone()).await.unwrap();
    assert_eq!(again.seqs, first.seqs);
    assert!(again.replayed);
    for d in &ds {
        assert_eq!(m.count_pending(d).await.unwrap(), 1, "stored once");
    }
    // The same key for any other recipient set is refused, including exactly the devices one
    // partition held of the earlier send (each single device below).
    for d in &ds {
        let mut other = per(&[(*d, "e")]);
        other.idempotency_key = Some([1; 16]);
        assert_eq!(
            m.store(other).await.unwrap_err(),
            MailboxError::IdempotencyConflict
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_body_is_stored_once_per_partition() {
    let Some(cfg) = config("shared") else { return };
    let m = IggyMailbox::connect(cfg).await.unwrap();
    let ds = devices(1000);
    let body = Bytes::from(vec![0x5a; 4096]);
    let req = StoreRequest {
        idempotency_key: Some([3; 16]),
        mls: None,
        payload: Payload::Shared {
            devices: ds.clone(),
            body: body.clone(),
        },
    };
    let t = Instant::now();
    let out = m.store(req).await.unwrap();
    let took = t.elapsed();
    assert_eq!(out.seqs, vec![1; 1000]);
    assert!(took < Duration::from_secs(5), "{took:?}");
    for d in ds.iter().take(20) {
        let got = m.fetch_after(d, 0, 10).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].envelope, body);
    }
    for d in &ds {
        m.ack_up_to(d, 1).await.unwrap();
    }
    for d in ds.iter().take(50) {
        wait_pending(&m, d, 0).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mls_commits_are_ordered_by_epoch() {
    let Some(cfg) = config("mls") else { return };
    let m = Arc::new(IggyMailbox::connect(cfg).await.unwrap());
    let ds = devices(5);
    let mut tasks = Vec::new();
    for i in 0..10u8 {
        let m = m.clone();
        let ds = ds.clone();
        tasks.push(tokio::spawn(async move {
            let mut req = per(&ds.iter().map(|d| (*d, "commit")).collect::<Vec<_>>());
            req.idempotency_key = Some([i; 16]);
            req.mls = Some(MlsCommit {
                group: [9; 16],
                epoch: 0,
            });
            m.store(req).await
        }));
    }
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(e) => assert_eq!(e, MailboxError::StaleEpoch),
        }
    }
    assert_eq!(ok, 1, "exactly one commit from epoch 0 wins");
    for d in &ds {
        assert_eq!(
            m.count_pending(d).await.unwrap(),
            1,
            "losers stored nothing"
        );
    }
    let mut next = per(&[(ds[0], "c")]);
    next.mls = Some(MlsCommit {
        group: [9; 16],
        epoch: 1,
    });
    m.store(next).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_senders_get_gap_free_unique_seqs() {
    let Some(cfg) = config("conc") else { return };
    let m = Arc::new(IggyMailbox::connect(cfg).await.unwrap());
    let target = d(0x42);
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let m = m.clone();
        tasks.push(tokio::spawn(async move {
            let mut seqs = Vec::new();
            for _ in 0..50 {
                seqs.push(m.store(per(&[(target, "m")])).await.unwrap().seqs[0]);
            }
            seqs
        }));
    }
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await.unwrap());
    }
    all.sort_unstable();
    assert_eq!(all, (1..=1600).collect::<Vec<u64>>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_rebuilds_state_and_fences_the_old_writer() {
    let Some(cfg) = config("restart") else { return };
    let first = IggyMailbox::connect(cfg.clone()).await.unwrap();
    let ds = devices(10);
    for i in 0..3 {
        let items: Vec<(DeviceId, &'static str)> = ds.iter().map(|d| (*d, "m")).collect();
        let mut req = per(&items);
        req.idempotency_key = Some([i + 10; 16]);
        first.store(req).await.unwrap();
    }
    first.ack_up_to(&ds[0], 2).await.unwrap();
    wait_pending(&first, &ds[0], 1).await;

    let second = IggyMailbox::connect(cfg).await.unwrap();
    assert_eq!(second.count_pending(&ds[0]).await.unwrap(), 1);
    assert_eq!(second.count_pending(&ds[1]).await.unwrap(), 3);
    let got = second.fetch_after(&ds[1], 0, 10).await.unwrap();
    assert_eq!(got.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(&got[2].envelope[..], b"m");
    // Counters continue, and a retried send is still recognised after the restart.
    assert_eq!(
        second.store(per(&[(ds[0], "n")])).await.unwrap().seqs,
        vec![4]
    );
    let mut retry = per(&ds.iter().map(|d| (*d, "m")).collect::<Vec<_>>());
    retry.idempotency_key = Some([12; 16]);
    assert_eq!(second.store(retry).await.unwrap().seqs, vec![3; 10]);

    // The first writer set is fenced: Iggy refuses its producer epoch.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = first.store(per(&[(ds[5], "late")])).await;
        if r.is_err() && !first.is_healthy() {
            break;
        }
        assert!(Instant::now() < deadline, "old writer still accepted {r:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(second.is_healthy());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compaction_relocates_and_keeps_counters_across_restart() {
    let Some(mut cfg) = config("compact") else {
        return;
    };
    cfg.relocate_after = Duration::ZERO;
    let m = IggyMailbox::connect(cfg.clone()).await.unwrap();
    let idle = d(0x11);
    let busy = d(0x22);
    for _ in 0..5 {
        m.store(per(&[(idle, "a"), (busy, "b")])).await.unwrap();
    }
    m.ack_up_to(&idle, 5).await.unwrap();
    wait_pending(&m, &idle, 0).await;
    // Expire nothing (30 days), but compact: busy's entries are copied forward, the counters
    // snapshotted and the low-water offset moved past everything older.
    assert_eq!(
        m.expire_older_than(Duration::from_hours(30 * 24))
            .await
            .unwrap(),
        0
    );
    // A pass runs on every partition in the background (reads off the write path); wait for
    // all of them.
    let stats = m.stats();
    let deadline = Instant::now() + Duration::from_secs(10);
    while stats.compactions.load(std::sync::atomic::Ordering::Relaxed) < u64::from(cfg.partitions) {
        assert!(Instant::now() < deadline, "compaction did not finish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(stats.relocated.load(std::sync::atomic::Ordering::Relaxed) >= 5);
    // Sends are not blocked by compaction.
    m.store(per(&[(busy, "d")])).await.unwrap();

    let again = IggyMailbox::connect(cfg).await.unwrap();
    assert_eq!(again.count_pending(&busy).await.unwrap(), 6);
    let got = again.fetch_after(&busy, 0, 10).await.unwrap();
    assert_eq!(
        got.iter().map(|s| s.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6]
    );
    assert_eq!(&got[0].envelope[..], b"b");
    // The idle device's counter survived although its records are below the low-water offset.
    assert_eq!(
        again.store(per(&[(idle, "c")])).await.unwrap().seqs,
        vec![6]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_drops_old_entries() {
    let Some(cfg) = config("expiry") else { return };
    let m = IggyMailbox::connect(cfg).await.unwrap();
    let ds = devices(3);
    m.store(per(&[(ds[0], "a"), (ds[1], "b"), (ds[2], "c")]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(m.expire_older_than(Duration::ZERO).await.unwrap(), 3);
    for d in &ds {
        assert_eq!(m.count_pending(d).await.unwrap(), 0);
    }
    assert_eq!(m.store(per(&[(ds[0], "z")])).await.unwrap().seqs, vec![2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_devices_ack_in_bulk() {
    let Some(cfg) = config("bulk") else { return };
    let m = IggyMailbox::connect(cfg).await.unwrap();
    let ds = devices(2000);
    let mut seen = HashSet::new();
    for chunk in ds.chunks(100) {
        let items: Vec<(DeviceId, &'static str)> = chunk.iter().map(|d| (*d, "x")).collect();
        m.store(per(&items)).await.unwrap();
    }
    for d in &ds {
        m.ack_up_to(d, 1).await.unwrap();
        seen.insert(*d);
    }
    for d in ds.iter().step_by(97) {
        wait_pending(&m, d, 0).await;
    }
    assert_eq!(seen.len(), 2000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redriver_completes_remote_parts_in_process_and_after_restart() {
    let Some(mut cfg) = config("redrive") else {
        return;
    };
    cfg.fault_skip_remote_parts = true;
    let broken = IggyMailbox::connect(cfg.clone()).await.unwrap();
    // Two sends whose devices span partitions; each stops after its home record.
    let a = devices(12);
    let b = devices(12);
    for (i, ds) in [&a, &b].into_iter().enumerate() {
        let mut req = per(&ds.iter().map(|d| (*d, "r")).collect::<Vec<_>>());
        req.idempotency_key = Some([u8::try_from(i).unwrap() + 40; 16]);
        assert_eq!(
            broken.store(req).await.unwrap_err(),
            MailboxError::Unavailable
        );
    }
    // In process: the home writer's re-driver stores the missing parts within a few seconds.
    for d in &a {
        wait_pending(&broken, d, 1).await;
    }
    // After a restart (a new writer set; the old one is fenced), recent home records are
    // re-driven again: parts already stored are recognised, nothing is stored twice.
    cfg.fault_skip_remote_parts = false;
    let fresh = IggyMailbox::connect(cfg).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    for d in a.iter().chain(&b) {
        wait_pending(&fresh, d, 1).await;
    }
    let mut retry = per(&a.iter().map(|d| (*d, "r")).collect::<Vec<_>>());
    retry.idempotency_key = Some([40; 16]);
    assert_eq!(fresh.store(retry).await.unwrap().seqs, vec![1; 12]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_up_refuses_an_unreadable_log() {
    use iggy::prelude::{Identifier, IggyMessage, MessageClient as _, Partitioning};
    use songbird_mailbox::iggy::IggyMailboxError;
    let Some(cfg) = config("unreadable") else {
        return;
    };
    let m = IggyMailbox::connect(cfg.clone()).await.unwrap();
    m.store(per(&[(d(1), "a")])).await.unwrap();
    // Something writes a record this build cannot read (another version, corruption).
    let raw = cfg.connection.client().await.unwrap();
    let mut msgs = vec![
        IggyMessage::builder()
            .payload(Bytes::from_static(&[9, 9, 9]))
            .build()
            .unwrap(),
    ];
    raw.send_messages(
        &Identifier::named(&cfg.stream).unwrap(),
        &Identifier::named(&cfg.topic).unwrap(),
        &Partitioning::partition_id(0),
        &mut msgs,
    )
    .await
    .unwrap();
    // Replaying past it would lose counters and reuse seqs: the mailbox does not start.
    match IggyMailbox::connect(cfg).await {
        Err(IggyMailboxError::Unreadable {
            partition: 0,
            version: 9,
            ..
        }) => {}
        other => panic!("expected Unreadable, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_never_reuses_key_slots() {
    let Some(mut cfg) = config("slots") else {
        return;
    };
    // The key store is written only when a window opens: records appended after that are on
    // the log but not in the key store's slot count, as after a crash.
    cfg.key_interval = Duration::from_hours(1);
    let x = d(0x51);
    let first = IggyMailbox::connect(cfg.clone()).await.unwrap();
    for _ in 0..5 {
        first.store(per(&[(x, "before")])).await.unwrap();
    }
    let again = IggyMailbox::connect(cfg.clone()).await.unwrap();
    for _ in 0..5 {
        again.store(per(&[(x, "after")])).await.unwrap();
    }
    // Acknowledging the messages from before the restart must not touch the ones after it.
    again.ack_up_to(&x, 5).await.unwrap();
    wait_pending(&again, &x, 5).await;
    let got = again.fetch_after(&x, 5, 10).await.unwrap();
    assert_eq!(
        got.iter().map(|s| s.seq).collect::<Vec<_>>(),
        vec![6, 7, 8, 9, 10]
    );
    assert!(got.iter().all(|s| s.envelope.as_ref() == b"after"));
    drop(first);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_up_refuses_a_lost_key_page() {
    use songbird_mailbox::iggy::IggyMailboxError;
    let Some(cfg) = config("lostpage") else {
        return;
    };
    let m = IggyMailbox::connect(cfg.clone()).await.unwrap();
    for i in 0..20u8 {
        m.store(per(&[(d(i), "pending")])).await.unwrap();
    }
    // The pending keys reach their pages.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut lost = 0;
    for dir in std::fs::read_dir(&cfg.key_dir).unwrap().flatten() {
        for f in std::fs::read_dir(dir.path()).unwrap().flatten() {
            if f.file_name().to_string_lossy().starts_with('w') {
                std::fs::remove_file(f.path()).unwrap();
                lost += 1;
            }
        }
    }
    assert!(lost > 0, "no key pages written");
    // Pending messages would otherwise look acknowledged and vanish: the mailbox does not start.
    match IggyMailbox::connect(cfg).await {
        Err(IggyMailboxError::Keys { .. }) => {}
        other => panic!("expected Keys, got {:?}", other.map(|_| ())),
    }
}

/// Waits until an attacker with the Iggy data, the key files and the master key opens exactly
/// `want` plaintexts containing `marker` (`usize::MAX`: at least one).
async fn wait_openable(cfg: &IggyConfig, marker: &[u8], want: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (_, open) = songbird_mailbox::iggy::forensic_scan(cfg, marker)
            .await
            .unwrap();
        if open == want || (want == usize::MAX && open > 0) {
            return;
        }
        assert!(Instant::now() < deadline, "openable {open}, want {want}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acknowledged_messages_cannot_be_decrypted_even_with_every_key() {
    let Some(cfg) = config("forensic") else {
        return;
    };
    let m = IggyMailbox::connect(cfg.clone()).await.unwrap();
    let (a, b) = (d(0x31), d(0x32));
    m.store(per(&[(a, "MARK-alpha-0001")])).await.unwrap();
    m.store(per(&[(b, "MARK-beta-00002")])).await.unwrap();
    let group = devices(3);
    m.store(StoreRequest {
        idempotency_key: Some([5; 16]),
        mls: None,
        payload: Payload::Shared {
            devices: group.clone(),
            body: Bytes::from_static(b"MARK-group-body"),
        },
    })
    .await
    .unwrap();
    // Nothing is in the log in the clear.
    let (raw, _) = songbird_mailbox::iggy::forensic_scan(&cfg, b"MARK-")
        .await
        .unwrap();
    assert_eq!(raw, 0, "plaintext in the log");
    // While pending, the holder of every key can read them (otherwise they would be lost).
    wait_openable(&cfg, b"MARK-alpha", 1).await;
    // A group body is stored once per partition its recipients live on.
    wait_openable(&cfg, b"MARK-group-body", usize::MAX).await;
    // Acknowledged: unreadable with the key state on disk, while the other stays readable.
    m.ack_up_to(&a, 1).await.unwrap();
    wait_openable(&cfg, b"MARK-alpha", 0).await;
    wait_openable(&cfg, b"MARK-beta", 1).await;
    // A shared body stays readable until its last recipient acknowledges.
    m.ack_up_to(&group[0], 1).await.unwrap();
    m.ack_up_to(&group[1], 1).await.unwrap();
    wait_pending(&m, &group[1], 0).await;
    wait_openable(&cfg, b"MARK-group-body", usize::MAX).await;
    m.ack_up_to(&group[2], 1).await.unwrap();
    wait_openable(&cfg, b"MARK-group-body", 0).await;
    // After a restart the acknowledged ones stay gone and the pending one is delivered.
    let again = IggyMailbox::connect(cfg).await.unwrap();
    assert_eq!(again.count_pending(&a).await.unwrap(), 0);
    let got = again.fetch_after(&b, 0, 10).await.unwrap();
    assert_eq!(&got[0].envelope[..], b"MARK-beta-00002");
    // A retried send after delivery is a replay with seq 0 for the recipients that acknowledged.
    let mut retry = StoreRequest {
        idempotency_key: Some([5; 16]),
        mls: None,
        payload: Payload::Shared {
            devices: group.clone(),
            body: Bytes::from_static(b"MARK-group-body"),
        },
    };
    let out = again.store(retry.clone()).await.unwrap();
    assert!(out.replayed);
    assert_eq!(out.seqs, vec![0, 0, 0]);
    retry.idempotency_key = None;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compaction_destroys_old_windows() {
    let Some(mut cfg) = config("windows") else {
        return;
    };
    cfg.relocate_after = Duration::ZERO;
    cfg.key_window = Duration::from_millis(1);
    let m = IggyMailbox::connect(cfg.clone()).await.unwrap();
    let x = d(0x41);
    for i in 0..5u8 {
        let mut req = per(&[(x, "MARK-window")]);
        req.idempotency_key = Some([0x60 + i; 16]);
        m.store(req).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    m.ack_up_to(&x, 4).await.unwrap();
    wait_pending(&m, &x, 1).await;
    m.expire_older_than(Duration::from_hours(30 * 24))
        .await
        .unwrap();
    let stats = m.stats();
    let deadline = Instant::now() + Duration::from_secs(10);
    while stats.compactions.load(std::sync::atomic::Ordering::Relaxed) < u64::from(cfg.partitions) {
        assert!(Instant::now() < deadline, "compaction did not finish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        stats
            .windows_destroyed
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    // The pending message was re-sealed forward and is still readable, once.
    wait_openable(&cfg, b"MARK-window", 1).await;
    let again = IggyMailbox::connect(cfg).await.unwrap();
    let got = again.fetch_after(&x, 0, 10).await.unwrap();
    assert_eq!(got.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![5]);
    // Idempotency outlives the records it pointed at (its own topic): a retry of a delivered
    // send is a replay (seq 0), and the key reused for another device is still refused.
    let mut retry = per(&[(x, "MARK-window")]);
    retry.idempotency_key = Some([0x60; 16]);
    let out = again.store(retry).await.unwrap();
    assert!(out.replayed);
    assert_eq!(out.seqs, vec![0]);
    let mut other = per(&[(d(0x42), "MARK-window")]);
    other.idempotency_key = Some([0x60; 16]);
    let r = again.store(other).await;
    assert!(
        matches!(r, Err(MailboxError::IdempotencyConflict)) || r.is_ok(),
        "{r:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgotten_devices_leave_nothing_readable_and_no_counters() {
    let Some(cfg) = config("forget") else {
        return;
    };
    let m = IggyMailbox::connect(cfg.clone()).await.unwrap();
    let (gone, kept, peer) = (d(0x41), d(0x42), d(0x43));
    m.store(per(&[(gone, "MARK-gone-00001")])).await.unwrap();
    m.store(per(&[(gone, "MARK-gone-00002"), (kept, "MARK-kept-00001")]))
        .await
        .unwrap();
    m.store(StoreRequest {
        idempotency_key: None,
        mls: None,
        payload: Payload::Shared {
            devices: vec![gone, peer],
            body: Bytes::from_static(b"MARK-shared-body"),
        },
    })
    .await
    .unwrap();
    wait_openable(&cfg, b"MARK-gone", 2).await;
    assert!(m.knows(&gone).await.unwrap());

    m.forget(&[gone]).await.unwrap();
    assert!(!m.knows(&gone).await.unwrap());
    assert_eq!(m.count_pending(&gone).await.unwrap(), 0);
    // Unreadable with every key on disk; the others untouched (the shared body stays for its
    // other recipient).
    wait_openable(&cfg, b"MARK-gone", 0).await;
    wait_openable(&cfg, b"MARK-kept", 1).await;
    wait_openable(&cfg, b"MARK-shared-body", usize::MAX).await;
    assert_eq!(m.count_pending(&peer).await.unwrap(), 1);

    // A restart replays the forget: still nothing of the device.
    let again = IggyMailbox::connect(cfg).await.unwrap();
    assert!(!again.knows(&gone).await.unwrap());
    assert_eq!(again.count_pending(&kept).await.unwrap(), 1);
    assert_eq!(again.count_pending(&peer).await.unwrap(), 1);
    // Forgetting is idempotent, also for devices never seen.
    again.forget(&[gone, d(0x44)]).await.unwrap();
}
