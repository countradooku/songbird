//! The SurrealDB mailbox against a real SurrealDB 4 (see `crates/surreal/tests/live.rs` for the
//! environment variables). Each test uses its own database.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use songbird_mailbox::surreal::{SurrealConfig, SurrealMailbox};
use songbird_mailbox::{Mailbox, MailboxError, MlsCommit, NewEnvelope, Payload, StoreRequest};
use songbird_surreal::{Config as RpcConfig, Value};
use songbird_types::DeviceId;

fn config(name: &str) -> Option<SurrealConfig> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_SURREALDB") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_SURREALDB").is_err(),
            "SONGBIRD_REQUIRE_SURREALDB is set but SONGBIRD_TEST_SURREALDB is not"
        );
        return None;
    };
    Some(SurrealConfig {
        rpc: RpcConfig {
            host: addr.split(':').next().unwrap_or("localhost").to_owned(),
            addr,
            tls: None,
            user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
            pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS")
                .expect("SONGBIRD_TEST_SURREALDB_PASS"),
            namespace: "songbird_test".into(),
            database: format!(
                "{name}_{}_{}",
                std::process::id(),
                DeviceId::random()
                    .unwrap()
                    .to_hex_unredacted()
                    .get(..8)
                    .unwrap()
            ),
            timeout: Duration::from_secs(10),
            max_message_bytes: 64 << 20,
        },
        max_batch: 256,
        max_wait: Duration::from_millis(1),
        ack_interval: Duration::from_millis(20),
        max_per_device: 10_000,
        idempotency_secret: [7; 32],
    })
}

fn d(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
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

async fn wait_pending(m: &SurrealMailbox, dev: &DeviceId, want: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if m.count_pending(dev).await.unwrap() == want {
            return;
        }
        assert!(Instant::now() < deadline, "pending never reached {want}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn store_fetch_ack_and_seq_rules() {
    let Some(cfg) = config("basic") else { return };
    let m = SurrealMailbox::connect(cfg).await.unwrap();
    assert_eq!(m.store_generation().await.unwrap(), 1);
    let out = m
        .store(per(&[(d(1), "a"), (d(2), "b"), (d(1), "c")]))
        .await
        .unwrap();
    assert_eq!(out.seqs, vec![1, 1, 2]);
    let got = m.fetch_after(&d(1), 0, 10).await.unwrap();
    assert_eq!(got.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(got[1].envelope, Bytes::from_static(b"c"));
    assert_eq!(m.fetch_after(&d(1), 1, 10).await.unwrap().len(), 1);
    assert_eq!(m.fetch_after(&d(1), 0, 1).await.unwrap().len(), 1);
    m.ack_up_to(&d(1), 2).await.unwrap();
    wait_pending(&m, &d(1), 0).await;
    // seq is never reused after deletes.
    assert_eq!(m.store(per(&[(d(1), "e")])).await.unwrap().seqs, vec![3]);
    assert_eq!(m.count_pending(&d(2)).await.unwrap(), 1);
}

#[tokio::test]
async fn idempotency_replays_and_conflicts() {
    let Some(cfg) = config("idem") else { return };
    let m = SurrealMailbox::connect(cfg).await.unwrap();
    let mut req = per(&[(d(1), "a"), (d(2), "b")]);
    req.idempotency_key = Some([3; 16]);
    let first = m.store(req.clone()).await.unwrap();
    let again = m.store(req).await.unwrap();
    assert!(!first.replayed && again.replayed);
    assert_eq!(first.seqs, again.seqs);
    assert_eq!(m.count_pending(&d(1)).await.unwrap(), 1, "stored once");
    let mut other = per(&[(d(3), "c")]);
    other.idempotency_key = Some([3; 16]);
    assert_eq!(m.store(other).await, Err(MailboxError::IdempotencyConflict));
    assert_eq!(m.count_pending(&d(3)).await.unwrap(), 0);
    // The record is a keyed hash: the raw key is nowhere.
    let keys = m
        .query_one("SELECT VALUE meta::id(id)[0] FROM idem;", Vec::new())
        .await
        .unwrap();
    let k = keys.as_array().unwrap()[0].as_bytes().unwrap().clone();
    assert_eq!(k.len(), 32);
    assert_ne!(&k[..16], &[3; 16]);
}

#[tokio::test]
async fn one_bad_send_does_not_fail_its_batch() {
    let Some(mut cfg) = config("partial") else {
        return;
    };
    cfg.max_per_device = 2;
    cfg.max_wait = Duration::from_millis(20);
    let m = Arc::new(SurrealMailbox::connect(cfg).await.unwrap());
    m.store(per(&[(d(9), "x"), (d(9), "y")])).await.unwrap();
    // Sent together so they share a transaction: one full mailbox, one fine send.
    let (a, b) = tokio::join!(m.store(per(&[(d(9), "z")])), m.store(per(&[(d(8), "ok")])));
    assert_eq!(a, Err(MailboxError::Full));
    assert_eq!(b.unwrap().seqs, vec![1]);
    assert_eq!(m.count_pending(&d(9)).await.unwrap(), 2);
}

#[tokio::test]
async fn shared_body_is_stored_once() {
    let Some(cfg) = config("shared") else { return };
    let m = SurrealMailbox::connect(cfg).await.unwrap();
    let devices: Vec<DeviceId> = (0..1000u32)
        .map(|i| {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&i.to_be_bytes());
            DeviceId::from_bytes(b)
        })
        .collect();
    let body = Bytes::from(vec![0xAB; 4096]);
    let t0 = Instant::now();
    let out = m
        .store(StoreRequest {
            idempotency_key: Some([1; 16]),
            mls: None,
            payload: Payload::Shared {
                devices: devices.clone(),
                body: body.clone(),
            },
        })
        .await
        .unwrap();
    let took = t0.elapsed();
    assert_eq!(out.seqs.len(), 1000);
    assert!(out.seqs.iter().all(|s| *s == 1));
    // One body; 1,000 index entries, none carrying the ciphertext.
    let bodies = m
        .query_one("RETURN count(SELECT id FROM body);", Vec::new())
        .await
        .unwrap();
    assert_eq!(bodies.as_i64(), Some(1));
    let entries = m
        .query_one("RETURN [count(SELECT id FROM mailbox), count(SELECT id FROM mailbox WHERE env != NONE)];", Vec::new())
        .await
        .unwrap();
    assert_eq!(entries.as_array().unwrap()[0].as_i64(), Some(1000));
    assert_eq!(entries.as_array().unwrap()[1].as_i64(), Some(0));
    assert_eq!(
        m.fetch_after(&devices[500], 0, 10).await.unwrap()[0].envelope,
        body
    );
    // The body is deleted when the last device acknowledges.
    for dev in &devices[..999] {
        m.ack_up_to(dev, 1).await.unwrap();
    }
    wait_pending(&m, &devices[998], 0).await;
    let refs = m
        .query_one("SELECT VALUE refs FROM body;", Vec::new())
        .await
        .unwrap();
    assert_eq!(refs.as_array().unwrap()[0].as_i64(), Some(1));
    m.ack_up_to(&devices[999], 1).await.unwrap();
    wait_pending(&m, &devices[999], 0).await;
    let left = m
        .query_one("RETURN count(SELECT id FROM body);", Vec::new())
        .await
        .unwrap();
    assert_eq!(left.as_i64(), Some(0));
    eprintln!("1,000-device shared send: {took:?}");
}

#[tokio::test]
async fn mls_commits_are_ordered_by_epoch() {
    let Some(cfg) = config("mls") else { return };
    let m = Arc::new(SurrealMailbox::connect(cfg).await.unwrap());
    let commit = |epoch, key: u8| StoreRequest {
        idempotency_key: Some([key; 16]),
        mls: Some(MlsCommit {
            group: [5; 16],
            epoch,
        }),
        payload: Payload::Shared {
            devices: vec![d(1), d(2)],
            body: Bytes::from_static(b"commit"),
        },
    };
    // Ten concurrent commits from epoch 0: exactly one wins.
    let mut tasks = Vec::new();
    for k in 0..10u8 {
        let m = Arc::clone(&m);
        tasks.push(tokio::spawn(
            async move { m.store(commit(0, k + 10)).await },
        ));
    }
    let mut won = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => won += 1,
            Err(e) => assert_eq!(e, MailboxError::StaleEpoch),
        }
    }
    assert_eq!(won, 1);
    assert_eq!(m.count_pending(&d(1)).await.unwrap(), 1);
    assert!(m.store(commit(1, 50)).await.is_ok());
    assert_eq!(m.store(commit(1, 51)).await, Err(MailboxError::StaleEpoch));
}

#[tokio::test]
async fn concurrent_senders_get_gap_free_unique_seqs() {
    let Some(cfg) = config("concurrent") else {
        return;
    };
    let m = Arc::new(SurrealMailbox::connect(cfg).await.unwrap());
    let mut tasks = Vec::new();
    for t in 0..50u8 {
        let m = Arc::clone(&m);
        tasks.push(tokio::spawn(async move {
            let mut seqs = Vec::new();
            for i in 0..20u8 {
                let mut req = per(&[(d(1), "x"), (d(t + 100), "y")]);
                req.idempotency_key = Some([t, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                seqs.push(m.store(req).await.unwrap().seqs[0]);
            }
            seqs
        }));
    }
    let mut all = HashSet::new();
    for t in tasks {
        for s in t.await.unwrap() {
            assert!(all.insert(s), "duplicate seq {s}");
        }
    }
    assert_eq!(all.len(), 1000);
    assert_eq!(*all.iter().max().unwrap(), 1000);
    let stats = m.stats();
    let commits = stats.commits.load(Ordering::Relaxed);
    assert!(
        commits < 1000,
        "group commit batched {commits} transactions for 1000 sends"
    );
    eprintln!(
        "1000 sends in {commits} transactions, {} retries",
        stats.retries.load(Ordering::Relaxed)
    );
}

#[tokio::test]
async fn expiry_deletes_old_entries_and_bodies() {
    let Some(cfg) = config("expiry") else { return };
    let m = SurrealMailbox::connect(cfg).await.unwrap();
    m.store(per(&[(d(1), "old")])).await.unwrap();
    m.store(StoreRequest {
        idempotency_key: None,
        mls: None,
        payload: Payload::Shared {
            devices: vec![d(1), d(2)],
            body: Bytes::from_static(b"group"),
        },
    })
    .await
    .unwrap();
    // Nothing is older than an hour.
    assert_eq!(
        m.expire_older_than(Duration::from_hours(1)).await.unwrap(),
        0
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        m.expire_older_than(Duration::from_secs(1)).await.unwrap(),
        3
    );
    assert_eq!(m.count_pending(&d(1)).await.unwrap(), 0);
    let bodies = m
        .query_one(
            "RETURN count(SELECT id FROM body);",
            vec![("x".into(), Value::Null)],
        )
        .await
        .unwrap();
    assert_eq!(bodies.as_i64(), Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_devices_ack_in_bulk() {
    let Some(cfg) = config("bulkack") else { return };
    let m = Arc::new(SurrealMailbox::connect(cfg).await.unwrap());
    let devices: Vec<DeviceId> = (0..500).map(|_| DeviceId::random().unwrap()).collect();
    for round in 0..10u64 {
        let mut tasks = Vec::new();
        for d in &devices {
            let m = Arc::clone(&m);
            let d = *d;
            tasks.push(tokio::spawn(async move {
                let mut req = per(&[(d, "x")]);
                let mut k = [0u8; 16];
                k[..16].copy_from_slice(&d.as_bytes()[..]);
                k[0] ^= u8::try_from(round).unwrap();
                req.idempotency_key = Some(k);
                m.store(req).await.unwrap()
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        for d in &devices {
            m.ack_up_to(d, round + 1).await.unwrap();
        }
    }
    for d in devices.iter().take(5) {
        wait_pending(&m, d, 0).await;
    }
    let left = m
        .query_one("RETURN count(SELECT id FROM mailbox);", Vec::new())
        .await
        .unwrap();
    assert_eq!(left.as_i64(), Some(0));
}
