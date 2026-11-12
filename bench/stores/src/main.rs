//! Mailbox store comparison: SurrealDB (M2), Valkey, Apache Iggy, behind the same `Mailbox`
//! trait and the same closed-loop workload as `crates/mailbox/examples/commit_bench.rs`.
//!
//! Settings come from the environment (semgrep refuses argv in this repository):
//!
//! ```text
//! STORE=valkey|iggy|surreal SENDERS=128 SECS=10 RECIPIENTS=1 SHARED=0 CYCLE=1 DEVICES=10000 \
//!   VALKEY_URL=redis://:pass@127.0.0.1:47379 IGGY_URL=iggy://iggy:pass@127.0.0.1:47890 \
//!   SURREAL_ADDR=127.0.0.1:47801 SURREAL_PASS=… cargo run --release
//! ```
//!
//! `CYCLE=1` also acknowledges every stored entry (the store deletes it in its batched ACK path),
//! which is what a delivered message costs end to end. After the run every device's `seq`s are
//! checked: exactly 1..=n, no gap, no duplicate.

mod iggy_mb;
mod sharded;
mod valkey;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use songbird_mailbox::surreal::{SurrealConfig, SurrealMailbox};
use songbird_mailbox::{Mailbox, NewEnvelope, Payload, StoreRequest};
use songbird_types::DeviceId;

fn setting(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn device(i: u64, run: u64) -> DeviceId {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ run).to_le_bytes());
    b[8..].copy_from_slice(&run.to_le_bytes());
    DeviceId::from_bytes(b)
}

struct Result_ {
    retries: u64,
    sends: u64,
    entries: u64,
    errors: u64,
    lat: Vec<u64>,
    seqs: Vec<(DeviceId, u64)>,
}

async fn run<M: Mailbox>(m: Arc<M>) {
    let senders = setting("SENDERS", 64);
    let secs = setting("SECS", 10);
    let recipients = setting("RECIPIENTS", 1) as usize;
    let shared = setting("SHARED", 0) == 1;
    let cycle = setting("CYCLE", 1) == 1;
    let devices = setting("DEVICES", 10_000);
    let size = setting("SIZE", 256) as usize;
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let deadline = Instant::now() + Duration::from_secs(secs);
    let start = Instant::now();
    let mut tasks = Vec::new();
    for t in 0..senders {
        let m = m.clone();
        tasks.push(tokio::spawn(async move {
            let mut rng = Rng(run_id ^ (t + 1).wrapping_mul(0xA24B_AED4_963E_E407) | 1);
            let env = Bytes::from(vec![0xAB; size]);
            let mut r = Result_ { retries: 0, sends: 0, entries: 0, errors: 0, lat: Vec::new(), seqs: Vec::new() };
            while Instant::now() < deadline {
                let mut devs: Vec<DeviceId> = Vec::with_capacity(recipients);
                while devs.len() < recipients {
                    let d = device(rng.next() % devices, run_id);
                    if !devs.contains(&d) {
                        devs.push(d);
                    }
                }
                let payload = if shared {
                    Payload::Shared { devices: devs.clone(), body: env.clone() }
                } else {
                    Payload::PerDevice(
                        devs.iter().map(|d| NewEnvelope { device: *d, envelope: env.clone() }).collect(),
                    )
                };
                let mut key = [0u8; 16];
                key[..8].copy_from_slice(&rng.next().to_le_bytes());
                key[8..].copy_from_slice(&rng.next().to_le_bytes());
                let req = StoreRequest { idempotency_key: Some(key), mls: None, payload };
                let t0 = Instant::now();
                // A failed or timed-out store has an uncertain outcome: retry with the same
                // idempotency key, as clients do; a committed first attempt is replayed.
                let mut res = m.store(req.clone()).await;
                let mut tries = 1;
                while matches!(res, Err(songbird_mailbox::MailboxError::Unavailable)) && tries < 5 {
                    r.retries += 1;
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    res = m.store(req.clone()).await;
                }
                match res {
                    Ok(out) => {
                        r.lat.push(t0.elapsed().as_micros() as u64);
                        r.sends += 1;
                        r.entries += out.seqs.len() as u64;
                        for (d, s) in devs.iter().zip(&out.seqs) {
                            r.seqs.push((*d, *s));
                            if cycle {
                                let _ = m.ack_up_to(d, *s).await;
                            }
                        }
                    }
                    Err(_) => r.errors += 1,
                }
            }
            r
        }));
    }
    let mut all = Result_ { retries: 0, sends: 0, entries: 0, errors: 0, lat: Vec::new(), seqs: Vec::new() };
    for t in tasks {
        let r = t.await.unwrap();
        all.sends += r.sends;
        all.entries += r.entries;
        all.errors += r.errors;
        all.retries += r.retries;
        all.lat.extend(r.lat);
        all.seqs.extend(r.seqs);
    }
    let el = start.elapsed().as_secs_f64();
    all.lat.sort_unstable();
    let p = |q: f64| all.lat.get(((all.lat.len() as f64 - 1.0) * q) as usize).copied().unwrap_or(0);
    // Seq check: per device exactly 1..=n.
    let mut per: HashMap<DeviceId, Vec<u64>> = HashMap::new();
    for (d, s) in &all.seqs {
        per.entry(*d).or_default().push(*s);
    }
    let mut bad = 0;
    for v in per.values_mut() {
        v.sort_unstable();
        if v.iter().enumerate().any(|(i, s)| *s != i as u64 + 1) {
            bad += 1;
        }
    }
    // Pending after the ACK path has had time to run.
    let mut left = 0;
    if cycle {
        tokio::time::sleep(Duration::from_millis(500)).await;
        for d in per.keys().take(200) {
            left += m.count_pending(d).await.unwrap_or(u64::MAX);
        }
    }
    println!(
        "store={}{} senders={senders} recipients={recipients} shared={shared} cycle={cycle}: {:.0} sends/s, {:.0} entries/s, errors={}, retries={}, latency p50={}us p99={}us p99.9={}us max={}us, seq_check={} ({} devices), pending_after_ack(200 devices)={}",
        std::env::var("STORE").unwrap_or_default(),
        std::env::var("LABEL").unwrap_or_default(),
        all.sends as f64 / el,
        all.entries as f64 / el,
        all.errors,
        all.retries,
        p(0.5),
        p(0.99),
        p(0.999),
        all.lat.last().copied().unwrap_or(0),
        if bad == 0 { "PASS" } else { "FAIL" },
        per.len(),
        left,
    );
}

fn main() {
    let threads = setting("THREADS", 4) as usize;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let ack_interval = Duration::from_millis(setting("ACK_MS", 50));
        let max_batch = setting("MAX_BATCH", 256) as usize;
        match env("STORE").as_str() {
            "valkey" => {
                // VALKEY_URL: one URL, or several separated by commas (sharded by device).
                let mut shards = Vec::new();
                for url in env("VALKEY_URL").split(',') {
                    shards.push(
                        valkey::ValkeyMailbox::connect(valkey::ValkeyConfig {
                            url: url.to_owned(),
                            connections: setting("CONNS", 4) as usize,
                            max_per_device: 1_000_000,
                            ack_interval,
                            idempotency_secret: random_secret(),
                        })
                        .await
                        .unwrap(),
                    );
                }
                if shards.len() == 1 {
                    run(Arc::new(shards.pop().unwrap())).await;
                } else {
                    run(Arc::new(sharded::Sharded { shards })).await;
                }
            }
            "iggy" => {
                let m = iggy_mb::IggyMailbox::connect(iggy_mb::IggyConfig {
                    url: env("IGGY_URL"),
                    partitions: setting("PARTITIONS", 4) as u32,
                    max_batch,
                    max_per_device: 1_000_000,
                    ack_interval,
                    idempotency_secret: random_secret(),
                })
                .await
                .unwrap();
                run(Arc::new(m)).await;
            }
            "iggyprod" => {
                // The production mailbox (crates/mailbox/src/iggy).
                let url = env("IGGY_ADDR");
                let connection = songbird_mailbox::iggy::IggyConnection {
                    addr: url,
                    tls_domain: None,
                    tls_ca_file: None,
                    user: "iggy".into(),
                    pass: env("IGGY_PASS"),
                };
                let mut cfg = songbird_mailbox::iggy::IggyConfig::new(connection, random_secret(), std::env::temp_dir().join(format!("songbird-bench-keys-{}", std::process::id())), random_secret());
                cfg.stream = format!("bench{}", std::process::id());
                cfg.partitions = setting("PARTITIONS", 4) as u32;
                cfg.max_batch = max_batch;
                cfg.max_per_device = 1_000_000;
                cfg.ack_interval = ack_interval;
                cfg.cache_bytes = 256 << 20;
                let stream = cfg.stream.clone();
                let admin = cfg.connection.client().await.unwrap();
                let m = songbird_mailbox::iggy::IggyMailbox::connect(cfg).await.unwrap();
                run(Arc::new(m)).await;
                // Free the space (tmpfs runs fill gigabytes).
                use iggy::prelude::StreamClient as _;
                let _ = admin.delete_stream(&iggy::prelude::Identifier::named(&stream).unwrap()).await;
            }
            "surreal" => {
                let addr = env("SURREAL_ADDR");
                let m = SurrealMailbox::connect(SurrealConfig {
                    rpc: songbird_surreal::Config {
                        host: addr.split(':').next().unwrap().to_owned(),
                        addr,
                        tls: None,
                        user: "root".into(),
                        pass: env("SURREAL_PASS"),
                        namespace: "bench".into(),
                        database: format!("s{}", std::process::id()),
                        timeout: Duration::from_secs(30),
                        max_message_bytes: 64 << 20,
                    },
                    max_batch,
                    max_wait: Duration::ZERO,
                    ack_interval,
                    max_per_device: 1_000_000,
                    idempotency_secret: random_secret(),
                })
                .await
                .unwrap();
                run(Arc::new(m)).await;
            }
            other => panic!("unknown STORE {other}"),
        }
    });
}

/// A fresh random idempotency secret for each benchmark run (never a fixed key).
fn random_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    aws_lc_rs::rand::fill(&mut k).expect("system randomness");
    k
}
