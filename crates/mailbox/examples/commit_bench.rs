//! Group-commit throughput of the SurrealDB mailbox (milestone 2 gate: "SurrealDB commits per
//! second measured").
//!
//! ```text
//! SURREAL_ADDR=127.0.0.1:47801 SURREAL_PASS=… BENCH_SENDERS=128 BENCH_SECS=10 \
//!     BENCH_MAX_BATCH=256 BENCH_MAX_WAIT_US=0 BENCH_RECIPIENTS=1 BENCH_SHARED=0 \
//!     cargo run --release -p songbird-mailbox --example commit_bench
//! ```
//!
//! Settings come from environment variables (all optional except the SurrealDB ones).
//! `BENCH_SENDERS` tasks each store one send after another (closed loop), each send to `BENCH_RECIPIENTS`
//! random devices (per-device envelopes of 256 bytes, or one shared body with `BENCH_SHARED=1`). Prints
//! sends/s, transactions/s, mean sends per transaction and store latency percentiles.
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a benchmark tool"
)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use songbird_mailbox::surreal::{SurrealConfig, SurrealMailbox};
use songbird_mailbox::{Mailbox, NewEnvelope, Payload, StoreRequest};
use songbird_types::DeviceId;

fn setting(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let senders = setting("BENCH_SENDERS", 64);
    let secs = setting("BENCH_SECS", 10);
    let max_batch = setting("BENCH_MAX_BATCH", 256);
    let max_wait_us = setting("BENCH_MAX_WAIT_US", 0);
    let recipients = setting("BENCH_RECIPIENTS", 1);
    let shared = setting("BENCH_SHARED", 0) == 1;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let addr = std::env::var("SURREAL_ADDR").expect("SURREAL_ADDR");
        let cfg = SurrealConfig {
            rpc: songbird_surreal::Config {
                host: addr.split(':').next().unwrap().to_owned(),
                addr,
                tls: None,
                user: "root".into(),
                pass: std::env::var("SURREAL_PASS").expect("SURREAL_PASS"),
                namespace: "bench".into(),
                database: format!("b{}", std::process::id()),
                timeout: Duration::from_secs(30),
                max_message_bytes: 64 << 20,
            },
            max_batch: usize::try_from(max_batch).unwrap(),
            max_wait: Duration::from_micros(max_wait_us),
            ack_interval: Duration::from_millis(50),
            max_per_device: 1_000_000,
            idempotency_secret: [1; 32],
        };
        let m = Arc::new(SurrealMailbox::connect(cfg).await.unwrap());
        let devices: Arc<Vec<DeviceId>> =
            Arc::new((0..10_000).map(|_| DeviceId::random().unwrap()).collect());
        let until = Instant::now() + Duration::from_secs(secs);
        let started = Instant::now();
        let mut tasks = Vec::new();
        for t in 0..senders {
            let m = Arc::clone(&m);
            let devices = Arc::clone(&devices);
            tasks.push(tokio::spawn(async move {
                let mut lat = Vec::new();
                let mut n = 0u64;
                let env = Bytes::from(vec![0xA5; 256]);
                while Instant::now() < until {
                    let pick = |k: u64| devices[((t * 7919 + n * 104_729 + k * 31) % 10_000) as usize];
                    let devs: Vec<DeviceId> = (0..recipients).map(pick).collect();
                    let payload = if shared {
                        Payload::Shared { devices: devs, body: env.clone() }
                    } else {
                        Payload::PerDevice(
                            devs.into_iter().map(|device| NewEnvelope { device, envelope: env.clone() }).collect(),
                        )
                    };
                    let mut key = [0u8; 16];
                    key[..8].copy_from_slice(&t.to_be_bytes());
                    key[8..].copy_from_slice(&n.to_be_bytes());
                    let t0 = Instant::now();
                    m.store(StoreRequest { idempotency_key: Some(key), mls: None, payload, expires_after: None }).await.unwrap();
                    lat.push(t0.elapsed().as_micros() as u32);
                    n += 1;
                }
                lat
            }));
        }
        let mut lat: Vec<u32> = Vec::new();
        for t in tasks {
            lat.extend(t.await.unwrap());
        }
        let elapsed = started.elapsed().as_secs_f64();
        lat.sort_unstable();
        let pct = |q: f64| lat[((lat.len() as f64 * q) as usize).min(lat.len() - 1)];
        let s = m.stats();
        let commits = s.commits.load(Ordering::Relaxed) as f64;
        let sends = s.sends.load(Ordering::Relaxed) as f64;
        println!(
            "senders={senders} recipients={recipients} shared={shared} max_batch={max_batch} max_wait_us={max_wait_us}: \
             {:.0} sends/s, {:.0} entries/s, {:.0} commits/s, {:.1} sends/commit, retries={}, \
             latency p50={}us p99={}us p99.9={}us",
            sends / elapsed,
            s.entries.load(Ordering::Relaxed) as f64 / elapsed,
            commits / elapsed,
            sends / commits.max(1.0),
            s.retries.load(Ordering::Relaxed),
            pct(0.5),
            pct(0.99),
            pct(0.999)
        );
    });
}
