//! `run`: simulated devices on the real client, 1:1 traffic, optional connection chaos, checker.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use bytes::{BufMut as _, Bytes, BytesMut};
use songbird_client::{Client, ClientConfig, ClientError, DeviceKey, Event, ResumeState, State};
use songbird_proto::frame::{Recipient, SendStatus};
use songbird_types::DeviceId;
use tokio::sync::watch;

use crate::checker::{self, MsgId, Received};
use crate::stats;

/// Payload header: run ID u32, sender u32, counter u64, send time u64 (ns since run epoch).
/// The run ID tells this run's messages from ones an earlier run left in a mailbox.
const HEADER: usize = 4 + 4 + 8 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Scenario {
    /// Steady 1:1 traffic.
    Steady,
    /// Steady traffic while connections are dropped at random, plus one storm that drops every
    /// connection at once halfway through.
    Reconnect,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Delivery server `host:port`.
    #[arg(long)]
    addr: String,
    /// Server name the devices sign (must match the server's `server_name`).
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// `seeds.txt` from `songbird-loadgen keys`.
    #[arg(long)]
    seeds: PathBuf,
    /// Use only the first N devices (default: all).
    #[arg(long)]
    devices: Option<usize>,
    /// Scenario.
    #[arg(long, value_enum, default_value_t = Scenario::Steady)]
    scenario: Scenario,
    /// Seconds of sending.
    #[arg(long, default_value_t = 10)]
    secs: u64,
    /// Total messages per second across all devices.
    #[arg(long, default_value_t = 1000)]
    rate: u64,
    /// Envelope size in bytes (at least 20).
    #[arg(long, default_value_t = 256)]
    size: usize,
    /// Load generator worker threads.
    #[arg(long, default_value_t = 4)]
    threads: usize,
    /// New connections started per second during ramp-up.
    #[arg(long, default_value_t = 1000)]
    connect_rate: u64,
    /// Longest wait after sending stops for every accepted message to arrive.
    #[arg(long, default_value_t = 60)]
    settle_secs: u64,
    /// Reconnect scenario: one random connection is dropped every this many milliseconds.
    #[arg(long, default_value_t = 200)]
    chaos_every_ms: u64,
}

pub(crate) fn main(a: &Args) -> anyhow::Result<bool> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(a.threads.max(1))
        .enable_all()
        .build()?;
    rt.block_on(run(a))
}

fn load_seeds(path: &std::path::Path, limit: Option<usize>) -> anyhow::Result<Vec<DeviceKey>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if limit.is_some_and(|l| out.len() >= l) {
            break;
        }
        let mut parts = line.split_whitespace();
        let (Some(id), Some(seed), None) = (parts.next(), parts.next(), parts.next()) else {
            bail!("seeds line {}: expected `<device hex> <seed hex>`", i + 1);
        };
        let id = DeviceId::parse_hex(id).with_context(|| format!("seeds line {}", i + 1))?;
        let mut s = [0u8; 32];
        hex::decode_to_slice(seed, &mut s).with_context(|| format!("seeds line {}", i + 1))?;
        out.push(DeviceKey::from_seed(id, &s)?);
    }
    Ok(out)
}

/// xorshift64*: per-task pseudo-random choices without syscalls (not security relevant).
struct Rng(u64);
impl Rng {
    fn new() -> Self {
        Self(getrandom::u64().unwrap_or(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

fn payload(run: u32, sender: u32, n: u64, sent_ns: u64, size: usize) -> Bytes {
    let mut b = BytesMut::with_capacity(size.max(HEADER));
    b.put_u32(run);
    b.put_u32(sender);
    b.put_u64(n);
    b.put_u64(sent_ns);
    b.resize(size.max(HEADER), 0xA5);
    b.freeze()
}

/// `None` for a message of another run (or not a load generator message at all).
fn parse(run: u32, body: &[u8]) -> Option<(MsgId, u64)> {
    let field = |at: std::ops::Range<usize>| body.get(at);
    let msg_run = u32::from_be_bytes(field(0..4)?.try_into().ok()?);
    let sender = u32::from_be_bytes(field(4..8)?.try_into().ok()?);
    let counter = u64::from_be_bytes(field(8..16)?.try_into().ok()?);
    let sent = u64::from_be_bytes(field(16..24)?.try_into().ok()?);
    (msg_run == run).then_some(((sender, counter), sent))
}

fn ns_since(epoch: Instant) -> u64 {
    u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

struct SenderOut {
    accepted: Vec<(usize, MsgId)>,
    rejected: u64,
    retries: u64,
}

#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn run(a: &Args) -> anyhow::Result<bool> {
    ensure!(a.size >= HEADER, "--size must be at least {HEADER}");
    let keys = load_seeds(&a.seeds, a.devices)?;
    let n = keys.len();
    ensure!(n >= 2, "need at least 2 devices");
    let ids: Arc<Vec<DeviceId>> = Arc::new(keys.iter().map(DeviceKey::device).collect());
    let mut cfg = ClientConfig::new(a.addr.clone(), a.server_name.clone());
    cfg.backoff.initial = Duration::from_millis(100);
    cfg.backoff.max = Duration::from_secs(5);
    cfg.event_capacity = 4096;

    // Ramp up.
    let t_connect = Instant::now();
    let mut clients = Vec::with_capacity(n);
    let mut events = Vec::with_capacity(n);
    let gap = Duration::from_secs_f64(
        1.0 / f64::from(u32::try_from(a.connect_rate.max(1)).unwrap_or(u32::MAX)),
    );
    for key in keys {
        let (c, ev) = Client::start(cfg.clone(), key, ResumeState::default());
        clients.push(c);
        events.push(ev);
        tokio::time::sleep(gap).await;
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    for c in &mut clients {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, c.wait_for(State::Connected)).await {
            Ok(State::Connected) => {}
            _ => bail!("not every device connected within 120 s"),
        }
    }
    let connect_secs = t_connect.elapsed().as_secs_f64();
    let clients: Vec<Arc<Client>> = clients.into_iter().map(Arc::new).collect();

    let epoch = Instant::now();
    let run_id = getrandom::u32()?;
    let delivered_total = Arc::new(AtomicU64::new(0));
    let (stop_recv_tx, stop_recv) = watch::channel(false);
    let mut receivers = Vec::with_capacity(n);
    for (c, mut ev) in clients.iter().cloned().zip(events) {
        let total = Arc::clone(&delivered_total);
        let mut stop = stop_recv.clone();
        receivers.push(tokio::spawn(async move {
            let mut got = Received::default();
            let mut lat: Vec<u32> = Vec::new();
            let mut failed = None;
            loop {
                tokio::select! {
                    _ = async { stop.wait_for(|s| *s).await.is_ok() } => break,
                    e = ev.recv() => match e {
                        Some(Event::Deliver { seq, envelope }) => {
                            if let Some((id, sent)) = parse(run_id, &envelope) {
                                got.items.push((seq, Some(id)));
                                let us = ns_since(epoch).saturating_sub(sent) / 1_000;
                                lat.push(u32::try_from(us).unwrap_or(u32::MAX));
                                total.fetch_add(1, Ordering::Relaxed);
                            } else {
                                got.items.push((seq, None));
                            }
                            // The app "stored" it: acknowledge (the client coalesces ACKs).
                            let _ = c.ack(seq).await;
                        }
                        Some(Event::Failed { code }) => failed = Some(code),
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            (got, lat, failed)
        }));
    }

    // Senders.
    let send_until = epoch + Duration::from_secs(a.secs);
    let settle_until = send_until + Duration::from_secs(a.settle_secs);
    let per_device = (f64::from(u32::try_from(a.rate).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(n).unwrap_or(u32::MAX)))
    .max(1e-3);
    let period = Duration::from_secs_f64(1.0 / per_device);
    let mut senders = Vec::with_capacity(n);
    for (i, c) in clients.iter().cloned().enumerate() {
        let ids = Arc::clone(&ids);
        let size = a.size;
        senders.push(tokio::spawn(async move {
            let me = u32::try_from(i).unwrap_or(u32::MAX);
            let mut rng = Rng::new();
            let mut out = SenderOut {
                accepted: Vec::new(),
                rejected: 0,
                retries: 0,
            };
            // Spread the first sends over one period.
            let first =
                Duration::from_nanos(rng.below(u64::try_from(period.as_nanos()).unwrap_or(1)));
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + first, period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut counter = 0u64;
            loop {
                // Stop at the end of the run even if the next tick is later (slow devices).
                tokio::select! {
                    _ = tick.tick() => {}
                    () = tokio::time::sleep_until(send_until.into()) => break,
                }
                if Instant::now() >= send_until {
                    break;
                }
                let to = {
                    let r = usize::try_from(rng.below(u64::try_from(ids.len() - 1).unwrap_or(1)))
                        .unwrap_or(0);
                    if r >= i { r + 1 } else { r }
                };
                let mut key = [0u8; 16];
                key[..8].copy_from_slice(&rng.next().to_be_bytes());
                key[8..].copy_from_slice(&rng.next().to_be_bytes());
                let Some(&dev) = ids.get(to) else { break };
                let body = payload(run_id, me, counter, ns_since(epoch), size);
                let rcpt = vec![Recipient {
                    device: dev,
                    envelope: body,
                }];
                // Retry with the same idempotency key until the server answers: a send that
                // failed with Disconnected may or may not have been stored; the key makes the
                // retry safe either way.
                loop {
                    match c.send(key, rcpt.clone()).await {
                        Ok(SendStatus::Accepted) => {
                            out.accepted.push((to, (me, counter)));
                            break;
                        }
                        Ok(SendStatus::Rejected {
                            reason,
                            retry_after_ms,
                        }) if reason.is_retryable() => {
                            out.retries += 1;
                            tokio::time::sleep(Duration::from_millis(u64::from(
                                retry_after_ms.max(10),
                            )))
                            .await;
                        }
                        Ok(_) => {
                            out.rejected += 1;
                            break;
                        }
                        Err(ClientError::NotConnected | ClientError::Disconnected) => {
                            out.retries += 1;
                            if Instant::now() > settle_until {
                                out.rejected += 1;
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        Err(ClientError::Stopped) => return out,
                    }
                }
                counter += 1;
            }
            out
        }));
    }

    // Chaos.
    let aborts = Arc::new(AtomicU64::new(0));
    let chaos = (a.scenario == Scenario::Reconnect).then(|| {
        let clients = clients.clone();
        let aborts = Arc::clone(&aborts);
        let every = Duration::from_millis(a.chaos_every_ms.max(1));
        let storm_at = epoch + Duration::from_secs(a.secs) / 2;
        tokio::spawn(async move {
            let mut rng = Rng::new();
            let mut stormed = false;
            while Instant::now() < send_until {
                tokio::time::sleep(every).await;
                if !stormed && Instant::now() >= storm_at {
                    stormed = true;
                    for c in &clients {
                        let _ = c.abort_connection().await;
                        aborts.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    let i = usize::try_from(rng.below(u64::try_from(clients.len()).unwrap_or(1)))
                        .unwrap_or(0);
                    if let Some(c) = clients.get(i) {
                        let _ = c.abort_connection().await;
                        aborts.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    });

    let mut expected: Vec<Vec<MsgId>> = vec![Vec::new(); n];
    let (mut accepted, mut rejected, mut retries) = (0u64, 0u64, 0u64);
    for s in senders {
        let out = s.await?;
        rejected += out.rejected;
        retries += out.retries;
        for (to, id) in out.accepted {
            accepted += 1;
            if let Some(e) = expected.get_mut(to) {
                e.push(id);
            }
        }
    }
    let send_secs = epoch.elapsed().as_secs_f64();
    if let Some(c) = chaos {
        c.await?;
    }
    // Settle: every accepted message delivered, or the deadline.
    let t_settle = Instant::now();
    while delivered_total.load(Ordering::Relaxed) < accepted && Instant::now() < settle_until {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let settle_secs = t_settle.elapsed().as_secs_f64();
    let _ = stop_recv_tx.send(true);
    let mut received = Vec::with_capacity(n);
    let mut lat = Vec::new();
    let mut failed = 0u64;
    for r in receivers {
        let (got, l, f) = r.await?;
        received.push(got);
        lat.extend(l);
        failed += u64::from(f.is_some());
    }
    for c in clients {
        if let Ok(c) = Arc::try_unwrap(c) {
            c.close().await;
        }
    }
    let report = checker::check(&expected, &received);
    let s = stats::summarize(&mut lat);
    println!(
        "scenario={:?} devices={n} secs={} target_rate={} size={} threads={}",
        a.scenario, a.secs, a.rate, a.size, a.threads
    );
    println!("connect: {n} devices in {connect_secs:.2}s");
    let achieved = crate::as_f64(accepted) / send_secs;
    println!(
        "sends: accepted={accepted} rejected={rejected} retries={retries} achieved_rate={achieved:.0}/s aborts={} failed_clients={failed}",
        aborts.load(Ordering::Relaxed)
    );
    println!("settle: {settle_secs:.2}s");
    println!("latency send->deliver (client-observed): {s}");
    println!(
        "checker: {} expected={} delivered={} lost={} duplicates={} seq_violations={} fifo_violations={} unexpected={} stale_from_earlier_runs={}",
        if report.passed() { "PASS" } else { "FAIL" },
        report.expected,
        report.delivered,
        report.lost,
        report.duplicates,
        report.seq_violations,
        report.fifo_violations,
        report.unexpected,
        report.stale
    );
    Ok(report.passed() && rejected == 0)
}
