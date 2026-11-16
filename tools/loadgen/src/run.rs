//! `run`: simulated devices on the real client (1:1 or group traffic, idle connections, connection
//! chaos and storms), the delivery checker, and the server's own figures from its admin endpoint.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use bytes::{BufMut as _, Bytes, BytesMut};
use songbird_client::{Client, ClientConfig, ClientError, DeviceKey, Event, ResumeState, State};
use songbird_proto::frame::{Recipient, SendHints, SendPayload, SendStatus};
use songbird_types::DeviceId;
use tokio::sync::watch;

use crate::checker::{self, MsgId, Received};
use crate::stats;

/// Payload header: run ID u32, sender u32, counter u64, send time u64 (ns since run epoch),
/// idempotency key (16 bytes, so the recipient can confirm a delivery receipt; D-0040). The run ID
/// tells this run's messages from ones an earlier run left in a mailbox.
const HEADER: usize = 4 + 4 + 8 + 8 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Scenario {
    /// Steady 1:1 traffic.
    Steady,
    /// Steady traffic while connections are dropped at random, plus one storm that drops every
    /// connection at once halfway through.
    Reconnect,
    /// Steady traffic across a restore done from outside (`bench/m6/restore-drill.sh`, D-0040):
    /// recipients confirm delivery receipts to senders, senders resend what has none when the
    /// store generation grows, and the checker allows what a restore legitimately causes
    /// (numbering restarts, repeats dropped by message ID) but never a lost message.
    Restore,
    /// Connections held open with no traffic: memory per idle connection (with `--admin`).
    Idle,
    /// Steady traffic; halfway through, every connection is dropped at once. Reports the time
    /// until every device is connected again (beta target: 60 s, zero loss).
    Storm,
    /// Group traffic: devices form groups of `--group-size`; each send is one shared body for
    /// the rest of the sender's group, stored once (`SendPayload::Shared`), fanned out by the
    /// server.
    Group,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Delivery server `host:port`; several separated by commas (devices are spread over them
    /// round-robin, so senders and recipients sit on different nodes).
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
    /// Restore scenario: the last N devices only receive and come online only after sending
    /// stops, so a restore during the run loses their whole mailbox and everything they get
    /// from before it comes from senders' resends.
    #[arg(long, default_value_t = 0)]
    offline_recipients: usize,
    /// Restore scenario, negative control: clients keep no send log, so nothing is resent after
    /// the restore and the checker must report lost messages.
    #[arg(long)]
    no_resend: bool,
    /// Delivery admin endpoints `host:port` (comma-separated): resident memory, CPU and
    /// descriptors before connecting, once connected and at the end (Linux servers).
    #[arg(long)]
    admin: Option<String>,
    /// Group scenario: members per group (the sender and the devices it sends to).
    #[arg(long, default_value_t = 256)]
    group_size: usize,
    /// PEM root to trust: connect with TLS 1.3 (as production does), each device with its own
    /// session cache so reconnects resume like a real app's. Plain WebSocket without it.
    #[arg(long)]
    tls_ca: Option<PathBuf>,
    /// Also write the results as one JSON object to this file (`bench/m7/suite.sh` compares
    /// them against a stored baseline).
    #[arg(long)]
    json_out: Option<PathBuf>,
}

/// The roots in `ca` (read once for every device).
fn tls_roots(ca: &std::path::Path) -> anyhow::Result<Arc<rustls::RootCertStore>> {
    use rustls_pki_types::pem::PemObject as _;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pki_types::CertificateDer::pem_file_iter(ca).context("reading --tls-ca")? {
        roots.add(c.context("reading --tls-ca")?)?;
    }
    Ok(Arc::new(roots))
}

/// A TLS 1.3 client configuration trusting `roots`, with a session cache of its own.
fn tls_config(roots: &Arc<rustls::RootCertStore>) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(Arc::clone(roots))
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(4);
    Ok(Arc::new(cfg))
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

fn payload(run: u32, sender: u32, n: u64, sent_ns: u64, key: &[u8; 16], size: usize) -> Bytes {
    let mut b = BytesMut::with_capacity(size.max(HEADER));
    b.put_u32(run);
    b.put_u32(sender);
    b.put_u64(n);
    b.put_u64(sent_ns);
    b.put_slice(key);
    // Padding that does not compress, like the ciphertext real envelopes are (a compressing file
    // system under the store must not flatter it).
    let mut x = ((u64::from(run) << 32) | u64::from(sender)) ^ n.rotate_left(17) ^ sent_ns | 1;
    while b.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let take = (size - b.len()).min(8);
        b.put_slice(x.to_le_bytes().get(..take).unwrap_or_default());
    }
    b.freeze()
}

/// `None` for a message of another run (or not a load generator message at all).
fn parse(run: u32, body: &[u8]) -> Option<(MsgId, u64, [u8; 16])> {
    let field = |at: std::ops::Range<usize>| body.get(at);
    let msg_run = u32::from_be_bytes(field(0..4)?.try_into().ok()?);
    let sender = u32::from_be_bytes(field(4..8)?.try_into().ok()?);
    let counter = u64::from_be_bytes(field(8..16)?.try_into().ok()?);
    let sent = u64::from_be_bytes(field(16..24)?.try_into().ok()?);
    let key: [u8; 16] = field(24..40)?.try_into().ok()?;
    (msg_run == run).then_some(((sender, counter), sent, key))
}

fn ns_since(epoch: Instant) -> u64 {
    u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// A device's receiving side: connected from the start, or coming online after sending stops.
enum Device {
    Online(Arc<Client>, tokio::sync::mpsc::Receiver<Event>),
    Late(Box<(DeviceKey, ClientConfig)>),
}

/// When the storm dropped every connection, and when the last device was connected again
/// (nanoseconds since the run's epoch; 0: not yet).
#[derive(Default)]
struct StormClock {
    at: AtomicU64,
    reconnected: AtomicU64,
    done: AtomicU64,
}

impl StormClock {
    fn start(&self, epoch: Instant) {
        self.at.store(ns_since(epoch).max(1), Ordering::Release);
    }

    /// A device connected: after the storm, the last of `online` to do so stops the clock.
    fn reconnected(&self, epoch: Instant, online: u64) {
        if self.at.load(Ordering::Acquire) == 0 {
            return;
        }
        if self.reconnected.fetch_add(1, Ordering::AcqRel) + 1 == online {
            self.done.store(ns_since(epoch), Ordering::Release);
        }
    }

    fn recovery(&self) -> Option<Duration> {
        let (at, done) = (
            self.at.load(Ordering::Acquire),
            self.done.load(Ordering::Acquire),
        );
        (at != 0 && done != 0).then(|| Duration::from_nanos(done.saturating_sub(at)))
    }
}

struct SenderOut {
    accepted: Vec<(usize, MsgId)>,
    sends: u64,
    rejected: u64,
    retries: u64,
}

#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
async fn run(a: &Args) -> anyhow::Result<bool> {
    ensure!(a.size >= HEADER, "--size must be at least {HEADER}");
    let keys = load_seeds(&a.seeds, a.devices)?;
    let n = keys.len();
    ensure!(n >= 2, "need at least 2 devices");
    let late = if a.scenario == Scenario::Restore {
        a.offline_recipients
    } else {
        0
    };
    ensure!(
        late + 2 <= n,
        "--offline-recipients leaves fewer than 2 senders"
    );
    let ids: Arc<Vec<DeviceId>> = Arc::new(keys.iter().map(DeviceKey::device).collect());
    let addrs: Vec<&str> = a.addr.split(',').filter(|s| !s.is_empty()).collect();
    ensure!(!addrs.is_empty(), "--addr is empty");
    let cfgs: Vec<ClientConfig> = addrs
        .iter()
        .map(|addr| {
            let mut cfg = ClientConfig::new((*addr).to_owned(), a.server_name.clone());
            cfg.backoff.initial = Duration::from_millis(100);
            cfg.backoff.max = Duration::from_secs(5);
            cfg.event_capacity = 4096;
            if a.no_resend {
                cfg.send_log_capacity = 0;
            }
            cfg
        })
        .collect();

    ensure!(a.group_size >= 2, "--group-size must be at least 2");
    let fig_start = match &a.admin {
        Some(addrs) => crate::admin::scrape(addrs).await?,
        None => None,
    };

    // Ramp up. With TLS each device gets a configuration (and session cache) of its own.
    let roots = a.tls_ca.as_deref().map(tls_roots).transpose()?;
    let device_cfg = |base: ClientConfig| -> anyhow::Result<ClientConfig> {
        let mut c = base;
        if let Some(r) = &roots {
            c.tls = Some(tls_config(r)?);
        }
        Ok(c)
    };
    let t_connect = Instant::now();
    let mut clients = Vec::with_capacity(n);
    let mut events = Vec::with_capacity(n);
    let mut keys = keys;
    // Offline recipients start later, from their own receiver task.
    let late_keys: Vec<(DeviceKey, ClientConfig)> = keys
        .split_off(n - late)
        .into_iter()
        .enumerate()
        .filter_map(|(j, k)| {
            cfgs.get((n - late + j) % cfgs.len())
                .and_then(|c| device_cfg(c.clone()).ok())
                .map(|c| (k, c))
        })
        .collect();
    let gap = Duration::from_secs_f64(
        1.0 / f64::from(u32::try_from(a.connect_rate.max(1)).unwrap_or(u32::MAX)),
    );
    for (i, key) in keys.into_iter().enumerate() {
        let Some(cfg) = cfgs.get(i % cfgs.len()).cloned() else {
            break;
        };
        let (c, ev) = Client::start(device_cfg(cfg)?, key, ResumeState::default());
        clients.push(c);
        events.push(ev);
        tokio::time::sleep(gap).await;
    }
    let deadline = Instant::now() + Duration::from_mins(2);
    for c in &mut clients {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, c.wait_for(State::Connected)).await {
            Ok(State::Connected) => {}
            _ => bail!("not every device connected within 120 s"),
        }
    }
    let connect_secs = t_connect.elapsed().as_secs_f64();
    let clients: Vec<Arc<Client>> = clients.into_iter().map(Arc::new).collect();
    let fig_connected = match &a.admin {
        Some(addrs) => crate::admin::scrape(addrs).await?,
        None => None,
    };
    // Storm scenario: when every connection was dropped, and when the last one came back.
    let storm = Arc::new(StormClock::default());
    let online_count = u64::try_from(clients.len()).unwrap_or(u64::MAX);

    let epoch = Instant::now();
    let send_until = epoch + Duration::from_secs(a.secs);
    let settle_until = send_until + Duration::from_secs(a.settle_secs);
    let run_id = getrandom::u32()?;
    let delivered_total = Arc::new(AtomicU64::new(0));
    let (stop_recv_tx, stop_recv) = watch::channel(false);
    let mut receivers = Vec::with_capacity(n);
    let receipts = a.scenario == Scenario::Restore;
    let all_clients = Arc::new(clients.clone());
    let online = clients
        .iter()
        .cloned()
        .zip(events)
        .map(|(c, ev)| Device::Online(c, ev));
    let offline = late_keys.into_iter().map(|kc| Device::Late(Box::new(kc)));
    for device in online.chain(offline) {
        let total = Arc::clone(&delivered_total);
        let mut stop = stop_recv.clone();
        let all_clients = Arc::clone(&all_clients);
        let storm = Arc::clone(&storm);
        receivers.push(tokio::spawn(async move {
            let (c, mut ev) = match device {
                Device::Online(c, ev) => (c, ev),
                Device::Late(kc) => {
                    let (key, cfg) = *kc;
                    tokio::time::sleep_until(send_until.into()).await;
                    let (c, ev) = Client::start(cfg, key, ResumeState::default());
                    (Arc::new(c), ev)
                }
            };
            let mut got = Received::default();
            let mut seen = std::collections::HashSet::new();
            let mut lat: Vec<u32> = Vec::new();
            let mut failed = None;
            loop {
                tokio::select! {
                    _ = async { stop.wait_for(|s| *s).await.is_ok() } => break,
                    e = ev.recv() => match e {
                        Some(Event::Deliver { seq, envelope }) => {
                            if let Some((id, sent, key)) = parse(run_id, &envelope) {
                                got.items.push((seq, Some(id)));
                                let us = ns_since(epoch).saturating_sub(sent) / 1_000;
                                lat.push(u32::try_from(us).unwrap_or(u32::MAX));
                                // Distinct messages: repeats after a restore do not count.
                                if seen.insert(id) {
                                    total.fetch_add(1, Ordering::Relaxed);
                                }
                                // The end-to-end delivery receipt, straight to the sender's
                                // client (in a real app it is a message of its own).
                                if receipts {
                                    let sender = usize::try_from(id.0).unwrap_or(usize::MAX);
                                    if let Some(s) = all_clients.get(sender) {
                                        let _ = s.confirm_delivered(key).await;
                                    }
                                }
                            } else {
                                got.items.push((seq, None));
                            }
                            // The app "stored" it: acknowledge (the client coalesces ACKs).
                            let _ = c.ack(seq).await;
                        }
                        Some(Event::Failed { code }) => failed = Some(code),
                        Some(Event::StoreGenerationChanged { .. }) => {
                            got.restores.push(got.items.len());
                        }
                        Some(Event::Connected { .. }) => storm.reconnected(epoch, online_count),
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            // A late device's client is this task's own (an online one is shared: kept).
            if let Ok(c) = Arc::try_unwrap(c) {
                c.close().await;
            }
            (got, lat, failed)
        }));
    }

    // Senders.
    let per_device = (f64::from(u32::try_from(a.rate).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(clients.len()).unwrap_or(u32::MAX)))
    .max(1e-3);
    let period = Duration::from_secs_f64(1.0 / per_device);
    let mut senders = Vec::with_capacity(n);
    // Group scenario: consecutive online devices form groups of `group_size`.
    let group_size = (a.scenario == Scenario::Group).then_some(a.group_size);
    let sending = a.scenario != Scenario::Idle;
    for (i, c) in clients.iter().cloned().enumerate().filter(|_| sending) {
        let ids = Arc::clone(&ids);
        let size = a.size;
        let online = clients.len();
        senders.push(tokio::spawn(async move {
            let me = u32::try_from(i).unwrap_or(u32::MAX);
            let mut rng = Rng::new();
            let mut out = SenderOut {
                accepted: Vec::new(),
                sends: 0,
                rejected: 0,
                retries: 0,
            };
            // This sender's group: the other members (Group scenario).
            let group: Vec<usize> = group_size.map_or_else(Vec::new, |g| {
                let start = i / g * g;
                (start..(start + g).min(online))
                    .filter(|&m| m != i)
                    .collect()
            });
            if group_size.is_some() && group.is_empty() {
                return out;
            }
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
                let mut key = [0u8; 16];
                key[..8].copy_from_slice(&rng.next().to_be_bytes());
                key[8..].copy_from_slice(&rng.next().to_be_bytes());
                let body = payload(run_id, me, counter, ns_since(epoch), &key, size);
                let (to, send): (Vec<usize>, SendPayload) = if group.is_empty() {
                    let to = {
                        let r =
                            usize::try_from(rng.below(u64::try_from(ids.len() - 1).unwrap_or(1)))
                                .unwrap_or(0);
                        if r >= i { r + 1 } else { r }
                    };
                    let Some(&dev) = ids.get(to) else { break };
                    (
                        vec![to],
                        SendPayload::PerDevice(vec![Recipient {
                            device: dev,
                            envelope: body,
                        }]),
                    )
                } else {
                    let devices = group.iter().filter_map(|&m| ids.get(m).copied()).collect();
                    (group.clone(), SendPayload::Shared { devices, body })
                };
                // Retry with the same idempotency key until the server answers: a send that
                // failed with Disconnected may or may not have been stored; the key makes the
                // retry safe either way.
                loop {
                    match c.send_with(key, SendHints::default(), send.clone()).await {
                        Ok(SendStatus::Accepted) => {
                            out.sends += 1;
                            out.accepted.extend(to.iter().map(|&t| (t, (me, counter))));
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
    let chaos = matches!(a.scenario, Scenario::Reconnect | Scenario::Storm).then(|| {
        let clients = clients.clone();
        let aborts = Arc::clone(&aborts);
        let storm = Arc::clone(&storm);
        let only_storm = a.scenario == Scenario::Storm;
        let every = Duration::from_millis(a.chaos_every_ms.max(1));
        let storm_at = epoch + Duration::from_secs(a.secs) / 2;
        tokio::spawn(async move {
            let mut rng = Rng::new();
            let mut stormed = false;
            while Instant::now() < send_until {
                tokio::time::sleep(every).await;
                if !stormed && Instant::now() >= storm_at {
                    stormed = true;
                    storm.start(epoch);
                    for c in &clients {
                        let _ = c.abort_connection().await;
                        aborts.fetch_add(1, Ordering::Relaxed);
                    }
                } else if !only_storm {
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
    let (mut accepted, mut rejected, mut retries, mut sends) = (0u64, 0u64, 0u64, 0u64);
    if !sending {
        tokio::time::sleep_until(send_until.into()).await;
    }
    for s in senders {
        let out = s.await?;
        sends += out.sends;
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
    let fig_end = match &a.admin {
        Some(addrs) => crate::admin::scrape(addrs).await?,
        None => None,
    };
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
    let achieved = crate::as_f64(sends) / send_secs;
    let deliveries = crate::as_f64(accepted) / send_secs;
    println!(
        "sends: accepted={sends} deliveries_expected={accepted} rejected={rejected} retries={retries} achieved_rate={achieved:.0}/s deliveries_rate={deliveries:.0}/s aborts={} failed_clients={failed}",
        aborts.load(Ordering::Relaxed)
    );
    let storm_recovery = storm.recovery();
    if a.scenario == Scenario::Storm {
        match storm_recovery {
            Some(d) => println!(
                "storm: every one of {online_count} devices connected again {:.2}s after the storm",
                d.as_secs_f64()
            ),
            None => println!("storm: NOT every device reconnected before the run ended"),
        }
    }
    let mut server = serde_json::Value::Null;
    if let (Some(s0), Some(s1), Some(s2)) = (fig_start, fig_connected, fig_end) {
        let per_conn = (s1.resident_bytes - s0.resident_bytes) / crate::as_f64(online_count);
        let cpu = s2.cpu_seconds - s1.cpu_seconds;
        let per_10k = if accepted > 0 {
            cpu / (crate::as_f64(accepted) / 10_000.0)
        } else {
            0.0
        };
        let store_p50 = s2.store_quantile(&s1, 0.5);
        let store_p99 = s2.store_quantile(&s1, 0.99);
        let ms = |v: Option<f64>| v.map_or_else(|| "-".into(), |s| format!("<={}ms", s * 1e3));
        println!(
            "server store latency (read to durably stored, bucket bound): p50 {} p99 {}",
            ms(store_p50),
            ms(store_p99)
        );
        println!(
            "server: rss_idle={:.1}MiB rss_connected={:.1}MiB rss_end={:.1}MiB per_connection={:.1}KiB open_fds={:.0} cpu_send_phase={cpu:.2}s cpu_per_10k_deliveries={per_10k:.3}s",
            s0.resident_bytes / 1_048_576.0,
            s1.resident_bytes / 1_048_576.0,
            s2.resident_bytes / 1_048_576.0,
            per_conn / 1024.0,
            s1.open_fds
        );
        server = serde_json::json!({
            "rss_idle_bytes": s0.resident_bytes,
            "rss_connected_bytes": s1.resident_bytes,
            "rss_end_bytes": s2.resident_bytes,
            "bytes_per_connection": per_conn,
            "open_fds": s1.open_fds,
            "cpu_send_phase_secs": cpu,
            "cpu_per_10k_deliveries_secs": per_10k,
            "store_p50_le_secs": store_p50.filter(|v| v.is_finite()),
            "store_p99_le_secs": store_p99.filter(|v| v.is_finite()),
        });
    }
    println!("settle: {settle_secs:.2}s");
    println!("latency send->deliver (client-observed): {s}");
    println!(
        "checker: {} expected={} delivered={} lost={} duplicates={} seq_violations={} fifo_violations={} unexpected={} stale_from_earlier_runs={} deduplicated_after_restore={}",
        if report.passed() { "PASS" } else { "FAIL" },
        report.expected,
        report.delivered,
        report.lost,
        report.duplicates,
        report.seq_violations,
        report.fifo_violations,
        report.unexpected,
        report.stale,
        report.deduplicated
    );
    if let Some(path) = &a.json_out {
        let j = serde_json::json!({
            "scenario": format!("{:?}", a.scenario).to_lowercase(),
            "devices": n,
            "secs": a.secs,
            "target_rate": a.rate,
            "size": a.size,
            "group_size": group_size,
            "tls": a.tls_ca.is_some(),
            "connect_secs": connect_secs,
            "sends": sends,
            "deliveries_expected": accepted,
            "rejected": rejected,
            "retries": retries,
            "send_rate": achieved,
            "delivery_rate": deliveries,
            "settle_secs": settle_secs,
            "latency_us": {"count": s.count, "p50": s.p50, "p99": s.p99, "p999": s.p999, "max": s.max},
            "storm_recovery_secs": storm_recovery.map(|d| d.as_secs_f64()),
            "server": server,
            "checker": {
                "passed": report.passed(),
                "expected": report.expected,
                "delivered": report.delivered,
                "lost": report.lost,
                "duplicates": report.duplicates,
                "seq_violations": report.seq_violations,
                "fifo_violations": report.fifo_violations,
            },
        });
        std::fs::write(path, format!("{j:#}\n")).context("writing --json-out")?;
    }
    Ok(report.passed() && rejected == 0)
}
