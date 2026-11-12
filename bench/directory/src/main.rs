//! M3 choices, measured on the same machine (master prompt §4):
//!
//! - `MODE=map`: the device directory `device -> (core, conn)`. Each thread loops for `SECS`:
//!   98 % lookups of random attached devices (every routed envelope), 1 % detach and 1 % attach
//!   (reconnect churn), over `DEVICES` devices. Reports operations/s and lookup p50/p99/p99.9
//!   (every 64th lookup timed).
//! - `MODE=chan`: the cross-core inbox. `CORES` consumer threads, each a current-thread Tokio
//!   runtime awaiting its inbox (as a delivery core would); `PRODUCERS` threads `try_send`
//!   timestamped messages to random cores (never blocking, as routing must not). Reports
//!   messages/s received, drops (inbox full) and send-to-receive p50/p99/p99.9.
//!
//! `THREADS`, `CORES`, `PRODUCERS`, `SECS`, `DEVICES`, `CAP` are environment variables.
#![allow(clippy::all)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

type Key = [u8; 16];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Val {
    core: u16,
    conn: u64,
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
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

fn key(i: u64) -> Key {
    // Random-looking 16 bytes, like a DeviceId.
    let a = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let b = a.rotate_left(29) ^ 0xD1B5_4A32_D192_ED03;
    let mut k = [0u8; 16];
    k[..8].copy_from_slice(&a.to_le_bytes());
    k[8..].copy_from_slice(&b.to_le_bytes());
    k
}

trait Directory: Send + Sync + 'static {
    fn get(&self, k: &Key) -> Option<Val>;
    fn insert(&self, k: Key, v: Val);
    fn remove(&self, k: &Key);
}

struct Locked(Mutex<HashMap<Key, Val>>);
impl Directory for Locked {
    fn get(&self, k: &Key) -> Option<Val> {
        self.0.lock().unwrap().get(k).copied()
    }
    fn insert(&self, k: Key, v: Val) {
        self.0.lock().unwrap().insert(k, v);
    }
    fn remove(&self, k: &Key) {
        self.0.lock().unwrap().remove(k);
    }
}

struct Papaya(papaya::HashMap<Key, Val>);
impl Directory for Papaya {
    fn get(&self, k: &Key) -> Option<Val> {
        self.0.pin().get(k).copied()
    }
    fn insert(&self, k: Key, v: Val) {
        self.0.pin().insert(k, v);
    }
    fn remove(&self, k: &Key) {
        self.0.pin().remove(k);
    }
}

struct Scc(scc::HashMap<Key, Val>);
impl Directory for Scc {
    fn get(&self, k: &Key) -> Option<Val> {
        self.0.read_sync(k, |_, v| *v)
    }
    fn insert(&self, k: Key, v: Val) {
        self.0.upsert_sync(k, v);
    }
    fn remove(&self, k: &Key) {
        self.0.remove_sync(k);
    }
}

struct Dash(dashmap::DashMap<Key, Val>);
impl Directory for Dash {
    fn get(&self, k: &Key) -> Option<Val> {
        self.0.get(k).map(|v| *v)
    }
    fn insert(&self, k: Key, v: Val) {
        self.0.insert(k, v);
    }
    fn remove(&self, k: &Key) {
        self.0.remove(k);
    }
}

fn pct(v: &mut [u64], p: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[((v.len() as f64 - 1.0) * p) as usize]
}

fn run_map<D: Directory>(name: &str, d: Arc<D>, threads: u64, devices: u64, secs: u64) {
    for i in 0..devices {
        d.insert(key(i), Val { core: 0, conn: i });
    }
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let mut hs = Vec::new();
    for t in 0..threads {
        let (d, stop, ops) = (d.clone(), stop.clone(), ops.clone());
        hs.push(std::thread::spawn(move || {
            let mut r = Rng(t * 7919 + 1);
            let mut lat = Vec::with_capacity(1 << 20);
            let mut n = 0u64;
            let mut hits = 0u64;
            while !stop.load(Ordering::Relaxed) {
                for _ in 0..256 {
                    let x = r.next();
                    let k = key(x % devices);
                    match x % 100 {
                        0 => d.remove(&k),
                        1 => d.insert(k, Val { core: (t % 16) as u16, conn: x }),
                        _ => {
                            if n % 64 == 0 {
                                let s = Instant::now();
                                let v = d.get(&k);
                                lat.push(s.elapsed().as_nanos() as u64);
                                hits += v.is_some() as u64;
                            } else {
                                hits += d.get(&k).is_some() as u64;
                            }
                        }
                    }
                    n += 1;
                }
            }
            ops.fetch_add(n, Ordering::Relaxed);
            std::hint::black_box(hits);
            lat
        }));
    }
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    let mut lat: Vec<u64> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let total = ops.load(Ordering::Relaxed);
    println!(
        "map={name} threads={threads} devices={devices}: {:.1} M ops/s, lookup p50={}ns p99={}ns p99.9={}ns",
        total as f64 / secs as f64 / 1e6,
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99),
        pct(&mut lat, 0.999)
    );
}

/// One inbox flavour: a sender usable from any thread with `try_send`, a receiver awaited on a
/// current-thread Tokio runtime.
trait Inbox: Sized + Send + 'static {
    type Tx: Clone + Send + Sync + 'static;
    fn make(cap: usize) -> (Self::Tx, Self);
    fn try_send(tx: &Self::Tx, v: u64) -> bool;
    async fn recv(&mut self) -> Option<u64>;
}

struct TokioIn(tokio::sync::mpsc::Receiver<u64>);
impl Inbox for TokioIn {
    type Tx = tokio::sync::mpsc::Sender<u64>;
    fn make(cap: usize) -> (Self::Tx, Self) {
        let (t, r) = tokio::sync::mpsc::channel(cap);
        (t, TokioIn(r))
    }
    fn try_send(tx: &Self::Tx, v: u64) -> bool {
        tx.try_send(v).is_ok()
    }
    async fn recv(&mut self) -> Option<u64> {
        self.0.recv().await
    }
}

struct KanalIn(kanal::AsyncReceiver<u64>);
impl Inbox for KanalIn {
    type Tx = kanal::AsyncSender<u64>;
    fn make(cap: usize) -> (Self::Tx, Self) {
        let (t, r) = kanal::bounded_async(cap);
        (t, KanalIn(r))
    }
    fn try_send(tx: &Self::Tx, v: u64) -> bool {
        matches!(tx.try_send(v), Ok(true))
    }
    async fn recv(&mut self) -> Option<u64> {
        self.0.recv().await.ok()
    }
}

/// crossbeam has no async receive: the consumer waits on a `Notify` the producers signal.
struct CrossIn(crossbeam_channel::Receiver<u64>, Arc<tokio::sync::Notify>);
impl Inbox for CrossIn {
    type Tx = (crossbeam_channel::Sender<u64>, Arc<tokio::sync::Notify>);
    fn make(cap: usize) -> (Self::Tx, Self) {
        let (t, r) = crossbeam_channel::bounded(cap);
        let n = Arc::new(tokio::sync::Notify::new());
        ((t, n.clone()), CrossIn(r, n))
    }
    fn try_send(tx: &Self::Tx, v: u64) -> bool {
        let ok = tx.0.try_send(v).is_ok();
        if ok {
            tx.1.notify_one();
        }
        ok
    }
    async fn recv(&mut self) -> Option<u64> {
        loop {
            if let Ok(v) = self.0.try_recv() {
                return Some(v);
            }
            self.1.notified().await;
        }
    }
}

fn run_chan<I: Inbox>(name: &str, cores: u64, producers: u64, cap: usize, secs: u64) {
    let epoch = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let mut txs = Vec::new();
    let mut consumers = Vec::new();
    for _ in 0..cores {
        let (tx, mut rx) = I::make(cap);
        txs.push(tx);
        let stop = stop.clone();
        consumers.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut lat = Vec::with_capacity(1 << 20);
                let mut n = 0u64;
                loop {
                    tokio::select! {
                        v = rx.recv() => {
                            let Some(sent) = v else { break };
                            if n % 16 == 0 {
                                let now = epoch.elapsed().as_nanos() as u64;
                                lat.push(now.saturating_sub(sent));
                            }
                            n += 1;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {
                            if stop.load(Ordering::Relaxed) { break; }
                        }
                    }
                }
                (n, lat)
            })
        }));
    }
    let txs = Arc::new(txs);
    let drops = Arc::new(AtomicU64::new(0));
    let mut ps = Vec::new();
    for p in 0..producers {
        let (txs, stop, drops) = (txs.clone(), stop.clone(), drops.clone());
        ps.push(std::thread::spawn(move || {
            let mut r = Rng(p * 104_729 + 3);
            let mut d = 0u64;
            // RATE: messages/s per producer (0: as fast as possible, an overload test).
            let rate = env("RATE", 0);
            let start = Instant::now();
            let mut sent = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if rate > 0 {
                    let due = Duration::from_nanos(sent * 1_000_000_000 / rate);
                    while start.elapsed() < due {
                        std::hint::spin_loop();
                    }
                }
                sent += 64;
                for _ in 0..64 {
                    let c = (r.next() % txs.len() as u64) as usize;
                    let now = epoch.elapsed().as_nanos() as u64;
                    if !I::try_send(&txs[c], now) {
                        d += 1;
                    }
                }
            }
            drops.fetch_add(d, Ordering::Relaxed);
        }));
    }
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    for p in ps {
        p.join().unwrap();
    }
    drop(txs);
    let mut total = 0;
    let mut lat = Vec::new();
    for c in consumers {
        let (n, l) = c.join().unwrap();
        total += n;
        lat.extend(l);
    }
    println!(
        "chan={name} cores={cores} producers={producers} cap={cap} rate={}: {:.2} M msgs/s received, dropped {:.1}%, latency p50={}ns p99={}ns p99.9={}ns",
        env("RATE", 0),
        total as f64 / secs as f64 / 1e6,
        100.0 * drops.load(Ordering::Relaxed) as f64
            / (total + drops.load(Ordering::Relaxed)).max(1) as f64,
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99),
        pct(&mut lat, 0.999)
    );
}

fn main() {
    let mode = std::env::var("MODE").unwrap_or_else(|_| "map".into());
    let secs = env("SECS", 3);
    if mode == "map" {
        let threads = env("THREADS", 4);
        let devices = env("DEVICES", 200_000);
        let which = std::env::var("MAP").unwrap_or_else(|_| "all".into());
        let all = which == "all";
        if all || which == "mutex" {
            run_map("mutex", Arc::new(Locked(Mutex::new(HashMap::new()))), threads, devices, secs);
        }
        if all || which == "papaya" {
            run_map("papaya", Arc::new(Papaya(papaya::HashMap::new())), threads, devices, secs);
        }
        if all || which == "scc" {
            run_map("scc", Arc::new(Scc(scc::HashMap::new())), threads, devices, secs);
        }
        if all || which == "dashmap" {
            run_map("dashmap", Arc::new(Dash(dashmap::DashMap::new())), threads, devices, secs);
        }
    } else {
        let cores = env("CORES", 4);
        let producers = env("PRODUCERS", 4);
        let cap = env("CAP", 4096) as usize;
        let which = std::env::var("CHAN").unwrap_or_else(|_| "all".into());
        let all = which == "all";
        if all || which == "tokio" {
            run_chan::<TokioIn>("tokio-mpsc", cores, producers, cap, secs);
        }
        if all || which == "kanal" {
            run_chan::<KanalIn>("kanal", cores, producers, cap, secs);
        }
        if all || which == "crossbeam" {
            run_chan::<CrossIn>("crossbeam+notify", cores, producers, cap, secs);
        }
    }
}

