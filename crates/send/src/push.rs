//! Push jobs for offline devices (D-0036).
//!
//! When a stored envelope's device has no session anywhere, the send path calls
//! [`Pusher::offline`], which never blocks and never touches Valkey: it puts the device in a
//! bounded channel. One task per process debounces (at most one job per device per window: a
//! burst of messages is one wake-up) and adds the jobs to the queue in pipelined batches. If the
//! buffer is full or the queue is unreachable the wake-up is dropped and counted: the message is
//! safe in the mailbox and the device fetches it at its next connection (runbook "Push jobs
//! dropped").

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use songbird_jobs::{Job, Queue, Work};
use songbird_service::telemetry::sharded::ShardedCounter as Counter;
use songbird_types::DeviceId;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

/// Wake-ups waiting for the batching task.
const BUFFER: usize = 65_536;
/// Most jobs per pipelined batch.
const BATCH: usize = 512;
/// Debounce entries are pruned when the map grows past this.
const PRUNE_ABOVE: usize = 100_000;

/// Push counters. Clones share their counts (`delivery` passes its own, so metric names stay).
#[derive(Debug, Clone, Default)]
pub struct PushMetrics {
    /// Push jobs enqueued (after debouncing).
    pub jobs: Counter,
    /// Wake-ups dropped (buffer full or job queue unreachable; the message is safe in the
    /// mailbox).
    pub dropped: Counter,
}

/// The senders' handle. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Pusher {
    tx: Option<mpsc::Sender<DeviceId>>,
    metrics: PushMetrics,
}

impl Pusher {
    /// No push jobs (tests, development without a job queue).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            tx: None,
            metrics: PushMetrics::default(),
        }
    }

    /// A pusher feeding a task started with [`run`].
    #[must_use]
    pub fn new(metrics: PushMetrics) -> (Self, mpsc::Receiver<DeviceId>) {
        let (tx, rx) = mpsc::channel(BUFFER);
        (
            Self {
                tx: Some(tx),
                metrics,
            },
            rx,
        )
    }

    /// A stored envelope's device is offline. Never blocks.
    pub fn offline(&self, device: DeviceId) {
        if let Some(tx) = &self.tx
            && tx.try_send(device).is_err()
        {
            self.metrics.dropped.inc();
        }
    }
}

/// Leading- and trailing-edge coalescing of wake-ups per device (D-0095), pure so it is tested
/// with paused time. The first wake-up for a device goes at once and opens a window; any later
/// one inside the window schedules a single wake-up at the window's end. A device that woke,
/// fetched and slept again inside the window is therefore woken again for what arrived after
/// its fetch, and a burst is at most two jobs.
#[derive(Debug)]
pub struct Coalescer {
    window: Duration,
    // Randomly seeded SipHash: keys are device IDs, which clients choose to target.
    windows: HashMap<DeviceId, Window>,
    // Trailing wake-ups by due time.
    due: BinaryHeap<Reverse<(Instant, DeviceId)>>,
}

/// A device's debounce window.
#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    /// A trailing wake-up is scheduled for the window's end.
    trailing: bool,
}

impl Coalescer {
    /// Coalescing over `window` (zero: every wake-up goes).
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            windows: HashMap::new(),
            due: BinaryHeap::new(),
        }
    }

    /// A wake-up for `d` at `now`: whether it goes now (otherwise it is folded into the window's
    /// trailing wake-up).
    pub fn offer(&mut self, d: DeviceId, now: Instant) -> bool {
        if self.window.is_zero() {
            return true;
        }
        if let Some(w) = self.windows.get_mut(&d)
            && now.saturating_duration_since(w.start) < self.window
        {
            if !w.trailing {
                w.trailing = true;
                self.due.push(Reverse((w.start + self.window, d)));
            }
            return false;
        }
        self.open(d, now);
        true
    }

    /// When the next trailing wake-up is due.
    #[must_use]
    pub fn next_due(&self) -> Option<Instant> {
        self.due.peek().map(|Reverse((t, _))| *t)
    }

    /// Takes up to `max` trailing wake-ups due at `now`; each opens a new window.
    pub fn take_due(&mut self, now: Instant, max: usize) -> Vec<DeviceId> {
        let mut out = Vec::new();
        while out.len() < max
            && let Some(Reverse((t, d))) = self.due.peek().copied()
            && t <= now
        {
            self.due.pop();
            self.open(d, now);
            out.push(d);
        }
        out
    }

    /// Forgets `d` (its job was dropped): its next wake-up goes at once.
    pub fn forget(&mut self, d: &DeviceId) {
        if self.windows.get(d).is_some_and(|w| !w.trailing) {
            self.windows.remove(d);
        }
    }

    /// Drops ended windows once the map is large.
    pub fn prune(&mut self, now: Instant) {
        if self.windows.len() > PRUNE_ABOVE {
            let window = self.window;
            self.windows
                .retain(|_, w| w.trailing || now.saturating_duration_since(w.start) < window);
        }
    }

    fn open(&mut self, d: DeviceId, now: Instant) {
        self.windows.insert(
            d,
            Window {
                start: now,
                trailing: false,
            },
        );
    }
}

/// Coalesces and batches wake-ups into the job queue until `stop` ([`Coalescer`]).
pub async fn run(
    queue: Arc<Queue>,
    mut rx: mpsc::Receiver<DeviceId>,
    debounce: Duration,
    metrics: PushMetrics,
    mut stop: watch::Receiver<bool>,
) {
    let mut c = Coalescer::new(debounce);
    let mut batch: Vec<Job> = Vec::with_capacity(BATCH);
    let mut sent: Vec<DeviceId> = Vec::with_capacity(BATCH);
    loop {
        let first = tokio::select! {
            d = rx.recv() => match d {
                Some(d) => Some(d),
                None => return,
            },
            () = sleep_until_or_never(c.next_due()) => None,
            _ = stop.changed() => return,
        };
        let now = Instant::now();
        sent.extend(c.take_due(now, BATCH));
        if let Some(d) = first
            && c.offer(d, now)
        {
            sent.push(d);
        }
        while sent.len() < BATCH {
            match rx.try_recv() {
                Ok(d) => {
                    if c.offer(d, now) {
                        sent.push(d);
                    }
                }
                Err(_) => break,
            }
        }
        batch.extend(
            sent.iter()
                .filter_map(|d| Job::new(Work::Push { device: *d }).ok()),
        );
        if !batch.is_empty() {
            let n = u64::try_from(batch.len()).unwrap_or(u64::MAX);
            match queue.enqueue(&batch).await {
                Ok(()) => metrics.jobs.inc_by(n),
                Err(e) => {
                    metrics.dropped.inc_by(n);
                    tracing::warn!(error = %e, "push jobs dropped: job queue unavailable");
                    // Let these devices be tried again on their next message.
                    for d in &sent {
                        c.forget(d);
                    }
                }
            }
        }
        batch.clear();
        sent.clear();
        c.prune(now);
    }
}

async fn sleep_until_or_never(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    #[test]
    fn a_burst_is_one_job_now_and_one_at_the_window_end() {
        let mut c = Coalescer::new(Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(c.offer(dev(1), t0));
        assert!(!c.offer(dev(1), t0 + Duration::from_millis(100)));
        assert!(!c.offer(dev(1), t0 + Duration::from_millis(900)));
        assert!(c.offer(dev(2), t0 + Duration::from_millis(900)));
        assert_eq!(c.next_due(), Some(t0 + Duration::from_secs(1)));
        assert!(c.take_due(t0 + Duration::from_millis(999), 10).is_empty());
        assert_eq!(c.take_due(t0 + Duration::from_secs(1), 10), vec![dev(1)]);
        assert_eq!(c.next_due(), None);
        // The trailing job opened a new window.
        assert!(!c.offer(dev(1), t0 + Duration::from_millis(1500)));
        assert_eq!(c.take_due(t0 + Duration::from_secs(2), 10), vec![dev(1)]);
        // A lone wake-up schedules nothing.
        assert!(c.offer(dev(3), t0 + Duration::from_secs(10)));
        assert_eq!(c.next_due(), None);
    }

    #[test]
    fn a_dropped_job_lets_the_next_wake_up_go_at_once() {
        let mut c = Coalescer::new(Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(c.offer(dev(1), t0));
        c.forget(&dev(1));
        assert!(c.offer(dev(1), t0));
        let mut z = Coalescer::new(Duration::ZERO);
        assert!(z.offer(dev(1), t0) && z.offer(dev(1), t0));
    }

    proptest::proptest! {
        /// Whatever the arrival times, each wake-up is followed (at or after it) by a job, and
        /// one device never gets more than two jobs within any window.
        #[test]
        fn every_wake_up_has_a_job_at_or_after_it(gaps in proptest::collection::vec(0u64..2500, 1..80)) {
            let window = Duration::from_secs(1);
            let mut c = Coalescer::new(window);
            let t0 = Instant::now();
            let mut t = t0;
            let (mut asks, mut jobs) = (Vec::new(), Vec::new());
            for g in gaps {
                t += Duration::from_millis(g);
                while let Some(due) = c.next_due() {
                    if due > t { break; }
                    jobs.extend(c.take_due(due, 1).iter().map(|_| due));
                }
                asks.push(t);
                if c.offer(dev(1), t) { jobs.push(t); }
            }
            while let Some(due) = c.next_due() {
                jobs.extend(c.take_due(due, 1).iter().map(|_| due));
            }
            for a in &asks {
                proptest::prop_assert!(jobs.iter().any(|j| j >= a));
            }
            for (i, j) in jobs.iter().enumerate() {
                let close = jobs[i..].iter().filter(|k| k.saturating_duration_since(*j) < window).count();
                proptest::prop_assert!(close <= 2);
            }
        }
    }
}
