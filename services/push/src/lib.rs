//! Songbird `push` service (Prompt 8, D-0036): consumes push jobs and wakes devices through
//! APNs, FCM and Web Push. The only holder of push credentials and of the key that opens push
//! registrations.
//!
//! Two streams, each with its own consumer (D-0095): `j:push` (message wake-ups) and `j:ring`
//! (call rings, which a backlog of message wake-ups must never delay). For each job:
//! 1. the registration is looked up under the keyed hash of the device ID
//!    ([`songbird_accounts::push_index`]) in the push database, the only store this service
//!    reads (D-0095: it holds no registry credential); none: done (the device fetches at its next connection);
//! 2. it is opened with the push service's X25519 key; failing to open: dead-lettered;
//! 3. it becomes a provider [`Target`]: the APNs alert token for a message, the `PushKit` token
//!    for a ring (none: done), FCM and Web Push as they are (a ring there is the same message as
//!    a wake-up: Google and the distributor cannot tell them apart);
//! 4. a ring past its `until_ms` is dropped unsent (a late ring is worse than none); a message
//!    wake-up goes through a leading- and trailing-edge debounce per device: the first wakes at
//!    once, later ones in the window become one more wake-up at the window's end, so a burst is
//!    at most two pushes and no stored message is left without a wake-up after it;
//! 5. the provider sends its one constant wake-up. Delivered: done. Unregistered: the
//!    registration row is deleted, then done. Retry: back to the queue (after the provider's
//!    delay, if it gave one). Failed: dead-lettered.
//!
//! Nothing here logs or counts per device: metrics carry the provider kind and the result only.
#![forbid(unsafe_code)]

pub mod config;
pub mod metrics;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aws_lc_rs::agreement::PrivateKey;
use songbird_accounts::push_token::{self, Registration};
use songbird_accounts::{PushStore, push_index};
use songbird_jobs::{ConsumeConfig, Job, Outcome, Queue, Stream, Work};
use songbird_push_providers::apns::Apns;
use songbird_push_providers::fcm::Fcm;
use songbird_push_providers::webpush::WebPush;
use songbird_push_providers::{Outcome as Sent, Provider, Target};
use tokio::sync::watch;
use tokio::time::Instant;
use zeroize::Zeroizing;

pub use config::{PushConfig, PushSettings};
pub use metrics::{Kind, PushMetrics};

/// The configured provider clients; a kind without one is skipped (counted).
#[derive(Debug, Default)]
pub struct Providers {
    /// Apple.
    pub apns: Option<Apns>,
    /// Firebase Cloud Messaging.
    pub fcm: Option<Fcm>,
    /// Web Push (`UnifiedPush`).
    pub webpush: Option<WebPush>,
}

/// What the debounce says about a wake-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Push now (a new window starts).
    Now,
    /// Inside a window that already pushed: run this job again after the delay, at the window's
    /// end (the trailing wake-up).
    Defer(Duration),
    /// Inside a window whose trailing wake-up is already scheduled: nothing to do.
    Drop,
}

/// Leading- and trailing-edge debounce, per key (D-0095). Keys are push indexes (keyed hashes),
/// never device IDs. Bounded: expired entries are swept, and if everything is fresh the map is
/// cleared (at worst one extra wake-up each, never a lost one).
#[derive(Debug)]
pub struct Debounce {
    window: Duration,
    cap: usize,
    seen: Mutex<HashMap<[u8; 32], Window>>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    trailing: bool,
}

impl Debounce {
    /// A debounce of `window` remembering at most `cap` keys.
    #[must_use]
    pub fn new(window: Duration, cap: usize) -> Self {
        Self {
            window,
            cap: cap.max(1),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Whether a wake-up for `key` goes now, later or not at all. `scheduled`: this job is a
    /// deferred (trailing) or retried one, which always goes and starts a new window.
    pub fn admit(&self, key: [u8; 32], scheduled: bool) -> Admit {
        if self.window.is_zero() {
            return Admit::Now;
        }
        let now = Instant::now();
        let mut m = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if !scheduled && let Some(w) = m.get_mut(&key) {
            let age = now.duration_since(w.start);
            if age < self.window {
                if w.trailing {
                    return Admit::Drop;
                }
                w.trailing = true;
                return Admit::Defer(self.window.saturating_sub(age));
            }
        }
        if m.len() >= self.cap && !m.contains_key(&key) {
            m.retain(|_, w| now.duration_since(w.start) < self.window || w.trailing);
            if m.len() >= self.cap {
                m.clear();
            }
        }
        m.insert(
            key,
            Window {
                start: now,
                trailing: false,
            },
        );
        Admit::Now
    }
}

/// Everything a job needs.
pub struct Handler {
    store: Arc<PushStore>,
    index_secret: Zeroizing<[u8; 32]>,
    push_key: PrivateKey,
    providers: Providers,
    debounce: Debounce,
    metrics: PushMetrics,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").finish_non_exhaustive()
    }
}

/// Why a [`Handler`] could not be built. Carries no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadPushKey;

impl std::fmt::Display for BadPushKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("push_key is not a valid X25519 private key")
    }
}

impl std::error::Error for BadPushKey {}

impl Handler {
    /// A handler opening registrations with `push_key` (the X25519 private key) found under
    /// `index_secret`'s keyed hashes.
    ///
    /// # Errors
    /// [`BadPushKey`].
    pub fn new(
        store: Arc<PushStore>,
        index_secret: &[u8; 32],
        push_key: &[u8; 32],
        providers: Providers,
        debounce: Duration,
        metrics: PushMetrics,
    ) -> Result<Self, BadPushKey> {
        let (push_key, _) = push_token::key_pair(push_key).map_err(|_| BadPushKey)?;
        Ok(Self {
            store,
            index_secret: Zeroizing::new(*index_secret),
            push_key,
            providers,
            debounce: Debounce::new(debounce, 100_000),
            metrics,
        })
    }

    /// Handles one job. Idempotent: a repeated job at worst sends one more identical wake-up.
    pub async fn handle(&self, job: Job) -> Outcome {
        let (device, ring) = match job.work {
            Work::Push { device } => (device, None),
            Work::Ring { device, until_ms } => {
                if unix_ms() > until_ms {
                    self.metrics.rings_expired.inc();
                    return Outcome::Done;
                }
                (device, Some(until_ms))
            }
            // Not ours (a job on the wrong stream cannot be sealed for it, but be strict).
            _ => return Outcome::Dead,
        };
        let call = ring.is_some();
        let index = push_index(&self.index_secret, &device);
        let sealed = match self.store.get(&index).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                self.metrics.no_registration.inc();
                return Outcome::Done;
            }
            Err(e) => {
                tracing::warn!(error = %e, "push database unavailable; push job retried");
                self.metrics.registry_errors.inc();
                return Outcome::Retry(None);
            }
        };
        let Ok(reg) = push_token::open(&self.push_key, &index, &sealed) else {
            tracing::warn!("a push registration does not open; job dead-lettered");
            self.metrics.unopenable.inc();
            return Outcome::Dead;
        };
        let Some((kind, target)) = self.target(reg, call) else {
            return Outcome::Done;
        };
        let configured = match kind {
            Kind::Apns => self.providers.apns.is_some(),
            Kind::Fcm => self.providers.fcm.is_some(),
            Kind::WebPush => self.providers.webpush.is_some(),
        };
        if !configured {
            self.metrics.result(kind, "unconfigured").inc();
            return Outcome::Done;
        }
        // Rings are not debounced (each is one call, budgeted by `api`). A deferred or retried
        // wake-up carries the burst's trailing push, so it always goes.
        if !call {
            match self.debounce.admit(index, job.attempt > 0) {
                Admit::Now => {}
                Admit::Defer(after) => {
                    self.metrics.result(kind, "deferred").inc();
                    return Outcome::Retry(Some(after));
                }
                Admit::Drop => {
                    self.metrics.result(kind, "debounced").inc();
                    return Outcome::Done;
                }
            }
        }
        let sent = match (&self.providers, kind) {
            (Providers { apns: Some(p), .. }, Kind::Apns) => p.send(&target).await,
            (Providers { fcm: Some(p), .. }, Kind::Fcm) => p.send(&target).await,
            (
                Providers {
                    webpush: Some(p), ..
                },
                Kind::WebPush,
            ) => p.send(&target).await,
            _ => return Outcome::Done,
        };
        match sent {
            Sent::Delivered => {
                self.metrics.result(kind, "sent").inc();
                Outcome::Done
            }
            Sent::Unregistered => {
                self.metrics.result(kind, "unregistered").inc();
                self.forget(&index, &sealed).await
            }
            Sent::Retry { after } => {
                // A ring is retried only while it can still ring in time.
                if let Some(until) = ring {
                    let wait =
                        after.map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    if unix_ms().saturating_add(wait) > until {
                        self.metrics.rings_expired.inc();
                        return Outcome::Done;
                    }
                }
                self.metrics.result(kind, "retried").inc();
                Outcome::Retry(after)
            }
            Sent::Failed => {
                self.metrics.result(kind, "failed").inc();
                // A ring cannot be redriven in time: count it, do not keep it.
                if call { Outcome::Done } else { Outcome::Dead }
            }
        }
    }

    /// The provider target for a registration: the `PushKit` token for a ring, the alert token
    /// for a message; `None` (counted) for a ring to an Apple device without a `PushKit` token.
    fn target(&self, reg: Registration, call: bool) -> Option<(Kind, Target)> {
        Some(match reg {
            Registration::Apns { token, voip } => {
                if call {
                    let Some(voip) = voip else {
                        self.metrics.calls_without_voip.inc();
                        return None;
                    };
                    (
                        Kind::Apns,
                        Target::Apns {
                            token: voip,
                            voip: true,
                        },
                    )
                } else {
                    (Kind::Apns, Target::Apns { token, voip: false })
                }
            }
            Registration::Fcm { token } => (Kind::Fcm, Target::Fcm { token }),
            Registration::WebPush {
                endpoint,
                p256dh,
                auth,
            } => (
                Kind::WebPush,
                Target::WebPush {
                    endpoint,
                    p256dh,
                    auth,
                },
            ),
        })
    }

    /// Deletes an unregistered registration, unless the device registered anew meanwhile (the
    /// row no longer holds what was sent to).
    async fn forget(&self, index: &[u8; 32], sealed: &[u8]) -> Outcome {
        let current = match self.store.get(index).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "push database unavailable; unregistered token kept for now");
                return Outcome::Retry(None);
            }
        };
        if current.as_deref() != Some(sealed) {
            return Outcome::Done;
        }
        match self.store.delete(&[*index]).await {
            Ok(()) => Outcome::Done,
            Err(e) => {
                tracing::warn!(error = %e, "push database unavailable; unregistered token kept for now");
                Outcome::Retry(None)
            }
        }
    }
}

/// The running consumers.
#[derive(Debug)]
pub struct Running {
    stop: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    /// Stops reading, finishes the jobs in hand and returns.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

/// Starts consuming `j:push` with `messages` and `j:ring` with `rings` settings (in-process: the
/// binary and tests alike). Two consumers, so a backlog of message wake-ups never delays a ring.
#[must_use]
pub fn spawn(
    queue: Arc<Queue>,
    handler: Arc<Handler>,
    messages: ConsumeConfig,
    rings: ConsumeConfig,
) -> Running {
    let (stop, rx) = watch::channel(false);
    let ring_consumer = consumer(
        Arc::clone(&queue),
        Arc::clone(&handler),
        Stream::Ring,
        rings,
        rx.clone(),
    );
    let message_consumer = consumer(queue, handler, Stream::Push, messages, rx);
    Running {
        stop,
        tasks: vec![message_consumer, ring_consumer],
    }
}

fn consumer(
    queue: Arc<Queue>,
    handler: Arc<Handler>,
    stream: Stream,
    cfg: ConsumeConfig,
    stop: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(songbird_jobs::consume(
        queue,
        stream,
        cfg,
        move |job| {
            let h = Arc::clone(&handler);
            async move { h.handle(job).await }
        },
        stop,
    ))
}

/// Unix time in milliseconds.
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_burst_is_one_leading_and_one_trailing_wake_up() {
        let d = Debounce::new(Duration::from_secs(1), 10);
        let k = [1; 32];
        assert_eq!(d.admit(k, false), Admit::Now);
        tokio::time::advance(Duration::from_millis(300)).await;
        assert_eq!(d.admit(k, false), Admit::Defer(Duration::from_millis(700)));
        assert_eq!(d.admit(k, false), Admit::Drop);
        assert_eq!(d.admit([2; 32], false), Admit::Now);
        // The deferred job comes back at the window's end and goes, starting a new window.
        tokio::time::advance(Duration::from_millis(700)).await;
        assert_eq!(d.admit(k, true), Admit::Now);
        assert_eq!(d.admit(k, false), Admit::Defer(Duration::from_secs(1)));
        tokio::time::advance(Duration::from_millis(2001)).await;
        assert_eq!(d.admit(k, false), Admit::Now);
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_is_bounded() {
        let d = Debounce::new(Duration::from_secs(1), 4);
        for i in 0..100u8 {
            assert_eq!(d.admit([i; 32], false), Admit::Now);
        }
        assert!(d.seen.lock().unwrap().len() <= 4);
        let d = Debounce::new(Duration::ZERO, 4);
        assert_eq!(d.admit([0; 32], false), Admit::Now);
        assert_eq!(d.admit([0; 32], false), Admit::Now);
    }

    proptest::proptest! {
        /// Whatever the arrival times, every wake-up request is followed (at or after its time)
        /// by a push, and pushes to one key are never closer than the window, except a deferred
        /// one meeting a new window.
        #[test]
        fn no_request_is_left_without_a_later_push(gaps in proptest::collection::vec(0u64..2500, 1..60)) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
            rt.block_on(async {
                let d = Debounce::new(Duration::from_secs(1), 10);
                let t0 = Instant::now();
                let mut requests = Vec::new();
                let mut pushes = Vec::new();
                let mut deferred: Vec<Instant> = Vec::new();
                for g in gaps {
                    // Deferred jobs due before the next request run first.
                    let next = Instant::now() + Duration::from_millis(g);
                    deferred.sort();
                    while let Some(&due) = deferred.first() {
                        if due > next { break; }
                        tokio::time::advance(due - Instant::now()).await;
                        deferred.remove(0);
                        assert_eq!(d.admit([7; 32], true), Admit::Now);
                        pushes.push(Instant::now());
                    }
                    tokio::time::advance(next - Instant::now()).await;
                    requests.push(Instant::now());
                    match d.admit([7; 32], false) {
                        Admit::Now => pushes.push(Instant::now()),
                        Admit::Defer(after) => deferred.push(Instant::now() + after),
                        Admit::Drop => {}
                    }
                }
                for due in deferred {
                    pushes.push(due.max(Instant::now()));
                }
                for r in &requests {
                    assert!(pushes.iter().any(|p| p >= r), "request at {:?} has no push after it", *r - t0);
                }
            });
        }
    }
}
