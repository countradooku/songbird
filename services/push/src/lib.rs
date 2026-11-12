//! Songbird `push` service (Prompt 8, D-0036): consumes push jobs and wakes devices through
//! APNs, FCM and Web Push. The only holder of push credentials and of the key that opens push
//! registrations.
//!
//! For each job (`Work::Push { device, call }`):
//! 1. the registration is looked up under the keyed hash of the device ID
//!    ([`songbird_accounts::push_index`]); none: done (the device fetches at its next connection);
//! 2. it is opened with the push service's X25519 key; failing to open: dead-lettered;
//! 3. it becomes a provider [`Target`]: the APNs alert token for a message, the `PushKit` token
//!    for a call (none: done), FCM and Web Push as they are;
//! 4. a short local debounce per device and kind turns a burst into one push;
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
use songbird_accounts::{Registry, push_index};
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

/// At most one push per key per window. Keys are push indexes (keyed hashes), never device IDs;
/// the map is bounded (oldest-first eviction is not needed: expired entries are swept, and if
/// everything is fresh the map is cleared rather than grown).
#[derive(Debug)]
pub struct Debounce {
    window: Duration,
    cap: usize,
    seen: Mutex<HashMap<([u8; 32], bool), Instant>>,
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

    /// Whether a push for `key` may go now (and, if so, starts its window).
    pub fn admit(&self, key: ([u8; 32], bool)) -> bool {
        if self.window.is_zero() {
            return true;
        }
        let now = Instant::now();
        let mut m = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(t) = m.get(&key)
            && now.duration_since(*t) < self.window
        {
            return false;
        }
        if m.len() >= self.cap {
            m.retain(|_, t| now.duration_since(*t) < self.window);
            if m.len() >= self.cap {
                m.clear();
            }
        }
        m.insert(key, now);
        true
    }
}

/// Everything a job needs.
pub struct Handler {
    registry: Arc<Registry>,
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
        registry: Arc<Registry>,
        index_secret: &[u8; 32],
        push_key: &[u8; 32],
        providers: Providers,
        debounce: Duration,
        metrics: PushMetrics,
    ) -> Result<Self, BadPushKey> {
        let (push_key, _) = push_token::key_pair(push_key).map_err(|_| BadPushKey)?;
        Ok(Self {
            registry,
            index_secret: Zeroizing::new(*index_secret),
            push_key,
            providers,
            debounce: Debounce::new(debounce, 100_000),
            metrics,
        })
    }

    /// Handles one job. Idempotent: a repeated job at worst sends one more identical wake-up.
    pub async fn handle(&self, job: Job) -> Outcome {
        let Work::Push { device, call } = job.work else {
            // Not ours (a job on the wrong stream cannot be sealed for it, but be strict).
            return Outcome::Dead;
        };
        let index = push_index(&self.index_secret, &device);
        let sealed = match self.registry.push_token(&index).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                self.metrics.no_registration.inc();
                return Outcome::Done;
            }
            Err(e) => {
                tracing::warn!(error = %e, "registry unavailable; push job retried");
                self.metrics.registry_errors.inc();
                return Outcome::Retry(None);
            }
        };
        let Ok(reg) = push_token::open(&self.push_key, &index, &sealed) else {
            tracing::warn!("a push registration does not open; job dead-lettered");
            self.metrics.unopenable.inc();
            return Outcome::Dead;
        };
        let (kind, target) = match reg {
            Registration::Apns { token, voip } => {
                if call {
                    let Some(voip) = voip else {
                        self.metrics.calls_without_voip.inc();
                        return Outcome::Done;
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
        // A retried job carries the burst's wake-up: only first attempts are debounced.
        if job.attempt == 0 && !self.debounce.admit((index, call)) {
            self.metrics.result(kind, "debounced").inc();
            return Outcome::Done;
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
                self.metrics.result(kind, "retried").inc();
                Outcome::Retry(after)
            }
            Sent::Failed => {
                self.metrics.result(kind, "failed").inc();
                Outcome::Dead
            }
        }
    }

    /// Deletes an unregistered registration, unless the device registered anew meanwhile (the
    /// row no longer holds what was sent to).
    async fn forget(&self, index: &[u8; 32], sealed: &[u8]) -> Outcome {
        let current = match self.registry.push_token(index).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "registry unavailable; unregistered token kept for now");
                return Outcome::Retry(None);
            }
        };
        if current.as_deref() != Some(sealed) {
            return Outcome::Done;
        }
        match self.registry.delete_push_tokens(&[*index]).await {
            Ok(()) => Outcome::Done,
            Err(e) => {
                tracing::warn!(error = %e, "registry unavailable; unregistered token kept for now");
                Outcome::Retry(None)
            }
        }
    }
}

/// A running consumer.
#[derive(Debug)]
pub struct Running {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Stops reading, finishes the jobs in hand and returns.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// Starts consuming `j:push` with `handler` (in-process: the binary and tests alike).
#[must_use]
pub fn spawn(queue: Arc<Queue>, handler: Arc<Handler>, cfg: ConsumeConfig) -> Running {
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(songbird_jobs::consume(
        queue,
        Stream::Push,
        cfg,
        move |job| {
            let h = Arc::clone(&handler);
            async move { h.handle(job).await }
        },
        rx,
    ));
    Running { stop, task }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn debounce_turns_a_burst_into_one() {
        let d = Debounce::new(Duration::from_secs(1), 10);
        let k = ([1; 32], false);
        assert!(d.admit(k));
        assert!(!d.admit(k));
        // Calls and messages are debounced apart.
        assert!(d.admit(([1; 32], true)));
        assert!(d.admit(([2; 32], false)));
        tokio::time::advance(Duration::from_millis(1001)).await;
        assert!(d.admit(k));
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_is_bounded() {
        let d = Debounce::new(Duration::from_secs(1), 4);
        for i in 0..100u8 {
            assert!(d.admit(([i; 32], false)));
        }
        assert!(d.seen.lock().unwrap().len() <= 4);
        let d = Debounce::new(Duration::ZERO, 4);
        assert!(d.admit(([0; 32], false)));
        assert!(d.admit(([0; 32], false)));
    }
}
