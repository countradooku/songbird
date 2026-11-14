//! Songbird `delivery` service: the WebSocket server that authenticates devices, stores
//! envelopes, routes them and streams them in order (master prompt §3–§5).
//!
//! Milestone 1 runs on one current-thread Tokio runtime with the in-memory mailbox and the
//! in-process router; milestones 2–4 swap in SurrealDB, the thread-per-core runtime and Valkey
//! routing behind the same traits.
//!
//! - [`server`]: listener, accept-rate limit and connection cap, TLS, HTTP upgrade, graceful
//!   drain on shutdown.
//! - [`session`]: one connection's protocol and the ordering algorithm.
//! - [`ordering`]: the pure ordering rule (property-tested).
//! - The send path itself (device-list check, idempotent store, routing, push on offline) is
//!   the `songbird-send` library (D-0037), shared with `api`; [`directory`] and [`push`] are
//!   re-exported from it.
#![forbid(unsafe_code)]

pub mod bucket;
pub mod config;
pub mod internal;
pub mod metrics;
pub mod ordering;
pub mod server;
pub mod session;
pub mod ws;

use songbird_proto::Limits;

pub use config::{DeliveryConfig, DeliverySettings};
pub use metrics::DeliveryMetrics;
pub use songbird_send::{Directory, LiveDirectory, Pusher, directory, push};
use songbird_send::{SendMetrics, SendPath};

/// What every session of a process shares (read-only apart from the mailbox and router).
#[derive(Debug)]
pub struct Shared<M, R> {
    /// `[delivery]` settings.
    pub config: DeliverySettings,
    /// Frame limits (from `config.limits`).
    pub limits: Limits,
    /// Device authentication keys (reloaded from the registry).
    pub directory: std::sync::Arc<LiveDirectory>,
    /// The mailbox store.
    pub mailbox: M,
    /// The router.
    pub router: R,
    /// Metrics.
    pub metrics: DeliveryMetrics,
    /// The send path's counters: the same counters as in `metrics` (names unchanged).
    pub send_metrics: SendMetrics,
    /// Push jobs for offline devices (disabled unless configured).
    pub push: Pusher,
    /// The store generation from the registry (D-0040); 0 until known, then the mailbox's
    /// configured value is not used.
    pub generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<M, R> Shared<M, R> {
    /// Bundles the parts.
    #[must_use]
    pub fn new(
        config: DeliverySettings,
        directory: Directory,
        mailbox: M,
        router: R,
        metrics: DeliveryMetrics,
    ) -> Self {
        Self {
            limits: config.limits.limits(),
            config,
            directory: std::sync::Arc::new(directory.into()),
            mailbox,
            router,
            send_metrics: metrics.send(),
            metrics,
            push: Pusher::disabled(),
            generation: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// The send path over this process's directory, mailbox, router and push jobs (borrows
    /// only: free to build per send).
    pub fn send_path(&self) -> SendPath<'_, M, R> {
        SendPath {
            directory: &self.directory,
            mailbox: &self.mailbox,
            router: &self.router,
            push: &self.push,
            metrics: &self.send_metrics,
        }
    }

    /// With push jobs for offline devices.
    #[must_use]
    pub fn with_push(mut self, push: Pusher) -> Self {
        self.push = push;
        self
    }
}
