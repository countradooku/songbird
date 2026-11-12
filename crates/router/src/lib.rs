//! Routing stored envelopes to the session holding a device.
//!
//! Routing is an optimisation over the mailbox, never a source of truth (invariant 2 of the
//! master prompt): a notification may be dropped at any point and the session recovers it from
//! the mailbox. That is what lets every queue here be bounded and every send non-blocking
//! (invariant 5: a slow client never slows anyone else).
//!
//! - [`Router::attach`] claims a device for a session, replacing (and signalling) any older
//!   session for it (invariant 4). Sessions attach **before** draining their mailbox, so an
//!   envelope stored during the drain is either fetched by it or routed live afterwards.
//! - [`Router::route`] hands a stored envelope to the device's session without blocking. If the
//!   session's inbox is full the notification is dropped and the session is marked lagged; it
//!   then drains from the mailbox.
//! - Ephemeral events go through a separate, smaller lane and are simply dropped when it is full.
//!
//! Milestone 1 ships [`LocalRouter`] (one process). Milestone 4 adds the Valkey pub/sub router
//! (one channel per device) behind the same trait.
#![forbid(unsafe_code)]

pub mod valkey;

use std::future::{Future, ready};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use songbird_types::DeviceId;
use tokio::sync::{Notify, mpsc};

/// A stored envelope, announced to the session that holds its device.
#[derive(Clone)]
pub struct Live {
    /// The envelope's per-device sequence number.
    pub seq: u64,
    /// The envelope (shared, never copied per recipient).
    pub envelope: Bytes,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live")
            .field("seq", &self.seq)
            .field("len", &self.envelope.len())
            .finish()
    }
}

/// Out-of-band signals from the router to a session. Lock-free flags plus one wake-up.
#[derive(Debug, Default)]
pub struct Signals {
    lagged: AtomicBool,
    replaced: AtomicBool,
    notify: Notify,
}

impl Signals {
    /// Whether at least one notification was dropped since the last call; clears the flag.
    pub fn take_lagged(&self) -> bool {
        self.lagged.swap(false, Ordering::AcqRel)
    }

    /// Whether a newer session took over this device.
    pub fn is_replaced(&self) -> bool {
        self.replaced.load(Ordering::Acquire)
    }

    /// Resolves after a signal was raised (or immediately if one is pending).
    pub async fn notified(&self) {
        self.notify.notified().await;
    }

    fn lag(&self) {
        self.lagged.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    fn replace(&self) {
        self.replaced.store(true, Ordering::Release);
        self.notify.notify_one();
    }
}

/// Inbox sizes for one session.
#[derive(Debug, Clone, Copy)]
pub struct InboxSizes {
    /// Stored-envelope notifications.
    pub live: usize,
    /// Ephemeral events.
    pub ephemeral: usize,
}

/// The router's side of a session.
#[derive(Debug, Clone)]
struct Handle {
    conn: u64,
    live: mpsc::Sender<Live>,
    ephemeral: mpsc::Sender<Bytes>,
    signals: Arc<Signals>,
}

/// The session's side: what it receives.
#[derive(Debug)]
pub struct Inbox {
    /// Identifies this attachment (for [`Router::detach`]).
    pub conn: u64,
    /// Stored-envelope notifications.
    pub live: mpsc::Receiver<Live>,
    /// Ephemeral events.
    pub ephemeral: mpsc::Receiver<Bytes>,
    /// Lag and replacement signals.
    pub signals: Arc<Signals>,
}

/// Result of routing one envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routed {
    /// Queued for the device's session.
    Queued,
    /// The session's inbox was full: dropped, session marked lagged (it drains the mailbox).
    Lagged,
    /// No session holds the device: it is offline (a push job will be queued, milestone 5).
    Offline,
}

/// Routes notifications to sessions.
pub trait Router: Send + Sync + 'static {
    /// Claims `device` for a new session and returns its inbox. Any older session for the device
    /// is signalled to close (invariant 4).
    fn attach(&self, device: DeviceId, sizes: InboxSizes) -> impl Future<Output = Inbox> + Send;

    /// Releases `device` if attachment `conn` still holds it.
    fn detach(&self, device: &DeviceId, conn: u64) -> impl Future<Output = ()> + Send;

    /// Announces a stored envelope. Never blocks on the recipient.
    fn route(&self, device: &DeviceId, live: Live) -> impl Future<Output = Routed> + Send;

    /// Delivers an ephemeral event if the device is connected and its lane has room.
    fn route_ephemeral(
        &self,
        device: &DeviceId,
        payload: Bytes,
    ) -> impl Future<Output = Routed> + Send;
}

/// Routes within one process, across all its cores.
///
/// The device directory is a lock-free concurrent map (`papaya`, D-0032: of papaya, scc and
/// dashmap the fastest and with the best p99 lookup from 4 to 16 threads; a `Mutex<HashMap>`
/// collapsed to 4.8 M operations/s with a 31 µs p99 at 16 threads). Routing reads the session's
/// handle under the map's guard and sends to its inbox without cloning it, so the hot path takes
/// no lock and touches no shared reference count.
#[derive(Debug, Default)]
pub struct LocalRouter {
    sessions: papaya::HashMap<DeviceId, Handle>,
    next_conn: AtomicU64,
}

impl LocalRouter {
    /// An empty router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Devices currently attached.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.sessions.len()
    }

    /// Whether a session holds `device` here.
    #[must_use]
    pub fn holds(&self, device: &DeviceId) -> bool {
        self.sessions.pin().contains_key(device)
    }

    /// Drops this node's session for `device` (a newer one connected on another node): it is
    /// signalled to close as replaced (invariant 4). Returns whether one was held.
    pub fn evict(&self, device: &DeviceId) -> bool {
        match self.sessions.pin().remove(device) {
            Some(h) => {
                h.signals.replace();
                true
            }
            None => false,
        }
    }

    /// Marks every session lagged so each drains its mailbox (after routing may have lost
    /// notifications, e.g. a Valkey reconnect).
    pub fn lag_all(&self) {
        for (_, h) in &self.sessions.pin() {
            h.signals.lag();
        }
    }

    fn attach_now(&self, device: DeviceId, sizes: InboxSizes) -> Inbox {
        let (live_tx, live) = mpsc::channel(sizes.live.max(1));
        let (eph_tx, ephemeral) = mpsc::channel(sizes.ephemeral.max(1));
        let signals = Arc::new(Signals::default());
        let conn = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let handle = Handle {
            conn,
            live: live_tx,
            ephemeral: eph_tx,
            signals: Arc::clone(&signals),
        };
        if let Some(old) = self.sessions.pin().insert(device, handle) {
            old.signals.replace();
        }
        Inbox {
            conn,
            live,
            ephemeral,
            signals,
        }
    }
}

// Everything here completes synchronously; each method returns a ready future.
impl Router for LocalRouter {
    fn attach(&self, device: DeviceId, sizes: InboxSizes) -> impl Future<Output = Inbox> + Send {
        ready(self.attach_now(device, sizes))
    }

    fn detach(&self, device: &DeviceId, conn: u64) -> impl Future<Output = ()> + Send {
        // Only this attachment's entry: a newer session for the device stays.
        let _ = self.sessions.pin().remove_if(device, |_, h| h.conn == conn);
        ready(())
    }

    fn route(&self, device: &DeviceId, live: Live) -> impl Future<Output = Routed> + Send {
        let map = self.sessions.pin();
        let r = match map.get(device) {
            None => Routed::Offline,
            Some(h) => match h.live.try_send(live) {
                Ok(()) => Routed::Queued,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    h.signals.lag();
                    Routed::Lagged
                }
                // The session ended between lookup and send: it will detach; treat as offline.
                Err(mpsc::error::TrySendError::Closed(_)) => Routed::Offline,
            },
        };
        ready(r)
    }

    fn route_ephemeral(
        &self,
        device: &DeviceId,
        payload: Bytes,
    ) -> impl Future<Output = Routed> + Send {
        let map = self.sessions.pin();
        let r = match map.get(device) {
            None => Routed::Offline,
            Some(h) => match h.ephemeral.try_send(payload) {
                Ok(()) => Routed::Queued,
                // Ephemeral events are dropped first under pressure and never trigger a drain.
                Err(mpsc::error::TrySendError::Full(_)) => Routed::Lagged,
                Err(mpsc::error::TrySendError::Closed(_)) => Routed::Offline,
            },
        };
        ready(r)
    }
}

/// The router chosen at start-up from configuration.
#[derive(Debug)]
pub enum AnyRouter {
    /// One node (development, tests, a single server).
    Local(LocalRouter),
    /// Several nodes over Valkey (D-0034).
    Valkey(valkey::ValkeyRouter),
}

impl Router for AnyRouter {
    async fn attach(&self, device: DeviceId, sizes: InboxSizes) -> Inbox {
        match self {
            Self::Local(r) => r.attach(device, sizes).await,
            Self::Valkey(r) => r.attach(device, sizes).await,
        }
    }

    async fn detach(&self, device: &DeviceId, conn: u64) {
        match self {
            Self::Local(r) => r.detach(device, conn).await,
            Self::Valkey(r) => r.detach(device, conn).await,
        }
    }

    async fn route(&self, device: &DeviceId, live: Live) -> Routed {
        match self {
            Self::Local(r) => r.route(device, live).await,
            Self::Valkey(r) => r.route(device, live).await,
        }
    }

    async fn route_ephemeral(&self, device: &DeviceId, payload: Bytes) -> Routed {
        match self {
            Self::Local(r) => r.route_ephemeral(device, payload).await,
            Self::Valkey(r) => r.route_ephemeral(device, payload).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZES: InboxSizes = InboxSizes {
        live: 2,
        ephemeral: 1,
    };

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn live(seq: u64) -> Live {
        Live {
            seq,
            envelope: Bytes::from_static(b"e"),
        }
    }

    #[tokio::test]
    async fn newer_attach_replaces_older() {
        let r = LocalRouter::new();
        let old = r.attach(d(1), SIZES).await;
        let new = r.attach(d(1), SIZES).await;
        assert!(old.signals.is_replaced());
        assert!(!new.signals.is_replaced());
        // The older session's detach must not remove the newer one.
        r.detach(&d(1), old.conn).await;
        assert_eq!(r.attached(), 1);
        r.detach(&d(1), new.conn).await;
        assert_eq!(r.attached(), 0);
    }

    #[tokio::test]
    async fn full_inbox_drops_and_marks_lagged_without_blocking() {
        let r = LocalRouter::new();
        let mut inbox = r.attach(d(1), SIZES).await;
        assert_eq!(r.route(&d(1), live(1)).await, Routed::Queued);
        assert_eq!(r.route(&d(1), live(2)).await, Routed::Queued);
        assert_eq!(r.route(&d(1), live(3)).await, Routed::Lagged);
        assert!(inbox.signals.take_lagged());
        assert!(!inbox.signals.take_lagged(), "flag clears");
        assert_eq!(inbox.live.recv().await.unwrap().seq, 1);
        assert_eq!(r.route(&d(2), live(1)).await, Routed::Offline);
    }

    #[tokio::test]
    async fn ephemeral_lane_drops_when_full() {
        let r = LocalRouter::new();
        let inbox = r.attach(d(1), SIZES).await;
        let p = Bytes::from_static(b"typing");
        assert_eq!(r.route_ephemeral(&d(1), p.clone()).await, Routed::Queued);
        assert_eq!(r.route_ephemeral(&d(1), p).await, Routed::Lagged);
        assert!(
            !inbox.signals.take_lagged(),
            "ephemeral never triggers a drain"
        );
    }
}
