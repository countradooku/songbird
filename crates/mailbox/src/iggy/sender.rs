//! A process that only sends (D-0044): `api` stores the sends it accepts over HTTP on the
//! partitions' owners, over node links, exactly as a delivery node that does not own a partition
//! does, and holds nothing else of the mailbox.
//!
//! - **No Iggy, no keys, no partitions here.** It never connects to Iggy, never holds a key store
//!   or a master key, never takes a lease and never registers as a member, so an `api` host has
//!   nothing to read even if compromised; every partition is remote.
//! - **Owners from the leases.** Every `refresh` it reads each partition's lease (one `MGET`; the
//!   lease value names the owner and its link address) and points the partition at that owner.
//!   A partition without a lease (a failover in progress) answers `Unavailable` until the next
//!   read: the client retries with its hint, as it does over the WebSocket.
//! - **Store only.** Owners admit `api.` certificates for the store of a send and refuse anything
//!   else ([`super::ClusterConfig::senders`]). The split of a send across partitions is the
//!   owners' own code ([`super::store_on`]), with the idempotency tag computed the same way, so a
//!   retry over the WebSocket after an HTTP attempt (or the reverse) is stored once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::hmac;
use songbird_link::{LinkClient, LinkTls};
use tokio::sync::watch;

use super::cluster::{LinkPeer, Member};
use super::partitions::{Partitions, Peer, Slot};
use super::{StoreOpts, store_on};
use crate::{MailboxError, StoreOutcome, StoreRequest, StoreSend};

/// Settings of a send-only node.
#[derive(Clone)]
pub struct IggySenderConfig {
    /// Iggy stream of the mailbox (as on the delivery nodes).
    pub stream: String,
    /// Iggy topic of the mailbox.
    pub topic: String,
    /// Partitions of the topic (as on the delivery nodes).
    pub partitions: u32,
    /// The delivery nodes' idempotency secret: tags must match theirs for a retry to be one.
    pub idempotency_secret: [u8; 32],
    /// Longest wait for an owner's answer.
    pub timeout: Duration,
    /// This node's link identity (`api.<host>.songbird.internal`, internal CA).
    pub link_tls: LinkTls,
    /// The Valkey holding the delivery nodes' leases (read only).
    pub valkey: redis::Client,
    /// How often the owners are read again (a third of the lease is the delivery nodes' own
    /// renewal period).
    pub refresh: Duration,
}

impl std::fmt::Debug for IggySenderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IggySenderConfig")
            .field("partitions", &self.partitions)
            .finish_non_exhaustive()
    }
}

struct Inner {
    parts: Partitions,
    idem: hmac::Key,
    n: u32,
    prefix: String,
    conn: songbird_router::conn::ValkeyConn,
    tls: LinkTls,
    timeout: Duration,
    /// Each partition's owner as last read (member ID), to repoint only on a change.
    owners: Mutex<Vec<Option<u64>>>,
    /// One link per owner, reused across partitions and refreshes.
    links: Mutex<HashMap<u64, Arc<LinkPeer>>>,
    /// Partitions with a known owner.
    known: AtomicU32,
}

/// The store operation of the mailbox, on a node that owns no partition (`api`).
pub struct IggySender {
    inner: Arc<Inner>,
    stop: watch::Sender<bool>,
}

impl std::fmt::Debug for IggySender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IggySender")
            .field("partitions", &self.inner.n)
            .finish_non_exhaustive()
    }
}

impl IggySender {
    /// Connects to the lease store, reads the owners once and keeps reading them every
    /// `refresh` until dropped. Partitions without an owner yet answer `Unavailable`.
    ///
    /// # Errors
    /// [`MailboxError::Unavailable`]: Valkey unreachable, or no partitions configured.
    pub async fn connect(cfg: IggySenderConfig) -> Result<Self, MailboxError> {
        if cfg.partitions == 0 {
            return Err(MailboxError::Unavailable);
        }
        let conn = songbird_router::conn::ValkeyConn::connect(cfg.valkey)
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        let n = cfg.partitions;
        let inner = Arc::new(Inner {
            parts: Partitions::new(n, cfg.timeout),
            idem: hmac::Key::new(hmac::HMAC_SHA256, &cfg.idempotency_secret),
            n,
            prefix: format!("songbird:{}:{}", cfg.stream, cfg.topic),
            conn,
            tls: cfg.link_tls,
            timeout: cfg.timeout,
            owners: Mutex::new(vec![None; super::idx(n)]),
            links: Mutex::new(HashMap::new()),
            known: AtomicU32::new(0),
        });
        inner.refresh().await;
        let (stop, mut stop_rx) = watch::channel(false);
        let i = Arc::clone(&inner);
        let every = cfg.refresh.max(Duration::from_millis(100));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => i.refresh().await,
                    _ = async { stop_rx.wait_for(|s| *s).await.is_ok() } => return,
                }
            }
        });
        Ok(Self { inner, stop })
    }

    /// Partitions whose owner is known (readiness, tests).
    #[must_use]
    pub fn known(&self) -> u32 {
        self.inner.known.load(Ordering::Relaxed)
    }

    /// Tests only: asks `device`'s partition owner for what a sender may not have, a fetch and
    /// an acknowledgement of everything; an owner must refuse both.
    #[doc(hidden)]
    pub async fn try_forbidden(
        &self,
        device: &songbird_types::DeviceId,
    ) -> (
        Result<Vec<crate::Stored>, MailboxError>,
        Result<(), MailboxError>,
    ) {
        let p = super::partition_of(device, self.inner.n);
        (
            self.inner.parts.fetch(p, *device, 0, 10).await,
            self.inner.parts.ack(p, *device, u64::MAX).await,
        )
    }
}

impl Drop for IggySender {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

impl Inner {
    /// Reads every lease and points each partition at its owner (or nowhere).
    async fn refresh(&self) {
        let keys: Vec<String> = (0..self.n)
            .map(|p| format!("{}:lease:{p}", self.prefix))
            .collect();
        let Ok(holders) = self
            .conn
            .query::<Vec<Option<String>>>(redis::cmd("MGET").arg(&keys))
            .await
        else {
            // Valkey unreachable: keep the owners last read (sends to a moved partition answer
            // `NotOwner`, seen as unavailable, until Valkey is back).
            return;
        };
        let mut owners = self
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut known = 0;
        for (p, holder) in (0..self.n).zip(holders) {
            let member = holder.as_deref().and_then(Member::decode);
            let id = member.as_ref().map(|m| m.id);
            if id.is_some() {
                known += 1;
            }
            let Some(slot) = owners.get_mut(super::idx(p)) else {
                continue;
            };
            if *slot == id {
                continue;
            }
            *slot = id;
            match member {
                Some(m) => {
                    let link: Arc<dyn Peer> = self.link(&m);
                    self.parts.set(p, Slot::Remote(link));
                }
                None => self.parts.set(p, Slot::Unknown),
            }
        }
        self.known.store(known, Ordering::Relaxed);
    }

    fn link(&self, m: &Member) -> Arc<LinkPeer> {
        let mut links = self
            .links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Links to members no longer named by any lease go (their connections close).
        if links.len() > 4 * super::idx(self.n) {
            links.clear();
        }
        Arc::clone(links.entry(m.id).or_insert_with(|| {
            Arc::new(LinkPeer {
                client: LinkClient::new(m.addr, &m.name, self.tls.clone()),
                timeout: self.timeout,
            })
        }))
    }
}

impl StoreSend for IggySender {
    async fn store_send(&self, req: StoreRequest) -> Result<StoreOutcome, MailboxError> {
        let o = StoreOpts {
            // No partition is local here; the owner checks its own capacity.
            max_per_device: u64::MAX,
            mark_done: false,
            fault_skip_remote_parts: false,
        };
        let i = &self.inner;
        store_on(&i.parts, &i.idem, i.n, req, o).await
    }
}
