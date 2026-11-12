//! Where each partition's writer is (D-0034): on this node, on another node (reached over a node
//! link), or nowhere known yet. Every per-partition operation goes through here, so a send, a
//! fetch or an ACK works the same whichever node owns the device's partition.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use songbird_types::DeviceId;
use tokio::sync::oneshot;

use super::wire::{JobData, Request, Response};
use super::{Entry, Job, Part, PartResult, StoreJob, n64};
use crate::{MailboxError, Stored};

/// A node that owns partitions this one does not.
pub(crate) trait Peer: Send + Sync + 'static {
    /// Sends a request to the owner and waits for its answer.
    fn call(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response, MailboxError>> + Send + '_>>;
}

/// Sends a partition's key-store writes to its standby node (D-0034).
pub(crate) trait Replicator: Send + Sync + 'static {
    /// Delivers one write; failures are counted, not returned (the owner keeps running).
    fn replicate(
        &self,
        p: u32,
        replica: super::keys::Replica,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// One partition's writer.
#[derive(Clone)]
pub(crate) enum Slot {
    Local(Arc<Part>),
    Remote(Arc<dyn Peer>),
    Unknown,
}

/// Every partition's slot.
pub(crate) struct Partitions {
    slots: Vec<RwLock<Slot>>,
    timeout: Duration,
}

fn unavailable<T>() -> Result<T, MailboxError> {
    Err(MailboxError::Unavailable)
}

impl Partitions {
    pub(crate) fn new(count: u32, timeout: Duration) -> Self {
        Self {
            slots: (0..count).map(|_| RwLock::new(Slot::Unknown)).collect(),
            timeout,
        }
    }

    pub(crate) fn count(&self) -> u32 {
        u32::try_from(self.slots.len()).unwrap_or(u32::MAX)
    }

    pub(crate) fn set(&self, p: u32, slot: Slot) {
        if let Some(s) = self.slots.get(super::idx(p)) {
            *s.write().unwrap_or_else(std::sync::PoisonError::into_inner) = slot;
        }
    }

    pub(crate) fn get(&self, p: u32) -> Slot {
        self.slots.get(super::idx(p)).map_or(Slot::Unknown, |s| {
            s.read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
    }

    /// The local writer of `p`, if this node owns it.
    pub(crate) fn local(&self, p: u32) -> Option<Arc<Part>> {
        match self.get(p) {
            Slot::Local(part) => Some(part),
            _ => None,
        }
    }

    /// Every partition this node owns.
    pub(crate) fn locals(&self) -> Vec<Arc<Part>> {
        (0..self.count()).filter_map(|p| self.local(p)).collect()
    }

    async fn remote(&self, peer: &Arc<dyn Peer>, req: Request) -> Result<Response, MailboxError> {
        match tokio::time::timeout(self.timeout, peer.call(req)).await {
            Ok(Ok(Response::NotOwner) | Err(_)) | Err(_) => unavailable(),
            Ok(Ok(r)) => Ok(r),
        }
    }

    /// Stores `job` on partition `p` and waits for its outcome.
    pub(crate) async fn submit(&self, p: u32, job: JobData) -> PartResult {
        match self.get(p) {
            Slot::Local(part) => {
                let (tx, rx) = oneshot::channel();
                let j = StoreJob {
                    tag: job.tag,
                    mls: job.mls,
                    local: job.local,
                    remote: job.remote,
                    reply: tx,
                };
                part.tx
                    .send(Job::Store(j))
                    .await
                    .map_err(|_| MailboxError::Unavailable)?;
                match tokio::time::timeout(self.timeout, rx).await {
                    Ok(Ok(r)) => r,
                    _ => unavailable(),
                }
            }
            Slot::Remote(peer) => match self.remote(&peer, Request::Store { p, job }).await? {
                Response::Store(r) => r,
                _ => unavailable(),
            },
            Slot::Unknown => unavailable(),
        }
    }

    pub(crate) async fn ack(&self, p: u32, device: DeviceId, seq: u64) -> Result<(), MailboxError> {
        match self.get(p) {
            Slot::Local(part) => part
                .tx
                .send(Job::Ack(device, seq))
                .await
                .map_err(|_| MailboxError::Unavailable),
            Slot::Remote(peer) => {
                match self.remote(&peer, Request::Ack { p, device, seq }).await? {
                    Response::Done(r) => r,
                    _ => unavailable(),
                }
            }
            Slot::Unknown => unavailable(),
        }
    }

    /// Tells the home partition `p` that the part of the send `tag` on `part` is stored.
    pub(crate) async fn part_done(&self, p: u32, tag: [u8; 32], part: u32) {
        match self.get(p) {
            Slot::Local(home) => {
                let _ = home.tx.send(Job::PartDone(tag, part)).await;
            }
            Slot::Remote(peer) => {
                let _ = self.remote(&peer, Request::PartDone { p, tag, part }).await;
            }
            // The home's re-driver completes it.
            Slot::Unknown => {}
        }
    }

    pub(crate) async fn fetch(
        &self,
        p: u32,
        device: DeviceId,
        after: u64,
        limit: usize,
    ) -> Result<Vec<Stored>, MailboxError> {
        match self.get(p) {
            Slot::Local(part) => fetch_local(&part, &device, after, limit).await,
            Slot::Remote(peer) => {
                let limit = u32::try_from(limit).unwrap_or(u32::MAX);
                let req = Request::Fetch {
                    p,
                    device,
                    after,
                    limit,
                };
                match self.remote(&peer, req).await? {
                    Response::Fetch(r) => r,
                    _ => unavailable(),
                }
            }
            Slot::Unknown => unavailable(),
        }
    }

    pub(crate) async fn pending(&self, p: u32, device: DeviceId) -> Result<u64, MailboxError> {
        match self.get(p) {
            Slot::Local(part) => Ok(pending_local(&part, &device)),
            Slot::Remote(peer) => match self.remote(&peer, Request::Count { p, device }).await? {
                Response::Count(r) => r,
                _ => unavailable(),
            },
            Slot::Unknown => unavailable(),
        }
    }

    /// Expires old entries on `p` (a local partition; each owner expires its own).
    pub(crate) async fn expire_local(part: &Part, age_ms: u64) -> Result<u64, MailboxError> {
        let (tx, rx) = oneshot::channel();
        part.tx
            .send(Job::Expire(age_ms, tx))
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        rx.await.map_err(|_| MailboxError::Unavailable)
    }
}

/// Pending entries of `device` in a local partition.
pub(crate) fn pending_local(part: &Part, device: &DeviceId) -> u64 {
    let st = part.shared.lock();
    st.devices.get(device).map_or(0, |s| n64(s.pending.len()))
}

/// Fetches from a local partition.
pub(crate) async fn fetch_local(
    part: &Part,
    device: &DeviceId,
    after_seq: u64,
    limit: usize,
) -> Result<Vec<Stored>, MailboxError> {
    let entries: Vec<Entry> = {
        let st = part.shared.lock();
        st.devices
            .get(device)
            .map(|s| {
                s.pending
                    .iter()
                    .filter(|e| e.seq > after_seq)
                    .take(limit)
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    };
    let offsets: Vec<u64> = entries.iter().map(|e| e.offset).collect();
    let recs = part.shared.sealed(&part.shared.reader, &offsets).await?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let s = recs.get(&e.offset).ok_or(MailboxError::Unavailable)?;
        out.push(Stored {
            seq: e.seq,
            envelope: part.shared.envelope(s, &e)?,
        });
    }
    Ok(out)
}

/// Serves a request from another node against this node's partitions.
pub(crate) async fn serve(parts: &Partitions, req: Request) -> Response {
    let Some(part) = parts.local(req.partition()) else {
        return Response::NotOwner;
    };
    match req {
        Request::Store { p, job } => Response::Store(parts.submit(p, job).await),
        Request::Ack { p, device, seq } => Response::Done(parts.ack(p, device, seq).await),
        Request::Fetch {
            device,
            after,
            limit,
            ..
        } => Response::Fetch(
            fetch_local(
                &part,
                &device,
                after,
                usize::try_from(limit).unwrap_or(usize::MAX),
            )
            .await,
        ),
        Request::Count { device, .. } => Response::Count(Ok(pending_local(&part, &device))),
        Request::Expire { age_ms, .. } => {
            Response::Count(Partitions::expire_local(&part, age_ms).await)
        }
        Request::PartDone {
            tag, part: other, ..
        } => {
            let _ = part.tx.send(Job::PartDone(tag, other)).await;
            Response::Done(Ok(()))
        }
        // Handled by the cluster: it is for a partition this node is the standby of.
        Request::KeyStore { .. } => Response::Done(Err(MailboxError::Unavailable)),
    }
}
