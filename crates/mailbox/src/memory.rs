//! In-memory mailbox for tests, development and the load generator's local runs.
//!
//! Not durable: a process restart loses everything, exactly like a restore that loses the
//! mailbox (clients recover through the store generation). It keeps the trait's ordering,
//! all-or-nothing, idempotency and MLS-epoch contract, so the session algorithm tested against it
//! holds against SurrealDB ([`crate::surreal`]). One `Mutex` guards the state: acceptable for a
//! stand-in, never used in deployments.

use std::collections::{HashMap, VecDeque};
use std::future::{Future, ready};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use aws_lc_rs::hmac;
use bytes::Bytes;
use songbird_types::DeviceId;

use crate::{
    IDEMPOTENCY_RETENTION, Mailbox, MailboxError, StoreOutcome, StoreRequest, Stored,
    idempotency_tag,
};

#[derive(Default)]
struct DeviceBox {
    /// Last `seq` allocated; never decreases, so a `seq` is never reused.
    last_seq: u64,
    /// Unacknowledged envelopes, ascending by `seq` and by store time. Shared bodies are the
    /// same `Bytes` for every device (one allocation).
    entries: VecDeque<(u64, Instant, Bytes)>,
}

/// An idempotency record: when, and which (device, seq) the send stored.
struct Record {
    at: Instant,
    stored: Vec<(DeviceId, u64)>,
}

#[derive(Default)]
struct Inner {
    // std `HashMap` uses a randomly seeded SipHash (`RandomState`).
    boxes: HashMap<DeviceId, DeviceBox>,
    idempotency: HashMap<[u8; 32], Record>,
    epochs: HashMap<[u8; 16], u64>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("devices", &self.boxes.len())
            .field("idempotency_keys", &self.idempotency.len())
            .field("groups", &self.epochs.len())
            .finish()
    }
}

/// An in-memory [`Mailbox`].
pub struct MemoryMailbox {
    inner: Mutex<Inner>,
    max_per_device: usize,
    store_generation: u64,
    /// Keys idempotency records, so the store never holds a client's key itself.
    idempotency_hmac: hmac::Key,
}

impl std::fmt::Debug for MemoryMailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryMailbox")
            .field("inner", &self.inner)
            .field("max_per_device", &self.max_per_device)
            .field("store_generation", &self.store_generation)
            .finish_non_exhaustive()
    }
}

impl MemoryMailbox {
    /// A mailbox holding at most `max_per_device` unacknowledged envelopes per device.
    #[must_use]
    pub fn new(max_per_device: usize, store_generation: u64) -> Self {
        let mut secret = [0u8; 32];
        // A failing OS random source leaves a zero key: records still work, only less private
        // against someone who can read this process's memory, who could read them anyway.
        let _ = getrandom::fill(&mut secret);
        Self {
            inner: Mutex::new(Inner::default()),
            max_per_device,
            store_generation,
            idempotency_hmac: hmac::Key::new(hmac::HMAC_SHA256, &secret),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Release builds abort on panic, so the lock is only ever poisoned in tests.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Unacknowledged envelopes for `device` (tests and diagnostics).
    #[must_use]
    pub fn pending(&self, device: &DeviceId) -> usize {
        self.lock().boxes.get(device).map_or(0, |b| b.entries.len())
    }

    /// Unacknowledged envelopes across all devices (tests and diagnostics).
    #[must_use]
    pub fn total_pending(&self) -> usize {
        self.lock().boxes.values().map(|b| b.entries.len()).sum()
    }

    /// [`Mailbox::store`] without the future (test wrappers).
    ///
    /// # Errors
    /// As [`Mailbox::store`].
    pub fn store_now_for_tests(&self, req: &StoreRequest) -> Result<StoreOutcome, MailboxError> {
        self.store_now(req, Instant::now())
    }

    fn store_now(&self, req: &StoreRequest, now: Instant) -> Result<StoreOutcome, MailboxError> {
        let record_id = req
            .idempotency_key
            .map(|k| idempotency_tag(&self.idempotency_hmac, &k));
        let mut inner = self.lock();
        if let Some(r) = record_id.and_then(|id| inner.idempotency.get(&id)) {
            // Scoped to the recipients: a replay must name the same devices, in order.
            let same = r.stored.len() == req.payload.len()
                && r.stored
                    .iter()
                    .zip(req.payload.devices())
                    .all(|((d, _), dev)| d == dev);
            if !same {
                return Err(MailboxError::IdempotencyConflict);
            }
            return Ok(StoreOutcome {
                seqs: r.stored.iter().map(|(_, s)| *s).collect(),
                replayed: true,
            });
        }
        if let Some(m) = req.mls
            && inner.epochs.get(&m.group).copied().unwrap_or(0) != m.epoch
        {
            return Err(MailboxError::StaleEpoch);
        }
        // Check capacity for the whole send first, so a failure stores nothing. Counting
        // repeats pairwise avoids a per-send map (sends name each device once in practice).
        let devices: Vec<&DeviceId> = req.payload.devices().collect();
        for (i, d) in devices.iter().enumerate() {
            let n = devices
                .get(..i)
                .unwrap_or_default()
                .iter()
                .filter(|o| *o == d)
                .count()
                + 1;
            let have = inner.boxes.get(*d).map_or(0, |b| b.entries.len());
            if have.saturating_add(n) > self.max_per_device {
                return Err(MailboxError::Full);
            }
        }
        let mut seqs = Vec::with_capacity(devices.len());
        for (i, d) in devices.iter().enumerate() {
            let env = req
                .payload
                .envelope(i)
                .cloned()
                .ok_or(MailboxError::Unavailable)?;
            let b = inner.boxes.entry(**d).or_default();
            b.last_seq = b.last_seq.checked_add(1).ok_or(MailboxError::Unavailable)?;
            b.entries.push_back((b.last_seq, now, env));
            seqs.push(b.last_seq);
        }
        if let Some(m) = req.mls {
            inner.epochs.insert(m.group, m.epoch.saturating_add(1));
        }
        if let Some(id) = record_id {
            let stored = devices
                .iter()
                .map(|d| **d)
                .zip(seqs.iter().copied())
                .collect();
            inner.idempotency.insert(id, Record { at: now, stored });
        }
        Ok(StoreOutcome {
            seqs,
            replayed: false,
        })
    }

    fn expire_at(&self, age: Duration, now: Instant) -> u64 {
        let mut inner = self.lock();
        let mut removed = 0u64;
        for b in inner.boxes.values_mut() {
            while b
                .entries
                .front()
                .is_some_and(|(_, at, _)| now.saturating_duration_since(*at) > age)
            {
                b.entries.pop_front();
                removed += 1;
            }
        }
        inner
            .idempotency
            .retain(|_, r| now.saturating_duration_since(r.at) <= IDEMPOTENCY_RETENTION);
        removed
    }
}

// The in-memory store completes synchronously; each method returns a ready future.
impl Mailbox for MemoryMailbox {
    fn store(
        &self,
        req: StoreRequest,
    ) -> impl Future<Output = Result<StoreOutcome, MailboxError>> + Send {
        ready(self.store_now(&req, Instant::now()))
    }

    fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<Stored>, MailboxError>> + Send {
        let inner = self.lock();
        let out = inner.boxes.get(device).map_or_else(Vec::new, |b| {
            let start = b.entries.partition_point(|(s, _, _)| *s <= after_seq);
            b.entries
                .range(start..)
                .take(limit)
                .map(|(seq, _, e)| Stored {
                    seq: *seq,
                    envelope: e.clone(),
                })
                .collect()
        });
        ready(Ok(out))
    }

    fn ack_up_to(
        &self,
        device: &DeviceId,
        up_to_seq: u64,
    ) -> impl Future<Output = Result<(), MailboxError>> + Send {
        let mut inner = self.lock();
        if let Some(b) = inner.boxes.get_mut(device) {
            while b.entries.front().is_some_and(|(s, _, _)| *s <= up_to_seq) {
                b.entries.pop_front();
            }
        }
        ready(Ok(()))
    }

    fn expire_older_than(
        &self,
        age: Duration,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        ready(Ok(self.expire_at(age, Instant::now())))
    }

    fn store_generation(&self) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        ready(Ok(self.store_generation))
    }

    fn count_pending(
        &self,
        device: &DeviceId,
    ) -> impl Future<Output = Result<u64, MailboxError>> + Send {
        ready(Ok(u64::try_from(self.pending(device)).unwrap_or(u64::MAX)))
    }

    fn forget(&self, devices: &[DeviceId]) -> impl Future<Output = Result<(), MailboxError>> + Send {
        let mut inner = self.lock();
        for d in devices {
            inner.boxes.remove(d);
        }
        ready(Ok(()))
    }

    fn knows(&self, device: &DeviceId) -> impl Future<Output = Result<bool, MailboxError>> + Send {
        ready(Ok(self.lock().boxes.contains_key(device)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlsCommit, NewEnvelope, Payload};
    use proptest::prelude::*;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn env(device: DeviceId, s: &'static str) -> NewEnvelope {
        NewEnvelope {
            device,
            envelope: Bytes::from_static(s.as_bytes()),
        }
    }

    fn per(items: Vec<NewEnvelope>) -> StoreRequest {
        StoreRequest {
            idempotency_key: None,
            mls: None,
            payload: Payload::PerDevice(items),
        }
    }

    fn keyed(k: u8, items: Vec<NewEnvelope>) -> StoreRequest {
        StoreRequest {
            idempotency_key: Some([k; 16]),
            ..per(items)
        }
    }

    #[tokio::test]
    async fn seq_is_per_device_and_gap_free() {
        let m = MemoryMailbox::new(100, 1);
        let out = m
            .store(per(vec![env(d(1), "a"), env(d(2), "b"), env(d(1), "c")]))
            .await
            .unwrap();
        assert_eq!(out.seqs, vec![1, 1, 2]);
        let got = m.fetch_after(&d(1), 0, 10).await.unwrap();
        assert_eq!(got.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(got[1].envelope, Bytes::from_static(b"c"));
    }

    #[tokio::test]
    async fn ack_deletes_and_seq_is_never_reused() {
        let m = MemoryMailbox::new(100, 1);
        m.store(per(vec![env(d(1), "a"), env(d(1), "b")]))
            .await
            .unwrap();
        m.ack_up_to(&d(1), 2).await.unwrap();
        assert_eq!(m.pending(&d(1)), 0);
        assert_eq!(
            m.store(per(vec![env(d(1), "c")])).await.unwrap().seqs,
            vec![3]
        );
        m.ack_up_to(&d(1), 99).await.unwrap();
        assert_eq!(m.count_pending(&d(1)).await.unwrap(), 0);
        m.ack_up_to(&d(9), 1).await.unwrap();
    }

    #[tokio::test]
    async fn full_mailbox_stores_nothing() {
        let m = MemoryMailbox::new(2, 1);
        m.store(per(vec![env(d(1), "a")])).await.unwrap();
        let batch = vec![env(d(2), "x"), env(d(1), "b"), env(d(1), "c")];
        assert_eq!(m.store(per(batch)).await, Err(MailboxError::Full));
        assert_eq!(m.pending(&d(2)), 0, "all or nothing");
        assert_eq!(
            m.store(per(vec![env(d(1), "b")])).await.unwrap().seqs,
            vec![2]
        );
    }

    #[tokio::test]
    async fn retried_send_is_stored_once() {
        let m = MemoryMailbox::new(10, 1);
        let batch = vec![env(d(1), "a"), env(d(2), "b")];
        let first = m.store(keyed(7, batch.clone())).await.unwrap();
        let again = m.store(keyed(7, batch.clone())).await.unwrap();
        assert!(!first.replayed && again.replayed);
        assert_eq!(first.seqs, again.seqs);
        assert_eq!(m.total_pending(), 2);
        let other = m.store(keyed(8, batch)).await.unwrap();
        assert_eq!(other.seqs, vec![2, 2]);
        // The same key for other recipients is refused and stores nothing.
        assert_eq!(
            m.store(keyed(7, vec![env(d(3), "c")])).await,
            Err(MailboxError::IdempotencyConflict)
        );
        assert_eq!(m.pending(&d(3)), 0);
        // Records hold a keyed hash, never the key itself.
        assert!(!m.lock().idempotency.keys().any(|k| k.starts_with(&[7; 16])));
    }

    #[tokio::test]
    async fn shared_body_is_one_buffer_for_every_device() {
        let m = MemoryMailbox::new(10, 1);
        let body = Bytes::from(vec![9u8; 1000]);
        let req = StoreRequest {
            idempotency_key: None,
            mls: None,
            payload: Payload::Shared {
                devices: vec![d(1), d(2), d(3)],
                body: body.clone(),
            },
        };
        assert_eq!(m.store(req).await.unwrap().seqs, vec![1, 1, 1]);
        for x in 1..=3 {
            let got = m.fetch_after(&d(x), 0, 10).await.unwrap();
            assert_eq!(got[0].envelope.as_ptr(), body.as_ptr(), "not copied");
        }
    }

    #[tokio::test]
    async fn mls_commits_are_ordered_by_epoch() {
        let m = MemoryMailbox::new(10, 1);
        let commit = |epoch| StoreRequest {
            idempotency_key: None,
            mls: Some(MlsCommit {
                group: [5; 16],
                epoch,
            }),
            payload: Payload::PerDevice(vec![env(d(1), "c")]),
        };
        assert!(m.store(commit(0)).await.is_ok());
        // A second commit from epoch 0 lost the race.
        assert_eq!(m.store(commit(0)).await, Err(MailboxError::StaleEpoch));
        assert!(m.store(commit(1)).await.is_ok());
        assert_eq!(m.pending(&d(1)), 2);
    }

    #[test]
    fn expiry_removes_only_old_entries() {
        let m = MemoryMailbox::new(10, 1);
        let t0 = Instant::now();
        m.store_now(&per(vec![env(d(1), "old")]), t0).unwrap();
        m.store_now(&per(vec![env(d(1), "new")]), t0 + Duration::from_secs(10))
            .unwrap();
        assert_eq!(
            m.expire_at(Duration::from_secs(5), t0 + Duration::from_secs(11)),
            1
        );
        assert_eq!(m.pending(&d(1)), 1);
    }

    proptest! {
        /// Any interleaving of stores and acks keeps fetch_after strictly ascending and above
        /// the last ack, and every stored seq is fetched exactly once until acknowledged.
        #[test]
        fn fetch_is_ordered_and_complete(ops in proptest::collection::vec((any::<bool>(), 0u64..20), 1..60)) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let m = MemoryMailbox::new(1000, 1);
                let dev = d(7);
                let mut acked = 0u64;
                let mut stored = 0u64;
                for (store, n) in ops {
                    if store {
                        stored = *m.store(per(vec![env(dev, "e")])).await.unwrap().seqs.last().unwrap();
                    } else {
                        let up = n.min(stored);
                        m.ack_up_to(&dev, up).await.unwrap();
                        acked = acked.max(up);
                    }
                    let got: Vec<u64> = m.fetch_after(&dev, 0, 1000).await.unwrap().iter().map(|s| s.seq).collect();
                    let want: Vec<u64> = (acked + 1..=stored).collect();
                    prop_assert_eq!(got, want);
                }
                Ok(())
            })?;
        }
    }
}
