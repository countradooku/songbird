//! In-memory state of one partition, rebuilt from the log on start (no I/O here). It owns the
//! partition's key ring: every entry that leaves the index (acknowledged, expired, copied forward)
//! has its leaf punctured here, and a shared body's leaf goes with the record's last entry.

use std::collections::{BTreeMap, HashMap, VecDeque};

use songbird_types::DeviceId;

use super::keys::KeyRing;
use super::record::NEVER;

/// A pending (un-acknowledged) entry: where its sealed slot is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) seq: u64,
    /// Iggy offset of the record holding it.
    pub(crate) offset: u64,
    /// Key window and leaf of its slot.
    pub(crate) window: u64,
    pub(crate) leaf: u32,
    /// When the send was accepted (ms).
    pub(crate) at_ms: u64,
    /// The send's deadline (ms; [`NEVER`] for none): never fetched after it, dropped by the
    /// next compaction.
    pub(crate) expires_ms: u64,
}

/// One device's counters and pending entries (ascending `seq`).
#[derive(Debug, Default)]
pub(crate) struct DeviceState {
    pub(crate) last: u64,
    pub(crate) acked: u64,
    pub(crate) pending: VecDeque<Entry>,
}

/// A record that still holds pending entries.
#[derive(Debug, Clone, Copy)]
struct RecInfo {
    window: u64,
    live: u32,
    /// Leaf of a shared body, punctured with the record's last entry.
    body_leaf: Option<u32>,
}

/// What a record says, in the form the state needs (built by the writer from what it appended,
/// or by replay from what it could open; punctured entries are simply absent).
#[derive(Debug, Clone)]
pub(crate) enum Fact {
    Store {
        at_ms: u64,
        /// The send's deadline, from the disappearing hint.
        expires_ms: Option<u64>,
        /// Idempotency tag and keyed recipient-set fingerprint.
        tag: Option<([u8; 32], [u8; 16])>,
        mls: Option<([u8; 16], u64)>,
        /// (device, seq, leaf).
        entries: Vec<(DeviceId, u64, u32)>,
        body_leaf: Option<u32>,
    },
    Relocate {
        /// (device, seq, `at_ms`, `expires_ms` or [`NEVER`], leaf).
        entries: Vec<(DeviceId, u64, u64, u64, u32)>,
    },
    Ack(Vec<(DeviceId, u64)>),
    Owner(u16),
    Snapshot {
        owner: u16,
        devices: Vec<(DeviceId, u64, u64)>,
        groups: Vec<([u8; 16], u64)>,
    },
    Forget(Vec<DeviceId>),
}

/// One partition.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) devices: HashMap<DeviceId, DeviceState>,
    /// MLS group -> current epoch.
    pub(crate) epochs: HashMap<[u8; 16], u64>,
    /// Idempotency tag -> what a retry needs (kept for the idempotency window).
    pub(crate) idem: HashMap<[u8; 32], Idem>,
    /// Offset -> records still holding pending entries.
    records: BTreeMap<u64, RecInfo>,
    /// Window -> last offset sealed with it.
    windows: BTreeMap<u64, u64>,
    /// (first offset, `at_ms`) of each appended batch, ascending; maps a time to an offset.
    pub(crate) times: VecDeque<(u64, u64)>,
    /// Highest producer epoch recorded.
    pub(crate) owner_epoch: u16,
    /// Next offset of the partition.
    pub(crate) next_offset: u64,
    /// The partition's keys.
    pub(crate) ring: KeyRing,
}

/// A send's idempotency record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Idem {
    /// Keyed fingerprint of the send's whole recipient set.
    pub(crate) fp: [u8; 16],
    /// When the send was accepted (ms).
    pub(crate) at_ms: u64,
    /// Offset of this partition's store record of the send.
    pub(crate) offset: u64,
}

impl State {
    /// A state over a loaded key ring.
    pub(crate) fn with_ring(ring: KeyRing) -> Self {
        Self {
            ring,
            ..Self::default()
        }
    }

    /// Records a send's idempotency entry (the first one wins).
    pub(crate) fn add_idem(&mut self, tag: [u8; 32], idem: Idem) {
        self.idem.entry(tag).or_insert(idem);
    }

    /// Drops idempotency entries accepted before `cutoff_ms`.
    pub(crate) fn prune_idem(&mut self, cutoff_ms: u64) {
        self.idem.retain(|_, i| i.at_ms >= cutoff_ms);
    }

    fn puncture(&mut self, window: u64, leaf: u32) {
        // A failing cipher here would be a broken build; the leaf then stays until the window
        // is destroyed.
        let _ = self.ring.puncture(window, leaf);
    }

    fn record_add(&mut self, offset: u64, window: u64) {
        self.records
            .entry(offset)
            .or_insert(RecInfo {
                window,
                live: 0,
                body_leaf: None,
            })
            .live += 1;
    }

    fn record_remove(&mut self, offset: u64) {
        let gone = match self.records.get_mut(&offset) {
            Some(r) => {
                r.live = r.live.saturating_sub(1);
                (r.live == 0).then_some(*r)
            }
            None => None,
        };
        if let Some(r) = gone {
            self.records.remove(&offset);
            if let Some(b) = r.body_leaf {
                self.puncture(r.window, b);
            }
        }
    }

    /// Lowest offset still holding a pending entry.
    pub(crate) fn min_live(&self) -> Option<u64> {
        self.records.keys().next().copied()
    }

    /// The first recorded batch offset at or after `at_ms` (or the head).
    pub(crate) fn offset_at(&self, at_ms: u64) -> u64 {
        self.times
            .iter()
            .find(|(_, t)| *t >= at_ms)
            .map_or(self.next_offset, |(o, _)| *o)
    }

    pub(crate) fn note_batch(&mut self, first_offset: u64, at_ms: u64) {
        if self.times.back().is_none_or(|(o, _)| *o < first_offset) {
            self.times.push_back((first_offset, at_ms));
        }
    }

    pub(crate) fn prune_times(&mut self, before: u64) {
        while self.times.front().is_some_and(|(o, _)| *o < before) {
            self.times.pop_front();
        }
    }

    /// Records a pending entry (keeps `seq` order; a relocated copy replaces the old one, whose
    /// leaf is punctured). An entry already acknowledged is punctured, not kept.
    fn insert(&mut self, device: DeviceId, e: Entry) {
        let st = self.devices.entry(device).or_default();
        st.last = st.last.max(e.seq);
        if e.seq <= st.acked {
            self.puncture(e.window, e.leaf);
            return;
        }
        let pos = st.pending.partition_point(|x| x.seq < e.seq);
        let old = match st.pending.get_mut(pos) {
            Some(x) if x.seq == e.seq => {
                let old = *x;
                *x = e;
                Some(old)
            }
            _ => {
                st.pending.insert(pos, e);
                None
            }
        };
        if let Some(o) = old {
            self.puncture(o.window, o.leaf);
            self.record_remove(o.offset);
        }
        self.record_add(e.offset, e.window);
    }

    /// Acknowledges `device` up to `seq`: the entries leave the index and their leaves are
    /// punctured.
    pub(crate) fn ack(&mut self, device: &DeviceId, seq: u64) {
        let st = self.devices.entry(*device).or_default();
        st.last = st.last.max(seq);
        if seq <= st.acked {
            return;
        }
        st.acked = seq;
        let mut gone = Vec::new();
        while st.pending.front().is_some_and(|e| e.seq <= seq) {
            if let Some(e) = st.pending.pop_front() {
                gone.push(e);
            }
        }
        for e in gone {
            self.puncture(e.window, e.leaf);
            self.record_remove(e.offset);
        }
    }

    /// Forgets a deleted device (D-0036): every pending entry is acknowledged (leaves
    /// punctured) and its counters dropped, so nothing of it is left in memory, in snapshots or
    /// in the key store.
    pub(crate) fn forget(&mut self, device: &DeviceId) {
        let last = self.devices.get(device).map(|s| s.last);
        if let Some(last) = last {
            self.ack(device, last);
            self.devices.remove(device);
        }
    }

    /// Devices with entries accepted at or before `cutoff_ms`, and the highest such `seq` of each.
    /// Expiry is written as an acknowledgement up to it (entries of a device are in `seq` and
    /// time order, so the expired ones are a prefix).
    pub(crate) fn expired(&self, cutoff_ms: u64) -> Vec<(DeviceId, u64)> {
        self.devices
            .iter()
            .filter_map(|(d, st)| {
                st.pending
                    .iter()
                    .take_while(|e| e.at_ms <= cutoff_ms)
                    .last()
                    .map(|e| (*d, e.seq))
            })
            .collect()
    }

    /// Drops every pending entry whose deadline is at or before `now_ms` (the disappearing
    /// hint): it leaves the index and its leaf is punctured, so it can never be read again, nor
    /// come back on replay (punctured slots are absent). Not an acknowledgement: the device's
    /// cursor does not move and its `seq` is simply skipped. Returns how many.
    pub(crate) fn drop_expired(&mut self, now_ms: u64) -> u64 {
        let mut gone = Vec::new();
        for st in self.devices.values_mut() {
            if st.pending.iter().all(|e| e.expires_ms > now_ms) {
                continue;
            }
            st.pending.retain(|e| {
                let keep = e.expires_ms > now_ms;
                if !keep {
                    gone.push(*e);
                }
                keep
            });
        }
        let n = u64::try_from(gone.len()).unwrap_or(u64::MAX);
        for e in gone {
            self.puncture(e.window, e.leaf);
            self.record_remove(e.offset);
        }
        n
    }

    /// Pending entries stored in records before `offset`: (device, entry).
    pub(crate) fn entries_before(&self, offset: u64) -> Vec<(DeviceId, Entry)> {
        let mut out = Vec::new();
        for (d, st) in &self.devices {
            for e in &st.pending {
                if e.offset < offset {
                    out.push((*d, *e));
                }
            }
        }
        out.sort_by_key(|(_, e)| (e.offset, e.leaf));
        out
    }

    /// Destroys the keys of every window whose records are all below `low` (except `keep`, the
    /// window being written). Returns how many.
    pub(crate) fn destroy_windows_below(&mut self, low: u64, keep: Option<u64>) -> usize {
        let doomed: Vec<u64> = self
            .windows
            .iter()
            .filter(|(w, last)| **last < low && Some(**w) != keep)
            .map(|(w, _)| *w)
            .collect();
        for w in &doomed {
            self.windows.remove(w);
            self.ring.destroy(*w);
        }
        doomed.len()
    }

    /// Applies one record at `offset`, sealed in `window`.
    pub(crate) fn apply(
        &mut self,
        offset: u64,
        window: u64,
        fact: &Fact,
        tag_window_ms: u64,
        now_ms: u64,
    ) {
        self.next_offset = self.next_offset.max(offset + 1);
        let last = self.windows.entry(window).or_default();
        *last = (*last).max(offset);
        match fact {
            Fact::Store {
                at_ms,
                expires_ms,
                tag,
                mls,
                entries,
                body_leaf,
            } => {
                self.note_batch(offset, *at_ms);
                if let (Some((t, fp)), true) = (tag, at_ms.saturating_add(tag_window_ms) >= now_ms)
                {
                    self.add_idem(
                        *t,
                        Idem {
                            fp: *fp,
                            at_ms: *at_ms,
                            offset,
                        },
                    );
                }
                if let Some((g, e)) = mls {
                    let cur = self.epochs.entry(*g).or_default();
                    *cur = (*cur).max(*e);
                }
                for (d, seq, leaf) in entries {
                    self.insert(
                        *d,
                        Entry {
                            seq: *seq,
                            offset,
                            window,
                            leaf: *leaf,
                            at_ms: *at_ms,
                            expires_ms: expires_ms.unwrap_or(NEVER),
                        },
                    );
                }
                if let Some(b) = body_leaf {
                    match self.records.get_mut(&offset) {
                        Some(r) => r.body_leaf = Some(*b),
                        // Nobody left to read it.
                        None => self.puncture(window, *b),
                    }
                }
            }
            Fact::Relocate { entries } => {
                for (d, seq, at_ms, expires_ms, leaf) in entries {
                    self.insert(
                        *d,
                        Entry {
                            seq: *seq,
                            offset,
                            window,
                            leaf: *leaf,
                            at_ms: *at_ms,
                            expires_ms: *expires_ms,
                        },
                    );
                }
            }
            Fact::Ack(items) => {
                for (d, s) in items {
                    self.ack(d, *s);
                }
            }
            Fact::Owner(epoch) => self.owner_epoch = self.owner_epoch.max(*epoch),
            Fact::Snapshot {
                owner,
                devices,
                groups,
            } => {
                self.owner_epoch = self.owner_epoch.max(*owner);
                for (d, last, acked) in devices {
                    let st = self.devices.entry(*d).or_default();
                    st.last = st.last.max(*last);
                    self.ack(d, *acked);
                }
                for (g, e) in groups {
                    let cur = self.epochs.entry(*g).or_default();
                    *cur = (*cur).max(*e);
                }
            }
            Fact::Forget(devices) => {
                for d in devices {
                    self.forget(d);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn state() -> (State, u64) {
        let mut ring = KeyRing::default();
        let w = ring.open_window(0).unwrap();
        ring.reserve(w, 100).unwrap();
        (State::with_ring(ring), w)
    }

    fn store(entries: &[(u8, u64, u32)], at: u64, tag: Option<[u8; 32]>) -> Fact {
        Fact::Store {
            at_ms: at,
            expires_ms: None,
            tag: tag.map(|t| (t, [0; 16])),
            mls: None,
            entries: entries.iter().map(|(b, s, l)| (d(*b), *s, *l)).collect(),
            body_leaf: None,
        }
    }

    #[test]
    fn ack_removes_entries_and_punctures_their_leaves() {
        let (mut st, w) = state();
        st.apply(0, w, &Fact::Owner(3), 1000, 10);
        st.apply(
            1,
            w,
            &store(&[(1, 1, 0), (2, 1, 1)], 5, Some([7; 32])),
            1000,
            10,
        );
        st.apply(2, w, &store(&[(1, 2, 2)], 6, None), 1000, 10);
        st.apply(3, w, &Fact::Ack(vec![(d(1), 1)]), 1000, 10);
        assert_eq!(st.owner_epoch, 3);
        assert_eq!(st.next_offset, 4);
        let one = &st.devices[&d(1)];
        assert_eq!((one.last, one.acked, one.pending.len()), (2, 1, 1));
        assert_eq!(st.idem[&[7; 32]].offset, 1);
        assert!(
            st.ring.leaf(w, 0).unwrap().is_none(),
            "acknowledged: punctured"
        );
        assert!(st.ring.leaf(w, 1).unwrap().is_some(), "pending: readable");
        assert_eq!(st.min_live(), Some(1));
        st.ack(&d(2), 1);
        assert_eq!(st.min_live(), Some(2));
        assert!(st.ring.leaf(w, 1).unwrap().is_none());
    }

    #[test]
    fn forget_punctures_everything_and_drops_the_counters() {
        let (mut st, w) = state();
        st.apply(1, w, &store(&[(1, 1, 0), (2, 1, 1)], 5, None), 1000, 10);
        st.apply(2, w, &store(&[(1, 2, 2), (1, 3, 3)], 6, None), 1000, 10);
        st.apply(3, w, &Fact::Forget(vec![d(1), d(9)]), 1000, 10);
        assert!(!st.devices.contains_key(&d(1)), "counters dropped");
        assert!(
            !st.devices.contains_key(&d(9)),
            "unknown devices are not created"
        );
        for leaf in [0, 2, 3] {
            assert!(st.ring.leaf(w, leaf).unwrap().is_none(), "punctured");
        }
        assert!(
            st.ring.leaf(w, 1).unwrap().is_some(),
            "other devices untouched"
        );
        assert_eq!(st.devices[&d(2)].pending.len(), 1);
        // Record 2 held only the forgotten device: nothing in it is still needed.
        assert_eq!(st.min_live(), Some(1));
        st.ack(&d(2), 1);
        assert_eq!(st.min_live(), None);
    }

    #[test]
    fn shared_body_goes_with_the_last_entry() {
        let (mut st, w) = state();
        st.apply(
            1,
            w,
            &Fact::Store {
                at_ms: 1,
                expires_ms: None,
                tag: None,
                mls: None,
                entries: vec![(d(1), 1, 0), (d(2), 1, 1)],
                body_leaf: Some(2),
            },
            0,
            0,
        );
        st.ack(&d(1), 1);
        assert!(
            st.ring.leaf(w, 2).unwrap().is_some(),
            "device 2 still needs it"
        );
        st.ack(&d(2), 1);
        assert!(st.ring.leaf(w, 2).unwrap().is_none());
    }

    #[test]
    fn relocation_replaces_and_punctures_the_old_location() {
        let (mut st, w) = state();
        st.apply(1, w, &store(&[(1, 1, 0), (1, 2, 1)], 5, None), 1000, 10);
        st.apply(
            9,
            w,
            &Fact::Relocate {
                entries: vec![(d(1), 1, 5, NEVER, 7)],
            },
            1000,
            10,
        );
        let p = &st.devices[&d(1)].pending;
        assert_eq!((p[0].seq, p[0].offset, p[0].leaf), (1, 9, 7));
        assert!(st.ring.leaf(w, 0).unwrap().is_none(), "old copy punctured");
        assert_eq!(st.min_live(), Some(1));
    }

    #[test]
    fn counters_never_go_back() {
        let (mut st, w) = state();
        st.apply(
            5,
            w,
            &Fact::Snapshot {
                owner: 2,
                devices: vec![(d(4), 10, 10)],
                groups: vec![([1; 16], 3)],
            },
            0,
            0,
        );
        assert_eq!(st.epochs[&[1; 16]], 3);
        assert_eq!(st.owner_epoch, 2);
        // An older entry replayed after it cannot lower the counter or come back; its leaf is
        // punctured on the way.
        st.apply(6, w, &store(&[(4, 9, 3)], 1, None), 0, 0);
        assert_eq!(st.devices[&d(4)].last, 10);
        assert!(st.devices[&d(4)].pending.is_empty());
        assert!(st.ring.leaf(w, 3).unwrap().is_none());
        // An acknowledgement alone raises the counter (its entry may be unreadable).
        st.ack(&d(5), 4);
        assert_eq!(st.devices[&d(5)].last, 4);
    }

    #[test]
    fn expiry_is_a_prefix_and_windows_are_destroyed_below_low_water() {
        let (mut st, w) = state();
        st.apply(1, w, &store(&[(1, 1, 0)], 100, None), 0, 0);
        st.apply(2, w, &store(&[(1, 2, 1)], 200, None), 0, 0);
        assert_eq!(st.offset_at(150), 2);
        assert_eq!(st.expired(150), vec![(d(1), 1)]);
        assert_eq!(
            st.destroy_windows_below(3, Some(w)),
            0,
            "the current window stays"
        );
        assert_eq!(
            st.destroy_windows_below(2, None),
            0,
            "it still has a record at 2"
        );
        assert_eq!(st.destroy_windows_below(3, None), 1);
        assert!(st.ring.meta(w).is_none());
    }

    #[test]
    fn entries_past_their_deadline_are_dropped_wherever_they_are() {
        let (mut st, w) = state();
        st.apply(1, w, &store(&[(1, 1, 0)], 5, None), 1000, 10);
        // A disappearing send in the middle of the device's queue, to two devices (shared body).
        st.apply(
            2,
            w,
            &Fact::Store {
                at_ms: 6,
                expires_ms: Some(100),
                tag: None,
                mls: None,
                entries: vec![(d(1), 2, 1), (d(2), 1, 2)],
                body_leaf: Some(3),
            },
            1000,
            10,
        );
        st.apply(3, w, &store(&[(1, 3, 4)], 7, None), 1000, 10);
        assert_eq!(st.drop_expired(99), 0);
        assert_eq!(st.drop_expired(100), 2);
        let seqs: Vec<u64> = st.devices[&d(1)].pending.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 3], "seq 2 skipped, the others kept");
        assert_eq!(st.devices[&d(1)].acked, 0, "not an acknowledgement");
        assert!(st.devices[&d(2)].pending.is_empty());
        for leaf in [1, 2, 3] {
            assert!(
                st.ring.leaf(w, leaf).unwrap().is_none(),
                "leaf {leaf} punctured"
            );
        }
        assert!(st.ring.leaf(w, 0).unwrap().is_some());
        // Its record holds nothing any more.
        st.ack(&d(1), 3);
        assert_eq!(st.min_live(), None);
    }

    #[test]
    fn idempotency_entries_prune_by_age() {
        let (mut st, _) = state();
        let e = |at| Idem {
            fp: [1; 16],
            at_ms: at,
            offset: 0,
        };
        st.add_idem([1; 32], e(10));
        st.add_idem([2; 32], e(20));
        st.add_idem([1; 32], e(99));
        assert_eq!(st.idem[&[1; 32]].at_ms, 10, "the first one wins");
        st.prune_idem(15);
        assert_eq!(st.idem.len(), 1);
    }
}
