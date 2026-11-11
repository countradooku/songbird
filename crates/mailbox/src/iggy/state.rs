//! In-memory state of one partition, rebuilt from the log on start (no I/O here).

use std::collections::{BTreeMap, HashMap, VecDeque};

use songbird_types::DeviceId;

use super::record::{Local, Record};

/// A pending (un-acknowledged) entry: where its ciphertext is in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) seq: u64,
    /// Iggy offset of the record holding it.
    pub(crate) offset: u64,
    /// Its index in that record.
    pub(crate) slot: u32,
    /// When the send was accepted (ms).
    pub(crate) at_ms: u64,
}

/// One device's counters and pending entries (ascending `seq`).
#[derive(Debug, Default)]
pub(crate) struct DeviceState {
    pub(crate) last: u64,
    pub(crate) acked: u64,
    pub(crate) pending: VecDeque<Entry>,
}

/// One partition.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) devices: HashMap<DeviceId, DeviceState>,
    /// MLS group -> current epoch.
    pub(crate) epochs: HashMap<[u8; 16], u64>,
    /// Tag prefix -> offsets of store records carrying a tag with that prefix (verified against
    /// the record on a hit).
    pub(crate) tags: HashMap<u64, TagSlot>,
    /// Offset -> number of pending entries in the record at that offset.
    pub(crate) live: BTreeMap<u64, u32>,
    /// (first offset, `at_ms`) of each appended batch, ascending; maps a time to an offset.
    pub(crate) times: VecDeque<(u64, u64)>,
    /// Highest producer epoch recorded.
    pub(crate) owner_epoch: u16,
    /// Next offset of the partition.
    pub(crate) next_offset: u64,
}

/// Offsets for one tag prefix (almost always one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TagSlot {
    One(u64),
    Many(Vec<u64>),
}

pub(crate) fn tag_prefix(tag: &[u8; 32]) -> u64 {
    let mut p = [0u8; 8];
    p.copy_from_slice(tag.get(..8).unwrap_or(&[0; 8]));
    u64::from_le_bytes(p)
}

impl State {
    /// Offsets whose record may carry `tag`.
    pub(crate) fn tag_candidates(&self, tag: &[u8; 32]) -> Vec<u64> {
        match self.tags.get(&tag_prefix(tag)) {
            None => Vec::new(),
            Some(TagSlot::One(o)) => vec![*o],
            Some(TagSlot::Many(v)) => v.clone(),
        }
    }

    pub(crate) fn add_tag(&mut self, tag: &[u8; 32], offset: u64) {
        let p = tag_prefix(tag);
        match self.tags.get_mut(&p) {
            None => {
                self.tags.insert(p, TagSlot::One(offset));
            }
            Some(slot) => {
                let mut v = match slot {
                    TagSlot::One(o) => vec![*o],
                    TagSlot::Many(v) => std::mem::take(v),
                };
                if !v.contains(&offset) {
                    v.push(offset);
                }
                *slot = TagSlot::Many(v);
            }
        }
    }

    /// Drops tags recorded before `offset` (older than the idempotency window).
    pub(crate) fn prune_tags(&mut self, offset: u64) {
        self.tags.retain(|_, slot| match slot {
            TagSlot::One(o) => *o >= offset,
            TagSlot::Many(v) => {
                v.retain(|o| *o >= offset);
                !v.is_empty()
            }
        });
    }

    fn live_add(&mut self, offset: u64) {
        *self.live.entry(offset).or_default() += 1;
    }

    fn live_remove(&mut self, offset: u64) {
        if let Some(n) = self.live.get_mut(&offset) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.live.remove(&offset);
            }
        }
    }

    /// Lowest offset still holding a pending entry.
    pub(crate) fn min_live(&self) -> Option<u64> {
        self.live.keys().next().copied()
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

    /// Records a new pending entry (keeps `seq` order; a relocated copy replaces the old one).
    pub(crate) fn insert(&mut self, device: DeviceId, e: Entry) {
        let st = self.devices.entry(device).or_default();
        st.last = st.last.max(e.seq);
        if e.seq <= st.acked {
            return;
        }
        let pos = st.pending.partition_point(|x| x.seq < e.seq);
        let old = match st.pending.get_mut(pos) {
            Some(x) if x.seq == e.seq => {
                let old = x.offset;
                *x = e;
                Some(old)
            }
            _ => {
                st.pending.insert(pos, e);
                None
            }
        };
        if let Some(o) = old {
            self.live_remove(o);
        }
        self.live_add(e.offset);
    }

    /// Acknowledges `device` up to `seq`.
    pub(crate) fn ack(&mut self, device: &DeviceId, seq: u64) {
        let Some(st) = self.devices.get_mut(device) else {
            let st = DeviceState {
                last: seq,
                acked: seq,
                ..DeviceState::default()
            };
            self.devices.insert(*device, st);
            return;
        };
        if seq <= st.acked {
            return;
        }
        st.acked = seq;
        let mut gone = Vec::new();
        while st.pending.front().is_some_and(|e| e.seq <= seq) {
            if let Some(e) = st.pending.pop_front() {
                gone.push(e.offset);
            }
        }
        for o in gone {
            self.live_remove(o);
        }
    }

    /// Removes entries accepted before `cutoff_ms`; returns how many.
    pub(crate) fn expire(&mut self, cutoff_ms: u64) -> u64 {
        let mut gone = Vec::new();
        for st in self.devices.values_mut() {
            st.pending.retain(|e| {
                let keep = e.at_ms >= cutoff_ms;
                if !keep {
                    gone.push(e.offset);
                }
                keep
            });
        }
        let n = u64::try_from(gone.len()).unwrap_or(u64::MAX);
        for o in gone {
            self.live_remove(o);
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
        out.sort_by_key(|(_, e)| (e.offset, e.slot));
        out
    }

    /// Applies one record read back from the log at `offset` (start-up replay).
    pub(crate) fn apply(&mut self, offset: u64, rec: &Record, tag_window_ms: u64, now_ms: u64) {
        self.next_offset = self.next_offset.max(offset + 1);
        match rec {
            Record::Store {
                tag,
                at_ms,
                mls,
                local,
                ..
            } => {
                self.note_batch(offset, *at_ms);
                if let (Some((t, _)), true) = (tag, at_ms.saturating_add(tag_window_ms) >= now_ms) {
                    self.add_tag(t, offset);
                }
                if let Some((g, e)) = mls {
                    let cur = self.epochs.entry(*g).or_default();
                    *cur = (*cur).max(*e);
                }
                for slot in 0..local.len() {
                    if let Some((d, seq)) = local.entry(slot) {
                        let slot = u32::try_from(slot).unwrap_or(u32::MAX);
                        self.insert(
                            d,
                            Entry {
                                seq,
                                offset,
                                slot,
                                at_ms: *at_ms,
                            },
                        );
                    }
                }
            }
            Record::Ack(items) => {
                for (d, s) in items {
                    self.ack(d, *s);
                }
            }
            Record::Relocate(items) => {
                for (slot, (d, seq, at_ms, _)) in items.iter().enumerate() {
                    let slot = u32::try_from(slot).unwrap_or(u32::MAX);
                    self.insert(
                        *d,
                        Entry {
                            seq: *seq,
                            offset,
                            slot,
                            at_ms: *at_ms,
                        },
                    );
                }
            }
            Record::Owner { epoch } => self.owner_epoch = self.owner_epoch.max(*epoch),
            Record::Snapshot {
                owner,
                devices,
                groups,
            } => {
                self.owner_epoch = self.owner_epoch.max(*owner);
                for (d, last, acked) in devices {
                    let st = self.devices.entry(*d).or_default();
                    st.last = st.last.max(*last);
                    if *acked > st.acked {
                        let acked = *acked;
                        self.ack(d, acked);
                    }
                }
                for (g, e) in groups {
                    let cur = self.epochs.entry(*g).or_default();
                    *cur = (*cur).max(*e);
                }
            }
        }
    }
}

/// The (device, seq) pairs of a store record's local entries, in slot order.
pub(crate) fn local_seqs(local: &Local) -> Vec<(DeviceId, u64)> {
    (0..local.len()).filter_map(|i| local.entry(i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn store(entries: &[(u8, u64)], at: u64, tag: Option<[u8; 32]>) -> Record {
        Record::Store {
            tag: tag.map(|t| (t, [0; 16])),
            at_ms: at,
            mls: None,
            local: Local::PerDevice(
                entries
                    .iter()
                    .map(|(b, s)| (d(*b), *s, Bytes::from_static(b"e")))
                    .collect(),
            ),
            remote: vec![],
        }
    }

    #[test]
    fn replay_rebuilds_counters_pending_and_tags() {
        let mut st = State::default();
        st.apply(0, &Record::Owner { epoch: 3 }, 1000, 10);
        st.apply(1, &store(&[(1, 1), (2, 1)], 5, Some([7; 32])), 1000, 10);
        st.apply(2, &store(&[(1, 2)], 6, None), 1000, 10);
        st.apply(3, &Record::Ack(vec![(d(1), 1)]), 1000, 10);
        assert_eq!(st.owner_epoch, 3);
        assert_eq!(st.next_offset, 4);
        let one = &st.devices[&d(1)];
        assert_eq!((one.last, one.acked, one.pending.len()), (2, 1, 1));
        assert_eq!(st.tag_candidates(&[7; 32]), vec![1]);
        assert_eq!(st.min_live(), Some(1));
        st.ack(&d(2), 1);
        assert_eq!(st.min_live(), Some(2));
    }

    #[test]
    fn relocation_replaces_the_old_location() {
        let mut st = State::default();
        st.apply(1, &store(&[(1, 1), (1, 2)], 5, None), 1000, 10);
        st.apply(
            9,
            &Record::Relocate(vec![(d(1), 1, 5, Bytes::from_static(b"e"))]),
            1000,
            10,
        );
        let p = &st.devices[&d(1)].pending;
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].seq, p[0].offset, p[0].slot), (1, 9, 0));
        assert_eq!(st.live.get(&1), Some(&1));
        assert_eq!(st.live.get(&9), Some(&1));
    }

    #[test]
    fn snapshot_keeps_counters_for_idle_devices() {
        let mut st = State::default();
        st.apply(
            5,
            &Record::Snapshot {
                owner: 2,
                devices: vec![(d(4), 10, 10)],
                groups: vec![([1; 16], 3)],
            },
            0,
            0,
        );
        let s = &st.devices[&d(4)];
        assert_eq!((s.last, s.acked), (10, 10));
        assert_eq!(st.epochs[&[1; 16]], 3);
        assert_eq!(st.owner_epoch, 2);
        // An older store record replayed after it cannot lower the counter or revive entries.
        st.apply(6, &store(&[(4, 9)], 1, None), 0, 0);
        assert_eq!(st.devices[&d(4)].last, 10);
        assert!(st.devices[&d(4)].pending.is_empty());
    }

    #[test]
    fn tags_collide_safely_and_prune() {
        let mut st = State::default();
        let mut a = [1u8; 32];
        let mut b = [1u8; 32];
        a[31] = 1;
        b[31] = 2;
        st.add_tag(&a, 4);
        st.add_tag(&b, 7);
        assert_eq!(st.tag_candidates(&a), vec![4, 7]);
        st.prune_tags(5);
        assert_eq!(st.tag_candidates(&b), vec![7]);
        st.prune_tags(8);
        assert!(st.tags.is_empty());
    }

    #[test]
    fn expiry_and_times() {
        let mut st = State::default();
        st.apply(1, &store(&[(1, 1)], 100, None), 0, 0);
        st.apply(2, &store(&[(1, 2)], 200, None), 0, 0);
        assert_eq!(st.offset_at(150), 2);
        assert_eq!(st.offset_at(999), 3);
        assert_eq!(st.entries_before(2).len(), 1);
        assert_eq!(st.expire(150), 1);
        assert_eq!(st.devices[&d(1)].pending.len(), 1);
        st.prune_times(2);
        assert_eq!(st.times.len(), 1);
    }
}
