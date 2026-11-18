//! One device's replica of the account's records, and how it syncs (PROTOCOL §10.1).
//!
//! The replica holds what it last verified from the server (each logical key's record and its
//! ID, at a store version) and the local edits not yet written. A sync is:
//!
//! 1. read the head; if its version is the one the replica holds, only check the manifest;
//! 2. otherwise read every ID, read the records it does not know, and verify: the manifest
//!    opens under the storage key, names this version, and its digest matches the IDs; the
//!    version is never below one already seen; every record opens under its ID;
//! 3. merge: per logical key the record with the greatest stamp wins, local edits included;
//! 4. write the local edits that still win, with a new manifest, as one compare-and-swap. If
//!    another device wrote first (409), go back to 1.
//!
//! Deleting a key writes a tombstone. Tombstones are collected by the next write after
//! [`HORIZON_MS`]; a device away longer drops its own edits older than the horizon before it
//! merges, so an old edit cannot bring back a key deleted long ago.

use std::collections::{BTreeMap, BTreeSet};

use songbird_proto::storage::{Head, ID_LEN, Ids, Record, Write};

use crate::hlc::{Clock, Hlc};
use crate::record::{
    Manifest, RecordPlain, StorageKey, ids_digest, open_manifest, open_record, seal_manifest,
    seal_record,
};
use crate::{HORIZON_MS, SyncError};

type Id = [u8; ID_LEN];

/// A verified record the replica holds.
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    id: Id,
    plain: RecordPlain,
}

/// A write prepared from the replica, to commit once the server accepts it.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// What to send.
    pub write: Write,
    new_entries: Vec<(String, Entry)>,
    removed: Vec<Id>,
    key: Option<StorageKey>,
}

/// One device's replica.
#[derive(Debug, Clone)]
pub struct Replica {
    key: StorageKey,
    clock: Clock,
    committed: BTreeMap<String, Entry>,
    ids: BTreeSet<Id>,
    /// IDs on the server to delete at the next write: duplicates of a key, expired tombstones.
    garbage: BTreeSet<Id>,
    version: u64,
    highest_seen: u64,
    pending: BTreeMap<String, RecordPlain>,
}

impl Replica {
    /// An empty replica for a device (`node` is its random clock node ID).
    #[must_use]
    pub fn new(key: StorageKey, node: [u8; 16]) -> Self {
        Self {
            key,
            clock: Clock::new(node),
            committed: BTreeMap::new(),
            ids: BTreeSet::new(),
            garbage: BTreeSet::new(),
            version: 0,
            highest_seen: 0,
            pending: BTreeMap::new(),
        }
    }

    /// The store version the replica last verified.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The storage key.
    #[must_use]
    pub fn key(&self) -> &StorageKey {
        &self.key
    }

    /// Replaces the storage key (another device rotated it and sent the new one). The next sync
    /// reads the store again from scratch.
    pub fn set_key(&mut self, key: StorageKey) {
        self.key = key;
        self.committed.clear();
        self.ids.clear();
        self.garbage.clear();
        self.version = 0;
    }

    /// Whether local edits are waiting to be written.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty() || !self.garbage.is_empty()
    }

    fn current(&self, key: &str) -> Option<&RecordPlain> {
        self.pending
            .get(key)
            .or_else(|| self.committed.get(key).map(|e| &e.plain))
    }

    /// A key's value (local edits first); `None` if absent or deleted.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.current(key)
            .filter(|p| !p.deleted)
            .map(|p| p.value.as_slice())
    }

    /// Every live key and value, in key order.
    #[must_use]
    pub fn entries(&self) -> Vec<(String, Vec<u8>)> {
        let keys: BTreeSet<&String> = self.committed.keys().chain(self.pending.keys()).collect();
        keys.into_iter()
            .filter_map(|k| self.get(k).map(|v| (k.clone(), v.to_vec())))
            .collect()
    }

    /// Every live key under a prefix, in key order.
    #[must_use]
    pub fn with_prefix(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        self.entries()
            .into_iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .collect()
    }

    /// Sets a key (a local edit, written at the next sync).
    ///
    /// # Errors
    /// [`SyncError::Malformed`] for a key or value too long.
    pub fn set(&mut self, key: &str, value: Vec<u8>, phys_ms: u64) -> Result<Hlc, SyncError> {
        self.edit(key, Some(value), phys_ms)
    }

    /// Deletes a key (a tombstone, written at the next sync).
    ///
    /// # Errors
    /// [`SyncError::Malformed`] for a key too long.
    pub fn delete(&mut self, key: &str, phys_ms: u64) -> Result<Hlc, SyncError> {
        self.edit(key, None, phys_ms)
    }

    fn edit(&mut self, key: &str, value: Option<Vec<u8>>, phys_ms: u64) -> Result<Hlc, SyncError> {
        if key.is_empty() || key.len() > crate::record::MAX_KEY {
            return Err(SyncError::Malformed);
        }
        if value
            .as_ref()
            .is_some_and(|v| v.len() > crate::record::MAX_VALUE)
        {
            return Err(SyncError::Malformed);
        }
        let current = self.current(key).map(RecordPlain::hlc);
        let hlc = self.clock.stamp_after(current, phys_ms);
        self.pending
            .insert(key.to_owned(), RecordPlain::new(key, hlc, value));
        Ok(hlc)
    }

    /// Checks a head against what the replica holds: `Ok(true)` if the store moved on and must
    /// be read.
    ///
    /// # Errors
    /// [`SyncError::Rollback`] for a version below one already seen; [`SyncError::Tampered`] or
    /// [`SyncError::KeyChanged`] for a manifest that does not open or does not match.
    pub fn check_head(&self, head: &Head) -> Result<bool, SyncError> {
        if head.version < self.highest_seen {
            return Err(SyncError::Rollback);
        }
        if head.version != self.version {
            return Ok(true);
        }
        if head.version == 0 {
            return if head.manifest.is_empty() {
                Ok(false)
            } else {
                Err(SyncError::Tampered)
            };
        }
        let m = open_manifest(&self.key, &head.manifest)?;
        let ids: Vec<Id> = self.ids.iter().copied().collect();
        if m.version != head.version || m.digest != ids_digest(&ids) {
            return Err(SyncError::Tampered);
        }
        Ok(false)
    }

    /// The IDs in `ids` the replica must read.
    #[must_use]
    pub fn missing(&self, ids: &Ids) -> Vec<Id> {
        ids.ids
            .iter()
            .filter(|i| !self.ids.contains(*i))
            .copied()
            .collect()
    }

    /// Verifies what was read and merges it. `records` must hold every ID [`Replica::missing`]
    /// named (more is fine). Returns the keys whose visible value changed.
    ///
    /// # Errors
    /// [`SyncError::Rollback`], [`SyncError::Tampered`], [`SyncError::KeyChanged`] as for
    /// [`Replica::check_head`]; [`SyncError::Stale`] when the store moved on between the reads
    /// (read again).
    pub fn apply(
        &mut self,
        head: &Head,
        ids: &Ids,
        records: &[Record],
        phys_ms: u64,
    ) -> Result<Vec<String>, SyncError> {
        if head.version < self.highest_seen || ids.version < self.highest_seen {
            return Err(SyncError::Rollback);
        }
        if ids.version != head.version {
            return Err(SyncError::Stale);
        }
        let set: BTreeSet<Id> = ids.ids.iter().copied().collect();
        if set.len() != ids.ids.len() {
            return Err(SyncError::Tampered);
        }
        if head.version == 0 {
            if !head.manifest.is_empty() || !set.is_empty() {
                return Err(SyncError::Tampered);
            }
        } else {
            let m = open_manifest(&self.key, &head.manifest)?;
            if m.version != head.version || m.digest != ids_digest(&ids.ids) {
                return Err(SyncError::Tampered);
            }
        }
        // Every record of the new set, verified: known ones from the replica, new ones opened.
        let known: BTreeMap<Id, &Entry> = self.committed.values().map(|e| (e.id, e)).collect();
        let fetched: BTreeMap<Id, &Record> = records.iter().map(|r| (r.id, r)).collect();
        let mut by_key: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
        for id in &set {
            let entry = if let Some(e) = known.get(id) {
                (*e).clone()
            } else if let Some(r) = fetched.get(id) {
                Entry {
                    id: *id,
                    plain: open_record(&self.key, id, &r.blob)?,
                }
            } else if self.garbage.contains(id) {
                continue;
            } else {
                return Err(SyncError::Stale);
            };
            by_key
                .entry(entry.plain.key.clone())
                .or_default()
                .push(entry);
        }
        let before: BTreeMap<String, Option<Vec<u8>>> = self
            .entries()
            .into_iter()
            .map(|(k, v)| (k, Some(v)))
            .collect();
        let mut committed = BTreeMap::new();
        let mut garbage = BTreeSet::new();
        for (key, mut entries) in by_key {
            entries.sort_by_key(|e| e.plain.hlc());
            let Some(winner) = entries.pop() else {
                continue;
            };
            // A key written twice (a client that did not delete its old record): the loser goes.
            garbage.extend(entries.into_iter().map(|e| e.id));
            self.clock.observe(winner.plain.hlc(), phys_ms);
            if winner.plain.deleted && winner.plain.wall_ms.saturating_add(HORIZON_MS) < phys_ms {
                garbage.insert(winner.id);
                continue;
            }
            committed.insert(key, winner);
        }
        // Local edits: dropped if older than the horizon, or if the store holds a newer stamp.
        self.pending.retain(|k, p| {
            p.wall_ms.saturating_add(HORIZON_MS) >= phys_ms
                && committed.get(k).is_none_or(|e| p.hlc() > e.plain.hlc())
        });
        self.committed = committed;
        self.ids = set;
        self.garbage = garbage;
        self.version = head.version;
        self.highest_seen = self.highest_seen.max(head.version);
        let after: BTreeMap<String, Vec<u8>> = self.entries().into_iter().collect();
        let mut changed: Vec<String> = after
            .iter()
            .filter(|(k, v)| before.get(*k).and_then(|x| x.as_ref()) != Some(*v))
            .map(|(k, _)| k.clone())
            .collect();
        changed.extend(before.keys().filter(|k| !after.contains_key(*k)).cloned());
        changed.sort();
        changed.dedup();
        Ok(changed)
    }

    /// Collects what the horizon expired: the replica's own tombstones older than
    /// [`HORIZON_MS`] go to the next write's deletions, and local edits older than it are
    /// dropped (a device back after so long merges nothing stale).
    pub fn expire(&mut self, phys_ms: u64) {
        let old = |wall: u64| wall.saturating_add(HORIZON_MS) < phys_ms;
        let expired: Vec<String> = self
            .committed
            .iter()
            .filter(|(_, e)| e.plain.deleted && old(e.plain.wall_ms))
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            if let Some(e) = self.committed.remove(&k) {
                self.garbage.insert(e.id);
            }
        }
        self.pending.retain(|_, p| !old(p.wall_ms));
    }

    /// Prepares the write of every local edit, or `None` if there is nothing to write.
    ///
    /// # Errors
    /// [`SyncError::Random`], [`SyncError::Crypto`], [`SyncError::Malformed`].
    pub fn prepare(&self) -> Result<Option<Prepared>, SyncError> {
        if !self.has_pending() {
            return Ok(None);
        }
        let mut removed: Vec<Id> = self.garbage.iter().copied().collect();
        let mut inserts = Vec::with_capacity(self.pending.len());
        let mut new_entries = Vec::with_capacity(self.pending.len());
        for (key, plain) in &self.pending {
            if let Some(e) = self.committed.get(key) {
                removed.push(e.id);
            }
            let (id, blob) = seal_record(&self.key, plain)?;
            inserts.push(Record { id, blob });
            new_entries.push((
                key.clone(),
                Entry {
                    id,
                    plain: plain.clone(),
                },
            ));
        }
        removed.sort_unstable();
        removed.dedup();
        let gone: BTreeSet<Id> = removed.iter().copied().collect();
        let ids: Vec<Id> = self
            .ids
            .iter()
            .filter(|i| !gone.contains(*i))
            .copied()
            .chain(inserts.iter().map(|r| r.id))
            .collect();
        let next = self.version.checked_add(1).ok_or(SyncError::Malformed)?;
        let manifest = seal_manifest(
            &self.key,
            &Manifest {
                version: next,
                digest: ids_digest(&ids),
            },
        )?;
        Ok(Some(Prepared {
            write: Write {
                expected: self.version,
                manifest,
                deletes: removed.clone(),
                inserts,
            },
            new_entries,
            removed,
            key: None,
        }))
    }

    /// Prepares a key rotation: every record rewritten under `new_key` with fresh IDs, every old
    /// ID deleted, in one write. Local edits are included.
    ///
    /// # Errors
    /// As [`Replica::prepare`].
    pub fn prepare_rotation(&self, new_key: StorageKey) -> Result<Prepared, SyncError> {
        let mut all: BTreeMap<String, RecordPlain> = self
            .committed
            .iter()
            .map(|(k, e)| (k.clone(), e.plain.clone()))
            .collect();
        all.extend(self.pending.iter().map(|(k, p)| (k.clone(), p.clone())));
        let mut inserts = Vec::with_capacity(all.len());
        let mut new_entries = Vec::with_capacity(all.len());
        for (key, plain) in all {
            let (id, blob) = seal_record(&new_key, &plain)?;
            inserts.push(Record { id, blob });
            new_entries.push((key, Entry { id, plain }));
        }
        let removed: Vec<Id> = self
            .ids
            .iter()
            .chain(self.garbage.iter())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let ids: Vec<Id> = inserts.iter().map(|r| r.id).collect();
        let next = self.version.checked_add(1).ok_or(SyncError::Malformed)?;
        let manifest = seal_manifest(
            &new_key,
            &Manifest {
                version: next,
                digest: ids_digest(&ids),
            },
        )?;
        Ok(Prepared {
            write: Write {
                expected: self.version,
                manifest,
                deletes: removed.clone(),
                inserts,
            },
            new_entries,
            removed,
            key: Some(new_key),
        })
    }

    /// The server accepted a prepared write at `version`.
    pub fn committed(&mut self, prepared: Prepared, version: u64) {
        if let Some(k) = prepared.key {
            self.key = k;
            self.committed.clear();
            self.ids.clear();
        }
        for id in &prepared.removed {
            self.ids.remove(id);
            self.garbage.remove(id);
        }
        self.committed
            .retain(|_, e| !prepared.removed.contains(&e.id));
        for (key, entry) in prepared.new_entries {
            // An edit made while the write was in flight stays pending.
            if self
                .pending
                .get(&key)
                .is_some_and(|p| p.hlc() == entry.plain.hlc())
            {
                self.pending.remove(&key);
            }
            self.ids.insert(entry.id);
            self.committed.insert(key, entry);
        }
        self.version = version;
        self.highest_seen = self.highest_seen.max(version);
    }
}

/// A replica's saved form (protobuf; the app keeps it in its encrypted local store).
#[derive(Clone, PartialEq, ::prost::Message)]
struct SavedEntry {
    #[prost(bytes = "vec", tag = "1")]
    id: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    plain: Option<RecordPlain>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct Saved {
    #[prost(bytes = "vec", tag = "1")]
    key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    node: Vec<u8>,
    #[prost(uint64, tag = "3")]
    clock_wall: u64,
    #[prost(uint32, tag = "4")]
    clock_counter: u32,
    #[prost(uint64, tag = "5")]
    version: u64,
    #[prost(uint64, tag = "6")]
    highest_seen: u64,
    #[prost(message, repeated, tag = "7")]
    committed: Vec<SavedEntry>,
    #[prost(bytes = "vec", repeated, tag = "8")]
    ids: Vec<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "9")]
    garbage: Vec<Vec<u8>>,
    #[prost(message, repeated, tag = "10")]
    pending: Vec<RecordPlain>,
}

impl Replica {
    /// The replica's state, to keep on the device (it includes the storage key: keep it in the
    /// app's protected storage).
    #[must_use]
    pub fn save(&self) -> Vec<u8> {
        use prost::Message as _;
        let last = self.clock.last();
        Saved {
            key: self.key.as_bytes().to_vec(),
            node: self.clock.node().to_vec(),
            clock_wall: last.wall_ms,
            clock_counter: last.counter,
            version: self.version,
            highest_seen: self.highest_seen,
            committed: self
                .committed
                .values()
                .map(|e| SavedEntry {
                    id: e.id.to_vec(),
                    plain: Some(e.plain.clone()),
                })
                .collect(),
            ids: self.ids.iter().map(|i| i.to_vec()).collect(),
            garbage: self.garbage.iter().map(|i| i.to_vec()).collect(),
            pending: self.pending.values().cloned().collect(),
        }
        .encode_to_vec()
    }

    /// A replica from [`Replica::save`]'s bytes.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn load(bytes: &[u8]) -> Result<Self, SyncError> {
        use prost::Message as _;
        let s = Saved::decode(bytes).map_err(|_| SyncError::Malformed)?;
        let id16 = |b: &[u8]| <Id>::try_from(b).map_err(|_| SyncError::Malformed);
        let key: [u8; 32] = s
            .key
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::Malformed)?;
        let node = id16(&s.node)?;
        let mut clock = Clock::new(node);
        clock.observe(
            Hlc {
                wall_ms: s.clock_wall,
                counter: s.clock_counter,
                node,
            },
            u64::MAX,
        );
        let mut committed = BTreeMap::new();
        for e in s.committed {
            let plain = e.plain.ok_or(SyncError::Malformed)?;
            committed.insert(
                plain.key.clone(),
                Entry {
                    id: id16(&e.id)?,
                    plain,
                },
            );
        }
        Ok(Self {
            key: StorageKey::from_bytes(key),
            clock,
            committed,
            ids: s.ids.iter().map(|i| id16(i)).collect::<Result<_, _>>()?,
            garbage: s
                .garbage
                .iter()
                .map(|i| id16(i))
                .collect::<Result<_, _>>()?,
            version: s.version,
            highest_seen: s.highest_seen,
            pending: s.pending.into_iter().map(|p| (p.key.clone(), p)).collect(),
        })
    }
}
