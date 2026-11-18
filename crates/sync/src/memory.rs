//! The reference record store: the server's rules (compare-and-swap, caps, lengths) in memory.
//!
//! The property tests run devices against it, and its fault switches play a malicious server
//! (withholding, replaying, rolling back, swapping records). The app uses it while it has no
//! account on a real server.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use songbird_proto::storage::{Head, ID_LEN, Ids, Record, Write, valid_record_len};

use crate::{Remote, SyncError, WriteOutcome};

/// What the store holds at one version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The version.
    pub version: u64,
    /// The manifest.
    pub manifest: Vec<u8>,
    /// The records by ID.
    pub records: BTreeMap<[u8; ID_LEN], Vec<u8>>,
}

/// Faults a malicious server injects.
#[derive(Debug, Clone, Default)]
pub struct Faults {
    /// Leave this ID out of ID lists and reads.
    pub withhold: Option<[u8; ID_LEN]>,
    /// Serve this older snapshot instead of the current one.
    pub serve: Option<Snapshot>,
    /// List this ID but never serve its record.
    pub unreadable: Option<[u8; ID_LEN]>,
}

/// The in-memory store.
#[derive(Debug, Default)]
pub struct MemoryServer {
    state: RefCell<Snapshot>,
    history: RefCell<Vec<Snapshot>>,
    /// Faults to inject.
    pub faults: RefCell<Faults>,
    /// Most records.
    pub max_records: usize,
    /// Writes applied.
    pub writes: RefCell<u64>,
}

impl MemoryServer {
    /// An empty store with the default caps.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_records: 10_000,
            ..Self::default()
        }
    }

    /// The current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.state.borrow().clone()
    }

    /// Every snapshot ever written, oldest first.
    #[must_use]
    pub fn history(&self) -> Vec<Snapshot> {
        self.history.borrow().clone()
    }

    fn served(&self) -> Snapshot {
        let f = self.faults.borrow();
        let mut s = f
            .serve
            .clone()
            .unwrap_or_else(|| self.state.borrow().clone());
        if let Some(w) = f.withhold {
            s.records.remove(&w);
        }
        s
    }

    /// Applies a write as the server does.
    pub fn apply(&self, w: &Write) -> WriteOutcome {
        let mut s = self.state.borrow_mut();
        if w.expected != s.version {
            return WriteOutcome::Conflict(s.version);
        }
        if w.inserts.iter().any(|r| !valid_record_len(r.blob.len())) {
            return WriteOutcome::Full;
        }
        let mut next = s.clone();
        for d in &w.deletes {
            next.records.remove(d);
        }
        for r in &w.inserts {
            if next.records.insert(r.id, r.blob.clone()).is_some() {
                return WriteOutcome::Full;
            }
        }
        if next.records.len() > self.max_records {
            return WriteOutcome::Full;
        }
        next.version += 1;
        next.manifest.clone_from(&w.manifest);
        self.history.borrow_mut().push(s.clone());
        *s = next;
        *self.writes.borrow_mut() += 1;
        WriteOutcome::Applied(s.version)
    }
}

impl Remote for MemoryServer {
    fn head(&self) -> impl Future<Output = Result<Head, SyncError>> {
        let s = self.served();
        std::future::ready(Ok(Head {
            version: s.version,
            manifest: s.manifest,
        }))
    }

    fn ids(&self) -> impl Future<Output = Result<Ids, SyncError>> {
        let s = self.served();
        std::future::ready(Ok(Ids {
            version: s.version,
            ids: s.records.keys().copied().collect(),
        }))
    }

    fn read(&self, ids: &[[u8; ID_LEN]]) -> impl Future<Output = Result<Vec<Record>, SyncError>> {
        let mut s = self.served();
        if let Some(u) = self.faults.borrow().unreadable {
            s.records.remove(&u);
        }
        std::future::ready(Ok(ids
            .iter()
            .filter_map(|i| {
                s.records.get(i).map(|b| Record {
                    id: *i,
                    blob: b.clone(),
                })
            })
            .collect()))
    }

    fn write(&self, w: &Write) -> impl Future<Output = Result<WriteOutcome, SyncError>> {
        std::future::ready(Ok(self.apply(w)))
    }
}

/// Runs a future that never waits (the in-memory store's) to completion.
///
/// # Errors
/// [`SyncError::Remote`] if the future waits.
pub fn block_on<T, F: Future<Output = Result<T, SyncError>>>(f: F) -> Result<T, SyncError> {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => Err(SyncError::Remote),
    }
}
