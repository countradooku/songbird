//! A backup and a restore over any [`BackupStore`] (PROTOCOL §11.6, §11.8).
//!
//! **Backup**: read the store's manifest and chunk list; write the content on a blocking thread
//! (chunking and sealing are CPU work) while new chunks upload concurrently; swap the manifest
//! only after every chunk is stored; then delete chunks no manifest references. A crash at any
//! point leaves the previous backup intact, and the chunks already uploaded are reused next
//! time.
//!
//! **Restore**: read the manifest (refusing one older than this device has seen), download every
//! chunk into staging concurrently, then verify everything (`songbird_backup_format::reader`)
//! before the caller writes anything.

use std::collections::HashSet;
use std::sync::Arc;

use futures_util::StreamExt as _;
use songbird_backup_format::object::{self, Opened, Seen};
use songbird_backup_format::reader::{self, ChunkSource, Staging, Verified};
use songbird_backup_format::schema::{Manifest, Platform};
use songbird_backup_format::writer::{ChunkSink, Info, Stats, Writer};
use songbird_backup_format::{BackupKeys, ChunkName, OsRng};

use crate::store::{BackupStore, StoreError};

/// What can stop a run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RunError {
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The backup is damaged, foreign, too new, rolled back or forked.
    #[error(transparent)]
    Format(#[from] songbird_backup_format::Error),
    /// The store has no backup.
    #[error("no backup in this place")]
    Empty,
    /// The store has lost a backup this device has seen (emptied, or another vault).
    #[error("the backup this device made is gone from this place")]
    Lost,
    /// A thread failed.
    #[error("internal error")]
    Join,
}

/// The lock serializing backup runs to one kind of store in this process.
fn run_lock(kind: &'static str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: std::sync::Mutex<
        std::collections::BTreeMap<&'static str, Arc<tokio::sync::Mutex<()>>>,
    > = std::sync::Mutex::new(std::collections::BTreeMap::new());
    let mut m = LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(m.entry(kind).or_default())
}

/// Whether every chunk `manifest` names that this run did not upload itself (it reused it from
/// the store's listing) is still in the store.
async fn reused_present(
    store: &dyn BackupStore,
    manifest: &Manifest,
    put_names: &HashSet<ChunkName>,
) -> Result<(), RunError> {
    // Only what this run reused rather than uploaded needs looking for.
    let mut reused = HashSet::new();
    for c in manifest.streams.iter().flat_map(|s| s.chunks.iter()) {
        let n = ChunkName::from_slice(&c.name)
            .ok_or(songbird_backup_format::Error::Malformed("manifest"))?;
        if !put_names.contains(&n) {
            reused.insert(n);
        }
    }
    if !reused.is_empty() {
        let present: HashSet<ChunkName> = store.list().await?.into_iter().collect();
        if !reused.is_subset(&present) {
            return Err(songbird_backup_format::Error::Missing.into());
        }
    }
    Ok(())
}

/// What a backup run did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Done {
    /// What this device must remember: the new manifest.
    pub seen: Seen,
    /// The writer's costs.
    pub stats: Stats,
    /// Chunks deleted afterwards (no longer referenced).
    pub deleted: u64,
}

/// How a run behaves.
#[derive(Debug, Clone)]
pub struct Options {
    /// Uploads or downloads in flight.
    pub concurrency: usize,
    /// The app's version string (in the manifest, informational).
    pub app_version: String,
    /// The platform (in the manifest, informational).
    pub platform: Platform,
    /// Now, in UTC milliseconds.
    pub now_ms: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            concurrency: 4,
            app_version: String::new(),
            platform: Platform::Unknown,
            now_ms: 0,
        }
    }
}

/// The store's current manifest, opened and checked against what this device has seen.
///
/// # Errors
/// [`RunError::Lost`] when the store is empty but this device has seen a backup there.
pub async fn current(
    store: &dyn BackupStore,
    keys: &BackupKeys,
    seen: Option<Seen>,
) -> Result<Option<Opened>, RunError> {
    match store.manifest().await? {
        Some(obj) => Ok(Some(object::open_manifest(keys, &obj, seen)?)),
        None if seen.is_some() => Err(RunError::Lost),
        None => Ok(None),
    }
}

/// Makes a backup: `content` writes the records and media in canonical order (on a blocking
/// thread).
///
/// # Errors
/// [`RunError`]. [`StoreError::Conflict`] when another device swapped first: run again.
pub async fn backup<F>(
    store: Arc<dyn BackupStore>,
    keys: Arc<BackupKeys>,
    seen: Option<Seen>,
    opts: Options,
    content: F,
) -> Result<Done, RunError>
where
    F: FnOnce(&mut Writer<'_, ChannelSinkHandle>) -> Result<(), songbird_backup_format::Error>
        + Send
        + 'static,
{
    // One run per kind of store at a time in this process: a run's collection of unreferenced
    // chunks must not delete what another run is about to reference (D-0125).
    let lock = run_lock(store.kind());
    let _held = lock.lock().await;
    store.open().await?;
    let prev = current(store.as_ref(), &keys, seen).await?;
    let stored: Vec<ChunkName> = store.list().await?;
    let generation = prev.as_ref().map_or(0, |p| p.generation);
    let info = Info {
        generation: generation + 1,
        previous: prev.as_ref().map(|p| p.hash),
        created_ms: opts.now_ms,
        app_version: opts.app_version.clone(),
        platform: opts.platform,
    };
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<(ChunkName, Vec<u8>)>(opts.concurrency.max(1) * 2);
    let wkeys = Arc::clone(&keys);
    let prev_manifest: Option<Manifest> = prev.map(|p| p.manifest);
    let known = stored.clone();
    let writer = tokio::task::spawn_blocking(move || {
        let mut rng = OsRng;
        let mut w = Writer::new(
            &wkeys,
            prev_manifest.as_ref(),
            &mut rng,
            ChannelSinkHandle(tx),
        );
        w.known(known);
        content(&mut w)?;
        let (obj, manifest, stats, _) = w.finish(&info)?;
        Ok::<_, songbird_backup_format::Error>((obj, manifest, stats))
    });
    // Upload as chunks arrive, `concurrency` at a time; the first failure stops the writer.
    let mut put_names: HashSet<ChunkName> = HashSet::new();
    let uploads = async {
        let mut inflight = futures_util::stream::FuturesUnordered::new();
        loop {
            tokio::select! {
                next = rx.recv(), if inflight.len() < opts.concurrency.max(1) => match next {
                    Some((name, obj)) => {
                        put_names.insert(name);
                        let s = Arc::clone(&store);
                        inflight.push(async move { put_retrying(s.as_ref(), &name, obj).await });
                    }
                    None => break,
                },
                Some(r) = inflight.next(), if !inflight.is_empty() => r?,
            }
        }
        while let Some(r) = inflight.next().await {
            r?;
        }
        Ok::<(), StoreError>(())
    };
    let uploaded = uploads.await;
    let written = writer.await.map_err(|_| RunError::Join)?;
    uploaded?;
    let (obj, manifest, stats) = written?;
    // Every chunk the new manifest names is in the store before it becomes the backup (a chunk
    // listed at the start may have gone since, for instance collected by a run elsewhere).
    reused_present(store.as_ref(), &manifest, &put_names).await?;
    let hash = object::manifest_hash(&obj);
    store.swap_manifest(generation, obj).await?;
    if !store.atomic_swap() {
        // A store without an atomic swap (D-0122): the backup counts only if the manifest read
        // back is this one. Otherwise another writer overtook it; its chunks are collected later.
        let back = store.manifest().await?;
        if back.as_deref().map(object::manifest_hash) != Some(hash) {
            let current = back
                .as_deref()
                .and_then(|m| object::manifest_generation(m).ok())
                .unwrap_or(0);
            return Err(StoreError::Conflict { current }.into());
        }
    }
    // Chunks referenced by no manifest: from replaced backups and failed runs.
    let referenced: HashSet<Vec<u8>> = manifest
        .streams
        .iter()
        .flat_map(|s| s.chunks.iter().map(|c| c.name.clone()))
        .collect();
    let garbage: Vec<ChunkName> = store
        .list()
        .await?
        .into_iter()
        .filter(|n| !referenced.contains(n.0.as_slice()))
        .collect();
    store.delete(&garbage).await?;
    Ok(Done {
        seen: Seen {
            generation: generation + 1,
            hash,
        },
        stats,
        deleted: u64::try_from(garbage.len()).unwrap_or(u64::MAX),
    })
}

/// The sink a backup's content closure writes into: new chunks go to the uploaders.
pub struct ChannelSinkHandle(tokio::sync::mpsc::Sender<(ChunkName, Vec<u8>)>);

impl std::fmt::Debug for ChannelSinkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelSinkHandle")
    }
}

impl ChunkSink for ChannelSinkHandle {
    fn put(
        &mut self,
        name: &ChunkName,
        object: Vec<u8>,
    ) -> Result<(), songbird_backup_format::Error> {
        self.0
            .blocking_send((*name, object))
            .map_err(|_| songbird_backup_format::Error::Store("upload stopped".into()))
    }
}

async fn put_retrying(
    store: &dyn BackupStore,
    name: &ChunkName,
    obj: Vec<u8>,
) -> Result<(), StoreError> {
    let mut wait = 250u64;
    for _ in 0..5 {
        match store.put(name, obj.clone()).await {
            Err(StoreError::Throttled { retry_after_ms }) => {
                tokio::time::sleep(std::time::Duration::from_millis(retry_after_ms.max(wait)))
                    .await;
            }
            Err(StoreError::Unavailable { .. }) => {
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            r => return r,
        }
        wait = (wait * 2).min(8_000);
    }
    store.put(name, obj).await
}

async fn get_retrying(store: &dyn BackupStore, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
    let mut wait = 250u64;
    for _ in 0..5 {
        match store.get(name).await {
            Err(StoreError::Throttled { retry_after_ms }) => {
                tokio::time::sleep(std::time::Duration::from_millis(retry_after_ms.max(wait)))
                    .await;
            }
            Err(StoreError::Unavailable { .. }) => {
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            r => return r,
        }
        wait = (wait * 2).min(8_000);
    }
    store.get(name).await
}

/// Reads staging as the source of [`reader::verify`] (the chunks are already downloaded).
struct StagedSource<'a>(&'a dyn Staging);

impl ChunkSource for StagedSource<'_> {
    fn get(&mut self, name: &ChunkName) -> Result<Vec<u8>, songbird_backup_format::Error> {
        self.0.get(name)
    }
}

/// The staging the chunks were downloaded into, as verify's staging: nothing to keep again.
struct Same<'a>(&'a dyn Staging);

impl Staging for Same<'_> {
    fn put(&mut self, _: &ChunkName, _: Vec<u8>) -> Result<(), songbird_backup_format::Error> {
        Ok(())
    }
    fn get(&self, name: &ChunkName) -> Result<Vec<u8>, songbird_backup_format::Error> {
        self.0.get(name)
    }
}

/// A verified backup ready to apply: read it with
/// `songbird_backup_format::reader::Backup::new(keys, &opened.manifest, staging)`.
pub struct Restored<S> {
    /// The opened manifest.
    pub opened: Opened,
    /// The verified chunks (still encrypted).
    pub staging: S,
    /// What verification read.
    pub verified: Verified,
}

impl<S> std::fmt::Debug for Restored<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Restored")
            .field("verified", &self.verified)
            .finish_non_exhaustive()
    }
}

/// Downloads and verifies the store's backup into `staging`. Nothing is applied: the caller
/// applies the returned backup in one transaction.
///
/// # Errors
/// [`RunError::Empty`]; the format's errors for anything damaged; the store's.
pub async fn restore<S>(
    store: Arc<dyn BackupStore>,
    keys: Arc<BackupKeys>,
    seen: Option<Seen>,
    mut staging: S,
    concurrency: usize,
) -> Result<Restored<S>, RunError>
where
    S: Staging + Send + 'static,
{
    let opened = current(store.as_ref(), &keys, seen)
        .await?
        .ok_or(RunError::Empty)?;
    let mut names: Vec<ChunkName> = vec![];
    let mut seen_names = HashSet::new();
    for c in opened.manifest.streams.iter().flat_map(|s| s.chunks.iter()) {
        let n = ChunkName::from_slice(&c.name)
            .ok_or(songbird_backup_format::Error::Malformed("manifest"))?;
        if seen_names.insert(n) {
            names.push(n);
        }
    }
    let mut downloads = futures_util::stream::iter(names.into_iter().map(|n| {
        let s = Arc::clone(&store);
        async move {
            match get_retrying(s.as_ref(), &n).await {
                Ok(o) => Ok((n, o)),
                Err(StoreError::NotFound) => {
                    Err(RunError::Format(songbird_backup_format::Error::Missing))
                }
                Err(e) => Err(RunError::Store(e)),
            }
        }
    }))
    .buffer_unordered(concurrency.max(1));
    let most = object::max_chunk_object();
    while let Some(r) = downloads.next().await {
        let (n, o) = r?;
        // Bounded before it is kept: a store can't fill memory or disk with oversized objects.
        if o.len() > most {
            return Err(songbird_backup_format::Error::Malformed("chunk").into());
        }
        staging.put(&n, o)?;
    }
    let k = Arc::clone(&keys);
    let (opened, staging, verified) = tokio::task::spawn_blocking(move || {
        let v = reader::verify(
            &k,
            &opened.manifest,
            &mut StagedSource(&staging),
            &mut Same(&staging),
        )?;
        Ok::<_, songbird_backup_format::Error>((opened, staging, v))
    })
    .await
    .map_err(|_| RunError::Join)??;
    Ok(Restored {
        opened,
        staging,
        verified,
    })
}
