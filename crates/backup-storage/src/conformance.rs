//! The conformance suite every adapter passes (Prompt 10's gate): the same checks against
//! memory, a folder, the Songbird vault, S3, `WebDAV` and the Google Drive, `OneDrive` and
//! Dropbox emulators. A native adapter (iCloud Drive) runs the same suite on the device.
//!
//! Each check returns a message naming what failed, so a test prints which rule an adapter
//! broke.

use std::collections::HashSet;
use std::sync::Arc;

use songbird_backup_format::object::{self, ChunkName};
use songbird_backup_format::schema::{Manifest, Platform, Stream, StreamKind};
use songbird_backup_format::synth::{self, Shape};
use songbird_backup_format::{BackupKeys, OsRng, reader::MemoryStaging};

use crate::run::{self, Options};
use crate::store::{BackupStore, StoreError};

/// What the suite exercises (smaller numbers for slow emulators).
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    /// Chunks put for the listing check (over 1,000 crosses a page of every adapter).
    pub many: usize,
    /// Writers racing for one generation.
    pub racers: usize,
    /// The largest chunk is put and read back (8 MiB of plaintext).
    pub largest: bool,
    /// A whole backup and restore through [`run`].
    pub backup: bool,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            many: 1_050,
            racers: 8,
            largest: true,
            backup: true,
        }
    }
}

/// What the suite measured.
#[derive(Debug, Default, Clone, Copy)]
pub struct Report {
    /// Checks passed.
    pub checks: u32,
}

fn fail(what: &str, detail: impl std::fmt::Debug) -> String {
    format!("{what}: {detail:?}")
}

/// A real chunk object (the vault checks shapes) of `n` random plaintext bytes.
fn chunk(keys: &BackupKeys, n: usize) -> (ChunkName, Vec<u8>) {
    let mut p = vec![0u8; n];
    let _ = getrandom::fill(&mut p);
    let name = object::chunk_name(keys, &p);
    let obj = object::seal_chunk(keys, &name, &p, &mut OsRng).unwrap_or_default();
    (name, obj)
}

fn manifest(keys: &BackupKeys, generation: u64, tag: &str) -> Vec<u8> {
    let m = Manifest {
        format_version: 1,
        min_reader_version: 1,
        app_version: tag.to_owned(),
        streams: vec![Stream {
            kind: StreamKind::Records.into(),
            sha256: aws_sha256(&[]),
            ..Stream::default()
        }],
        ..Manifest::default()
    };
    object::seal_manifest(keys, generation, &m, &mut OsRng).unwrap_or_default()
}

fn aws_sha256(b: &[u8]) -> Vec<u8> {
    // SHA-256 of a stream's bytes, as the manifest records it (`manifest_hash` is plain SHA-256).
    object::manifest_hash(b).to_vec()
}

/// Runs every check against `store`, which must start empty or be emptied by `destroy`.
///
/// # Errors
/// A message naming the first rule the store broke.
#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "the suite: one block per rule"
)]
pub async fn run(
    store: Arc<dyn BackupStore>,
    keys: Arc<BackupKeys>,
    plan: Plan,
) -> Result<Report, String> {
    let mut rep = Report::default();
    let s = store.as_ref();
    let k = keys.as_ref();

    // Opening is idempotent; a destroyed store opens empty.
    s.open().await.map_err(|e| fail("open", e))?;
    s.destroy().await.map_err(|e| fail("destroy (start)", e))?;
    s.open().await.map_err(|e| fail("open after destroy", e))?;
    s.open().await.map_err(|e| fail("open twice", e))?;
    if !s
        .list()
        .await
        .map_err(|e| fail("list (empty)", e))?
        .is_empty()
    {
        return Err("a destroyed store still lists chunks".into());
    }
    if s.manifest()
        .await
        .map_err(|e| fail("manifest (empty)", e))?
        .is_some()
    {
        return Err("a destroyed store still has a manifest".into());
    }
    rep.checks += 1;

    // A missing chunk is NotFound.
    let (missing, _) = chunk(k, 10);
    match s.get(&missing).await {
        Err(StoreError::NotFound) => {}
        other => {
            return Err(fail(
                "get of a missing chunk must be NotFound",
                other.map(|v| v.len()),
            ));
        }
    }
    rep.checks += 1;

    // Round trips, byte for byte, small to the largest.
    let mut sizes = vec![1usize, 1_000, 300_000, 1 << 20];
    if plan.largest {
        sizes.push(8 << 20);
    }
    let mut stored = vec![];
    for n in sizes {
        let (name, obj) = chunk(k, n);
        s.put(&name, obj.clone())
            .await
            .map_err(|e| fail("put", (n, e)))?;
        let got = s.get(&name).await.map_err(|e| fail("get", (n, e)))?;
        if got != obj {
            return Err(format!("get returned other bytes for a {n}-byte chunk"));
        }
        stored.push(name);
    }
    rep.checks += 1;

    // Putting a name again succeeds, and what is read back is a valid object of that name.
    let p = vec![7u8; 500];
    let name = object::chunk_name(k, &p);
    for _ in 0..2 {
        let o = object::seal_chunk(k, &name, &p, &mut OsRng).map_err(|e| fail("seal", e))?;
        s.put(&name, o).await.map_err(|e| fail("put again", e))?;
    }
    let got = s
        .get(&name)
        .await
        .map_err(|e| fail("get after put again", e))?;
    object::open_chunk(k, &name, 500, &got)
        .map_err(|e| fail("an object put twice no longer opens", e))?;
    stored.push(name);
    rep.checks += 1;

    // Listing returns every name once, across pages.
    for _ in 0..plan.many {
        let (name, obj) = chunk(k, 16);
        s.put(&name, obj).await.map_err(|e| fail("put (many)", e))?;
        stored.push(name);
    }
    let listed = s.list().await.map_err(|e| fail("list", e))?;
    let set: HashSet<_> = listed.iter().copied().collect();
    if set.len() != listed.len() {
        return Err("list returned a name twice".into());
    }
    let want: HashSet<_> = stored.iter().copied().collect();
    if set != want {
        return Err(format!(
            "list returned {} names, {} stored",
            set.len(),
            want.len()
        ));
    }
    rep.checks += 1;

    // Deleting removes exactly those names; unknown names are fine.
    let (gone, keep) = stored.split_at(stored.len() / 2);
    let mut del: Vec<ChunkName> = gone.to_vec();
    del.push(missing);
    s.delete(&del).await.map_err(|e| fail("delete", e))?;
    let listed: HashSet<_> = s
        .list()
        .await
        .map_err(|e| fail("list after delete", e))?
        .into_iter()
        .collect();
    if listed != keep.iter().copied().collect::<HashSet<_>>() {
        return Err(format!(
            "after delete, list has {} names, {} expected",
            listed.len(),
            keep.len()
        ));
    }
    if let Some(g) = gone.first()
        && !matches!(s.get(g).await, Err(StoreError::NotFound))
    {
        return Err("a deleted chunk is still readable".into());
    }
    rep.checks += 1;

    // The manifest: compare-and-swap on the generation.
    let m1 = manifest(k, 1, "one");
    s.swap_manifest(0, m1.clone())
        .await
        .map_err(|e| fail("first swap", e))?;
    if s.manifest().await.map_err(|e| fail("manifest", e))? != Some(m1.clone()) {
        return Err("the manifest read back differs".into());
    }
    match s.swap_manifest(0, manifest(k, 1, "late")).await {
        Err(StoreError::Conflict { current: 1 }) => {}
        other => return Err(fail("a stale swap must conflict with generation 1", other)),
    }
    if s.swap_manifest(1, manifest(k, 3, "skip")).await.is_ok() {
        return Err("a swap skipping a generation was accepted".into());
    }
    let m2 = manifest(k, 2, "two");
    s.swap_manifest(1, m2.clone())
        .await
        .map_err(|e| fail("second swap", e))?;
    if s.manifest().await.map_err(|e| fail("manifest", e))? != Some(m2) {
        return Err("the second manifest read back differs".into());
    }
    rep.checks += 1;

    // Racing writers: exactly one wins the generation.
    let mut tasks = vec![];
    for i in 0..plan.racers {
        let st = Arc::clone(&store);
        let obj = manifest(k, 3, &format!("racer {i}"));
        tasks.push(tokio::spawn(async move {
            let r = st.swap_manifest(2, obj.clone()).await;
            (r, obj)
        }));
    }
    let mut winners = vec![];
    for t in tasks {
        let (r, obj) = t.await.map_err(|e| fail("racer", e))?;
        match r {
            Ok(()) => winners.push(obj),
            Err(StoreError::Conflict { .. }) => {}
            Err(e) => return Err(fail("a racer failed otherwise than by conflict", e)),
        }
    }
    if winners.len() != 1 && (s.atomic_swap() || winners.is_empty()) {
        return Err(format!("{} racers won generation 3", winners.len()));
    }
    let stored = s
        .manifest()
        .await
        .map_err(|e| fail("manifest after race", e))?;
    if !stored.as_ref().is_some_and(|m| winners.contains(m)) {
        return Err("the stored manifest is not a winner's".into());
    }
    rep.checks += 1;

    // A whole backup and restore, then an incremental one.
    if plan.backup {
        s.destroy().await.map_err(|e| fail("destroy", e))?;
        let shape = Shape {
            seed: 21,
            chats: 6,
            messages_per_chat: 120,
            media_every: 30,
            media_sizes: &[2_000, 1_100_000],
            contacts: 5,
        };
        let opts = Options {
            concurrency: 4,
            app_version: "conformance".into(),
            platform: Platform::Linux,
            now_ms: 1,
        };
        let one = run::backup(
            Arc::clone(&store),
            Arc::clone(&keys),
            None,
            opts.clone(),
            move |w| synth::write(w, &shape, 0).map(|_| ()),
        )
        .await
        .map_err(|e| fail("backup", e))?;
        let two = run::backup(
            Arc::clone(&store),
            Arc::clone(&keys),
            Some(one.seen),
            opts.clone(),
            move |w| synth::write(w, &shape, 5).map(|_| ()),
        )
        .await
        .map_err(|e| fail("second backup", e))?;
        if two.stats.new_chunks >= one.stats.new_chunks {
            return Err(format!(
                "the second backup uploaded {} chunks, the first {}",
                two.stats.new_chunks, one.stats.new_chunks
            ));
        }
        let restored = run::restore(
            Arc::clone(&store),
            Arc::clone(&keys),
            Some(two.seen),
            MemoryStaging::default(),
            4,
        )
        .await
        .map_err(|e| fail("restore", e))?;
        let b = songbird_backup_format::reader::Backup::new(
            k,
            &restored.opened.manifest,
            &restored.staging,
        );
        let records = b
            .records()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| fail("restored records", e))?;
        if records.is_empty() || restored.opened.generation != 2 {
            return Err("the restore read nothing".into());
        }
        // Nothing unreferenced is left behind.
        let referenced: HashSet<Vec<u8>> = restored
            .opened
            .manifest
            .streams
            .iter()
            .flat_map(|st| st.chunks.iter().map(|c| c.name.clone()))
            .collect();
        let left = s.list().await.map_err(|e| fail("list after backups", e))?;
        if left.iter().any(|x| !referenced.contains(x.0.as_slice())) {
            return Err("unreferenced chunks were left after a backup".into());
        }
        // A device that saw generation 2 refuses an older backup the store serves.
        if run::restore(
            Arc::clone(&store),
            Arc::clone(&keys),
            Some(object::Seen {
                generation: 3,
                hash: [0; 32],
            }),
            MemoryStaging::default(),
            2,
        )
        .await
        .is_ok()
        {
            return Err("a rolled-back store was restored".into());
        }
        rep.checks += 1;
    }

    // Destroy empties everything.
    s.destroy().await.map_err(|e| fail("destroy (end)", e))?;
    s.open()
        .await
        .map_err(|e| fail("open after destroy (end)", e))?;
    if !s
        .list()
        .await
        .map_err(|e| fail("list after destroy", e))?
        .is_empty()
        || s.manifest()
            .await
            .map_err(|e| fail("manifest after destroy", e))?
            .is_some()
    {
        return Err("destroy left something".into());
    }
    rep.checks += 1;
    Ok(rep)
}

/// One step of [`incremental_cost`].
#[derive(Debug, Clone)]
pub struct Step {
    /// What changed.
    pub what: &'static str,
    /// Chunks uploaded.
    pub new_chunks: u64,
    /// Object bytes uploaded.
    pub new_bytes: u64,
    /// Chunks reused.
    pub reused_chunks: u64,
    /// Chunks deleted afterwards.
    pub deleted: u64,
    /// Plaintext bytes in the backup.
    pub plaintext: u64,
    /// Wall time.
    pub seconds: f64,
}

/// The incremental cost of backups on a large history (Prompt 10's gate): a first backup,
/// the same again, a day of new messages in every chat, and deletions of old messages.
///
/// # Errors
/// A message naming the step that failed.
pub async fn incremental_cost(
    store: Arc<dyn BackupStore>,
    keys: Arc<BackupKeys>,
    shape: Shape,
    day: u32,
    drop_oldest: u32,
) -> Result<Vec<Step>, String> {
    store.destroy().await.map_err(|e| fail("destroy", e))?;
    let mut seen = None;
    let mut out = vec![];
    for (what, extra, drop) in [
        ("first backup", 0, 0),
        ("nothing changed", 0, 0),
        ("a day of messages in every chat", day, 0),
        (
            "the oldest messages of every chat deleted",
            day,
            drop_oldest,
        ),
    ] {
        let t = std::time::Instant::now();
        let opts = Options {
            concurrency: 8,
            app_version: "cost".into(),
            platform: Platform::Linux,
            now_ms: 1,
        };
        let done = run::backup(
            Arc::clone(&store),
            Arc::clone(&keys),
            seen,
            opts,
            move |w| synth::write_edited(w, &shape, extra, drop).map(|_| ()),
        )
        .await
        .map_err(|e| fail(what, e))?;
        seen = Some(done.seen);
        out.push(Step {
            what,
            new_chunks: done.stats.new_chunks,
            new_bytes: done.stats.new_bytes,
            reused_chunks: done.stats.reused_chunks,
            deleted: done.deleted,
            plaintext: done.stats.plaintext_bytes,
            seconds: t.elapsed().as_secs_f64(),
        });
    }
    Ok(out)
}
