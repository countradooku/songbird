//! Prompt 10 (D-0121): the conformance suite on the stores that need no server: memory, a
//! folder, and an archive file made from it.
#![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

use std::sync::Arc;

use songbird_backup_format::RecoveryKey;
use songbird_backup_format::reader::MemoryStaging;
use songbird_backup_storage::conformance::{self, Plan};
use songbird_backup_storage::local::{ArchiveStore, LocalStore, export_archive};
use songbird_backup_storage::memory::MemoryStore;
use songbird_backup_storage::run::{self, Options};
use songbird_backup_storage::{BackupStore, StoreError};

fn keys(b: u8) -> Arc<songbird_backup_format::BackupKeys> {
    Arc::new(RecoveryKey::from_secret([b; 32]).derive().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_conforms() {
    let r = conformance::run(Arc::new(MemoryStore::default()), keys(1), Plan::default()).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_folder_conforms() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::new(dir.path().join("backup")));
    let r = conformance::run(store, keys(2), Plan::default()).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_archive_file_restores_and_refuses_damage() {
    let k = keys(3);
    let dir = tempfile::tempdir().unwrap();
    let folder: Arc<dyn BackupStore> = Arc::new(LocalStore::new(dir.path().join("b")));
    let shape = songbird_backup_format::synth::Shape {
        seed: 4,
        chats: 4,
        messages_per_chat: 60,
        media_every: 20,
        media_sizes: &[3_000, 1_200_000],
        contacts: 3,
    };
    run::backup(
        Arc::clone(&folder),
        Arc::clone(&k),
        None,
        Options::default(),
        move |w| songbird_backup_format::synth::write(w, &shape, 0).map(|_| ()),
    )
    .await
    .unwrap();
    let file = dir.path().join("chats.songbird-backup");
    export_archive(folder.as_ref(), &file).await.unwrap();
    let archive: Arc<dyn BackupStore> = Arc::new(ArchiveStore::open_file(&file).await.unwrap());
    let r = run::restore(
        Arc::clone(&archive),
        Arc::clone(&k),
        None,
        MemoryStaging::default(),
        4,
    )
    .await
    .unwrap();
    assert!(r.verified.records > 200);
    assert!(matches!(
        archive
            .put(&songbird_backup_format::ChunkName([0; 32]), vec![])
            .await,
        Err(StoreError::Protocol(_))
    ));

    // One flipped byte in the file: the restore fails loudly.
    let mut bytes = std::fs::read(&file).unwrap();
    let at = bytes.len() - 5_000;
    bytes[at] ^= 1;
    let bad = dir.path().join("bad.songbird-backup");
    std::fs::write(&bad, &bytes).unwrap();
    let damaged: Arc<dyn BackupStore> = Arc::new(ArchiveStore::open_file(&bad).await.unwrap());
    let e = run::restore(damaged, Arc::clone(&k), None, MemoryStaging::default(), 4)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("damaged"), "{e}");
    // Truncated: refused before reading.
    std::fs::write(&bad, &bytes[..bytes.len() - 1]).unwrap();
    assert!(ArchiveStore::open_file(&bad).await.is_err());
    // Another recovery key: nothing opens.
    let e = run::restore(archive, keys(9), None, MemoryStaging::default(), 4)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("damaged"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_that_lost_a_seen_backup_is_reported() {
    let k = keys(5);
    let store: Arc<dyn BackupStore> = Arc::new(MemoryStore::default());
    let shape = songbird_backup_format::synth::Shape {
        seed: 1,
        chats: 1,
        messages_per_chat: 5,
        media_every: 0,
        media_sizes: &[],
        contacts: 0,
    };
    let done = run::backup(
        Arc::clone(&store),
        Arc::clone(&k),
        None,
        Options::default(),
        move |w| songbird_backup_format::synth::write(w, &shape, 0).map(|_| ()),
    )
    .await
    .unwrap();
    store.destroy().await.unwrap();
    let e = run::restore(store, k, Some(done.seen), MemoryStaging::default(), 2)
        .await
        .unwrap_err();
    assert!(matches!(e, run::RunError::Lost), "{e:?}");
}

/// The worst store without an atomic swap: it overwrites blindly. Two primaries backing up at
/// once (only possible around an account recovery) never lose a backup silently: a device whose
/// backup was overwritten is told, at once or at its next run, by the hash chain.
/// Each device's own view of the one shared store (runs on one device take turns; two devices
/// don't know of each other).
struct Blind(Arc<MemoryStore>, &'static str);

#[async_trait::async_trait]
impl BackupStore for Blind {
    fn kind(&self) -> &'static str {
        self.1
    }
    fn atomic_swap(&self) -> bool {
        false
    }
    async fn open(&self) -> Result<(), StoreError> {
        Ok(())
    }
    async fn put(
        &self,
        n: &songbird_backup_format::ChunkName,
        o: Vec<u8>,
    ) -> Result<(), StoreError> {
        self.0.put(n, o).await
    }
    async fn get(&self, n: &songbird_backup_format::ChunkName) -> Result<Vec<u8>, StoreError> {
        self.0.get(n).await
    }
    async fn list(&self) -> Result<Vec<songbird_backup_format::ChunkName>, StoreError> {
        self.0.list().await
    }
    async fn delete(&self, n: &[songbird_backup_format::ChunkName]) -> Result<(), StoreError> {
        // Chunk deletion is left out: a racing writer's garbage collection could otherwise
        // delete the other's new chunks, which the real adapters avoid by being one device.
        let _ = n;
        Ok(())
    }
    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.0.manifest().await
    }
    async fn swap_manifest(&self, _: u64, object: Vec<u8>) -> Result<(), StoreError> {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        self.0.force_manifest(Some(object));
        Ok(())
    }
    async fn destroy(&self) -> Result<(), StoreError> {
        self.0.destroy().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_race_on_a_store_without_an_atomic_swap_is_never_silent() {
    let k = keys(6);
    for round in 0..10u64 {
        let shared = Arc::new(MemoryStore::default());
        let store: Arc<dyn BackupStore> = Arc::new(Blind(Arc::clone(&shared), "blind-a"));
        let other: Arc<dyn BackupStore> = Arc::new(Blind(shared, "blind-b"));
        let shape = |seed| songbird_backup_format::synth::Shape {
            seed,
            chats: 2,
            messages_per_chat: 20,
            media_every: 0,
            media_sizes: &[],
            contacts: 1,
        };
        let a = tokio::spawn(run::backup(
            Arc::clone(&store),
            Arc::clone(&k),
            None,
            Options::default(),
            move |w| songbird_backup_format::synth::write(w, &shape(round * 2 + 1), 0).map(|_| ()),
        ));
        let b = tokio::spawn(run::backup(
            Arc::clone(&other),
            Arc::clone(&k),
            None,
            Options::default(),
            move |w| songbird_backup_format::synth::write(w, &shape(round * 2 + 2), 0).map(|_| ()),
        ));
        let (a, b) = (a.await.unwrap(), b.await.unwrap());
        assert!(a.is_ok() || b.is_ok(), "nobody's backup was kept");
        let stored = songbird_backup_format::object::manifest_hash(
            &store.manifest().await.unwrap().unwrap(),
        );
        for done in [a, b].into_iter().flatten() {
            if done.seen.hash != stored {
                // Overtaken after its read-back: its next run is refused as a fork.
                let next = run::current(store.as_ref(), &k, Some(done.seen)).await;
                assert!(
                    matches!(
                        next,
                        Err(run::RunError::Format(songbird_backup_format::Error::Fork))
                    ),
                    "an overwritten backup went unnoticed: {next:?}"
                );
            }
        }
    }
}

const SMALL: songbird_backup_format::synth::Shape = songbird_backup_format::synth::Shape {
    seed: 3,
    chats: 2,
    messages_per_chat: 50,
    media_every: 10,
    media_sizes: &[3_000],
    contacts: 1,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_object_is_refused_before_it_is_kept() {
    let k = keys(8);
    let mem = Arc::new(MemoryStore::default());
    let store: Arc<dyn BackupStore> = mem.clone();
    run::backup(
        Arc::clone(&store),
        Arc::clone(&k),
        None,
        Options::default(),
        move |w| songbird_backup_format::synth::write(w, &SMALL, 0).map(|_| ()),
    )
    .await
    .unwrap();
    let first = store.list().await.unwrap()[0];
    let most = songbird_backup_format::object::max_chunk_object();
    mem.tamper(&first, |o| o.resize(most + 1, 0));
    let e = run::restore(store, k, None, MemoryStaging::default(), 2)
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            run::RunError::Format(songbird_backup_format::Error::Malformed("chunk"))
        ),
        "{e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runs_at_once_never_leave_a_backup_naming_missing_chunks() {
    // A background run and one the user started, at once, many times over: whatever wins, the
    // backup in the store restores.
    let k = keys(9);
    let store: Arc<dyn BackupStore> = Arc::new(MemoryStore::default());
    for round in 0..6u32 {
        let runs: Vec<_> = (0..3u32)
            .map(|i| {
                let (s, k) = (Arc::clone(&store), Arc::clone(&k));
                tokio::spawn(async move {
                    run::backup(s, k, None, Options::default(), move |w| {
                        songbird_backup_format::synth::write_edited(w, &SMALL, round * 10 + i, i)
                            .map(|_| ())
                    })
                    .await
                })
            })
            .collect();
        for r in runs {
            let _ = r.await.unwrap();
        }
        run::restore(
            Arc::clone(&store),
            Arc::clone(&k),
            None,
            MemoryStaging::default(),
            2,
        )
        .await
        .unwrap();
    }
}
