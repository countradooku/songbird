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
        &Options::default(),
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
        &Options::default(),
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
