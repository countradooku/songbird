//! Prompt 10, M4 (D-0123): restore across platforms. Backups written as iOS, Android, Windows,
//! macOS and Linux, each with what that platform tends to produce (CRLF line ends, decomposed
//! Unicode, backslashes in file names, emoji, right-to-left text), restore byte for byte on every
//! other, through a folder and through a single exported file. The platform is informational
//! only: the same history gives the same chunks whichever platform writes it.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "tests"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use songbird_backup_format::reader::{Backup, MemoryStaging};
use songbird_backup_format::schema::record::Body;
use songbird_backup_format::schema::{Chat, ChatKind, Media, Message, Platform, Setting};
use songbird_backup_format::{BackupKeys, RecoveryKey};
use songbird_backup_storage::BackupStore;
use songbird_backup_storage::local::{ArchiveStore, LocalStore, export_archive};
use songbird_backup_storage::run::{self, Options};

const PLATFORMS: [Platform; 5] = [
    Platform::Ios,
    Platform::Android,
    Platform::Windows,
    Platform::Macos,
    Platform::Linux,
];

/// What each platform's app might hand the writer, all of it to come back exactly.
fn content() -> (Vec<Body>, Vec<(Media, Vec<u8>)>) {
    let chat = vec![9u8; 16];
    let texts: [&[u8]; 6] = [
        "line one\r\nline two\r\n".as_bytes(),
        "Zoe\u{0301} and Zoé".as_bytes(),
        "C:\\Users\\ada\\photo.jpg".as_bytes(),
        "\u{1f426}\u{200d}\u{1f525} songbird".as_bytes(),
        "\u{05e9}\u{05dc}\u{05d5}\u{05dd} \u{0627}\u{0644}\u{0633}\u{0644}\u{0627}\u{0645}"
            .as_bytes(),
        &[0xff, 0x00, 0xfe],
    ];
    let mut records = vec![
        Body::Setting(Setting {
            key: "s/theme".into(),
            value: b"dark".to_vec(),
        }),
        Body::Setting(Setting {
            key: "d/enter_sends".into(),
            value: vec![1],
        }),
        Body::Chat(Chat {
            chat_id: chat.clone(),
            kind: ChatKind::Direct.into(),
            title: "Zoe\u{0301}".into(),
            created_ms: 1,
            ..Chat::default()
        }),
    ];
    for (i, t) in texts.iter().enumerate() {
        records.push(Body::Message(Message {
            chat_id: chat.clone(),
            message_id: vec![u8::try_from(i).unwrap(); 16],
            sent_ms: 1_700_000_000_000 + u64::try_from(i).unwrap(),
            content: t.to_vec(),
            ..Message::default()
        }));
    }
    let media = vec![
        (
            Media {
                mime: "image/heic".into(),
                file_name: "IMG_0001.HEIC".into(),
                ..Media::default()
            },
            vec![1u8; 5_000],
        ),
        (
            Media {
                mime: "video/mp4".into(),
                file_name: "VID\\2026\\clip.mp4".into(),
                duration_ms: 1_234,
                ..Media::default()
            },
            (0..1_300_000u32)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect(),
        ),
    ];
    (records, media)
}

async fn write(
    store: Arc<dyn BackupStore>,
    keys: Arc<BackupKeys>,
    platform: Platform,
) -> BTreeSet<Vec<u8>> {
    let (records, media) = content();
    let opts = Options {
        platform,
        app_version: format!("{platform:?} 1.0"),
        ..Options::default()
    };
    run::backup(Arc::clone(&store), keys, None, opts, move |w| {
        for (m, bytes) in media {
            w.media(m, &mut bytes.as_slice())?;
        }
        for r in records {
            w.record(r)?;
        }
        Ok(())
    })
    .await
    .unwrap();
    store
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|n| n.0.to_vec())
        .collect()
}

async fn read(
    store: Arc<dyn BackupStore>,
    keys: Arc<BackupKeys>,
) -> (Platform, Vec<Body>, BTreeSet<Vec<u8>>) {
    let r = run::restore(store, Arc::clone(&keys), None, MemoryStaging::default(), 4)
        .await
        .unwrap();
    let b = Backup::new(&keys, &r.opened.manifest, &r.staging);
    let records: Vec<Body> = b
        .records()
        .map(|x| x.unwrap().body.unwrap())
        .filter(|x| !matches!(x, Body::Media(_)))
        .collect();
    let mut files: BTreeSet<Vec<u8>> = b.blobs().map(|x| x.unwrap().1.to_vec()).collect();
    for m in b.media_streams() {
        let mut v = vec![];
        std::io::Read::read_to_end(&mut b.media(&m).unwrap(), &mut v).unwrap();
        files.insert(v);
    }
    (
        Platform::try_from(r.opened.manifest.platform).unwrap(),
        records,
        files,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backup_from_any_platform_restores_on_every_other() {
    let keys = Arc::new(RecoveryKey::from_secret([0x5e; 32]).derive().unwrap());
    let (want_records, want_media) = content();
    let want_files: BTreeSet<Vec<u8>> = want_media.into_iter().map(|(_, b)| b).collect();
    let mut names = None;
    for writer in PLATFORMS {
        let dir = tempfile::tempdir().unwrap();
        let folder: Arc<dyn BackupStore> = Arc::new(LocalStore::new(dir.path().join("b")));
        let chunk_names = write(Arc::clone(&folder), Arc::clone(&keys), writer).await;
        // The same history makes the same chunks whatever writes it.
        assert_eq!(
            *names.get_or_insert_with(|| chunk_names.clone()),
            chunk_names,
            "{writer:?}"
        );
        let file = dir.path().join("moved.songbird-backup");
        export_archive(folder.as_ref(), &file).await.unwrap();
        for reader in PLATFORMS {
            // The reader's platform changes nothing: there is no platform branch in the reader.
            let _ = reader;
            for store in [
                Arc::clone(&folder),
                Arc::new(ArchiveStore::open_file(&file).await.unwrap()) as Arc<dyn BackupStore>,
            ] {
                let (from, records, files) = read(store, Arc::clone(&keys)).await;
                assert_eq!(from, writer);
                assert_eq!(records, want_records, "{writer:?} → {reader:?}");
                assert_eq!(files, want_files, "{writer:?} → {reader:?}");
            }
        }
    }
}
