//! Prompt 10, M1 (D-0120): the backup format end to end: recovery keys, round trips,
//! incremental backups, corruption and truncation, rollback, and bounds.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::collections::BTreeMap;

use songbird_backup_format::chunker::Params;
use songbird_backup_format::object::{self, ChunkName, Seen};
use songbird_backup_format::reader::{self, Backup, ChunkSource, MemoryStaging, Staging};
use songbird_backup_format::schema::{Manifest, Platform, StreamKind, record::Body};
use songbird_backup_format::synth::{self, Shape};
use songbird_backup_format::writer::{ChunkSink, Info, Stats, Writer};
use songbird_backup_format::{BackupKeys, Error, FixedRng, OsRng, RecoveryKey};

/// A store in memory, in insertion order.
#[derive(Default, Clone)]
struct Store(BTreeMap<ChunkName, Vec<u8>>);

impl ChunkSink for &mut Store {
    fn put(&mut self, name: &ChunkName, object: Vec<u8>) -> Result<(), Error> {
        self.0.insert(*name, object);
        Ok(())
    }
}
impl ChunkSource for Store {
    fn get(&mut self, name: &ChunkName) -> Result<Vec<u8>, Error> {
        self.0.get(name).cloned().ok_or(Error::Missing)
    }
}

const SMALL: Params = Params {
    min: 2 << 10,
    avg: 8 << 10,
    max: 32 << 10,
    hard: !0u64 << (64 - 15),
    easy: !0u64 << (64 - 11),
};

const SHAPE: Shape = Shape {
    seed: 11,
    chats: 12,
    messages_per_chat: 150,
    media_every: 25,
    media_sizes: &[3_000, 40_000, 1_200_000],
    contacts: 20,
};

fn keys() -> BackupKeys {
    RecoveryKey::from_secret([7; 32]).derive().unwrap()
}

fn info(generation: u64, previous: Option<[u8; 32]>) -> Info {
    Info {
        generation,
        previous,
        created_ms: 1_800_000_000_000,
        app_version: "test".into(),
        platform: Platform::Linux,
    }
}

/// Writes `shape` (with `extra` messages per chat) on top of `previous`.
fn backup(
    keys: &BackupKeys,
    store: &mut Store,
    shape: &Shape,
    extra: u32,
    previous: Option<(&Manifest, [u8; 32], u64)>,
    params: Params,
) -> (Vec<u8>, Manifest, Stats, Vec<Body>) {
    let mut rng = OsRng;
    let mut w = Writer::with_params(keys, previous.map(|p| p.0), &mut rng, &mut *store, params);
    let written = synth::write(&mut w, shape, extra).unwrap();
    let (obj, m, stats, _) = w
        .finish(&info(
            previous.map_or(1, |p| p.2 + 1),
            previous.map(|p| p.1),
        ))
        .unwrap();
    (obj, m, stats, written)
}

fn restore(keys: &BackupKeys, store: &mut Store, obj: &[u8]) -> Result<Vec<Body>, Error> {
    let opened = object::open_manifest(keys, obj, None)?;
    let mut staging = MemoryStaging::default();
    reader::verify(keys, &opened.manifest, store, &mut staging)?;
    let b = Backup::new(keys, &opened.manifest, &staging);
    b.records().map(|r| r.map(|r| r.body.unwrap())).collect()
}

fn without_media(v: Vec<Body>) -> Vec<Body> {
    v.into_iter()
        .filter(|b| !matches!(b, Body::Media(_)))
        .collect()
}

#[test]
fn recovery_keys_round_trip_forgive_formatting_and_catch_typos() {
    for _ in 0..50 {
        let k = RecoveryKey::generate(&mut OsRng).unwrap();
        let shown = k.display();
        assert_eq!(shown.len(), 64 + 15);
        assert_eq!(k.groups().len(), 16);
        assert_eq!(RecoveryKey::parse(&shown).unwrap(), k);
        // Lower case, spaces instead of dashes, look-alikes.
        let loose = shown
            .to_lowercase()
            .replace('-', " ")
            .replace('1', "l")
            .replace('0', "O");
        assert_eq!(RecoveryKey::parse(&loose).unwrap(), k);
        // One character changed is caught by the check (64 bits), not a wrong vault.
        let mut typo: Vec<char> = k.to_chars().chars().collect();
        typo[17] = if typo[17] == 'A' { 'B' } else { 'A' };
        let typo: String = typo.into_iter().collect();
        assert!(matches!(RecoveryKey::parse(&typo), Err(Error::KeyCheck)));
        // Two adjacent characters swapped.
        let mut swap: Vec<char> = k.to_chars().chars().collect();
        if swap[30] != swap[31] {
            swap.swap(30, 31);
            let swap: String = swap.into_iter().collect();
            assert!(matches!(RecoveryKey::parse(&swap), Err(Error::KeyCheck)));
        }
    }
    let k = RecoveryKey::from_secret([0; 32]);
    let c = k.to_chars();
    assert!(matches!(
        RecoveryKey::parse(&c[..63]),
        Err(Error::KeyLength)
    ));
    assert!(matches!(
        RecoveryKey::parse(&format!("{}0", *c)),
        Err(Error::KeyLength)
    ));
    assert!(matches!(
        RecoveryKey::parse(&format!("U{}", &c[1..])),
        Err(Error::KeyCharacter)
    ));
    assert!(matches!(RecoveryKey::parse(""), Err(Error::KeyLength)));
    assert_eq!(format!("{k:?}"), "RecoveryKey(..)");
    assert!(!format!("{:?}", k.derive().unwrap()).contains("vault"));
}

#[test]
fn different_keys_derive_unrelated_vaults() {
    let a = RecoveryKey::from_secret([1; 32]).derive().unwrap();
    let b = RecoveryKey::from_secret([2; 32]).derive().unwrap();
    assert_ne!(a.vault_id, b.vault_id);
    assert_ne!(a.access_hash(), b.access_hash());
    let all = [
        &a.vault_id,
        &*a.vault_access,
        &*a.manifest,
        &*a.chunk,
        &*a.chunk_name,
    ];
    for (i, x) in all.iter().enumerate() {
        for y in &all[i + 1..] {
            assert_ne!(x, y);
        }
    }
}

#[test]
fn a_backup_restores_exactly_what_was_written() {
    let k = keys();
    let mut store = Store::default();
    let (obj, m, stats, written) = backup(&k, &mut store, &SHAPE, 0, None, SMALL);
    assert!(stats.new_chunks > 20, "{stats:?}");
    // Every referenced chunk was either new or reused (a repeated large file is cut again and
    // counted as reused, then dropped as a duplicate).
    let referenced = m
        .streams
        .iter()
        .map(|s| u64::try_from(s.chunks.len()).unwrap())
        .sum::<u64>();
    assert!(stats.reused_chunks + stats.new_chunks >= referenced);
    assert_eq!(u64::try_from(store.0.len()).unwrap(), stats.new_chunks);
    // Forwards stored once: fewer distinct media than media messages.
    let media_messages = 12 * 150 / 25;
    assert!(
        stats.media < media_messages,
        "{} of {media_messages}",
        stats.media
    );

    let restored = restore(&k, &mut store, &obj).unwrap();
    assert_eq!(without_media(restored.clone()), written);
    // Every media reference a message holds has its file.
    let opened = object::open_manifest(&k, &obj, None).unwrap();
    let mut staging = MemoryStaging::default();
    reader::verify(&k, &opened.manifest, &mut store, &mut staging).unwrap();
    let b = Backup::new(&k, &opened.manifest, &staging);
    let mut files = std::collections::HashMap::new();
    for blob in b.blobs() {
        let (r, data) = blob.unwrap();
        files.insert(r, data.to_vec());
    }
    for r in b.media_streams() {
        let mut v = vec![];
        std::io::Read::read_to_end(&mut b.media(&r).unwrap(), &mut v).unwrap();
        files.insert(r, v);
    }
    let mut checked = 0;
    for (c, chat) in written
        .iter()
        .filter(|b| matches!(b, Body::Chat(_)))
        .enumerate()
    {
        let Body::Chat(chat) = chat else {
            unreachable!()
        };
        for body in &written {
            if let Body::Message(msg) = body
                && msg.chat_id == chat.chat_id
                && let Some(r) = msg.media.first()
            {
                let n = u32::try_from((msg.sent_ms - 1_700_000_000_000) / 60_000).unwrap();
                let want = synth::media_of(&SHAPE, u32::try_from(c).unwrap(), n).unwrap();
                assert_eq!(files[&<[u8; 32]>::try_from(r.as_slice()).unwrap()], want);
                checked += 1;
            }
        }
    }
    assert_eq!(checked, media_messages);
    let _ = m;
}

#[test]
fn a_second_backup_uploads_only_what_changed() {
    let k = keys();
    let mut store = Store::default();
    let (obj1, m1, s1, _) = backup(&k, &mut store, &SHAPE, 0, None, SMALL);
    let h1 = object::manifest_hash(&obj1);

    // Nothing changed: no new chunk.
    let (_, _, same, _) = backup(&k, &mut store, &SHAPE, 0, Some((&m1, h1, 1)), SMALL);
    assert_eq!(same.new_chunks, 0, "{same:?}");

    // Ten new messages in every chat: a small fraction is new.
    let before = store.0.len();
    let (obj2, m2, s2, written) = backup(&k, &mut store, &SHAPE, 10, Some((&m1, h1, 1)), SMALL);
    assert!(
        s2.new_chunks * 4 < s1.new_chunks,
        "first {s1:?}, then {s2:?}"
    );
    assert_eq!(
        store.0.len(),
        before + usize::try_from(s2.new_chunks).unwrap()
    );
    let opened = object::open_manifest(
        &k,
        &obj2,
        Some(Seen {
            generation: 1,
            hash: h1,
        }),
    )
    .unwrap();
    assert_eq!(opened.generation, 2);
    assert_eq!(opened.manifest.previous, h1);
    assert_eq!(
        without_media(restore(&k, &mut store, &obj2).unwrap()),
        written
    );

    // Chunks only the old manifest references are what a client deletes afterwards.
    let names = |m: &Manifest| -> std::collections::HashSet<Vec<u8>> {
        m.streams
            .iter()
            .flat_map(|s| s.chunks.iter().map(|c| c.name.clone()))
            .collect()
    };
    let unreferenced = names(&m1).difference(&names(&m2)).count();
    assert!(unreferenced < usize::try_from(s1.new_chunks).unwrap() / 4);
}

#[test]
fn production_parameters_cut_megabyte_chunks() {
    let k = keys();
    let mut store = Store::default();
    let shape = Shape {
        chats: 40,
        messages_per_chat: 800,
        media_every: 0,
        ..SHAPE
    };
    let (obj, m, _, written) = backup(&k, &mut store, &shape, 0, None, Params::BACKUP);
    let records = &m.streams[0];
    assert_eq!(records.kind, i32::from(StreamKind::Records));
    for c in &records.chunks[..records.chunks.len() - 1] {
        assert!((1 << 20..=8 << 20).contains(&c.length), "{}", c.length);
    }
    assert_eq!(
        without_media(restore(&k, &mut store, &obj).unwrap()),
        written
    );
}

fn corrupt(f: impl Fn(&mut Store, &[ChunkName])) -> Error {
    let k = keys();
    let mut store = Store::default();
    let (obj, m, _, _) = backup(&k, &mut store, &SHAPE, 0, None, SMALL);
    let names: Vec<ChunkName> = m
        .streams
        .iter()
        .flat_map(|s| {
            s.chunks
                .iter()
                .map(|c| ChunkName::from_slice(&c.name).unwrap())
        })
        .collect();
    f(&mut store, &names);
    restore(&k, &mut store, &obj).expect_err("a damaged backup must not restore")
}

#[test]
fn damaged_chunks_fail_loudly() {
    // One flipped bit anywhere in a chunk: its tag fails.
    for at in [0usize, 3, 10, 40, 500] {
        let e = corrupt(|s, n| {
            let o = s.0.get_mut(&n[5]).unwrap();
            let i = at.min(o.len() - 1);
            o[i] ^= 1;
        });
        assert!(
            matches!(e, Error::Damaged(_) | Error::Malformed(_)),
            "{at}: {e:?}"
        );
    }
    let last = |s: &mut Store, n: &[ChunkName]| {
        let o = s.0.get_mut(&n[n.len() - 1]).unwrap();
        let l = o.len();
        o[l - 1] ^= 0x80;
    };
    assert!(matches!(corrupt(last), Error::Damaged(_)));
    // Truncated, extended, emptied.
    assert!(matches!(
        corrupt(|s, n| {
            s.0.get_mut(&n[2]).unwrap().truncate(100);
        }),
        Error::Damaged(_)
    ));
    assert!(matches!(
        corrupt(|s, n| s.0.get_mut(&n[2]).unwrap().extend_from_slice(&[0; 16])),
        Error::Damaged(_)
    ));
    assert!(matches!(
        corrupt(|s, n| s.0.get_mut(&n[2]).unwrap().clear()),
        Error::Malformed(_)
    ));
    // Missing.
    assert!(matches!(
        corrupt(|s, n| {
            s.0.remove(&n[7]);
        }),
        Error::Missing
    ));
    // Two chunks swapped (a store serving one under the other's name): the name is in the AAD.
    let e = corrupt(|s, n| {
        let a = s.0[&n[1]].clone();
        let b = s.0[&n[4]].clone();
        s.0.insert(n[1], b);
        s.0.insert(n[4], a);
    });
    assert!(matches!(e, Error::Damaged(_)), "{e:?}");
    // A chunk from another backup (another key) under a name of this one.
    let e = corrupt(|s, n| {
        let other = RecoveryKey::from_secret([9; 32]).derive().unwrap();
        let obj = object::seal_chunk(&other, &n[3], b"forged", &mut OsRng).unwrap();
        s.0.insert(n[3], obj);
    });
    assert!(matches!(e, Error::Damaged(_)), "{e:?}");
}

#[test]
fn damaged_manifests_fail_loudly() {
    let k = keys();
    let mut store = Store::default();
    let (obj, m, _, _) = backup(&k, &mut store, &SHAPE, 0, None, SMALL);
    for at in [0, 3, 5, 20, 40, obj.len() / 2, obj.len() - 1] {
        let mut bad = obj.clone();
        bad[at] ^= 4;
        let e = object::open_manifest(&k, &bad, None).unwrap_err();
        assert!(
            matches!(e, Error::Damaged(_) | Error::Malformed(_)),
            "{at}: {e:?}"
        );
    }
    for n in [0, 10, 36, 52, obj.len() - 1] {
        assert!(object::open_manifest(&k, &obj[..n], None).is_err());
    }
    // Another account's key, or the right key and another vault ID.
    let other = RecoveryKey::from_secret([8; 32]).derive().unwrap();
    assert!(matches!(
        object::open_manifest(&other, &obj, None),
        Err(Error::Damaged(_))
    ));
    let mut moved = keys();
    moved.vault_id[0] ^= 1;
    assert!(matches!(
        object::open_manifest(&moved, &obj, None),
        Err(Error::Damaged(_))
    ));
    // The generation is authenticated: a store cannot relabel one.
    let mut relabelled = obj.clone();
    relabelled[11] ^= 1;
    assert!(matches!(
        object::open_manifest(&k, &relabelled, None),
        Err(Error::Damaged(_))
    ));
    // A newer format that older readers must not half-read.
    let mut newer = m.clone();
    newer.min_reader_version = 2;
    let sealed = object::seal_manifest(&k, 1, &newer, &mut OsRng).unwrap();
    assert!(matches!(
        object::open_manifest(&k, &sealed, None),
        Err(Error::TooNew)
    ));
    // A manifest naming a stream whose length does not add up.
    let mut wrong = m.clone();
    wrong.streams[0].length += 1;
    let sealed = object::seal_manifest(&k, 1, &wrong, &mut OsRng).unwrap();
    assert!(matches!(
        object::open_manifest(&k, &sealed, None),
        Err(Error::Malformed(_))
    ));
    // A manifest whose stream hash does not match its chunks.
    let mut wrong = m;
    wrong.streams[0].sha256[0] ^= 1;
    let sealed = object::seal_manifest(&k, 1, &wrong, &mut OsRng).unwrap();
    assert!(matches!(
        restore(&k, &mut store, &sealed),
        Err(Error::StreamMismatch)
    ));
}

#[test]
fn a_store_cannot_roll_back_or_fork_a_device_that_has_seen_a_backup() {
    let k = keys();
    let mut store = Store::default();
    let (o1, m1, _, _) = backup(&k, &mut store, &SHAPE, 0, None, SMALL);
    let h1 = object::manifest_hash(&o1);
    let (o2, m2, _, _) = backup(&k, &mut store, &SHAPE, 3, Some((&m1, h1, 1)), SMALL);
    let seen2 = object::open_manifest(&k, &o2, None).unwrap().seen();
    // Garbage with an older or equal generation in its header is damage, not a tamper alarm:
    // only an authenticated header is judged.
    let mut junk = o1.clone();
    let last = junk.len() - 1;
    junk[last] ^= 1;
    assert!(matches!(
        object::open_manifest(&k, &junk, Some(seen2)),
        Err(Error::Damaged(_))
    ));
    // An older backup after a newer one: refused.
    assert!(matches!(
        object::open_manifest(&k, &o1, Some(seen2)),
        Err(Error::Rollback)
    ));
    // The same generation with other content: a fork.
    let (o2b, _, _, _) = backup(&k, &mut store, &SHAPE, 4, Some((&m1, h1, 1)), SMALL);
    assert!(matches!(
        object::open_manifest(&k, &o2b, Some(seen2)),
        Err(Error::Fork)
    ));
    // The next generation must chain to the one seen.
    let (o3, _, _, _) = backup(&k, &mut store, &SHAPE, 5, Some((&m2, [0; 32], 2)), SMALL);
    assert!(matches!(
        object::open_manifest(&k, &o3, Some(seen2)),
        Err(Error::Fork)
    ));
    let (o3, _, _, _) = backup(&k, &mut store, &SHAPE, 5, Some((&m2, seen2.hash, 2)), SMALL);
    assert_eq!(
        object::open_manifest(&k, &o3, Some(seen2))
            .unwrap()
            .generation,
        3
    );
    // The same manifest again is fine.
    assert!(object::open_manifest(&k, &o2, Some(seen2)).is_ok());
}

#[test]
fn staging_changed_after_verification_fails_on_read() {
    let k = keys();
    let mut store = Store::default();
    let (obj, _, _, _) = backup(&k, &mut store, &SHAPE, 0, None, SMALL);
    let opened = object::open_manifest(&k, &obj, None).unwrap();
    let mut staging = MemoryStaging::default();
    reader::verify(&k, &opened.manifest, &mut store, &mut staging).unwrap();
    let first = ChunkName::from_slice(&opened.manifest.streams[0].chunks[1].name).unwrap();
    let mut o = staging.get(&first).unwrap();
    o[50] ^= 1;
    staging.put(&first, o).unwrap();
    let b = Backup::new(&k, &opened.manifest, &staging);
    let r: Result<Vec<_>, _> = b.records().collect();
    assert!(matches!(r, Err(Error::Damaged(_))), "{r:?}");
}

#[test]
fn a_folder_stages_large_backups_encrypted() {
    let k = keys();
    let mut store = Store::default();
    let (obj, _, _, written) = backup(&k, &mut store, &SHAPE, 0, None, SMALL);
    let dir = tempfile::tempdir().unwrap();
    let opened = object::open_manifest(&k, &obj, None).unwrap();
    let mut staging = reader::DirStaging::new(dir.path().join("staging")).unwrap();
    let v = reader::verify(&k, &opened.manifest, &mut store, &mut staging).unwrap();
    assert_eq!(v.chunks, u64::try_from(store.0.len()).unwrap());
    // No plaintext on disk: a message text never appears in a staged file.
    let needle = match &written[written.len() - 1] {
        Body::Message(m) => m.content.clone(),
        _ => unreachable!(),
    };
    for e in std::fs::read_dir(dir.path().join("staging")).unwrap() {
        let bytes = std::fs::read(e.unwrap().path()).unwrap();
        assert!(!bytes.windows(needle.len()).any(|w| w == needle));
    }
    let b = Backup::new(&k, &opened.manifest, &staging);
    let got: Vec<Body> = b.records().map(|r| r.unwrap().body.unwrap()).collect();
    assert_eq!(without_media(got), written);
}

#[test]
fn fixed_randomness_gives_fixed_bytes_and_os_randomness_does_not() {
    let k = keys();
    let mk = |seed: [u8; 32]| {
        let mut store = Store::default();
        let mut rng = FixedRng::new(seed);
        let mut w = Writer::with_params(&k, None, &mut rng, &mut store, SMALL);
        synth::write(&mut w, &SHAPE, 0).unwrap();
        let (obj, ..) = w.finish(&info(1, None)).unwrap();
        (obj, store)
    };
    let (a, sa) = mk([1; 32]);
    let (b, sb) = mk([1; 32]);
    assert_eq!(a, b);
    assert_eq!(sa.0, sb.0);
    let (c, sc) = mk([2; 32]);
    assert_ne!(a, c);
    // Names depend only on content and key, never on randomness.
    assert_eq!(
        sa.0.keys().collect::<Vec<_>>(),
        sc.0.keys().collect::<Vec<_>>()
    );
}

#[test]
fn debug_output_never_shows_content() {
    let a = synth::account(1);
    let s = format!(
        "{a:?} {:?} {:?}",
        Body::Account(a.clone()),
        ChunkName([0xab; 32])
    );
    assert!(!s.contains("songbird.42") && !s.contains("ab"), "{s}");
}
