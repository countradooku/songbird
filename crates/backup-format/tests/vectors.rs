//! Prompt 10, M1 (D-0120): byte-exact vectors, the cross-platform determinism check, and the
//! compatibility suite (every published version's backup reads with this reader).
//!
//! `SONGBIRD_WRITE_BACKUP_VECTORS=1 cargo test -p songbird-backup-format --test vectors` writes
//! `vectors/v1/vectors.json`; published versions are never rewritten.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::collections::BTreeMap;

use aws_lc_rs::digest;
use serde_json::{Value, json};
use songbird_backup_format::chunker::Params;
use songbird_backup_format::object::{self, ChunkName};
use songbird_backup_format::reader::{self, Backup, ChunkSource, MemoryStaging};
use songbird_backup_format::schema::{Platform, record::Body};
use songbird_backup_format::synth::{self, Shape};
use songbird_backup_format::writer::{ChunkSink, Info, Writer};
use songbird_backup_format::{Error, FixedRng, RecoveryKey};

#[derive(Default)]
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

const SECRET: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];
const RNG_SEED: [u8; 32] = [0x5b; 32];

const TINY: Shape = Shape {
    seed: 3,
    chats: 2,
    messages_per_chat: 3,
    media_every: 2,
    media_sizes: &[100, 2_000],
    contacts: 1,
};

/// Large enough to cut several production-size chunks and to stream media.
const DETERMINISM: Shape = Shape {
    seed: 17,
    chats: 60,
    messages_per_chat: 700,
    media_every: 90,
    media_sizes: &[5_000, 1_500_000, 3_100_000, 700],
    contacts: 50,
};

fn info() -> Info {
    Info {
        generation: 1,
        previous: None,
        created_ms: 1_800_000_000_000,
        app_version: "vectors".into(),
        platform: Platform::Unknown,
    }
}

fn write(shape: &Shape, params: Params) -> (Vec<u8>, Store) {
    let keys = RecoveryKey::from_secret(SECRET).derive().unwrap();
    let mut store = Store::default();
    let mut rng = FixedRng::new(RNG_SEED);
    let mut w = Writer::with_params(&keys, None, &mut rng, &mut store, params);
    synth::write(&mut w, shape, 0).unwrap();
    let (obj, ..) = w.finish(&info()).unwrap();
    (obj, store)
}

fn sha(parts: &[&[u8]]) -> String {
    let mut c = digest::Context::new(&digest::SHA256);
    for p in parts {
        c.update(p);
    }
    hex::encode(c.finish())
}

fn current() -> Value {
    let key = RecoveryKey::from_secret(SECRET);
    let keys = key.derive().unwrap();
    let mut rng = FixedRng::new(RNG_SEED);
    let plain = b"hello, songbird";
    let name = object::chunk_name(&keys, plain);
    let chunk = object::seal_chunk(&keys, &name, plain, &mut rng).unwrap();
    let (manifest, store) = write(&TINY, Params::BACKUP);
    let (big, big_store) = write(&DETERMINISM, Params::BACKUP);
    let mut all: Vec<&[u8]> = vec![&big];
    all.extend(big_store.0.values().map(Vec::as_slice));
    json!({
        "version": 1,
        "recovery_key": {
            "secret": hex::encode(SECRET),
            "display": &*key.display(),
        },
        "keys": {
            "vault_id": hex::encode(keys.vault_id),
            "vault_access": hex::encode(*keys.vault_access),
            "access_hash": hex::encode(keys.access_hash()),
            "manifest": hex::encode(*keys.manifest),
            "chunk": hex::encode(*keys.chunk),
            "chunk_name": hex::encode(*keys.chunk_name),
            "gear_first_4": keys.gear[..4].iter().map(|g| format!("{g:016x}")).collect::<Vec<_>>(),
        },
        "chunk": {
            "rng_seed": hex::encode(RNG_SEED),
            "plaintext": hex::encode(plain),
            "name": name.to_hex(),
            "object": hex::encode(&chunk),
        },
        "backup": {
            "rng_seed": hex::encode(RNG_SEED),
            "manifest": hex::encode(&manifest),
            "chunks": store.0.iter().map(|(n, o)| (n.to_hex(), Value::String(hex::encode(o)))).collect::<serde_json::Map<_, _>>(),
        },
        "determinism": {
            "chunks": big_store.0.len(),
            "sha256_of_manifest_then_chunks_by_name": sha(&all),
        },
    })
}

fn path(version: u32) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join(format!("v{version}"))
        .join("vectors.json")
}

#[test]
fn this_build_produces_the_published_bytes() {
    let now = current();
    if std::env::var_os("SONGBIRD_WRITE_BACKUP_VECTORS").is_some() {
        let p = path(1);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, serde_json::to_string_pretty(&now).unwrap() + "\n").unwrap();
    }
    let published: Value =
        serde_json::from_str(&std::fs::read_to_string(path(1)).unwrap()).unwrap();
    // Field by field, so a difference names what changed.
    for k in ["recovery_key", "keys", "chunk", "backup", "determinism"] {
        assert_eq!(
            now[k],
            published[k],
            "vector {k} differs on {}",
            std::env::consts::ARCH
        );
    }
}

#[test]
fn the_recovery_key_vector_parses() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path(1)).unwrap()).unwrap();
    let k = RecoveryKey::parse(v["recovery_key"]["display"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(k.secret()), v["recovery_key"]["secret"]);
}

/// Every published version's backup verifies and reads with this reader.
#[test]
fn this_reader_restores_every_published_version() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let mut checked = 0;
    for e in std::fs::read_dir(root).unwrap() {
        let p = e.unwrap().path().join("vectors.json");
        if !p.exists() {
            continue;
        }
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let secret: [u8; 32] = hex::decode(v["recovery_key"]["secret"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let keys = RecoveryKey::from_secret(secret).derive().unwrap();
        let manifest = hex::decode(v["backup"]["manifest"].as_str().unwrap()).unwrap();
        let mut store = Store::default();
        for (n, o) in v["backup"]["chunks"].as_object().unwrap() {
            store.0.insert(
                ChunkName::from_hex(n).unwrap(),
                hex::decode(o.as_str().unwrap()).unwrap(),
            );
        }
        let opened = object::open_manifest(&keys, &manifest, None).unwrap();
        let mut staging = MemoryStaging::default();
        reader::verify(&keys, &opened.manifest, &mut store, &mut staging).unwrap();
        let b = Backup::new(&keys, &opened.manifest, &staging);
        let records: Vec<Body> = b.records().map(|r| r.unwrap().body.unwrap()).collect();
        assert!(matches!(records.first(), Some(Body::Account(a)) if a.identity_seed.len() == 32));
        assert!(records.iter().any(|r| matches!(r, Body::Message(_))));
        assert!(b.blobs().count() > 0);
        checked += 1;
    }
    assert!(checked >= 1);
}
