//! Throughput of the backup pipeline's parts (D-0120): the keyed chunker, chunk sealing and
//! opening (HMAC name, Padmé, XChaCha20-Poly1305), and a whole backup and verified restore.
//!
//! `cargo test --release -p songbird-backup-format --test bench -- --ignored --nocapture`
#![allow(
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::indexing_slicing,
    reason = "a benchmark"
)]

use std::collections::HashMap;
use std::time::Instant;

use songbird_backup_format::chunker::{self, Params};
use songbird_backup_format::object::{self, ChunkName};
use songbird_backup_format::reader::{self, ChunkSource, MemoryStaging};
use songbird_backup_format::schema::Platform;
use songbird_backup_format::synth::{self, Gen, Shape};
use songbird_backup_format::writer::{ChunkSink, Info, Writer};
use songbird_backup_format::{Error, OsRng, RecoveryKey};

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

#[derive(Default)]
struct Store(HashMap<ChunkName, Vec<u8>>);
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

#[test]
#[ignore = "a benchmark: run in release by hand"]
fn throughput() {
    let keys = RecoveryKey::from_secret([1; 32]).derive().unwrap();
    let data = Gen::new(1).bytes(256 << 20);
    let mb = data.len() as f64 / 1e6;
    let mut cut = vec![];
    let mut sizes = vec![];
    for _ in 0..5 {
        let t = Instant::now();
        let mut at = 0;
        sizes.clear();
        while let Some(c) = chunker::cut(&keys.gear, &Params::BACKUP, &data[at..], true) {
            sizes.push(c);
            at += c;
        }
        cut.push(mb / t.elapsed().as_secs_f64());
    }
    let avg = data.len() / sizes.len();
    eprintln!(
        "chunker: {:.0} MB/s, {} chunks of {:.2} MiB on average",
        median(cut),
        sizes.len(),
        avg as f64 / f64::from(1 << 20)
    );

    let piece = &data[..sizes[0]];
    let (mut seal, mut open) = (vec![], vec![]);
    for _ in 0..9 {
        let t = Instant::now();
        let name = object::chunk_name(&keys, piece);
        let o = object::seal_chunk(&keys, &name, piece, &mut OsRng).unwrap();
        seal.push(piece.len() as f64 / 1e6 / t.elapsed().as_secs_f64());
        let t = Instant::now();
        object::open_chunk(&keys, &name, u32::try_from(piece.len()).unwrap(), &o).unwrap();
        open.push(piece.len() as f64 / 1e6 / t.elapsed().as_secs_f64());
    }
    eprintln!(
        "chunk seal (name + pad + XChaCha20-Poly1305): {:.0} MB/s; open and check: {:.0} MB/s",
        median(seal),
        median(open)
    );

    let shape = Shape {
        seed: 5,
        chats: 200,
        messages_per_chat: 2_000,
        media_every: 40,
        media_sizes: &[40_000, 300_000, 2_500_000],
        contacts: 300,
    };
    let mut store = Store::default();
    let mut rng = OsRng;
    let t = Instant::now();
    let mut w = Writer::new(&keys, None, &mut rng, &mut store);
    synth::write(&mut w, &shape, 0).unwrap();
    let info = Info {
        generation: 1,
        previous: None,
        created_ms: 0,
        app_version: String::new(),
        platform: Platform::Macos,
    };
    let (obj, _, stats, _) = w.finish(&info).unwrap();
    let wt = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let opened = object::open_manifest(&keys, &obj, None).unwrap();
    let mut staging = MemoryStaging::default();
    reader::verify(&keys, &opened.manifest, &mut store, &mut staging).unwrap();
    let vt = t.elapsed().as_secs_f64();
    eprintln!(
        "backup of 400,000 messages and {} media files: {:.0} MB plaintext, {} chunks, {:.0} MB stored; written in {wt:.2} s ({:.0} MB/s), verified in {vt:.2} s; manifest {} bytes",
        stats.media,
        stats.plaintext_bytes as f64 / 1e6,
        stats.new_chunks,
        stats.new_bytes as f64 / 1e6,
        stats.plaintext_bytes as f64 / 1e6 / wt,
        obj.len()
    );
}
