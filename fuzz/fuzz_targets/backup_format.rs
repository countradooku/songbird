//! The backup format (Prompt 10, M1, D-0120): whatever a store or a person hands the reader
//! never panics: recovery keys, chunk and manifest objects, manifest plaintexts, and the record
//! and blob streams inside a correctly sealed chunk (what a writer with the key could produce).
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_backup_format::object::{self, ChunkName};
use songbird_backup_format::reader::{self, Backup, ChunkSource, MemoryStaging};
use songbird_backup_format::schema::{ChunkRef, Manifest, Stream, StreamKind};
use songbird_backup_format::{Error, FixedRng, RecoveryKey};

struct One(ChunkName, Vec<u8>);
impl ChunkSource for One {
    fn get(&mut self, name: &ChunkName) -> Result<Vec<u8>, Error> {
        if *name == self.0 { Ok(self.1.clone()) } else { Err(Error::Missing) }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = RecoveryKey::parse(s);
    }
    let keys = RecoveryKey::from_secret([5; 32]).derive().unwrap();
    let _ = object::manifest_generation(data);
    let _ = object::open_manifest(&keys, data, None);
    let _ = object::decode_manifest(data);
    if let Some((name, rest)) = data.split_first_chunk::<32>() {
        let _ = object::open_chunk(&keys, &ChunkName(*name), u32::try_from(rest.len()).unwrap_or(0), rest);
    }
    // The bytes as the plaintext of a records stream and of a small-media stream.
    if data.is_empty() || data.len() > 1 << 16 {
        return;
    }
    let name = object::chunk_name(&keys, data);
    let sealed = object::seal_chunk(&keys, &name, data, &mut FixedRng::new([1; 32])).unwrap();
    for kind in [StreamKind::Records, StreamKind::SmallMedia] {
        let sha = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
        let stream = Stream {
            kind: kind.into(),
            id: vec![],
            length: data.len() as u64,
            sha256: sha.as_ref().to_vec(),
            chunks: vec![ChunkRef { name: name.0.to_vec(), length: data.len() as u32 }],
        };
        let mut streams = vec![stream];
        if kind == StreamKind::SmallMedia {
            streams.insert(0, Stream { kind: StreamKind::Records.into(), sha256: aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"").as_ref().to_vec(), ..Stream::default() });
        }
        let m = Manifest { format_version: 1, min_reader_version: 1, streams, ..Manifest::default() };
        let mut staging = MemoryStaging::default();
        if reader::verify(&keys, &m, &mut One(name, sealed.clone()), &mut staging).is_ok() {
            let b = Backup::new(&keys, &m, &staging);
            for r in b.records() {
                let _ = r;
            }
            for r in b.blobs() {
                let _ = r;
            }
        }
    }
});
