//! Prompt 10, M1 (D-0120): any content round-trips, with any chunk boundaries.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::collections::HashMap;

use proptest::prelude::*;
use songbird_backup_format::chunker::Params;
use songbird_backup_format::object::{self, ChunkName};
use songbird_backup_format::reader::{self, Backup, ChunkSource, MemoryStaging};
use songbird_backup_format::schema::{Media, Message, Platform, Setting, record::Body};
use songbird_backup_format::writer::{ChunkSink, Info, Writer};
use songbird_backup_format::{Error, OsRng, RecoveryKey};

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

#[derive(Debug, Clone)]
enum Item {
    Setting(String, Vec<u8>),
    Message(Vec<u8>),
    Media(Vec<u8>),
}

fn item() -> impl Strategy<Value = Item> {
    prop_oneof![
        ("[a-z/]{1,20}", prop::collection::vec(any::<u8>(), 0..64))
            .prop_map(|(k, v)| Item::Setting(k, v)),
        prop::collection::vec(any::<u8>(), 0..3000).prop_map(Item::Message),
        (
            prop_oneof![0usize..40_000, 1_048_570usize..1_300_000],
            any::<u8>()
        )
            .prop_map(|(n, b)| Item::Media(vec![b; n])),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    #[test]
    fn anything_written_reads_back(items in prop::collection::vec(item(), 0..80), min in 64usize..2048) {
        let params = Params { min, avg: min * 4, max: min * 16, hard: !0u64 << (64 - 14), easy: !0u64 << (64 - 10) };
        let keys = RecoveryKey::from_secret([3; 32]).derive().unwrap();
        let mut store = Store::default();
        let mut rng = OsRng;
        let mut w = Writer::with_params(&keys, None, &mut rng, &mut store, params);
        let mut want = vec![];
        let mut files = HashMap::new();
        for it in &items {
            match it {
                Item::Setting(k, v) => {
                    let b = Body::Setting(Setting { key: k.clone(), value: v.clone() });
                    want.push(b.clone());
                    w.record(b).unwrap();
                }
                Item::Message(c) => {
                    let b = Body::Message(Message { content: c.clone(), ..Message::default() });
                    want.push(b.clone());
                    w.record(b).unwrap();
                }
                Item::Media(bytes) => {
                    let r = w.media(Media::default(), &mut bytes.as_slice()).unwrap();
                    files.insert(r, bytes.clone());
                }
            }
        }
        let info = Info { generation: 9, previous: None, created_ms: 0, app_version: String::new(), platform: Platform::Ios };
        let (obj, ..) = w.finish(&info).unwrap();
        let opened = object::open_manifest(&keys, &obj, None).unwrap();
        prop_assert_eq!(opened.generation, 9);
        let mut staging = MemoryStaging::default();
        reader::verify(&keys, &opened.manifest, &mut store, &mut staging).unwrap();
        let b = Backup::new(&keys, &opened.manifest, &staging);
        let got: Vec<Body> = b.records().map(|r| r.unwrap().body.unwrap()).filter(|b| !matches!(b, Body::Media(_))).collect();
        prop_assert_eq!(got, want);
        let mut restored: HashMap<[u8; 32], Vec<u8>> = b.blobs().map(|x| { let (r, d) = x.unwrap(); (r, d.to_vec()) }).collect();
        for r in b.media_streams() {
            let mut v = vec![];
            std::io::Read::read_to_end(&mut b.media(&r).unwrap(), &mut v).unwrap();
            restored.insert(r, v);
        }
        prop_assert_eq!(restored, files);
    }
}
