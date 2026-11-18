//! The record store (Prompt 9, M1): the server's decoders of writes, reads, heads and ID lists
//! never panic and re-encode byte for byte; the client's record and manifest openers never panic
//! on whatever the server sends.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proto::storage::{self, Head, Ids, Write};
use songbird_sync::StorageKey;
use songbird_sync::record::{open_manifest, open_record};

fuzz_target!(|data: &[u8]| {
    if let Ok(w) = Write::decode(data) {
        assert_eq!(w.encode(), data);
    }
    if let Ok(h) = Head::decode(data) {
        assert_eq!(h.encode(), data);
    }
    if let Ok(i) = Ids::decode(data) {
        assert_eq!(i.encode(), data);
    }
    if let Ok(ids) = storage::decode_read(data) {
        assert_eq!(storage::encode_read(&ids).ok().as_deref(), Some(data));
    }
    if let Ok(r) = storage::decode_records(data) {
        assert_eq!(storage::encode_records(&r), data);
    }
    let key = StorageKey::from_bytes([3; 32]);
    let _ = open_manifest(&key, data);
    if let Some((id, blob)) = data.split_first_chunk::<16>() {
        let _ = open_record(&key, id, blob);
    }
});
