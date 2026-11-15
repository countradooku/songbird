//! MLS KeyPackage checks (`songbird-keys::mls`, input to `PUT /v1/keypackages`) and the KeyPackage
//! upload and fetch decoders: never panic; a package that passes (the corpus seeds OpenMLS's own)
//! is within bounds and carries the reference of exactly its bytes; a decoded fetch answer
//! re-encodes byte for byte.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_keys::mls;
use songbird_proto::keys::{
    decode_key_package_bundles, decode_key_packages, encode_key_package_bundles,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = mls::check(data, &[0xD1; 16], 1_794_753_144) {
        assert!(data.len() <= mls::MAX_LEN);
        assert_eq!(c.reference, mls::reference(data));
    }
    let _ = decode_key_packages(data);
    if let Ok(b) = decode_key_package_bundles(data) {
        assert_eq!(encode_key_package_bundles(&b), data);
    }
});
