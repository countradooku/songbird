//! Username proof verification (input to `PUT /v1/username`) and the username parser: never
//! panic; nothing the fuzzer makes verifies; a parsed username's own proof verifies.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_keys::username::{HASH_LEN, Username, verify_proof};

fuzz_target!(|data: &[u8]| {
    if let Some((hash, proof)) = data.split_first_chunk::<HASH_LEN>() {
        assert!(!verify_proof(hash, proof));
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(u) = Username::parse(text)
    {
        assert!(verify_proof(&u.hash(), &u.proof(&[7; 32])));
    }
});
