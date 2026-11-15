//! Proof-of-work challenge decoder and authenticator (unauthenticated input inside
//! `POST /v1/registration`): never panics; anything decoded re-encodes byte for byte and has
//! parameters within bounds; nothing the fuzzer makes passes the MAC.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_pow::{ChallengeKey, decode};

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = decode(data) {
        assert_eq!(&c.bytes[..], data);
        assert!(c.params.in_bounds());
    }
    let key = ChallengeKey::derive(&[0x5A; 32]).expect("hkdf");
    assert!(key.check(data, 1_763_164_800_000, 600_000).is_err());
});
