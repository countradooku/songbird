//! Ed25519 public-key check (`songbird-keys`) on arbitrary 32 bytes: never panics, and accepts
//! only keys that verify nothing without a private key (checked here: an all-zero signature is
//! never valid under an accepted key).
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_keys::{ed25519_public_key_ok, ed25519_verify};

fuzz_target!(|data: &[u8]| {
    let Ok(key) = <[u8; 32]>::try_from(data) else {
        return;
    };
    if ed25519_public_key_ok(&key) {
        assert!(!ed25519_verify(&key, b"m", &[0; 64]));
    }
});
