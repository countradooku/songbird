//! Key directory decoders (`PUT /v1/keys` bodies, fetch answers) and the key checks behind them
//! (XEdDSA, X25519 honesty, ML-KEM-1024 modulus check): never panic; anything decoded
//! re-encodes byte for byte; nothing the fuzzer makes verifies as a signature.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_keys::{kem, xeddsa};
use songbird_proto::keys::{Upload, decode_bundles, encode_bundles};

fuzz_target!(|data: &[u8]| {
    if let Ok(u) = Upload::decode(data) {
        assert_eq!(u.encode(), data);
    }
    if let Ok(b) = decode_bundles(data) {
        assert_eq!(encode_bundles(&b), data);
    }
    let _ = kem::public_key_ok(data);
    if let Some((key, rest)) = data.split_first_chunk::<32>()
        && let Some((sig, message)) = rest.split_first_chunk::<64>()
    {
        let _ = xeddsa::x25519_public_key_ok(key);
        assert!(!xeddsa::verify(key, message, sig));
    }
});
