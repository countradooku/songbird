//! The SurrealDB CBOR decoder (every response the delivery service reads): never panics, stays
//! bounded, and anything it accepts re-encodes to an item that decodes to the same value.
#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use songbird_surreal::cbor;

fuzz_target!(|data: &[u8]| {
    let src = Bytes::copy_from_slice(data);
    if let Ok(v) = cbor::decode(&src) {
        let again = cbor::decode(&cbor::to_bytes(&v)).expect("re-encoding decodes");
        // NaN floats compare unequal to themselves; compare encodings instead.
        assert_eq!(cbor::to_bytes(&again), cbor::to_bytes(&v));
    }
});
