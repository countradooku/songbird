//! ID decoding from bytes and hex: never panics; round-trips.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_types::DeviceId;

fuzz_target!(|data: &[u8]| {
    if let Ok(id) = DeviceId::from_slice(data) {
        assert_eq!(id.as_bytes().as_slice(), data);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(id) = DeviceId::parse_hex(s) {
            assert_eq!(id.to_hex_unredacted(), s.to_ascii_lowercase());
        }
    }
});
