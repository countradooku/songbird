//! The proxy's ClientHello SNI scanner on arbitrary bytes: never panics, never reads past input,
//! and any host it returns is a valid DNS name.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proxy::sni::{Scan, scan, validate_host};

fuzz_target!(|data: &[u8]| {
    let mut scratch = vec![0u8; 16 * 1024];
    if let Ok(Scan::Host(h)) = scan(data, &mut scratch) {
        assert!(validate_host(h.as_bytes()).is_ok());
    }
});
