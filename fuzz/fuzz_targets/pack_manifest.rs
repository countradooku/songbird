//! Pack manifests (Prompt 6, M4, D-0083): the decoder never panics, and what it accepts is within
//! every bound and seals back to an object that opens to the same manifest.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_content::pack::{MAX_ITEMS, Manifest};

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Manifest::open(data) {
        assert!((1..=MAX_ITEMS).contains(&m.items.len()));
        let again = m.seal().unwrap();
        assert_eq!(Manifest::open(&again).unwrap(), m);
    }
});
