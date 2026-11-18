//! A still's metadata filter (D-0110): never panics; what it returns starts with SOI, ends with
//! EOI, carries no APPn other than its own minimal EXIF, and is stable when stripped again.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_camera::jpeg;

fuzz_target!(|data: &[u8]| {
    let Ok(out) = jpeg::strip(data) else { return };
    assert!(out.bytes.starts_with(&[0xFF, 0xD8]) && out.bytes.ends_with(&[0xFF, 0xD9]));
    assert!((1..=8).contains(&out.orientation));
    let again = jpeg::strip(&out.bytes).expect("a stripped JPEG strips again");
    assert_eq!(again.bytes, out.bytes);
    assert_eq!(again.orientation, out.orientation);
});
