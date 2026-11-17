//! The object store's multipart answers (Prompt 6, M2, D-0081): the bounded parsers never panic,
//! and what they accept is well formed (printable tokens, parts in increasing order).
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_s3::multipart::parse;

fuzz_target!(|data: &[u8]| {
    if let Ok(id) = parse::upload_id(data) {
        assert!(!id.is_empty() && id.bytes().all(|b| b.is_ascii_graphic()));
    }
    if let Ok(parts) = parse::list_parts(data) {
        assert!(parts.windows(2).all(|w| w[0].number < w[1].number));
        assert!(parts.iter().all(|p| p.number >= 1 && !p.etag.is_empty()));
    }
    if let Ok((ups, _)) = parse::list_uploads(data) {
        assert!(ups.iter().all(|u| !u.key.is_empty() && !u.upload_id.is_empty()));
    }
    let _ = parse::complete_result(data);
});
