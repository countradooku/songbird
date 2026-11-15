//! Registration request decoder (`POST /v1/registration`, unauthenticated input) and the invite
//! code parser: never panic; anything accepted re-encodes to the same bytes (one encoding per
//! request), and a parsed code formats back to a string that parses to the same code.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proto::registration::{MAX_LEN, MAX_SOLUTIONS, RegisterRequest, invite};

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = RegisterRequest::decode(data) {
        assert!(data.len() <= MAX_LEN);
        assert!(!r.solutions.is_empty() && r.solutions.len() <= MAX_SOLUTIONS);
        assert_eq!(r.encode(), data);
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Some(code) = invite::parse(text)
    {
        assert_eq!(invite::parse(&invite::format(&code)), Some(code));
    }
});
