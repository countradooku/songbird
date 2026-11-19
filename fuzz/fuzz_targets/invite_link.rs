//! Invite link parser (Prompt 11, D-0132): never panics; whatever parses, round-trips exactly.
//! The input is tried as is and after the link's prefix, so the fuzzer reaches the decoder.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proto::invite_link::{InviteLink, PREFIX};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    for link in [s.to_owned(), format!("{PREFIX}{s}")] {
        if let Some(l) = InviteLink::parse(&link) {
            assert_eq!(l.to_link(), link);
        }
    }
});
