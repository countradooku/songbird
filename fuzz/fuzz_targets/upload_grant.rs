//! Upload grants (Prompt 6, M2, D-0081): the grant decoder never panics, and whatever it accepts
//! is a length the attachment format produces, within the limits.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_api::media::{GrantRequest, part_count, part_len};

fuzz_target!(|data: &[u8]| {
    let max = 2u64 << 30;
    if let Some(g) = GrantRequest::decode(data, max, 1024) {
        assert!(g.size <= max && (1..=1024).contains(&g.fetches));
        assert!(songbird_proto::media::padded_from_ciphertext(g.size).is_some());
        // Its parts cover it exactly.
        let part = 16 << 20;
        let total: u64 = (1..=part_count(g.size, part))
            .map(|n| part_len(g.size, part, n).unwrap())
            .sum();
        assert_eq!(total, g.size);
    }
});
