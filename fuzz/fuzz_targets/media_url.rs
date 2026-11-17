//! Signed media URLs and `Range` headers (Prompt 6, M3, D-0082): the query and range parsers
//! never panic; an accepted query re-encodes to itself; an accepted range lies inside the object.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_api::media::{MediaQuery, RangeAsk, parse_range};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(q) = MediaQuery::parse(s) {
        let again = format!("e={}&z={}&s={}", q.expires, q.size, hex(&q.mac));
        assert_eq!(MediaQuery::parse(&again), Some(q));
    }
    let size = u64::from(data.first().copied().unwrap_or(0)) << (data.len() % 40);
    match parse_range(Some(s), size) {
        RangeAsk::Part(a, b) => assert!(a <= b && b < size),
        RangeAsk::Unsatisfiable | RangeAsk::Whole => {}
    }
});

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
