//! Proxy link parser: never panics; whatever parses, round-trips.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proxy::link::ProxyLink;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(l) = ProxyLink::parse(s, &["songbird.example"]) {
        assert_eq!(ProxyLink::parse(&l.to_app_link(), &[]).unwrap(), l);
    }
});
