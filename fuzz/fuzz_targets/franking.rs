//! Message franking (Prompt 4, M3 and M5): the franked-envelope and report decoders never panic,
//! and what they accept re-encodes byte for byte.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proto::envelope::Stamp;
use songbird_proto::report::Report;

fuzz_target!(|data: &[u8]| {
    if let Ok((stamp, envelope)) = Stamp::split(data) {
        assert_eq!(&stamp.prepend(envelope)[..], data);
    }
    if let Ok(r) = Report::decode(data) {
        assert_eq!(r.encode(), data);
    }
});
