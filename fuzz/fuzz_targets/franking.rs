//! Message franking (Prompt 4, M3 and M5): the franked-envelope decoder never panics, and what
//! it accepts re-encodes byte for byte.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proto::envelope::Stamp;

fuzz_target!(|data: &[u8]| {
    if let Ok((stamp, envelope)) = Stamp::split(data) {
        assert_eq!(&stamp.prepend(envelope)[..], data);
    }
});
