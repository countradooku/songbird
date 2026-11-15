//! Profiles and sealed sender (Prompt 3, M5): the profile upload and sender-certificate decoders
//! never panic, and whatever decodes re-encodes byte for byte.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proto::profile::{ProfileUpload, SenderCertificate};

fuzz_target!(|data: &[u8]| {
    if let Ok(u) = ProfileUpload::decode(data) {
        assert_eq!(u.encode(), data);
    }
    if let Ok(c) = SenderCertificate::decode(data) {
        assert_eq!(c.encode(), data);
    }
});
