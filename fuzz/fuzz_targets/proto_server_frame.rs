//! Server frame decoder (the client's input, including the protobuf control frames): never
//! panics; accepted hand-encoded frames re-encode to the same bytes.
#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use songbird_proto::{Limits, ServerFrame};

fuzz_target!(|data: &[u8]| {
    let msg = Bytes::copy_from_slice(data);
    if let Ok(f) = ServerFrame::decode(&msg, &Limits::DEFAULT) {
        if matches!(f, ServerFrame::Deliver { .. } | ServerFrame::Ephemeral { .. }) {
            assert_eq!(f.to_bytes(), msg);
        }
        let again = ServerFrame::decode(&f.to_bytes(), &Limits::DEFAULT).expect("re-encoding decodes");
        assert_eq!(again, f);
    }
});
