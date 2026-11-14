//! Client frame decoder (the server's hot-path input): never panics, honours small limits, and
//! anything it accepts re-encodes to the same bytes (one encoding per frame).
#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use songbird_proto::frame::SendPayload;
use songbird_proto::{ClientFrame, Limits};

const SMALL: Limits = Limits {
    max_envelope_bytes: 64,
    max_recipients: 4,
    max_send_bytes: 512,
    max_ephemeral_bytes: 32,
    max_control_bytes: 256,
};

fuzz_target!(|data: &[u8]| {
    let msg = Bytes::copy_from_slice(data);
    for limits in [Limits::DEFAULT, SMALL] {
        if let Ok(f) = ClientFrame::decode(&msg, &limits) {
            assert!(msg.len() <= limits.max_message_bytes());
            if let ClientFrame::Send(s) = &f {
                assert!(!s.payload.is_empty() && s.payload.len() <= limits.max_recipients);
                let fits = |len: usize| len > 0 && len <= limits.max_envelope_bytes;
                match &s.payload {
                    SendPayload::PerDevice(r) => assert!(r.iter().all(|r| fits(r.envelope.len()))),
                    SendPayload::Shared { body, .. } => assert!(fits(body.len())),
                }
            }
            // Protobuf bodies may have non-canonical encodings; hand-encoded frames may not.
            if !matches!(f, ClientFrame::Auth(_)) {
                assert_eq!(f.to_bytes(), msg);
            }
        }
    }
});
