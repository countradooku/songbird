//! Key transparency on akd (Prompt 3, D-0057): what a client decodes from the server (signed
//! heads and akd's lookup, history and append-only proofs in protobuf) never panics, and
//! arbitrary proofs never verify.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_akd::{Config, SignedHead, proofs};

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = SignedHead::decode(data) {
        assert_eq!(h.encode(), data);
    }
    let label = akd::AkdLabel(vec![1; 33]);
    if let Ok(p) = proofs::decode_lookup(data) {
        let _ = akd::client::lookup_verify::<Config>(&[7; 32], [0; 32], 1, label.clone(), p);
    }
    if let Ok(p) = proofs::decode_history(data) {
        let _ = akd::client::key_history_verify::<Config>(
            &[7; 32],
            [0; 32],
            1,
            label,
            p,
            akd::verify::history::HistoryVerificationParams::default(),
        );
    }
    let _ = proofs::decode_audit(data);
});
