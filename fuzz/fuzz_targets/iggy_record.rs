//! The mailbox's Iggy log records (read back on every start and every drain), its key-store files
//! and its node-to-node partition requests: the decoders never panic, stay bounded, and what the
//! record and request decoders accept re-encodes canonically.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    songbird_mailbox::iggy::fuzz_record(data);
});
