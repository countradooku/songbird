//! The mailbox's Iggy log records (read back on every start and every drain): the decoder never
//! panics, stays bounded, and what it accepts re-encodes canonically.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    songbird_mailbox::iggy::fuzz_record(data);
});
