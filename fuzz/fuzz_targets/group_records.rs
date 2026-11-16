//! Prompt 5's records (D-0070, D-0072, D-0073): the roles extension every client and the
//! delivery service decode, the registry roster the send path reads, a change-log entry, and
//! the delivery service's stored group record. Never panic; what decodes re-encodes byte for
//! byte (one encoding each).
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_groups::roles::Roles;
use songbird_groups::wire::LogEntry;
use songbird_groups::{Group, Record};

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Roles::decode(data) {
        assert_eq!(r.encode(), data);
    }
    if let Some(r) = songbird_send::Roster::from_bytes(0, data) {
        assert_eq!(songbird_send::Roster::encode(r.policy, &r.members), data);
        assert!(r.members.windows(2).all(|w| w[0].0 < w[1].0));
    }
    if let Ok(e) = LogEntry::parse(data) {
        assert_eq!(LogEntry::encode(e.ciphertext, e.signature), data);
    }
    if let Ok(rec) = Record::decode(data) {
        let _ = Group::load(rec);
    }
});
