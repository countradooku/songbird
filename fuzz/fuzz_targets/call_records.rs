//! Call records, lobby entries and room names (Prompt 7, M3, D-0088): every decoder of what
//! `valkey-hot` and LiveKit hand back never panics, and what decodes encodes back to itself.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_calls::RoomId;
use songbird_calls::records::{Call, GroupCall, LobbyEntry};

fuzz_target!(|data: &[u8]| {
    if let Some(c) = Call::decode(data) {
        assert_eq!(Call::decode(&c.encode()), Some(c));
    }
    if let Some(g) = GroupCall::decode(data) {
        assert_eq!(GroupCall::decode(&g.encode()), Some(g));
    }
    if let Some(e) = LobbyEntry::decode(data) {
        assert_eq!(LobbyEntry::decode(&e.encode()), Some(e));
    }
    if let Ok(s) = std::str::from_utf8(data)
        && let Some(r) = RoomId::parse(s)
    {
        assert_eq!(r.name(), s);
    }
});
