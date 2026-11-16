//! The MLS delivery service's own parsers (Prompt 5, `songbird-groups::wire`): the
//! `PrivateMessage` prefix read on the send path, the commit bundle and the `GroupInfo` signer.
//! Never panic; an accepted bundle re-encodes byte for byte; an accepted prefix is a whole
//! message whose group ID is 16 bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_groups::wire;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = wire::private_prefix(data) {
        assert_eq!(data.get(2..4), Some(&[0u8, 2][..]));
        assert_eq!(p.group.len(), 16);
    }
    if let Ok(b) = wire::Bundle::parse(data, 1 << 20) {
        assert_eq!(b.encode(), data);
    }
    let _ = wire::wire_format(data);
    let _ = wire::group_info_signer(data);
});
