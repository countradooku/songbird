//! Device messages (Prompt 3, M4, D-0052): the signed device list, the link request and the
//! provisioning plaintext decoders, and opening a provisioning envelope: never panic; whatever
//! decodes re-encodes byte for byte; a list that decodes has one primary and no device twice.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_proto::devices::{DeviceList, LinkRequest, Provision};

fuzz_target!(|data: &[u8]| {
    if let Ok(l) = DeviceList::decode(data) {
        assert_eq!(l.encode(), data);
        assert_eq!(l.devices.iter().filter(|d| d.primary).count(), 1);
        let mut ids: Vec<_> = l.devices.iter().map(|d| d.device).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), l.devices.len());
    }
    if let Ok(r) = LinkRequest::decode(data) {
        assert_eq!(r.encode(), data);
    }
    if let Ok(p) = Provision::decode(data) {
        assert_eq!(p.encode().unwrap(), data);
    }
    // Arbitrary bytes never open (a fixed key: the envelope's tag cannot be forged by chance).
    thread_local! {
        static KEY: songbird_keys::provisioning::ProvisioningKey =
            songbird_keys::provisioning::ProvisioningKey::generate().unwrap();
    }
    KEY.with(|k| assert!(songbird_keys::provisioning::open(k, data).is_err()));
});
