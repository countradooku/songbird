//! Device messages (Prompt 3, M4, D-0052): the signed device list, the link request and the
//! provisioning plaintext decoders, opening a provisioning envelope, and the WebAuthn
//! registration and assertion checks (M4b): never panic; whatever
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
    // WebAuthn: arbitrary attestation objects and assertions never panic, and never verify.
    let origins = ["https://example.org".to_owned()];
    let rp = songbird_keys::webauthn::RelyingParty {
        id: "example.org",
        origins: &origins,
        require_uv: false,
    };
    let (a, b) = data.split_at(data.len() / 2);
    let _ = songbird_keys::webauthn::check_registration(a, b, &[0; 32], &rp);
    let key = songbird_keys::webauthn::CredentialKey::Ed25519([0x5a; 32]);
    assert!(songbird_keys::webauthn::check_assertion(&key, 0, a, b, &[0; 64], &[0; 32], &rp).is_err());
});
