//! X-Wing KeyPackages made by OpenMLS pass Songbird's own upload check (D-0051 extended by
//! D-0066), with OpenMLS's `KeyPackageRef`; tampered ones are refused.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use openmls::prelude::OpenMlsProvider as _;
use openmls::prelude::tls_codec::Serialize as _;
use openmls_rust_crypto::OpenMlsRustCrypto;
use songbird_groups_harness::{Device, Dir, id_from};
use songbird_keys::mls::{self, MlsError, XWING_SUITE};
use songbird_types::AccountId;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn package() -> (Device, Vec<u8>) {
    let mut dir = Dir::default();
    let d = Device::new(1, AccountId::from_bytes(id_from(1, 0xA0)), &mut dir);
    let kp = d.key_package();
    let bytes = kp.tls_serialize_detached().unwrap();
    let r = kp.hash_ref(OpenMlsRustCrypto::default().crypto()).unwrap();
    assert_eq!(mls::reference(&bytes).as_slice(), r.as_slice());
    (d, bytes)
}

#[test]
fn openmls_x_wing_key_packages_pass_and_carry_their_reference() {
    let (d, bytes) = package();
    assert!(
        bytes.len() > 2048 && bytes.len() <= mls::MAX_LEN,
        "{} bytes",
        bytes.len()
    );
    let c = mls::check(&bytes, d.id.as_bytes(), now()).unwrap();
    assert_eq!(c.cipher_suite, XWING_SUITE);
    assert_eq!(c.reference, mls::reference(&bytes));
}

#[test]
fn tampered_x_wing_key_packages_are_refused() {
    let (d, bytes) = package();
    // Another device's upload.
    assert_eq!(
        mls::check(&bytes, &[0x77; 16], now()).unwrap_err(),
        MlsError::Identity
    );
    // The init key starts after version, suite and its two-byte length (1,216 > 63): an
    // ML-KEM-768 coefficient of 0xFFF is not below q.
    let mut bad = bytes.clone();
    bad[6..9].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    assert_eq!(
        mls::check(&bad, d.id.as_bytes(), now()).unwrap_err(),
        MlsError::Keys
    );
    // Its X25519 half replaced by a low-order point (all zeros).
    let mut low = bytes.clone();
    low[6 + 1184..6 + 1216].fill(0);
    assert_eq!(
        mls::check(&low, d.id.as_bytes(), now()).unwrap_err(),
        MlsError::Keys
    );
    // Every single flipped byte is refused (sampled every 7 bytes to keep it quick).
    for i in (0..bytes.len()).step_by(7) {
        let mut f = bytes.clone();
        f[i] ^= 0x01;
        assert!(
            mls::check(&f, d.id.as_bytes(), now()).is_err(),
            "byte {i} flipped was accepted"
        );
    }
}
