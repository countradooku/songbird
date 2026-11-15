//! KeyPackages made by OpenMLS 0.9.2 (`tools/openmls-vectors`, outside the workspace) through
//! Songbird's checks (D-0051): OpenMLS's X25519/Ed25519 packages pass, with OpenMLS's own
//! `KeyPackageRef`, the last-resort one is recognised, a P-256 one is refused; every kind of
//! tampering is refused with its reason.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use songbird_keys::mls::{MlsError, check};

const DEVICE: [u8; 16] = [0xD1; 16];

struct Vector {
    label: String,
    suite: u16,
    package: Vec<u8>,
    reference: [u8; 32],
}

fn vectors() -> (u64, Vec<Vector>) {
    let text = include_str!("openmls_keypackages.txt");
    let mut now = 0;
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f[0] == "now" {
            now = f[1].parse().unwrap();
            continue;
        }
        out.push(Vector {
            label: f[0].to_owned(),
            suite: u16::from_str_radix(f[1], 16).unwrap(),
            package: hex::decode(f[2]).unwrap(),
            reference: hex::decode(f[3]).unwrap().try_into().unwrap(),
        });
    }
    (now, out)
}

#[test]
fn openmls_packages_pass_with_openmls_references() {
    let (now, v) = vectors();
    for x in &v {
        let r = check(&x.package, &DEVICE, now);
        if x.suite == 0x0002 {
            assert_eq!(r, Err(MlsError::Unsupported), "{}", x.label);
            continue;
        }
        let c = r.unwrap_or_else(|e| panic!("{}: {e:?}", x.label));
        assert_eq!(c.reference, x.reference, "{}: KeyPackageRef", x.label);
        assert_eq!(c.cipher_suite, x.suite);
        assert_eq!(c.last_resort, x.label == "last-resort", "{}", x.label);
        assert!(c.not_after > now);
    }
}

#[test]
fn tampering_is_refused_with_its_reason() {
    let (now, v) = vectors();
    let p = &v.iter().find(|x| x.label == "plain").unwrap().package;
    // Another device's upload of this package.
    assert_eq!(check(p, &[0xD2; 16], now), Err(MlsError::Identity));
    // Expired, not yet valid.
    assert_eq!(
        check(p, &DEVICE, now + 200 * 86_400),
        Err(MlsError::Lifetime)
    );
    assert_eq!(check(p, &DEVICE, 1_000), Err(MlsError::Lifetime));
    // Every truncation, a trailing byte.
    for cut in 0..p.len() {
        assert!(check(&p[..cut], &DEVICE, now).is_err(), "cut {cut}");
    }
    let mut long = p.clone();
    long.push(0);
    assert_eq!(check(&long, &DEVICE, now), Err(MlsError::Malformed));
    // The last byte of the KeyPackage signature; another ciphersuite in the header.
    let mut sig = p.clone();
    let last = sig.len() - 1;
    sig[last] ^= 1;
    assert_eq!(check(&sig, &DEVICE, now), Err(MlsError::Signature));
    let mut suite = p.clone();
    suite[3] = 0x03;
    // Still an allowed suite, so the change is caught by the signature (the header is signed),
    // unless the capabilities do not list it.
    assert!(matches!(
        check(&suite, &DEVICE, now),
        Err(MlsError::Signature | MlsError::Unsupported)
    ));
    let mut version = p.clone();
    version[1] = 2;
    assert_eq!(check(&version, &DEVICE, now), Err(MlsError::Unsupported));
    // Any single flipped byte is refused (nothing in a package is unchecked).
    for i in 0..p.len() {
        let mut q = p.clone();
        q[i] ^= 0x01;
        assert!(check(&q, &DEVICE, now).is_err(), "byte {i}");
    }
}
