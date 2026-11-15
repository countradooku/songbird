//! XEdDSA against libsignal (commit `8be00c2`, built only in `tools/libsignal-vectors`, never
//! linked, D-0047): for private key 32 × `31` and 64 × `42` as the signing randomness, libsignal's
//! `PrivateKey::calculate_signature` gives this public key and signature; Songbird derives the
//! same key, produces the same bytes, and verifies them; libsignal verifies Songbird's signature
//! (`cargo run --release --bin xeddsa`). Published in `docs/PROTOCOL.md` §13.
#![allow(clippy::unwrap_used, reason = "tests")]

use songbird_keys::xeddsa::{Signer, verify};

const MESSAGE: &[u8] = b"songbird.v1/xeddsa-vector";
/// libsignal's serialization: `0x05` and the X25519 public key.
const PUBLIC: &str = "0504f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f3a";
const SIGNATURE: &str = "5bdccfa0250b116ef988e11c678a3562f8b37884cbc3c2ee720d87760a0e8cf0\
                         68aba378d09d70b2ad14b47a44709b3b72400c10bd2bdffbe84ee24b29373e82";

#[test]
fn songbird_and_libsignal_agree() {
    let signer = Signer::new(&[0x31; 32]);
    assert_eq!(format!("05{}", hex::encode(signer.public())), PUBLIC);
    let sig = signer.sign(MESSAGE, &[0x42; 64]);
    assert_eq!(hex::encode(sig), SIGNATURE);
    let theirs: [u8; 64] = hex::decode(SIGNATURE).unwrap().try_into().unwrap();
    assert!(verify(&signer.public(), MESSAGE, &theirs));
}
