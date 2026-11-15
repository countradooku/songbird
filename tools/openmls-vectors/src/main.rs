// Prints KeyPackages made by OpenMLS 0.9.2 for Songbird's own parser (D-0051): one line each,
// "<label> <ciphersuite> <hex of the TLS-serialized KeyPackage> <hex of its KeyPackageRef>".
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Serialize as _;

fn main() {
    let provider = OpenMlsRustCrypto::default();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    println!("now {now}");
    for (label, cs, last_resort) in [
        ("plain", Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, false),
        ("last-resort", Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, true),
        ("chacha", Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, false),
        ("p256", Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, false),
    ] {
        let signer = SignatureKeyPair::new(cs.signature_algorithm()).unwrap();
        let cred = CredentialWithKey {
            credential: BasicCredential::new(vec![0xD1; 16]).into(),
            signature_key: signer.public().into(),
        };
        let mut b = KeyPackage::builder();
        if last_resort {
            b = b.mark_as_last_resort();
        }
        let kp = b.build(cs, &provider, &signer, cred).unwrap();
        let bytes = kp.key_package().tls_serialize_detached().unwrap();
        let r = kp.key_package().hash_ref(provider.crypto()).unwrap();
        println!("{label} {:04x} {} {}", u16::from(cs), hex::encode(&bytes), hex::encode(r.as_slice()));
    }
}
