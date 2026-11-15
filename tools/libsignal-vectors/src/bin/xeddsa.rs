// libsignal's XEdDSA against Songbird's: same public key, byte-identical signature for the same
// randomness, and each verifies the other's.
use libsignal_core::curve::{PrivateKey, PublicKey};

struct Fixed;
impl rand::RngCore for Fixed {
    fn next_u32(&mut self) -> u32 { 0x4242_4242 }
    fn next_u64(&mut self) -> u64 { 0x4242_4242_4242_4242 }
    fn fill_bytes(&mut self, d: &mut [u8]) { d.fill(0x42) }
}
impl rand::CryptoRng for Fixed {}

fn main() {
    let private = PrivateKey::deserialize(&[0x31; 32]).unwrap();
    let public = private.public_key().unwrap();
    let message = b"songbird.v1/xeddsa-vector";
    let sig = private.calculate_signature(message, &mut Fixed).unwrap();
    println!("{} {}", hex::encode(public.serialize()), hex::encode(&sig));
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    let f: Vec<&str> = line.split_whitespace().collect();
    let theirs = PublicKey::deserialize(&hex::decode(f[0]).unwrap()).unwrap();
    println!("libsignal verifies songbird's signature: {}", theirs.verify_signature(message, &hex::decode(f[1]).unwrap()));
}
