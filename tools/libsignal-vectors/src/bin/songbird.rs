// Independent check of Songbird's unique-handle username proof with libsignal's poksho.
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use poksho::args::{PointArgs, ScalarArgs};
use poksho::{ShoApi, ShoHmacSha256, Statement};
use sha2::{Digest, Sha512};

fn main() {
    // Songbird's vector line (generator, hash, proof) on stdin, as `username_vector.txt` holds it.
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    let ours: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
    let mut sho = ShoHmacSha256::new(b"songbird.v1/username-generator");
    let wide: [u8; 64] = sho.squeeze_and_ratchet(64).try_into().unwrap();
    let g = RistrettoPoint::from_uniform_bytes(&wide);
    let mut h = Sha512::new();
    h.update(b"songbird.v1/username\0");
    h.update(b"radu");
    let s = Scalar::from_hash(h);
    let hash = s * g;
    let mut st = Statement::new();
    st.add("username_hash", &[("s", "G1")]);
    let mut sa = ScalarArgs::new();
    sa.add("s", s);
    let mut pa = PointArgs::new();
    pa.add("G1", g);
    pa.add("username_hash", hash);
    let msg = hash.compress().to_bytes();
    let proof = st.prove(&sa, &pa, &msg, &[0x11; 32]).unwrap();
    println!("{} {} {}", hex::encode(g.compress().as_bytes()), hex::encode(msg), hex::encode(&proof));
    // Verify Songbird's proof bytes with poksho.
    let our_hash: [u8; 32] = hex::decode(&ours[1]).unwrap().try_into().unwrap();
    let hp = CompressedRistretto(our_hash).decompress().unwrap();
    let mut pa2 = PointArgs::new();
    pa2.add("G1", g);
    pa2.add("username_hash", hp);
    println!("poksho verifies songbird's proof: {:?}", st.verify_proof(&hex::decode(&ours[2]).unwrap(), &pa2, &our_hash).is_ok());
}
