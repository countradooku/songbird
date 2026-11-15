// Prints libsignal reference vectors for Songbird's own username implementation.
use poksho::{ShoApi, ShoHmacSha256};
use usernames::Username;

fn main() {
    // SHO
    let mut sho = ShoHmacSha256::new(b"songbird-vector");
    sho.absorb_and_ratchet(b"input one");
    sho.absorb_and_ratchet(b"");
    let a = sho.squeeze_and_ratchet(70);
    sho.absorb_and_ratchet(b"after squeeze");
    let b = sho.squeeze_and_ratchet(32);
    println!("sho {} {}", hex::encode(a), hex::encode(b));
    // Hashes and proofs
    for (i, name) in ["abc.01", "Radu.42", "songbird_user.123456789", "a_1.99", "x__yz.1000",
        "abcdefghijklmnopqrstuvwxyz012345.10"].iter().enumerate() {
        let u = Username::new(name).unwrap();
        let r = [u8::try_from(i).unwrap() + 1; 32];
        let p = u.proof(&r).unwrap();
        assert!(Username::verify_proof(&p, u.hash()).is_ok());
        println!("name {} {} {} {}", name, hex::encode(r), hex::encode(u.hash()), hex::encode(p));
    }
    // Validation
    for s in ["abc.01", "ab.01", "abc.1", "abc.00", "abc.001", "abc.100", "1abc.01", "_abc.01",
        "ABC.01", "abc", "abc.", ".01", "a-b.01", "abc.+1", "abc.18446744073709551615",
        "abc.18446744073709551616", "abc.12a", "ab\u{e9}.01", "abc.def.01",
        "abcdefghijklmnopqrstuvwxyz0123456.10", "abcdefghijklmnopqrstuvwxyz012345678901234567890.10"] {
        match Username::new(s) {
            Ok(u) => println!("valid {s} {}", hex::encode(u.hash())),
            Err(e) => println!("invalid {s} {e:?}"),
        }
    }
}
