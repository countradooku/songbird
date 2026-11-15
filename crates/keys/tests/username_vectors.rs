//! The stateful hash object under the username proof matches libsignal's poksho `ShoHmacSha256`
//! byte for byte (`docs/PROTOCOL.md` §13), and Songbird's username hash and proof are fixed.
//!
//! - libsignal's own published vector (`rust/poksho/src/shohmacsha256.rs`, `test_vectors`).
//! - A longer sequence (empty input, a 70-byte squeeze across two blocks, absorbing after a
//!   squeeze) printed by libsignal at commit `8be00c2` through `poksho::ShoHmacSha256`, in a tool
//!   outside this repository's builds (libsignal is AGPL-3.0-only and is never linked here,
//!   D-0047). The same tool confirmed that this SHO, with libsignal's own labels and statement,
//!   reproduces libsignal's username hashes and proofs exactly (12 of 12), before the owner chose
//!   unique handles (D-0049).
#![allow(clippy::unwrap_used, reason = "tests")]

use songbird_keys::username::{Sho, Username, generator, verify_proof};

#[test]
fn sho_matches_libsignals_published_vector() {
    let mut sho = Sho::new(b"asd");
    sho.absorb_and_ratchet(b"asdasd");
    let mut out = [0u8; 65];
    sho.squeeze_and_ratchet(&mut out);
    assert_eq!(
        hex::encode(out),
        "392cb9449373037fa0c11aebed69cca3b7d3bc9790878f341729c65d5506442f\
         04986cb5c9098f277c3ea640a4dc6e90372b433a90af9aea7072eaba3398c4fe7a"
    );
}

#[test]
fn sho_matches_libsignal_on_a_longer_sequence() {
    let mut sho = Sho::new(b"songbird-vector");
    sho.absorb_and_ratchet(b"input one");
    sho.absorb_and_ratchet(b"");
    let mut a = [0u8; 70];
    sho.squeeze_and_ratchet(&mut a);
    sho.absorb_and_ratchet(b"after squeeze");
    let mut b = [0u8; 32];
    sho.squeeze_and_ratchet(&mut b);
    assert_eq!(
        hex::encode(a),
        "7d71ba6e0ee9ebe17dbee3f9382c7361e9d1a04efbfede75f95150a288065cb41cdecdb9a7f804dbfde4e1adbd213eff49ee7663bc28e3981d761068e5461bda833b07821045"
    );
    assert_eq!(
        hex::encode(b),
        "8b2fb32ab8a848c517888e958da9369129c638d7b13f46d86eeddc31ba5093a7"
    );
}

/// Songbird's published username vector (`docs/PROTOCOL.md` §13).
#[test]
fn username_vector() {
    let u = Username::parse("Radu").unwrap();
    let h = u.hash();
    let p = u.proof(&[0x11; 32]);
    assert!(verify_proof(&h, &p));
    let shown = format!(
        "{} {} {}",
        hex::encode(generator().compress().as_bytes()),
        hex::encode(h),
        hex::encode(p)
    );
    assert_eq!(shown, include_str!("username_vector.txt").trim());
}
