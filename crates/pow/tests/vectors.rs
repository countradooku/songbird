//! Published vector (`docs/PROTOCOL.md` §13): a fixed key, time and nonce give fixed challenge
//! bytes and fixed solutions, and the first solution's Argon2id output matches the reference
//! `argon2` command (phc-winner-argon2). Update only together with the protocol document.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use songbird_pow::{ChallengeKey, Params, evaluate, solve};

#[test]
fn vector() {
    let k = ChallengeKey::derive(&[0x42; 32]).unwrap();
    let c = k
        .issue_with_nonce(
            Params {
                memory_kib: 64,
                iterations: 1,
                bits: 4,
                solutions: 2,
            },
            1_763_164_800_000,
            [0x11; 16],
        )
        .unwrap();
    let s = solve(&c).unwrap().unwrap();
    let h = evaluate(&c, s[0]).unwrap();
    let shown = format!("{} {:?} {}", hex::encode(c.bytes), s, hex::encode(h));
    assert_eq!(shown, include_str!("vector.txt").trim());
}
