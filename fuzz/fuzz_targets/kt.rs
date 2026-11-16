//! Key transparency (Prompt 3, M6): leaf and tree-head decoders and both proof verifiers never
//! panic on arbitrary input; decoded values re-encode byte for byte.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_kt::{Leaf, TreeHead, verify_consistency, verify_inclusion};

fuzz_target!(|data: &[u8]| {
    if let Ok(l) = Leaf::decode(data) {
        assert_eq!(&l.encode()[..], data);
    }
    if let Ok(h) = TreeHead::decode(data) {
        assert_eq!(h.encode(), data);
    }
    // Arbitrary proofs: sizes from the first bytes, hashes from the rest.
    if data.len() >= 16 {
        let a = u64::from_be_bytes(data[..8].try_into().unwrap_or_default());
        let b = u64::from_be_bytes(data[8..16].try_into().unwrap_or_default());
        let proof: Vec<[u8; 32]> = data[16..]
            .chunks_exact(32)
            .map(|c| c.try_into().unwrap_or_default())
            .collect();
        let _ = verify_inclusion(&[1; 32], a, b, &proof, &[2; 32]);
        let _ = verify_consistency(a, b, &[1; 32], &[2; 32], &proof);
    }
});
