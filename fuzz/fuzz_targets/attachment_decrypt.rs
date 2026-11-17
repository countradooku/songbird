//! The attachment format (Prompt 6, M1, D-0080): the decryptor never panics on any ciphertext,
//! pointer or length, and anything it accepts after tampering is exactly the original plaintext.
#![no_main]
use libfuzzer_sys::fuzz_target;
use songbird_content::attachment::{Decryptor, Suite, decrypt, encrypt};

const KEY: [u8; 64] = [0x11; 64];
const SALT: [u8; 32] = [0x22; 32];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let suite = if sel & 1 == 0 { Suite::Aes256Gcm } else { Suite::ChaCha20Poly1305 };
    // Split the rest into a plaintext and a list of (position, xor) edits.
    let cut = rest.len() / 2;
    let (plain, edits) = rest.split_at(cut);
    let mut ct = Vec::new();
    let n = plain.len() as u64;
    let Ok(digest) = encrypt(suite, &KEY, &SALT, n, &mut &plain[..], &mut ct) else {
        return;
    };
    for e in edits.chunks_exact(3) {
        let at = usize::from(u16::from_le_bytes([e[0], e[1]])) % ct.len();
        ct[at] ^= e[2];
    }
    let claimed = if sel & 2 == 0 { n } else { n ^ u64::from(sel >> 2) };
    let mut out = Vec::new();
    if decrypt(&KEY, &digest, claimed, &mut &ct[..], &mut out).is_ok() {
        assert_eq!(claimed, n);
        assert_eq!(out, plain);
    }
    // Raw bytes as a header and a chunk.
    if let Ok(d) = Decryptor::new(&KEY, &digest, claimed, rest.get(..33).unwrap_or(rest)) {
        let mut chunk = rest.to_vec();
        let _ = d.open_chunk(u64::from(sel), &mut chunk);
    }
});
