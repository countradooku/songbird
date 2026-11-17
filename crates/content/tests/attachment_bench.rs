//! The AEAD measurement behind `Suite::DEFAULT` (D-0080): encrypt and decrypt throughput of the
//! whole attachment format (key derivation, chunking, padding check) for each suite.
//!
//! `cargo test --release -p songbird-content --test attachment_bench -- --ignored --nocapture`
#![allow(
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::indexing_slicing,
    reason = "a benchmark"
)]

use std::time::Instant;

use songbird_content::attachment::{KEY_LEN, SALT_LEN, Suite, decrypt, encrypt};

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

#[test]
#[ignore = "a benchmark: run in release by hand"]
fn aead_throughput() {
    let key = [0x42; KEY_LEN];
    let salt = [0x24; SALT_LEN];
    eprintln!("suite              size     encrypt MB/s  decrypt MB/s  (median of 9)");
    for (name, suite) in [
        ("ChaCha20-Poly1305", Suite::ChaCha20Poly1305),
        ("AES-256-GCM", Suite::Aes256Gcm),
    ] {
        for size in [64usize << 10, 1 << 20, 64 << 20] {
            let plain = vec![0x5au8; size];
            let mut ct = Vec::with_capacity(size + size / 64 + 1_100);
            let mut enc = Vec::new();
            let mut dec = Vec::new();
            let mut digest = [0u8; 32];
            for _ in 0..9 {
                ct.clear();
                let t = Instant::now();
                digest =
                    encrypt(suite, &key, &salt, size as u64, &mut &plain[..], &mut ct).unwrap();
                enc.push(size as f64 / t.elapsed().as_secs_f64() / 1e6);
                let mut out = Vec::with_capacity(size);
                let t = Instant::now();
                decrypt(&key, &digest, size as u64, &mut &ct[..], &mut out).unwrap();
                dec.push(size as f64 / t.elapsed().as_secs_f64() / 1e6);
            }
            std::hint::black_box(digest);
            eprintln!(
                "{name:<18} {:>5} KiB {:>12.0} {:>13.0}",
                size >> 10,
                median(enc),
                median(dec)
            );
        }
    }
}
