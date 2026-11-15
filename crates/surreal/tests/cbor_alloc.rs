//! The CBOR decoder's memory stays proportional to the items it actually decodes (invariant 7),
//! not to the counts the input claims.
//!
//! Found by the `surreal_cbor` fuzz target (nightly run 43618568338, out-of-memory after 3.5 M
//! inputs with a 25 MB live heap): every nested array or map reserved room for its claimed count,
//! checked only against the bytes left, so 64 nested headers each reserved for nearly the whole
//! input. Own test binary: the counting allocator is global.
#![allow(clippy::unwrap_used, clippy::as_conversions, reason = "test")]

use bytes::{BufMut, Bytes, BytesMut};
use songbird_surreal::cbor;

#[global_allocator]
static GLOBAL: songbird_alloc_count::Counting = songbird_alloc_count::Counting;

const INPUT: usize = 4096;
/// A decoded `Value` is tens of bytes for one input byte, and a growing `Vec` requests about
/// twice its final size in total; 256 bytes per input byte leaves room for both, and is an order
/// of magnitude below what claimed counts reserved before the fix (about 2 400).
const MAX_BYTES_PER_INPUT_BYTE: u64 = 256;

/// `depth` array headers, each claiming every byte that follows it, then `0x00` items.
fn nested_claims(major: u8, depth: usize) -> Bytes {
    let mut out = BytesMut::with_capacity(INPUT);
    for level in 0..depth {
        let after = INPUT - 3 * (level + 1);
        let n = u16::try_from(after / if major == 5 { 2 } else { 1 }).unwrap();
        // Additional info 25: a two-byte big-endian count follows.
        out.put_u8((major << 5) | 0x19);
        out.put_u16(n);
    }
    out.resize(INPUT, 0);
    out.freeze()
}

fn bytes_requested(input: &Bytes) -> u64 {
    songbird_alloc_count::count_this_thread(true);
    let before = songbird_alloc_count::snapshot().1;
    let result = cbor::decode(input);
    let after = songbird_alloc_count::snapshot().1;
    songbird_alloc_count::count_this_thread(false);
    assert!(result.is_err(), "the claims cannot all be met");
    after - before
}

#[test]
fn nested_array_claims_do_not_multiply_memory() {
    let input = nested_claims(4, cbor::MAX_DEPTH);
    let used = bytes_requested(&input);
    assert!(
        used <= MAX_BYTES_PER_INPUT_BYTE * INPUT as u64,
        "{used} bytes requested for a {INPUT}-byte input"
    );
}

#[test]
fn nested_map_claims_do_not_multiply_memory() {
    // Map keys must be text, so the innermost map fails on its first `0x00` key: what is
    // measured is the reservations alone.
    let input = nested_claims(5, cbor::MAX_DEPTH);
    let used = bytes_requested(&input);
    assert!(
        used <= MAX_BYTES_PER_INPUT_BYTE * INPUT as u64,
        "{used} bytes requested for a {INPUT}-byte input"
    );
}
