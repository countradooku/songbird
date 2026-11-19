//! The keyed content-defined chunker (PROTOCOL §11.3).
//!
//! `FastCDC` (Xia et al., USENIX ATC 2016) with normalized chunking at level 2: a rolling gear
//! hash `h = (h << 1) + gear[byte]` cuts where its top bits are zero, with a harder mask before
//! the average size and an easier one after. The gear table comes from the backup's `chunker`
//! key, so where chunks are cut reveals nothing about content to anyone without the key, while
//! the same content still cuts the same way in every backup: an insertion or a deletion changes
//! only the chunks around it.

/// Smallest chunk (except a stream's last).
pub const MIN: usize = 1 << 20;
/// Target average.
pub const AVG: usize = 2 << 20;
/// Largest chunk.
pub const MAX: usize = 8 << 20;
/// Before the average: 23 bits (one cut per 8 MiB on average).
const MASK_HARD: u64 = !0u64 << (64 - 23);
/// After the average: 19 bits (one cut per 512 KiB on average).
const MASK_EASY: u64 = !0u64 << (64 - 19);

/// Chunker parameters (tests use small ones; backups always use [`Params::BACKUP`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Smallest chunk.
    pub min: usize,
    /// Average.
    pub avg: usize,
    /// Largest.
    pub max: usize,
    /// Mask before the average.
    pub hard: u64,
    /// Mask after it.
    pub easy: u64,
}

impl Params {
    /// What every backup uses.
    pub const BACKUP: Self = Self {
        min: MIN,
        avg: AVG,
        max: MAX,
        hard: MASK_HARD,
        easy: MASK_EASY,
    };
}

/// Where to cut `data` (the start of the unchunked rest of a stream), or `None` when more data
/// may move the cut and `data` is not yet [`Params::max`] long. With `last` set, the rest is
/// the stream's end and a cut is always returned (the whole of `data` at most).
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "a u8 indexes a 256-entry table; this is the hot loop of every backup"
)]
pub fn cut(gear: &[u64; 256], params: &Params, data: &[u8], last: bool) -> Option<usize> {
    let p = params;
    let len = data.len();
    if len == 0 {
        return None;
    }
    if len <= p.min {
        return last.then_some(len);
    }
    let end = len.min(p.max);
    let normal = p.avg.min(end);
    let mut h = 0u64;
    // The hash over the bytes before `min` is not needed: its top bits only depend on the last
    // 64 bytes, so start 64 bytes early.
    let warm = p.min.saturating_sub(64);
    for &b in data.get(warm..p.min).unwrap_or_default() {
        h = (h << 1).wrapping_add(gear[usize::from(b)]);
    }
    let mut i = p.min;
    while i < normal {
        let b = data.get(i).copied().unwrap_or_default();
        h = (h << 1).wrapping_add(gear[usize::from(b)]);
        i += 1;
        if h & p.hard == 0 {
            return Some(i);
        }
    }
    while i < end {
        let b = data.get(i).copied().unwrap_or_default();
        h = (h << 1).wrapping_add(gear[usize::from(b)]);
        i += 1;
        if h & p.easy == 0 {
            return Some(i);
        }
    }
    if end == p.max || last {
        Some(end)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
    use super::*;

    fn gear(seed: u8) -> Box<[u64; 256]> {
        let mut g = Box::new([0u64; 256]);
        let mut x = u64::from(seed) | 1;
        for v in &mut *g {
            // splitmix64
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *v = z ^ (z >> 31);
        }
        g
    }

    fn chunks(g: &[u64; 256], p: &Params, data: &[u8]) -> Vec<usize> {
        let mut out = vec![];
        let mut at = 0;
        while let Some(c) = cut(g, p, &data[at..], true) {
            out.push(c);
            at += c;
        }
        out
    }

    const SMALL: Params = Params {
        min: 256,
        avg: 1024,
        max: 4096,
        hard: !0u64 << (64 - 12),
        easy: !0u64 << (64 - 8),
    };

    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect()
    }

    #[test]
    fn sizes_stay_within_bounds_and_cover_the_stream() {
        let g = gear(1);
        let data = noise(200_000, 7);
        let c = chunks(&g, &SMALL, &data);
        assert_eq!(c.iter().sum::<usize>(), data.len());
        for (i, &n) in c.iter().enumerate() {
            assert!(n <= SMALL.max);
            if i + 1 < c.len() {
                assert!(n > SMALL.min, "chunk {i} is {n}");
            }
        }
        let avg = data.len() / c.len();
        assert!((600..3000).contains(&avg), "average {avg}");
    }

    #[test]
    fn an_insertion_changes_only_nearby_chunks() {
        let g = gear(2);
        let data = noise(300_000, 9);
        let mut edited = data.clone();
        edited.splice(150_000..150_000, *b"inserted bytes");
        let a = chunks(&g, &SMALL, &data);
        let b = chunks(&g, &SMALL, &edited);
        let bounds = |c: &[usize]| {
            let mut at = 0;
            let mut v = vec![];
            for n in c {
                v.push((at, *n));
                at += n;
            }
            v
        };
        let (ba, bb) = (bounds(&a), bounds(&b));
        // Chunks wholly before the edit are identical; after it, shifted by 14 bytes.
        let before = ba.iter().filter(|(s, n)| s + n <= 150_000).count();
        assert_eq!(ba[..before], bb[..before]);
        let after_a: Vec<_> = ba
            .iter()
            .filter(|(s, _)| *s > 160_000)
            .map(|(s, n)| (s + 14, *n))
            .collect();
        let shared = after_a.iter().filter(|x| bb.contains(x)).count();
        assert!(shared + 2 >= after_a.len(), "{shared} of {}", after_a.len());
    }

    #[test]
    fn another_key_cuts_elsewhere() {
        let data = noise(100_000, 3);
        assert_ne!(
            chunks(&gear(1), &SMALL, &data),
            chunks(&gear(5), &SMALL, &data)
        );
    }

    #[test]
    fn a_partial_buffer_waits_for_more_unless_it_is_the_end() {
        let g = gear(1);
        let data = vec![0u8; SMALL.min];
        assert_eq!(cut(&g, &SMALL, &data, false), None);
        assert_eq!(cut(&g, &SMALL, &data, true), Some(SMALL.min));
        assert_eq!(cut(&g, &SMALL, &[], true), None);
        let full = noise(SMALL.max * 2, 1);
        assert!(cut(&g, &SMALL, &full, false).unwrap() <= SMALL.max);
    }
}
