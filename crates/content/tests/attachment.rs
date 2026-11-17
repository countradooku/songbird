//! The attachment format (PROTOCOL §7.1, D-0080): round trips, every way of tampering refused at
//! the chunk where it happens, and the published test vectors.
//!
//! `tools/attachment-vectors` checks the same vectors with an independent implementation (Node.js
//! and its OpenSSL), so the format is pinned by two codebases.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::many_single_char_names,
    reason = "tests"
)]

use proptest::prelude::*;
use songbird_content::attachment::{
    self, Decryptor, Encryptor, Error, KEY_LEN, SALT_LEN, Suite, decrypt, encrypt,
};
use songbird_proto::media::{self, CHUNK, HEADER, TAG};

const SUITES: [Suite; 2] = [Suite::ChaCha20Poly1305, Suite::Aes256Gcm];

fn data(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 31 + 7) % 251).unwrap())
        .collect()
}

fn seal(
    suite: Suite,
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    plain: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let mut out = Vec::new();
    let digest = encrypt(
        suite,
        key,
        salt,
        plain.len() as u64,
        &mut &plain[..],
        &mut out,
    )
    .unwrap();
    (out, digest)
}

fn open(key: &[u8], digest: &[u8], n: u64, ct: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decrypt(key, digest, n, &mut &ct[..], &mut out).map(|()| out)
}

#[test]
fn round_trips_at_every_boundary_in_both_suites() {
    let key = [0x42; KEY_LEN];
    let salt = [0x24; SALT_LEN];
    let c = usize::try_from(CHUNK).unwrap();
    for suite in SUITES {
        for n in [
            0,
            1,
            1_023,
            1_024,
            1_025,
            c - 1,
            c,
            c + 1,
            2 * c,
            3 * c + 17,
            1 << 20,
        ] {
            let plain = data(n);
            let (ct, digest) = seal(suite, &key, &salt, &plain);
            assert_eq!(
                ct.len() as u64,
                media::ciphertext_len(n as u64).unwrap(),
                "{n}"
            );
            assert_eq!(ct[0], suite.version());
            assert_eq!(
                media::padded_from_ciphertext(ct.len() as u64),
                media::padded_len(n as u64)
            );
            assert_eq!(open(&key, &digest, n as u64, &ct).unwrap(), plain, "{n}");
        }
    }
}

#[test]
fn pushing_in_odd_slices_gives_the_same_bytes() {
    let key = [7; KEY_LEN];
    let salt = [9; SALT_LEN];
    let plain = data(200_000);
    let (whole, _) = seal(Suite::DEFAULT, &key, &salt, &plain);
    let mut enc = Encryptor::new(Suite::DEFAULT, &key, &salt, plain.len() as u64).unwrap();
    let mut out = enc.header().to_vec();
    for piece in plain.chunks(4_093) {
        enc.push(piece, &mut out).unwrap();
    }
    assert_eq!(enc.ciphertext_len(), whole.len() as u64);
    enc.finish(&mut out).unwrap();
    assert_eq!(out, whole);
}

#[test]
fn lengths_must_match_exactly() {
    let key = [1; KEY_LEN];
    let salt = [2; SALT_LEN];
    let mut enc = Encryptor::new(Suite::DEFAULT, &key, &salt, 10).unwrap();
    let mut out = Vec::new();
    assert_eq!(enc.push(&[0; 11], &mut out), Err(Error::Length));
    enc.push(&[0; 9], &mut out).unwrap();
    assert_eq!(enc.finish(&mut out), Err(Error::Length));
    // `encrypt` refuses a reader with more or fewer bytes than announced.
    let mut sink = Vec::new();
    assert_eq!(
        encrypt(
            Suite::DEFAULT,
            &key,
            &salt,
            5,
            &mut &[0u8; 6][..],
            &mut sink
        ),
        Err(Error::Length)
    );
    assert_eq!(
        encrypt(
            Suite::DEFAULT,
            &key,
            &salt,
            5,
            &mut &[0u8; 4][..],
            &mut sink
        ),
        Err(Error::Length)
    );
}

#[test]
fn the_wrong_key_salt_digest_or_version_is_refused_before_any_chunk() {
    let key = [3; KEY_LEN];
    let salt = [4; SALT_LEN];
    let plain = data(5_000);
    let (ct, digest) = seal(Suite::DEFAULT, &key, &salt, &plain);
    let n = plain.len() as u64;
    let mut other = key;
    other[63] ^= 1;
    assert_eq!(open(&other, &digest, n, &ct), Err(Error::Commitment));
    let mut d = digest;
    d[0] ^= 1;
    assert_eq!(open(&key, &d, n, &ct), Err(Error::Commitment));
    let mut salted = ct.clone();
    salted[5] ^= 1;
    assert_eq!(open(&key, &digest, n, &salted), Err(Error::Commitment));
    // The other suite's version byte derives other keys: never a downgrade.
    let mut swapped = ct.clone();
    swapped[0] = Suite::ChaCha20Poly1305.version();
    assert_eq!(open(&key, &digest, n, &swapped), Err(Error::Commitment));
    for v in [0u8, 3, 0xff] {
        let mut bad = ct.clone();
        bad[0] = v;
        assert_eq!(open(&key, &digest, n, &bad), Err(Error::Header));
    }
    assert_eq!(open(&key[..32], &digest, n, &ct), Err(Error::Pointer));
    assert_eq!(open(&key, &digest[..31], n, &ct), Err(Error::Pointer));
    assert_eq!(open(&key, &digest, n, &ct[..20]), Err(Error::Header));
}

#[test]
fn reordering_truncating_extending_and_flipping_are_caught_at_their_chunk() {
    let key = [5; KEY_LEN];
    let salt = [6; SALT_LEN];
    let c = usize::try_from(CHUNK).unwrap();
    let plain = data(3 * c + 100); // padded to 4 chunks
    let n = plain.len() as u64;
    let (ct, digest) = seal(Suite::DEFAULT, &key, &salt, &plain);
    let h = usize::try_from(HEADER).unwrap();
    let full = c + usize::try_from(TAG).unwrap();

    // A flipped bit anywhere in chunk i fails chunk i.
    for i in 0..4u64 {
        let at = h + usize::try_from(i).unwrap() * full + 17;
        let mut bad = ct.clone();
        bad[at] ^= 0x80;
        assert_eq!(open(&key, &digest, n, &bad), Err(Error::Chunk(i)));
    }
    // Two chunks swapped: the first out of place fails.
    let mut swapped = ct.clone();
    let (a, b) = swapped[h..].split_at_mut(full);
    a.swap_with_slice(&mut b[..full]);
    assert_eq!(open(&key, &digest, n, &swapped), Err(Error::Chunk(0)));
    // Truncated at a chunk boundary: the new "last" chunk was sealed as not last.
    let cut = &ct[..h + 3 * full];
    assert_eq!(open(&key, &digest, n, cut), Err(Error::Chunk(3)));
    // A size claiming fewer chunks makes chunk 2 the last one, which it was not sealed as.
    assert!(matches!(
        open(&key, &digest, 2 * CHUNK + 5, &ct),
        Err(Error::Chunk(_))
    ));
    // Anything after the last chunk.
    let mut longer = ct.clone();
    longer.push(0);
    assert_eq!(open(&key, &digest, n, &longer), Err(Error::Trailing));
}

#[test]
fn padding_must_be_zeros_and_the_real_length_is_the_pointers() {
    let key = [8; KEY_LEN];
    let salt = [9; SALT_LEN];
    let plain = data(1_000); // padded to 1,024 like any size up to it
    let (ct, digest) = seal(Suite::DEFAULT, &key, &salt, &plain);
    // Claiming a shorter real length exposes non-zero bytes as "padding".
    assert_eq!(open(&key, &digest, 500, &ct), Err(Error::Padding));
    // A longer claim in the same bucket returns the zero padding as data: still authentic bytes,
    // and the pointer (encrypted, franked) is what the sender committed to.
    let zeros = vec![0u8; 1_000];
    let (zct, zd) = seal(Suite::DEFAULT, &key, &salt, &zeros);
    assert_eq!(open(&key, &zd, 1_024, &zct).unwrap(), vec![0u8; 1_024]);
}

#[test]
fn chunks_open_in_any_order_for_range_requests() {
    let key = [10; KEY_LEN];
    let salt = [11; SALT_LEN];
    let plain = data(5 * usize::try_from(CHUNK).unwrap() + 3);
    let n = plain.len() as u64;
    let (ct, digest) = seal(Suite::DEFAULT, &key, &salt, &plain);
    let dec = Decryptor::new(&key, &digest, n, &ct[..33]).unwrap();
    assert_eq!(dec.ciphertext_len(), ct.len() as u64);
    // Plaintext bytes 300,000..300,010 are in chunk 4.
    assert_eq!(dec.chunks_for(300_000, 300_010), Some((4, 4)));
    assert_eq!(dec.chunks_for(0, n + 1), None);
    for i in (0..dec.chunk_count()).rev() {
        let (s, e) = dec.chunk_range(i).unwrap();
        let mut sealed = ct[usize::try_from(s).unwrap()..usize::try_from(e).unwrap()].to_vec();
        let got = dec.open_chunk(i, &mut sealed).unwrap();
        let start = usize::try_from(i * CHUNK).unwrap();
        assert_eq!(got, &plain[start..(start + got.len())]);
    }
    assert!(dec.chunk_range(dec.chunk_count()).is_none());
    // A chunk under another index fails.
    let (s, e) = dec.chunk_range(1).unwrap();
    let mut sealed = ct[usize::try_from(s).unwrap()..usize::try_from(e).unwrap()].to_vec();
    assert_eq!(dec.open_chunk(2, &mut sealed), Err(Error::Chunk(2)));
}

#[test]
fn fresh_keys_and_salts_differ() {
    let (k1, s1) = attachment::fresh().unwrap();
    let (k2, s2) = attachment::fresh().unwrap();
    assert_ne!(*k1, *k2);
    assert_ne!(s1, s2);
    // Forwarding re-encrypts: the same file under fresh keys shares no ciphertext byte pattern.
    let plain = data(4_000);
    let (a, _) = seal(Suite::DEFAULT, &k1, &s1, &plain);
    let (b, _) = seal(Suite::DEFAULT, &k2, &s2, &plain);
    assert_eq!(a.len(), b.len());
    assert_ne!(a[33..], b[33..]);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn any_file_round_trips_and_any_flipped_byte_is_refused(
        n in 0usize..200_000,
        flip in any::<prop::sample::Index>(),
        suite in prop::sample::select(SUITES.to_vec()),
        key in any::<[u8; 32]>(),
    ) {
        let mut k = [0u8; KEY_LEN];
        k[..32].copy_from_slice(&key);
        let salt = [0x5a; SALT_LEN];
        let plain = data(n);
        let (ct, digest) = seal(suite, &k, &salt, &plain);
        prop_assert_eq!(open(&k, &digest, n as u64, &ct).unwrap(), plain);
        let mut bad = ct.clone();
        let at = flip.index(bad.len());
        bad[at] ^= 1;
        prop_assert!(open(&k, &digest, n as u64, &bad).is_err());
    }
}

/// The published vectors (PROTOCOL §13): key 64 × `0x11`, salt 32 × `0x22`, plaintext the bytes
/// `0x00, 0x01, … ` (i mod 256), at sizes that cover one chunk with padding and a full chunk plus a
/// short last one. Pinned by SHA-256 of the ciphertext, with the digest and the first and last
/// bytes in full.
#[test]
fn published_vectors() {
    let key = [0x11; KEY_LEN];
    let salt = [0x22; SALT_LEN];
    let mut lines = Vec::new();
    for suite in SUITES {
        for n in [0usize, 5, 70_000] {
            let plain: Vec<u8> = (0..n).map(|i| u8::try_from(i % 256).unwrap()).collect();
            let (ct, digest) = seal(suite, &key, &salt, &plain);
            let sha = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &ct);
            lines.push(format!(
                "{} {} {} {} {} {}",
                suite.version(),
                n,
                ct.len(),
                hex::encode(digest),
                hex::encode(sha.as_ref()),
                hex::encode(&ct[33..65]),
            ));
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/attachment/v1.txt");
    let got = lines.join("\n") + "\n";
    if std::env::var_os("SONGBIRD_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &got).unwrap();
    }
    let want = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(
        got, want,
        "vectors changed: the format is published, never edit it"
    );
}

/// A pack end to end (PROTOCOL §7.4): assets and the manifest encrypted under keys derived from
/// the pack key; a reader with only the link opens the manifest, then each asset against the
/// commitment the manifest lists. An asset from another pack, or a manifest under another pack
/// key, never opens.
#[test]
fn a_pack_opens_from_its_link_alone() {
    use songbird_content::pack::{Item, Kind, Manifest, object_key};
    let pack_key = [0x5c; 32];
    let assets: Vec<Vec<u8>> = (1..=3).map(|i| data(1_000 * i)).collect();
    let mut objects = Vec::new();
    let mut items = Vec::new();
    for (i, a) in assets.iter().enumerate() {
        let n = u16::try_from(i + 1).unwrap();
        let (_, salt) = attachment::fresh().unwrap();
        let (ct, digest) = seal(Suite::DEFAULT, &object_key(&pack_key, n).unwrap(), &salt, a);
        objects.push(ct);
        items.push(Item {
            object: u32::from(n),
            content_type: "image/webp".into(),
            size: a.len() as u64,
            digest: digest.to_vec(),
            ..Item::default()
        });
    }
    let manifest = Manifest {
        version: 1,
        kind: Kind::Stickers.into(),
        title: "Birds".into(),
        cover: 1,
        items,
        ..Manifest::default()
    }
    .seal()
    .unwrap();
    let (_, salt) = attachment::fresh().unwrap();
    let (mct, _) = seal(
        Suite::DEFAULT,
        &object_key(&pack_key, 0).unwrap(),
        &salt,
        &manifest,
    );

    // The reader, with only the link: the manifest's commitment comes from its header and the
    // derived key; it is opened at its padded length and finds its own end.
    let k0 = object_key(&pack_key, 0).unwrap();
    let d0 = attachment::commitment(&k0, &mct[..33]).unwrap();
    let padded = media::padded_from_ciphertext(mct.len() as u64).unwrap();
    let mut out = Vec::new();
    decrypt(&k0[..], &d0, padded, &mut &mct[..], &mut out).unwrap();
    let m = Manifest::open(&out).unwrap();
    for item in &m.items {
        let n = u16::try_from(item.object).unwrap();
        let ct = &objects[usize::from(n) - 1];
        let got = open(
            &object_key(&pack_key, n).unwrap()[..],
            &item.digest,
            item.size,
            ct,
        )
        .unwrap();
        assert_eq!(got, assets[usize::from(n) - 1]);
        // Under another pack's key: refused before any chunk.
        assert_eq!(
            open(
                &object_key(&[0x5d; 32], n).unwrap()[..],
                &item.digest,
                item.size,
                ct
            ),
            Err(Error::Commitment)
        );
    }
    // Asset 2 swapped in for asset 1 (same pack, wrong slot): its commitment is not item 1's.
    assert!(
        open(
            &object_key(&pack_key, 1).unwrap()[..],
            &m.items[0].digest,
            m.items[1].size,
            &objects[1]
        )
        .is_err()
    );
}
