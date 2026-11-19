//! Chunk and manifest objects (PROTOCOL §11.2, §11.4): what a store holds.
//!
//! ```text
//! chunk:    "SBC" | version u8 (1) | nonce [24] | XChaCha20-Poly1305(padded) || tag [16]
//!           AAD = the 28 header bytes || name [32]
//! manifest: "SBM" | version u8 (1) | generation u64 | nonce [24] | XChaCha20-Poly1305(padded) || tag [16]
//!           AAD = the 36 header bytes || vault ID [32]
//! padded:   length u32 | plaintext | zeros, to Padmé(max(4 + length, 1,024)) bytes
//! ```
//!
//! Integers are big-endian. Readers refuse nonzero padding, a length past the padding, unknown
//! versions and anything over the bounds below before allocating for it.

use std::fmt;

use aws_lc_rs::{digest, hmac};
use chacha20poly1305::aead::{AeadInPlace as _, KeyInit as _};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use prost::Message as _;
use zeroize::Zeroizing;

use crate::schema::{Manifest, StreamKind};
use crate::{BackupKeys, Error, READER_VERSION, Rng, chunker};

const CHUNK_MAGIC: &[u8; 3] = b"SBC";
const MANIFEST_MAGIC: &[u8; 3] = b"SBM";
const VERSION: u8 = 1;
const NONCE: usize = 24;
const TAG: usize = 16;
/// Chunk header bytes.
pub const CHUNK_HEADER: usize = 3 + 1 + NONCE;
/// Manifest header bytes.
pub const MANIFEST_HEADER: usize = 3 + 1 + 8 + NONCE;
/// Smallest padded plaintext.
const MIN_PADDED: usize = 1024;
/// Largest manifest plaintext (protobuf).
pub const MAX_MANIFEST: usize = 48 << 20;
/// Most streams in a manifest.
pub const MAX_STREAMS: usize = 1 << 20;
/// Most chunks in a manifest, over all streams.
pub const MAX_CHUNKS: usize = 1 << 21;
const MEDIA_CONTEXT: &[u8] = b"songbird.v1/backup-media\0";
const MEDIA_STREAM_CONTEXT: &[u8] = b"songbird.v1/backup-media-stream\0";

/// A chunk's name: `HMAC-SHA256(chunk-name key, plaintext)`. Shown as 64 lowercase hex
/// characters (safe on case-insensitive stores). `Debug` shows nothing of it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkName(pub [u8; 32]);

impl fmt::Debug for ChunkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChunkName(..)")
    }
}

impl ChunkName {
    /// Lowercase hex, the object name stores use.
    #[must_use]
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in self.0 {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Parses 64 lowercase hex characters.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return None;
        }
        let val = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut out = [0u8; 32];
        for (o, &[h, l]) in out.iter_mut().zip(b.as_chunks::<2>().0) {
            *o = (val(h)? << 4) | val(l)?;
        }
        Some(Self(out))
    }

    /// From a 32-byte slice.
    #[must_use]
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(b).ok().map(Self)
    }
}

fn hmac32(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&k);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// The name of a chunk with this plaintext.
#[must_use]
pub fn chunk_name(keys: &BackupKeys, plaintext: &[u8]) -> ChunkName {
    ChunkName(hmac32(&keys.chunk_name, &[plaintext]))
}

/// The reference of a small media file (stored as a `Blob`).
#[must_use]
pub fn media_ref(keys: &BackupKeys, bytes: &[u8]) -> [u8; 32] {
    hmac32(&keys.chunk_name, &[MEDIA_CONTEXT, bytes])
}

/// The reference of a streamed media file: over its length and its chunks' names.
#[must_use]
pub fn media_stream_ref(keys: &BackupKeys, length: u64, names: &[ChunkName]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, keys.chunk_name.as_ref());
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(MEDIA_STREAM_CONTEXT);
    ctx.update(&length.to_be_bytes());
    for n in names {
        ctx.update(&n.0);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// The padded length of `n` plaintext bytes.
#[must_use]
pub fn padded_len(n: usize) -> usize {
    let n = u64::try_from(n.saturating_add(4).max(MIN_PADDED)).unwrap_or(u64::MAX);
    usize::try_from(songbird_proto::media::padme(n)).unwrap_or(usize::MAX)
}

/// The largest chunk object.
#[must_use]
pub fn max_chunk_object() -> usize {
    CHUNK_HEADER + padded_len(chunker::MAX) + TAG
}

/// The largest manifest object.
#[must_use]
pub fn max_manifest_object() -> usize {
    MANIFEST_HEADER + padded_len(MAX_MANIFEST) + TAG
}

fn pad(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let len = u32::try_from(plaintext.len()).map_err(|_| Error::TooLarge("plaintext"))?;
    let mut v = Zeroizing::new(Vec::with_capacity(padded_len(plaintext.len()) + TAG));
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(plaintext);
    v.resize(padded_len(plaintext.len()), 0);
    Ok(v)
}

fn unpad(mut padded: Zeroizing<Vec<u8>>, what: &'static str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (len, rest) = padded.split_at_checked(4).ok_or(Error::Malformed(what))?;
    let mut l = [0u8; 4];
    l.copy_from_slice(len);
    let n = usize::try_from(u32::from_be_bytes(l)).map_err(|_| Error::Malformed(what))?;
    if n > rest.len() || padded_len(n) != padded.len() {
        return Err(Error::Malformed(what));
    }
    if rest.get(n..).is_some_and(|z| z.iter().any(|&b| b != 0)) {
        return Err(Error::Malformed(what));
    }
    padded.drain(..4);
    padded.truncate(n);
    Ok(padded)
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

/// Seals a chunk's plaintext under its name.
///
/// # Errors
/// [`Error::TooLarge`] past [`chunker::MAX`]; [`Error::Random`].
pub fn seal_chunk(
    keys: &BackupKeys,
    name: &ChunkName,
    plaintext: &[u8],
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, Error> {
    if plaintext.len() > chunker::MAX {
        return Err(Error::TooLarge("chunk"));
    }
    let mut nonce = [0u8; NONCE];
    rng.fill(&mut nonce)?;
    let mut head = [0u8; CHUNK_HEADER];
    head[..3].copy_from_slice(CHUNK_MAGIC);
    head[3] = VERSION;
    head[4..].copy_from_slice(&nonce);
    let mut buf = pad(plaintext)?;
    let tag = cipher(&keys.chunk)
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &[&head[..], &name.0[..]].concat(),
            &mut buf,
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(CHUNK_HEADER + buf.len() + TAG);
    out.extend_from_slice(&head);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens a chunk and checks it is the one named `name`, `length` plaintext bytes long.
///
/// # Errors
/// [`Error::Malformed`], [`Error::Damaged`] (tag), [`Error::WrongName`].
pub fn open_chunk(
    keys: &BackupKeys,
    name: &ChunkName,
    length: u32,
    object: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if object.len() > max_chunk_object() {
        return Err(Error::TooLarge("chunk"));
    }
    let (head, rest) = object
        .split_at_checked(CHUNK_HEADER)
        .ok_or(Error::Malformed("chunk"))?;
    if head.get(..3) != Some(CHUNK_MAGIC) || head.get(3) != Some(&VERSION) {
        return Err(Error::Malformed("chunk"));
    }
    let (ct, tag) = rest
        .split_at_checked(
            rest.len()
                .checked_sub(TAG)
                .ok_or(Error::Malformed("chunk"))?,
        )
        .ok_or(Error::Malformed("chunk"))?;
    let want = usize::try_from(length).map_err(|_| Error::Malformed("chunk"))?;
    if want > chunker::MAX || ct.len() != padded_len(want) {
        // A truncated or extended object: its length cannot be the named chunk's.
        return Err(Error::Damaged("chunk"));
    }
    let nonce = head.get(4..).ok_or(Error::Malformed("chunk"))?;
    let mut buf = Zeroizing::new(ct.to_vec());
    cipher(&keys.chunk)
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            &[head, &name.0[..]].concat(),
            &mut buf,
            Tag::from_slice(tag),
        )
        .map_err(|_| Error::Damaged("chunk"))?;
    let plain = unpad(buf, "chunk")?;
    if plain.len() != want {
        return Err(Error::Malformed("chunk"));
    }
    let got = chunk_name(keys, &plain);
    if aws_lc_rs::constant_time::verify_slices_are_equal(&got.0, &name.0).is_err() {
        return Err(Error::WrongName);
    }
    Ok(plain)
}

/// The generation in a manifest object's clear header, without opening it.
///
/// # Errors
/// [`Error::Malformed`].
pub fn manifest_generation(object: &[u8]) -> Result<u64, Error> {
    let head = object
        .get(..MANIFEST_HEADER)
        .ok_or(Error::Malformed("manifest"))?;
    if head.get(..3) != Some(MANIFEST_MAGIC) || head.get(3) != Some(&VERSION) {
        return Err(Error::Malformed("manifest"));
    }
    let mut g = [0u8; 8];
    g.copy_from_slice(head.get(4..12).ok_or(Error::Malformed("manifest"))?);
    Ok(u64::from_be_bytes(g))
}

/// SHA-256 of a manifest object (what the next manifest's `previous` holds).
#[must_use]
pub fn manifest_hash(object: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, object).as_ref());
    out
}

/// Seals a manifest as generation `generation` of the vault the keys name.
///
/// # Errors
/// [`Error::TooLarge`]; [`Error::Random`].
pub fn seal_manifest(
    keys: &BackupKeys,
    generation: u64,
    manifest: &Manifest,
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, Error> {
    let pb = Zeroizing::new(manifest.encode_to_vec());
    if pb.len() > MAX_MANIFEST {
        return Err(Error::TooLarge("manifest"));
    }
    let mut nonce = [0u8; NONCE];
    rng.fill(&mut nonce)?;
    let mut head = [0u8; MANIFEST_HEADER];
    head[..3].copy_from_slice(MANIFEST_MAGIC);
    head[3] = VERSION;
    head[4..12].copy_from_slice(&generation.to_be_bytes());
    head[12..].copy_from_slice(&nonce);
    let mut buf = pad(&pb)?;
    let tag = cipher(&keys.manifest)
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &[&head[..], &keys.vault_id[..]].concat(),
            &mut buf,
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(MANIFEST_HEADER + buf.len() + TAG);
    out.extend_from_slice(&head);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// The newest manifest this device has seen of a vault: anything older is a rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    /// Its generation.
    pub generation: u64,
    /// Its [`manifest_hash`].
    pub hash: [u8; 32],
}

/// An opened manifest.
#[derive(Debug, Clone)]
pub struct Opened {
    /// The generation from the header (authenticated).
    pub generation: u64,
    /// [`manifest_hash`] of the object.
    pub hash: [u8; 32],
    /// The plaintext, checked against the format's bounds.
    pub manifest: Manifest,
}

impl Opened {
    /// What a device remembers after reading this manifest.
    #[must_use]
    pub fn seen(&self) -> Seen {
        Seen {
            generation: self.generation,
            hash: self.hash,
        }
    }
}

/// Opens a manifest object, checks its bounds and that it does not roll back or fork from
/// `seen`.
///
/// # Errors
/// [`Error::Malformed`], [`Error::Damaged`] (tag, or another vault's manifest),
/// [`Error::TooNew`], [`Error::Rollback`], [`Error::Fork`].
pub fn open_manifest(
    keys: &BackupKeys,
    object: &[u8],
    seen: Option<Seen>,
) -> Result<Opened, Error> {
    if object.len() > max_manifest_object() {
        return Err(Error::TooLarge("manifest"));
    }
    let generation = manifest_generation(object)?;
    let hash = manifest_hash(object);
    if let Some(s) = seen {
        if generation < s.generation {
            return Err(Error::Rollback);
        }
        if generation == s.generation && hash != s.hash {
            return Err(Error::Fork);
        }
    }
    let (head, rest) = object
        .split_at_checked(MANIFEST_HEADER)
        .ok_or(Error::Malformed("manifest"))?;
    let (ct, tag) = rest
        .split_at_checked(
            rest.len()
                .checked_sub(TAG)
                .ok_or(Error::Malformed("manifest"))?,
        )
        .ok_or(Error::Malformed("manifest"))?;
    if ct.len() < MIN_PADDED {
        return Err(Error::Malformed("manifest"));
    }
    let nonce = head.get(12..).ok_or(Error::Malformed("manifest"))?;
    let mut buf = Zeroizing::new(ct.to_vec());
    cipher(&keys.manifest)
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            &[head, &keys.vault_id[..]].concat(),
            &mut buf,
            Tag::from_slice(tag),
        )
        .map_err(|_| Error::Damaged("manifest"))?;
    let plain = unpad(buf, "manifest")?;
    let manifest = decode_manifest(&plain)?;
    if let Some(s) = seen
        && generation == s.generation.saturating_add(1)
        && manifest.previous.as_slice() != s.hash.as_slice()
    {
        return Err(Error::Fork);
    }
    Ok(Opened {
        generation,
        hash,
        manifest,
    })
}

/// Decodes a manifest's plaintext and checks it against the format's bounds and this reader's
/// version (the part of [`open_manifest`] after decryption; fuzzed on its own).
///
/// # Errors
/// [`Error::Malformed`], [`Error::TooNew`], [`Error::TooLarge`].
pub fn decode_manifest(plain: &[u8]) -> Result<Manifest, Error> {
    if plain.len() > MAX_MANIFEST {
        return Err(Error::TooLarge("manifest"));
    }
    let manifest = Manifest::decode(plain).map_err(|_| Error::Malformed("manifest"))?;
    if manifest.min_reader_version > READER_VERSION {
        return Err(Error::TooNew);
    }
    if manifest.format_version == 0 || manifest.min_reader_version == 0 {
        return Err(Error::Malformed("manifest"));
    }
    check_bounds(&manifest)?;
    Ok(manifest)
}

fn check_bounds(m: &Manifest) -> Result<(), Error> {
    if m.streams.len() > MAX_STREAMS {
        return Err(Error::TooLarge("manifest"));
    }
    if !(m.previous.is_empty() || m.previous.len() == 32) {
        return Err(Error::Malformed("manifest"));
    }
    let mut chunks = 0usize;
    let mut records = 0;
    let mut small = 0;
    for s in &m.streams {
        chunks = chunks.saturating_add(s.chunks.len());
        if chunks > MAX_CHUNKS {
            return Err(Error::TooLarge("manifest"));
        }
        if s.sha256.len() != 32 {
            return Err(Error::Malformed("manifest"));
        }
        match StreamKind::try_from(s.kind) {
            Ok(StreamKind::Records) => records += 1,
            Ok(StreamKind::SmallMedia) => small += 1,
            Ok(StreamKind::Media) if s.id.len() != 32 => return Err(Error::Malformed("manifest")),
            _ => {}
        }
        let mut total = 0u64;
        for c in &s.chunks {
            if c.name.len() != 32 || c.length == 0 {
                return Err(Error::Malformed("manifest"));
            }
            if usize::try_from(c.length).map_or(true, |l| l > chunker::MAX) {
                return Err(Error::Malformed("manifest"));
            }
            total = total.saturating_add(u64::from(c.length));
        }
        if total != s.length {
            return Err(Error::Malformed("manifest"));
        }
    }
    if records != 1 || small > 1 {
        return Err(Error::Malformed("manifest"));
    }
    Ok(())
}
