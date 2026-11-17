//! The attachment format (Prompt 6, PROTOCOL §7.1, D-0080): files are encrypted on the device in
//! fixed-size chunks with a streaming AEAD, so large files can be streamed, resumed and verified
//! chunk by chunk, and their sizes are padded into buckets.
//!
//! ```text
//! pointer.key (64 random bytes) ─┐
//! header salt (32 random bytes) ─┴─ HKDF-SHA256(info = "songbird.v1/attachment\0" ‖ version)
//!                                   ├─ 32 bytes: the chunk key
//!                                   └─ 32 bytes: the key commitment (= pointer.digest)
//!
//! ciphertext = version ‖ salt ‖ seal(chunk 0) ‖ … ‖ seal(chunk k-1)
//! chunk i    = AEAD(key, nonce = 0x000000 ‖ be64(i) ‖ last?, aad = "", 64 KiB of padded plaintext)
//! ```
//!
//! This is the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár, CRYPTO 2015) as `age`
//! uses it: the nonce binds each chunk to its position and marks the last one, so reordering,
//! dropping, truncating and extending are all caught at the chunk where they happen. The
//! commitment, checked before any chunk, makes the format key-committing: a sender cannot make
//! one object open to different files under different keys (Albertini et al., USENIX Security
//! 2022). The salt keeps chunk keys unique even if an app reused a pointer key by mistake.
//!
//! The plaintext is padded with zeros to Padmé buckets ([`songbird_proto::media`]); the real
//! length travels only inside the encrypted pointer (`size`), and the zero padding is checked.
//! Thumbnails are ordinary attachments of their own. Forwarding encrypts again under a fresh key
//! and salt (a new object ID), so two messages cannot be linked by their objects.

use std::io::{Read, Write};

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hkdf;
use songbird_proto::media::{self, CHUNK, HEADER, TAG};
use zeroize::{Zeroize, Zeroizing};

/// The pointer key: 64 random bytes (`AttachmentPointer.key`).
pub const KEY_LEN: usize = 64;
/// The salt in the header.
pub const SALT_LEN: usize = 32;
/// The key commitment (`AttachmentPointer.digest`).
pub const DIGEST_LEN: usize = 32;
/// Domain separation of the key derivation; the version byte follows it.
pub const CONTEXT: &[u8] = b"songbird.v1/attachment\0";

// `CHUNK`, `TAG` and `HEADER` are small constants; these conversions cannot fail.
const CHUNK_USIZE: usize = 65_536;
const TAG_USIZE: usize = 16;
const HEADER_USIZE: usize = 33;
#[allow(clippy::as_conversions, reason = "compile-time check of constants")]
const _: () = assert!(
    CHUNK_USIZE as u64 == CHUNK
        && TAG_USIZE as u64 == TAG
        && HEADER_USIZE as u64 == HEADER
        && HEADER_USIZE == 1 + SALT_LEN
);

/// The AEAD under the chunks, named by the header's version byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// Version 1: ChaCha20-Poly1305 (RFC 8439).
    ChaCha20Poly1305,
    /// Version 2: AES-256-GCM.
    Aes256Gcm,
}

impl Suite {
    /// The suite apps write (D-0080 records the measurement behind it).
    pub const DEFAULT: Suite = Suite::Aes256Gcm;

    /// The header's version byte.
    #[must_use]
    pub fn version(self) -> u8 {
        match self {
            Suite::ChaCha20Poly1305 => 1,
            Suite::Aes256Gcm => 2,
        }
    }

    /// The suite for a version byte.
    #[must_use]
    pub fn from_version(v: u8) -> Option<Suite> {
        match v {
            1 => Some(Suite::ChaCha20Poly1305),
            2 => Some(Suite::Aes256Gcm),
            _ => None,
        }
    }

    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Suite::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
            Suite::Aes256Gcm => &aead::AES_256_GCM,
        }
    }
}

/// Why an attachment did not open. Carries no content and no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The header is short or names an unknown version.
    #[error("bad header")]
    Header,
    /// The pointer's key or digest has the wrong length.
    #[error("bad pointer")]
    Pointer,
    /// The commitment does not match: the wrong key, salt or object.
    #[error("key commitment mismatch")]
    Commitment,
    /// The plaintext length is past the format's limit, or the ciphertext is not the length it
    /// implies.
    #[error("bad length")]
    Length,
    /// A chunk failed authentication (tampered, reordered, truncated or extended).
    #[error("chunk {0} failed authentication")]
    Chunk(u64),
    /// The padding after the real plaintext is not all zeros.
    #[error("bad padding")]
    Padding,
    /// Bytes after the last chunk.
    #[error("trailing bytes")]
    Trailing,
    /// The reader or writer failed.
    #[error("i/o")]
    Io,
    /// The random number generator or the crypto library failed.
    #[error("crypto")]
    Crypto,
}

/// Chunk key and commitment for a pointer key, salt and suite.
struct Keys {
    aead: LessSafeKey,
    commitment: [u8; DIGEST_LEN],
}

struct Len64;
impl hkdf::KeyType for Len64 {
    fn len(&self) -> usize {
        64
    }
}

fn derive(suite: Suite, key: &[u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Result<Keys, Error> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(key);
    let version = [suite.version()];
    let info = [CONTEXT, &version[..]];
    let mut okm = Zeroizing::new([0u8; 64]);
    prk.expand(&info, Len64)
        .and_then(|o| o.fill(&mut okm[..]))
        .map_err(|_| Error::Crypto)?;
    let (k, c) = okm.split_at(32);
    let aead = LessSafeKey::new(UnboundKey::new(suite.algorithm(), k).map_err(|_| Error::Crypto)?);
    let mut commitment = [0u8; DIGEST_LEN];
    commitment.copy_from_slice(c);
    Ok(Keys { aead, commitment })
}

fn nonce(index: u64, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    if let Some(c) = n.get_mut(3..11) {
        c.copy_from_slice(&index.to_be_bytes());
    }
    if let Some(l) = n.get_mut(11) {
        *l = u8::from(last);
    }
    Nonce::assume_unique_for_key(n)
}

fn to_usize(v: u64) -> Result<usize, Error> {
    usize::try_from(v).map_err(|_| Error::Length)
}

/// Fills a fresh pointer key (64 bytes) and salt from the system's random number generator.
///
/// # Errors
/// [`Error::Crypto`] if the generator fails.
pub fn fresh() -> Result<(Zeroizing<[u8; KEY_LEN]>, [u8; SALT_LEN]), Error> {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let key = Zeroizing::new(
        aws_lc_rs::rand::generate::<[u8; KEY_LEN]>(&rng)
            .map_err(|_| Error::Crypto)?
            .expose(),
    );
    let salt = aws_lc_rs::rand::generate::<[u8; SALT_LEN]>(&rng)
        .map_err(|_| Error::Crypto)?
        .expose();
    Ok((key, salt))
}

/// Encrypts an attachment chunk by chunk.
///
/// Feed exactly `plaintext_len` bytes through [`Encryptor::push`] (any slicing), then call
/// [`Encryptor::finish`]; ciphertext comes out as each chunk fills. Memory stays at one chunk.
pub struct Encryptor {
    keys: Keys,
    header: [u8; HEADER_USIZE],
    plaintext_len: u64,
    padded_len: u64,
    taken: u64,
    index: u64,
    chunks: u64,
    buf: Vec<u8>,
}

impl std::fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encryptor")
            .field("plaintext_len", &self.plaintext_len)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl Drop for Encryptor {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl Encryptor {
    /// Starts an attachment of `plaintext_len` bytes.
    ///
    /// # Errors
    /// [`Error::Length`] past the format's limit; [`Error::Crypto`].
    pub fn new(
        suite: Suite,
        key: &[u8; KEY_LEN],
        salt: &[u8; SALT_LEN],
        plaintext_len: u64,
    ) -> Result<Self, Error> {
        let padded_len = media::padded_len(plaintext_len).ok_or(Error::Length)?;
        let keys = derive(suite, key, salt)?;
        let mut header = [0u8; HEADER_USIZE];
        let (v, s) = header.split_at_mut(1);
        v.copy_from_slice(&[suite.version()]);
        s.copy_from_slice(salt);
        Ok(Self {
            keys,
            header,
            plaintext_len,
            padded_len,
            taken: 0,
            index: 0,
            chunks: media::chunks(padded_len),
            buf: Vec::with_capacity(CHUNK_USIZE + TAG_USIZE),
        })
    }

    /// The header, which goes first.
    #[must_use]
    pub fn header(&self) -> [u8; HEADER_USIZE] {
        self.header
    }

    /// The key commitment, which goes into the pointer as `digest`.
    #[must_use]
    pub fn digest(&self) -> [u8; DIGEST_LEN] {
        self.keys.commitment
    }

    /// The whole ciphertext's length, header included: what the upload grant asks for.
    #[must_use]
    pub fn ciphertext_len(&self) -> u64 {
        media::ciphertext_len_padded(self.padded_len)
    }

    /// Adds plaintext; every chunk it completes is written to `out`.
    ///
    /// # Errors
    /// [`Error::Length`] if more than `plaintext_len` bytes arrive; [`Error::Io`]; [`Error::Crypto`].
    pub fn push(&mut self, mut data: &[u8], out: &mut impl Write) -> Result<(), Error> {
        let len = u64::try_from(data.len()).map_err(|_| Error::Length)?;
        if self
            .taken
            .checked_add(len)
            .is_none_or(|t| t > self.plaintext_len)
        {
            return Err(Error::Length);
        }
        self.taken += len;
        while !data.is_empty() {
            let room = CHUNK_USIZE - self.buf.len();
            let (now, rest) = data.split_at(room.min(data.len()));
            self.buf.extend_from_slice(now);
            data = rest;
            // A full chunk is sealed only once more input shows it is not the last one.
            if self.buf.len() == CHUNK_USIZE && self.index + 1 < self.chunks {
                self.seal(false, out)?;
            }
        }
        Ok(())
    }

    /// Pads, seals the remaining chunks and writes them.
    ///
    /// # Errors
    /// [`Error::Length`] if fewer than `plaintext_len` bytes were pushed; [`Error::Io`];
    /// [`Error::Crypto`].
    pub fn finish(mut self, out: &mut impl Write) -> Result<(), Error> {
        if self.taken != self.plaintext_len {
            return Err(Error::Length);
        }
        // The rest of the padded plaintext is zeros, chunk by chunk.
        let mut zeros = self.padded_len - self.plaintext_len;
        loop {
            let room = u64::try_from(CHUNK_USIZE - self.buf.len()).map_err(|_| Error::Length)?;
            let fill = room.min(zeros);
            self.buf.resize(self.buf.len() + to_usize(fill)?, 0);
            zeros -= fill;
            let last = self.index + 1 == self.chunks;
            if last {
                return self.seal(true, out);
            }
            self.seal(false, out)?;
        }
    }

    fn seal(&mut self, last: bool, out: &mut impl Write) -> Result<(), Error> {
        let tag = self
            .keys
            .aead
            .seal_in_place_separate_tag(nonce(self.index, last), Aad::empty(), &mut self.buf)
            .map_err(|_| Error::Crypto)?;
        out.write_all(&self.buf).map_err(|_| Error::Io)?;
        out.write_all(tag.as_ref()).map_err(|_| Error::Io)?;
        self.buf.zeroize();
        self.buf.clear();
        self.index += 1;
        Ok(())
    }
}

/// Encrypts `plaintext_len` bytes from `input` into `output`, header first, and returns the
/// digest for the pointer.
///
/// # Errors
/// [`Error::Length`] if `input` ends early or has more; [`Error::Io`]; [`Error::Crypto`].
pub fn encrypt(
    suite: Suite,
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    plaintext_len: u64,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<[u8; DIGEST_LEN], Error> {
    let mut enc = Encryptor::new(suite, key, salt, plaintext_len)?;
    output.write_all(&enc.header()).map_err(|_| Error::Io)?;
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_USIZE]);
    let mut left = plaintext_len;
    while left > 0 {
        let want = to_usize(left.min(CHUNK))?;
        let chunk = buf.get_mut(..want).ok_or(Error::Length)?;
        input.read_exact(chunk).map_err(|_| Error::Length)?;
        enc.push(chunk, output)?;
        left -= CHUNK.min(left);
    }
    let mut extra = [0u8; 1];
    if input.read(&mut extra).map_err(|_| Error::Io)? != 0 {
        return Err(Error::Length);
    }
    let digest = enc.digest();
    enc.finish(output)?;
    Ok(digest)
}

/// Opens an attachment chunk by chunk, in any order: what resumed downloads and range requests
/// need. Built from the pointer (key, digest, size) and the 33-byte header.
pub struct Decryptor {
    aead: LessSafeKey,
    plaintext_len: u64,
    padded_len: u64,
    chunks: u64,
}

impl std::fmt::Debug for Decryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decryptor")
            .field("plaintext_len", &self.plaintext_len)
            .field("chunks", &self.chunks)
            .finish_non_exhaustive()
    }
}

impl Decryptor {
    /// Checks the header against the pointer: version, then the key commitment (constant
    /// time) before any chunk is touched.
    ///
    /// # Errors
    /// [`Error::Pointer`], [`Error::Header`], [`Error::Length`], [`Error::Commitment`],
    /// [`Error::Crypto`].
    pub fn new(
        key: &[u8],
        digest: &[u8],
        plaintext_len: u64,
        header: &[u8],
    ) -> Result<Self, Error> {
        let key: &[u8; KEY_LEN] = key.try_into().map_err(|_| Error::Pointer)?;
        if digest.len() != DIGEST_LEN {
            return Err(Error::Pointer);
        }
        let (&version, salt) = header.split_first().ok_or(Error::Header)?;
        let suite = Suite::from_version(version).ok_or(Error::Header)?;
        let salt: &[u8; SALT_LEN] = salt.try_into().map_err(|_| Error::Header)?;
        let padded_len = media::padded_len(plaintext_len).ok_or(Error::Length)?;
        let keys = derive(suite, key, salt)?;
        verify_slices_are_equal(&keys.commitment, digest).map_err(|_| Error::Commitment)?;
        Ok(Self {
            aead: keys.aead,
            plaintext_len,
            padded_len,
            chunks: media::chunks(padded_len),
        })
    }

    /// The whole ciphertext's length, header included.
    #[must_use]
    pub fn ciphertext_len(&self) -> u64 {
        media::ciphertext_len_padded(self.padded_len)
    }

    /// How many chunks there are.
    #[must_use]
    pub fn chunk_count(&self) -> u64 {
        self.chunks
    }

    /// The ciphertext bytes `[start, end)` holding chunk `index`, or `None` past the last.
    #[must_use]
    pub fn chunk_range(&self, index: u64) -> Option<(u64, u64)> {
        (index < self.chunks).then(|| {
            let start = media::chunk_offset(index);
            let plain = self.padded_len.saturating_sub(index * CHUNK).min(CHUNK);
            (start, start + plain + TAG)
        })
    }

    /// The chunks `[first, last]` that hold plaintext bytes `[start, end)` (`end` > `start`,
    /// within the real length), for a range request.
    #[must_use]
    pub fn chunks_for(&self, start: u64, end: u64) -> Option<(u64, u64)> {
        (start < end && end <= self.plaintext_len).then(|| (start / CHUNK, (end - 1) / CHUNK))
    }

    /// Opens chunk `index` in place and returns its real plaintext (padding removed and checked
    /// to be zeros).
    ///
    /// # Errors
    /// [`Error::Length`] if `sealed` is not exactly that chunk; [`Error::Chunk`];
    /// [`Error::Padding`].
    pub fn open_chunk<'a>(&self, index: u64, sealed: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let (start, end) = self.chunk_range(index).ok_or(Error::Length)?;
        if u64::try_from(sealed.len()).map_err(|_| Error::Length)? != end - start {
            return Err(Error::Length);
        }
        let last = index + 1 == self.chunks;
        let plain = self
            .aead
            .open_in_place(nonce(index, last), Aad::empty(), sealed)
            .map_err(|_| Error::Chunk(index))?;
        // Bytes of this chunk that are real plaintext; the rest must be zero padding.
        let real = to_usize(self.plaintext_len.saturating_sub(index * CHUNK).min(CHUNK))?;
        let (data, pad) = plain.split_at(real.min(plain.len()));
        if pad.iter().fold(0u8, |acc, b| acc | b) != 0 {
            return Err(Error::Padding);
        }
        Ok(data)
    }
}

/// Opens a whole attachment from `input` (header first) into `output`, refusing anything after
/// the last chunk.
///
/// Plaintext reaches `output` chunk by chunk, after each chunk verified. If this fails partway,
/// what was written so far is authentic but incomplete: discard it.
///
/// # Errors
/// Any [`Error`].
pub fn decrypt(
    key: &[u8],
    digest: &[u8],
    plaintext_len: u64,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), Error> {
    let mut header = [0u8; HEADER_USIZE];
    input.read_exact(&mut header).map_err(|_| Error::Header)?;
    let dec = Decryptor::new(key, digest, plaintext_len, &header)?;
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_USIZE + TAG_USIZE]);
    for i in 0..dec.chunk_count() {
        let (s, e) = dec.chunk_range(i).ok_or(Error::Length)?;
        let sealed = buf.get_mut(..to_usize(e - s)?).ok_or(Error::Length)?;
        input.read_exact(sealed).map_err(|_| Error::Chunk(i))?;
        let plain = dec.open_chunk(i, sealed)?;
        output.write_all(plain).map_err(|_| Error::Io)?;
    }
    let mut extra = [0u8; 1];
    if input.read(&mut extra).map_err(|_| Error::Io)? != 0 {
        return Err(Error::Trailing);
    }
    Ok(())
}

/// The key commitment of an object, from its key and its 33-byte header. For an object whose key
/// alone proves it authentic (a pack's manifest, whose key derives from the pack key in the
/// link): it stands in for a pointer's `digest`.
///
/// # Errors
/// [`Error::Header`], [`Error::Crypto`].
pub fn commitment(key: &[u8; KEY_LEN], header: &[u8]) -> Result<[u8; DIGEST_LEN], Error> {
    let (&version, salt) = header.split_first().ok_or(Error::Header)?;
    let suite = Suite::from_version(version).ok_or(Error::Header)?;
    let salt: &[u8; SALT_LEN] = salt.try_into().map_err(|_| Error::Header)?;
    Ok(derive(suite, key, salt)?.commitment)
}
