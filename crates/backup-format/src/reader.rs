//! Restoring a backup in two phases (PROTOCOL §11.6).
//!
//! 1. [`verify`] fetches every chunk the manifest names from the store, checks it (tag, name,
//!    length, padding), checks each stream's length and SHA-256, decodes every record and blob,
//!    and keeps the **encrypted** objects in a [`Staging`] area. Nothing is restored yet.
//! 2. Only after `verify` succeeded does the caller read the backup ([`Backup`]) from staging
//!    and write it to its own, empty store. Each chunk is opened and checked again as it is
//!    read, so staging that changed in between fails too.
//!
//! A failure in either phase is an [`Error`] naming what failed; nothing has been written by
//! this crate, and the caller's rule is to apply the backup in one transaction or not at all.

use std::collections::{HashMap, HashSet};
use std::io::Read;

use aws_lc_rs::digest;
use zeroize::Zeroizing;

use crate::object::{self, ChunkName};
use crate::schema::{Blob, Manifest, Record, Stream, StreamKind};
use crate::writer::MAX_RECORD;
use crate::{BackupKeys, Error};

/// Where chunks come from.
pub trait ChunkSource {
    /// The object stored under `name`.
    ///
    /// # Errors
    /// [`Error::Missing`] when the store does not have it; [`Error::Store`].
    fn get(&mut self, name: &ChunkName) -> Result<Vec<u8>, Error>;
}

/// Where verified (still encrypted) chunks wait until the restore is applied.
pub trait Staging {
    /// Keeps an object.
    ///
    /// # Errors
    /// [`Error::Store`] or [`Error::Io`].
    fn put(&mut self, name: &ChunkName, object: Vec<u8>) -> Result<(), Error>;
    /// Returns a kept object.
    ///
    /// # Errors
    /// [`Error::Missing`].
    fn get(&self, name: &ChunkName) -> Result<Vec<u8>, Error>;
}

/// Staging in memory.
#[derive(Debug, Default)]
pub struct MemoryStaging(HashMap<ChunkName, Vec<u8>>);

impl Staging for MemoryStaging {
    fn put(&mut self, name: &ChunkName, object: Vec<u8>) -> Result<(), Error> {
        self.0.insert(*name, object);
        Ok(())
    }
    fn get(&self, name: &ChunkName) -> Result<Vec<u8>, Error> {
        self.0.get(name).cloned().ok_or(Error::Missing)
    }
}

/// Staging in a folder: one file per chunk, named by its hex name. The objects stay
/// encrypted on disk.
#[derive(Debug)]
pub struct DirStaging(std::path::PathBuf);

impl DirStaging {
    /// Uses (and creates) `dir`.
    ///
    /// # Errors
    /// [`Error::Io`].
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Result<Self, Error> {
        let d = dir.into();
        std::fs::create_dir_all(&d)?;
        Ok(Self(d))
    }
}

impl Staging for DirStaging {
    fn put(&mut self, name: &ChunkName, object: Vec<u8>) -> Result<(), Error> {
        std::fs::write(self.0.join(name.to_hex()), object)?;
        Ok(())
    }
    fn get(&self, name: &ChunkName) -> Result<Vec<u8>, Error> {
        match std::fs::read(self.0.join(name.to_hex())) {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::Missing),
            Err(e) => Err(e.into()),
        }
    }
}

/// What a verification read.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// Distinct chunks fetched and checked.
    pub chunks: u64,
    /// Object bytes fetched.
    pub object_bytes: u64,
    /// Records decoded.
    pub records: u64,
    /// Blobs decoded.
    pub blobs: u64,
}

fn name_of(c: &crate::schema::ChunkRef) -> Result<ChunkName, Error> {
    ChunkName::from_slice(&c.name).ok_or(Error::Malformed("manifest"))
}

/// Phase one: fetch and check everything the manifest names, into `staging`.
///
/// # Errors
/// The first failure: [`Error::Missing`], [`Error::Damaged`], [`Error::WrongName`],
/// [`Error::StreamMismatch`], [`Error::Malformed`], or the store's.
pub fn verify(
    keys: &BackupKeys,
    manifest: &Manifest,
    source: &mut dyn ChunkSource,
    staging: &mut dyn Staging,
) -> Result<Verified, Error> {
    let mut seen = HashSet::new();
    let mut v = Verified::default();
    for c in manifest.streams.iter().flat_map(|s| s.chunks.iter()) {
        let name = name_of(c)?;
        if !seen.insert(name) {
            continue;
        }
        let obj = source.get(&name)?;
        object::open_chunk(keys, &name, c.length, &obj)?;
        v.chunks += 1;
        v.object_bytes += u64::try_from(obj.len()).unwrap_or(u64::MAX);
        staging.put(&name, obj)?;
    }
    // Streams: lengths and hashes, and every record and blob decodes.
    let backup = Backup {
        keys,
        manifest,
        staging,
    };
    for s in &manifest.streams {
        let mut r = backup.stream(s);
        match StreamKind::try_from(s.kind) {
            Ok(StreamKind::Records) => {
                while let Some(rec) = next_delimited::<Record>(&mut r)? {
                    if rec.body.is_none() {
                        // A kind from a newer writer is ignored, not refused (§11.7).
                    }
                    v.records += 1;
                }
            }
            Ok(StreamKind::SmallMedia) => {
                while let Some(b) = next_delimited::<Blob>(&mut r)? {
                    if b.r#ref.len() != 32 {
                        return Err(Error::Malformed("blob"));
                    }
                    v.blobs += 1;
                }
            }
            _ => {
                std::io::copy(&mut r, &mut std::io::sink()).map_err(unwrap_io)?;
            }
        }
        r.finish()?;
    }
    Ok(v)
}

fn unwrap_io(e: std::io::Error) -> Error {
    match e.into_inner() {
        Some(inner) => match inner.downcast::<Error>() {
            Ok(b) => *b,
            Err(other) => Error::Io(std::io::Error::other(other)),
        },
        None => Error::Malformed("stream"),
    }
}

/// Reads the next length-delimited message, or `None` at the stream's end.
fn next_delimited<M: prost::Message + Default>(
    r: &mut StreamReader<'_>,
) -> Result<Option<M>, Error> {
    // A varint of at most 10 bytes; the stream may end only before its first byte.
    let mut len = 0u64;
    let mut shift = 0;
    loop {
        let mut b = [0u8; 1];
        let n = r.read(&mut b).map_err(unwrap_io)?;
        if n == 0 {
            if shift == 0 {
                return Ok(None);
            }
            return Err(Error::Malformed("record"));
        }
        len |= u64::from(b[0] & 0x7f) << shift;
        if b[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::Malformed("record"));
        }
    }
    let len = usize::try_from(len).map_err(|_| Error::Malformed("record"))?;
    if len > MAX_RECORD {
        return Err(Error::TooLarge("record"));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Malformed("record")
        } else {
            unwrap_io(e)
        }
    })?;
    M::decode(buf.as_slice())
        .map(Some)
        .map_err(|_| Error::Malformed("record"))
}

/// Phase two: a verified backup, read from staging.
pub struct Backup<'a> {
    keys: &'a BackupKeys,
    manifest: &'a Manifest,
    staging: &'a dyn Staging,
}

impl std::fmt::Debug for Backup<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Backup { .. }")
    }
}

impl<'a> Backup<'a> {
    /// A backup whose chunks [`verify`] put in `staging`.
    #[must_use]
    pub fn new(keys: &'a BackupKeys, manifest: &'a Manifest, staging: &'a dyn Staging) -> Self {
        Self {
            keys,
            manifest,
            staging,
        }
    }

    fn stream(&self, s: &'a Stream) -> StreamReader<'a> {
        StreamReader {
            keys: self.keys,
            staging: self.staging,
            stream: s,
            next: 0,
            buf: Zeroizing::new(Vec::new()),
            at: 0,
            hash: Some(digest::Context::new(&digest::SHA256)),
            read: 0,
        }
    }

    fn find(&self, kind: StreamKind) -> Option<&'a Stream> {
        self.manifest
            .streams
            .iter()
            .find(|s| StreamKind::try_from(s.kind) == Ok(kind))
    }

    /// Every record, in the order written.
    #[must_use]
    pub fn records(&self) -> Records<'a> {
        Records(self.find(StreamKind::Records).map(|s| self.stream(s)))
    }

    /// Every small media file, as `(reference, bytes)`.
    #[must_use]
    pub fn blobs(&self) -> Blobs<'a> {
        Blobs(self.find(StreamKind::SmallMedia).map(|s| self.stream(s)))
    }

    /// The references of the streamed media files.
    #[must_use]
    pub fn media_streams(&self) -> Vec<[u8; 32]> {
        self.manifest
            .streams
            .iter()
            .filter(|s| StreamKind::try_from(s.kind) == Ok(StreamKind::Media))
            .filter_map(|s| <[u8; 32]>::try_from(s.id.as_slice()).ok())
            .collect()
    }

    /// A streamed media file's bytes. The reader fails at its end if the stream does not
    /// match the manifest.
    #[must_use]
    pub fn media(&self, r: &[u8; 32]) -> Option<StreamReader<'a>> {
        self.manifest
            .streams
            .iter()
            .find(|s| StreamKind::try_from(s.kind) == Ok(StreamKind::Media) && s.id == r)
            .map(|s| self.stream(s))
    }
}

/// The records of a backup.
pub struct Records<'a>(Option<StreamReader<'a>>);

impl std::fmt::Debug for Records<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Records { .. }")
    }
}

impl Iterator for Records<'_> {
    type Item = Result<Record, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        let r = self.0.as_mut()?;
        match next_delimited::<Record>(r) {
            Ok(Some(rec)) => Some(Ok(rec)),
            Ok(None) => {
                let res = r.finish();
                self.0 = None;
                res.err().map(Err)
            }
            Err(e) => {
                self.0 = None;
                Some(Err(e))
            }
        }
    }
}

/// The small media files of a backup.
pub struct Blobs<'a>(Option<StreamReader<'a>>);

impl std::fmt::Debug for Blobs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Blobs { .. }")
    }
}

impl Iterator for Blobs<'_> {
    type Item = Result<([u8; 32], Zeroizing<Vec<u8>>), Error>;
    fn next(&mut self) -> Option<Self::Item> {
        let r = self.0.as_mut()?;
        match next_delimited::<Blob>(r) {
            Ok(Some(mut b)) => {
                let data = Zeroizing::new(std::mem::take(&mut b.data));
                if let Ok(id) = <[u8; 32]>::try_from(b.r#ref.as_slice()) {
                    Some(Ok((id, data)))
                } else {
                    self.0 = None;
                    Some(Err(Error::Malformed("blob")))
                }
            }
            Ok(None) => {
                let res = r.finish();
                self.0 = None;
                res.err().map(Err)
            }
            Err(e) => {
                self.0 = None;
                Some(Err(e))
            }
        }
    }
}

/// One stream's bytes, each chunk opened and checked as it is reached; the stream's length
/// and SHA-256 are checked at its end ([`StreamReader::finish`], or a read returning 0 after
/// the last byte fails if they do not match).
pub struct StreamReader<'a> {
    keys: &'a BackupKeys,
    staging: &'a dyn Staging,
    stream: &'a Stream,
    next: usize,
    buf: Zeroizing<Vec<u8>>,
    at: usize,
    hash: Option<digest::Context>,
    read: u64,
}

impl std::fmt::Debug for StreamReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamReader { .. }")
    }
}

impl StreamReader<'_> {
    fn fill(&mut self) -> Result<bool, Error> {
        let Some(c) = self.stream.chunks.get(self.next) else {
            return Ok(false);
        };
        let name = name_of(c)?;
        let obj = self.staging.get(&name)?;
        let plain = object::open_chunk(self.keys, &name, c.length, &obj)?;
        if let Some(h) = self.hash.as_mut() {
            h.update(&plain);
        }
        self.read += u64::from(c.length);
        self.buf = plain;
        self.at = 0;
        self.next += 1;
        Ok(true)
    }

    /// Checks the whole stream was read and matches the manifest.
    ///
    /// # Errors
    /// [`Error::StreamMismatch`].
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.next < self.stream.chunks.len() || self.at < self.buf.len() {
            return Err(Error::StreamMismatch);
        }
        let Some(h) = self.hash.take() else {
            return Ok(());
        };
        if self.read != self.stream.length || h.finish().as_ref() != self.stream.sha256.as_slice() {
            return Err(Error::StreamMismatch);
        }
        Ok(())
    }
}

impl Read for StreamReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.at >= self.buf.len() {
            match self.fill() {
                Ok(true) => {}
                Ok(false) => {
                    if self.hash.is_some() {
                        self.finish().map_err(std::io::Error::other)?;
                    }
                    return Ok(0);
                }
                Err(e) => return Err(std::io::Error::other(e)),
            }
        }
        let rest = self.buf.get(self.at..).unwrap_or_default();
        let n = rest.len().min(out.len());
        out.get_mut(..n)
            .unwrap_or_default()
            .copy_from_slice(rest.get(..n).unwrap_or_default());
        self.at += n;
        Ok(n)
    }
}
