//! Writing a backup (PROTOCOL §11.5).
//!
//! The caller feeds content in the canonical order (account, profile, settings, contacts,
//! groups, then each chat followed by its messages oldest first, each message's media just
//! before it); the writer encodes records, cuts streams into chunks, and hands the sink only the
//! chunks the previous manifest does not already reference. [`Writer::finish`] returns the
//! sealed manifest, which the caller stores with a compare-and-swap **after** every new chunk is
//! stored.

use std::collections::HashSet;
use std::io::Read;

use aws_lc_rs::digest;
use zeroize::Zeroizing;

use crate::chunker::{self, Params};
use crate::object::{self, ChunkName};
use crate::schema::{
    Blob, ChunkRef, Manifest, Media, Platform, Record, Stream, StreamKind, record::Body,
};
use crate::{BackupKeys, Error, FORMAT_VERSION, Rng};

/// Media under this many bytes are stored as `Blob`s in the small-media stream.
pub const SMALL_MEDIA: usize = chunker::MIN;
/// The largest record (encoded), so a reader can bound what it allocates.
pub const MAX_RECORD: usize = 4 << 20;
/// The largest single media file.
pub const MAX_MEDIA: u64 = 64 << 30;

/// Where new chunks go: a store adapter, a file, a transfer channel.
pub trait ChunkSink {
    /// Stores one sealed chunk object under its name.
    ///
    /// # Errors
    /// [`Error::Store`].
    fn put(&mut self, name: &ChunkName, object: Vec<u8>) -> Result<(), Error>;
}

/// What a backup cost.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Chunks handed to the sink.
    pub new_chunks: u64,
    /// Their object bytes.
    pub new_bytes: u64,
    /// Chunks already in the store (or written earlier in this backup).
    pub reused_chunks: u64,
    /// Plaintext bytes over every stream.
    pub plaintext_bytes: u64,
    /// Records written.
    pub records: u64,
    /// Distinct media files.
    pub media: u64,
}

struct StreamState {
    kind: StreamKind,
    id: Vec<u8>,
    buf: Zeroizing<Vec<u8>>,
    hash: digest::Context,
    length: u64,
    chunks: Vec<ChunkRef>,
    names: Vec<ChunkName>,
}

impl StreamState {
    fn new(kind: StreamKind) -> Self {
        Self {
            kind,
            id: vec![],
            buf: Zeroizing::new(Vec::new()),
            hash: digest::Context::new(&digest::SHA256),
            length: 0,
            chunks: vec![],
            names: vec![],
        }
    }
}

/// Information about the backup the manifest records.
#[derive(Debug, Clone)]
pub struct Info {
    /// The generation to write (the store's current one plus one; 1 for the first).
    pub generation: u64,
    /// The previous manifest's hash, if there is one.
    pub previous: Option<[u8; 32]>,
    /// Creation time (UTC milliseconds).
    pub created_ms: u64,
    /// The app's version string.
    pub app_version: String,
    /// The writing platform.
    pub platform: Platform,
}

/// A backup being written.
pub struct Writer<'a, S: ChunkSink> {
    keys: &'a BackupKeys,
    params: Params,
    rng: &'a mut dyn Rng,
    sink: S,
    known: HashSet<ChunkName>,
    media_seen: HashSet<[u8; 32]>,
    records: StreamState,
    small: StreamState,
    media: Vec<Stream>,
    stats: Stats,
    scratch: Vec<u8>,
}

impl<S: ChunkSink> std::fmt::Debug for Writer<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<'a, S: ChunkSink> Writer<'a, S> {
    /// A writer whose chunks are new unless `previous` (the store's current manifest) already
    /// references them.
    pub fn new(
        keys: &'a BackupKeys,
        previous: Option<&Manifest>,
        rng: &'a mut dyn Rng,
        sink: S,
    ) -> Self {
        Self::with_params(keys, previous, rng, sink, Params::BACKUP)
    }

    /// As [`Writer::new`] with other chunker parameters (tests only; readers accept any chunk
    /// up to [`chunker::MAX`]).
    pub fn with_params(
        keys: &'a BackupKeys,
        previous: Option<&Manifest>,
        rng: &'a mut dyn Rng,
        sink: S,
        params: Params,
    ) -> Self {
        let known = previous
            .into_iter()
            .flat_map(|m| m.streams.iter())
            .flat_map(|s| s.chunks.iter())
            .filter_map(|c| ChunkName::from_slice(&c.name))
            .collect();
        Self {
            keys,
            params,
            rng,
            sink,
            known,
            media_seen: HashSet::new(),
            records: StreamState::new(StreamKind::Records),
            small: StreamState::new(StreamKind::SmallMedia),
            media: vec![],
            stats: Stats::default(),
            scratch: Vec::new(),
        }
    }

    /// Names the store already holds besides the previous manifest's (for example chunks a
    /// failed backup uploaded): they are referenced, not uploaded again.
    pub fn known(&mut self, names: impl IntoIterator<Item = ChunkName>) {
        self.known.extend(names);
    }

    fn emit(&mut self, which: Which, data: &[u8]) -> Result<(), Error> {
        let name = object::chunk_name(self.keys, data);
        if self.known.insert(name) {
            let obj = object::seal_chunk(self.keys, &name, data, self.rng)?;
            self.stats.new_chunks += 1;
            self.stats.new_bytes += u64::try_from(obj.len()).unwrap_or(u64::MAX);
            self.sink.put(&name, obj)?;
        } else {
            self.stats.reused_chunks += 1;
        }
        let st = self.state(which);
        st.chunks.push(ChunkRef {
            name: name.0.to_vec(),
            length: u32::try_from(data.len()).map_err(|_| Error::TooLarge("chunk"))?,
        });
        st.names.push(name);
        Ok(())
    }

    fn state(&mut self, which: Which) -> &mut StreamState {
        match which {
            Which::Records => &mut self.records,
            Which::Small => &mut self.small,
        }
    }

    /// Cuts every full chunk off a stream's buffer (all of it when `last`).
    fn drain(&mut self, which: Which, last: bool) -> Result<(), Error> {
        let (keys, params) = (self.keys, self.params);
        loop {
            let st = self.state(which);
            if !last && st.buf.len() < params.max {
                return Ok(());
            }
            let Some(c) = chunker::cut(&keys.gear, &params, &st.buf, last) else {
                return Ok(());
            };
            let head: Zeroizing<Vec<u8>> = Zeroizing::new(st.buf.drain(..c).collect());
            self.emit(which, &head)?;
        }
    }

    fn append(&mut self, which: Which, bytes: &[u8]) -> Result<(), Error> {
        let st = self.state(which);
        st.hash.update(bytes);
        st.length += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        st.buf.extend_from_slice(bytes);
        self.stats.plaintext_bytes += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.drain(which, false)
    }

    fn delimited(&mut self, which: Which, msg: &impl prost::Message) -> Result<(), Error> {
        let n = msg.encoded_len();
        if n > MAX_RECORD {
            return Err(Error::TooLarge("record"));
        }
        let mut buf = std::mem::take(&mut self.scratch);
        buf.clear();
        msg.encode_length_delimited(&mut buf)
            .map_err(|_| Error::TooLarge("record"))?;
        let r = self.append(which, &buf);
        zeroize::Zeroize::zeroize(&mut buf);
        self.scratch = buf;
        r
    }

    /// Writes one record (anything but media, which goes through [`Writer::media`]).
    ///
    /// # Errors
    /// [`Error::TooLarge`] past [`MAX_RECORD`]; the sink's errors.
    pub fn record(&mut self, body: Body) -> Result<(), Error> {
        self.stats.records += 1;
        self.delimited(Which::Records, &Record { body: Some(body) })
    }

    /// Writes a media file (once, however often it is referenced) and its metadata record;
    /// returns its reference for the messages that show it. `meta.ref` and `meta.length` are
    /// filled in by the writer.
    ///
    /// # Errors
    /// [`Error::Io`] reading `content`; [`Error::TooLarge`] past [`MAX_MEDIA`]; the sink's.
    pub fn media(&mut self, mut meta: Media, content: &mut dyn Read) -> Result<[u8; 32], Error> {
        let mut head = Zeroizing::new(Vec::with_capacity(SMALL_MEDIA));
        content
            .take(u64::try_from(SMALL_MEDIA).unwrap_or(u64::MAX))
            .read_to_end(&mut head)?;
        let (r, length) = if head.len() < SMALL_MEDIA {
            let r = object::media_ref(self.keys, &head);
            let length = u64::try_from(head.len()).unwrap_or(u64::MAX);
            if self.media_seen.insert(r) {
                let blob = Blob {
                    r#ref: r.to_vec(),
                    data: head.to_vec(),
                };
                self.delimited(Which::Small, &blob)?;
                let mut b = blob;
                zeroize::Zeroize::zeroize(&mut b.data);
            } else {
                return Ok(r);
            }
            (r, length)
        } else {
            let (r, length, stream) = self.media_stream(&head, content)?;
            if !self.media_seen.insert(r) {
                return Ok(r);
            }
            self.media.push(stream);
            (r, length)
        };
        self.stats.media += 1;
        meta.r#ref = r.to_vec();
        meta.length = length;
        self.record(Body::Media(meta))?;
        Ok(r)
    }

    fn media_stream(
        &mut self,
        head: &[u8],
        rest: &mut dyn Read,
    ) -> Result<([u8; 32], u64, Stream), Error> {
        let mut buf = Zeroizing::new(Vec::with_capacity(self.params.max * 2));
        buf.extend_from_slice(head);
        let mut hash = digest::Context::new(&digest::SHA256);
        let mut length = 0u64;
        let mut chunks = vec![];
        let mut names = vec![];
        let mut eof = false;
        let mut read = Zeroizing::new(vec![0u8; 1 << 16]);
        loop {
            while !eof && buf.len() < self.params.max {
                let n = rest.read(&mut read)?;
                if n == 0 {
                    eof = true;
                } else {
                    buf.extend_from_slice(read.get(..n).unwrap_or_default());
                }
            }
            let Some(c) = chunker::cut(&self.keys.gear, &self.params, &buf, eof) else {
                break;
            };
            let part: Zeroizing<Vec<u8>> = Zeroizing::new(buf.drain(..c).collect());
            hash.update(&part);
            length += u64::try_from(part.len()).unwrap_or(u64::MAX);
            if length > MAX_MEDIA {
                return Err(Error::TooLarge("media"));
            }
            self.stats.plaintext_bytes += u64::try_from(part.len()).unwrap_or(u64::MAX);
            let name = object::chunk_name(self.keys, &part);
            if self.known.insert(name) {
                let obj = object::seal_chunk(self.keys, &name, &part, self.rng)?;
                self.stats.new_chunks += 1;
                self.stats.new_bytes += u64::try_from(obj.len()).unwrap_or(u64::MAX);
                self.sink.put(&name, obj)?;
            } else {
                self.stats.reused_chunks += 1;
            }
            chunks.push(ChunkRef {
                name: name.0.to_vec(),
                length: u32::try_from(part.len()).map_err(|_| Error::TooLarge("chunk"))?,
            });
            names.push(name);
        }
        let r = object::media_stream_ref(self.keys, length, &names);
        Ok((
            r,
            length,
            Stream {
                kind: StreamKind::Media.into(),
                id: r.to_vec(),
                length,
                sha256: hash.finish().as_ref().to_vec(),
                chunks,
            },
        ))
    }

    /// Flushes every stream and seals the manifest. Returns the manifest object (to store with
    /// a compare-and-swap after every chunk), its plaintext, the costs, and the sink.
    ///
    /// # Errors
    /// The sink's errors; [`Error::TooLarge`] for a manifest past the format's bounds.
    pub fn finish(mut self, info: &Info) -> Result<(Vec<u8>, Manifest, Stats, S), Error> {
        self.drain(Which::Records, true)?;
        self.drain(Which::Small, true)?;
        let close = |st: StreamState| Stream {
            kind: st.kind.into(),
            id: st.id,
            length: st.length,
            sha256: st.hash.finish().as_ref().to_vec(),
            chunks: st.chunks,
        };
        let records = std::mem::replace(&mut self.records, StreamState::new(StreamKind::Records));
        let small = std::mem::replace(&mut self.small, StreamState::new(StreamKind::SmallMedia));
        let mut streams = vec![close(records), close(small)];
        streams.append(&mut self.media);
        let manifest = Manifest {
            format_version: FORMAT_VERSION,
            min_reader_version: 1,
            created_ms: info.created_ms,
            app_version: info.app_version.clone(),
            platform: info.platform.into(),
            previous: info.previous.map(|h| h.to_vec()).unwrap_or_default(),
            streams,
        };
        let object = object::seal_manifest(self.keys, info.generation, &manifest, self.rng)?;
        Ok((object, manifest, self.stats, self.sink))
    }
}

#[derive(Clone, Copy)]
enum Which {
    Records,
    Small,
}
