//! Local export (PROTOCOL §11.8): a folder the user keeps (a drive, a computer, a synced
//! folder of any cloud), and a single `.songbird-backup` file to move by hand.
//!
//! Folder layout:
//!
//! ```text
//! <root>/chunks/<64 hex>   one file per chunk, written to a temporary name and renamed
//! <root>/manifest          the current manifest
//! <root>/manifest.lock     held while a manifest is swapped (created exclusively)
//! ```
//!
//! Archive file (`.songbird-backup`), read-only once written:
//!
//! ```text
//! "SBX" | version u8 (1) | manifest_len u32 | manifest | n u32 | n × (name [32] | len u32) | objects in index order
//! ```

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use songbird_backup_format::ChunkName;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use crate::store::{BackupStore, StoreError, check_next, generation_of};

/// How old a manifest lock must be to count as left by a writer that died.
const STALE_LOCK: std::time::Duration = std::time::Duration::from_secs(300);

/// A backup in a folder.
#[derive(Debug, Clone)]
pub struct LocalStore {
    root: PathBuf,
}

fn tmp_name() -> String {
    let mut r = [0u8; 8];
    let _ = getrandom::fill(&mut r);
    format!(".tmp-{}", hex::encode(r))
}

async fn write_atomically(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
    let tmp = dir.join(tmp_name());
    let mut f = tokio::fs::File::create(&tmp).await?;
    f.write_all(bytes).await?;
    f.sync_all().await?;
    drop(f);
    tokio::fs::rename(&tmp, dir.join(name)).await?;
    Ok(())
}

impl LocalStore {
    /// The backup in `root` (created by [`BackupStore::open`]).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn chunks(&self) -> PathBuf {
        self.root.join("chunks")
    }
}

#[async_trait]
impl BackupStore for LocalStore {
    fn kind(&self) -> &'static str {
        "local"
    }

    async fn open(&self) -> Result<(), StoreError> {
        tokio::fs::create_dir_all(self.chunks()).await?;
        Ok(())
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        write_atomically(&self.chunks(), &name.to_hex(), &object).await
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        match tokio::fs::read(self.chunks().join(name.to_hex())).await {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        let mut out = vec![];
        let mut rd = match tokio::fs::read_dir(self.chunks()).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(e) = rd.next_entry().await? {
            // Temporary files and anything else in the folder are not chunks.
            if let Some(n) = e.file_name().to_str().and_then(ChunkName::from_hex) {
                out.push(n);
            }
        }
        out.sort();
        Ok(out)
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        for n in names {
            match tokio::fs::remove_file(self.chunks().join(n.to_hex())).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        match tokio::fs::read(self.root.join("manifest")).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        check_next(expected, &object)?;
        let lock = self.root.join("manifest.lock");
        let mut tries = 0;
        let held = loop {
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock)
                .await
            {
                Ok(f) => break f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // A lock older than five minutes was left by a writer that died: break it
                    // once. A live one means another writer is swapping.
                    let stale = tokio::fs::metadata(&lock)
                        .await
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > STALE_LOCK);
                    if stale && tries == 0 {
                        tries += 1;
                        let _ = tokio::fs::remove_file(&lock).await;
                        continue;
                    }
                    let current = match self.manifest().await? {
                        Some(m) => generation_of(&m)?,
                        None => 0,
                    };
                    return Err(StoreError::Conflict { current });
                }
                Err(e) => return Err(e.into()),
            }
        };
        let result = async {
            let current = match self.manifest().await? {
                Some(m) => generation_of(&m)?,
                None => 0,
            };
            if current != expected {
                return Err(StoreError::Conflict { current });
            }
            write_atomically(&self.root, "manifest", &object).await
        }
        .await;
        drop(held);
        tokio::fs::remove_file(&lock).await?;
        result
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        match tokio::fs::remove_dir_all(&self.root).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

const ARCHIVE_MAGIC: &[u8; 4] = b"SBX\x01";
/// Most chunks an archive may index (the format's bound).
const MAX_ARCHIVE_CHUNKS: u32 = 1 << 21;

/// Writes every chunk and the manifest of `store` into one archive file.
///
/// # Errors
/// [`StoreError::NotFound`] when the store has no backup; the store's or the file's errors.
pub async fn export_archive(store: &dyn BackupStore, path: &Path) -> Result<u64, StoreError> {
    let manifest = store.manifest().await?.ok_or(StoreError::NotFound)?;
    let names = store.list().await?;
    let tmp = path.with_extension("partial");
    let mut f = tokio::io::BufWriter::new(tokio::fs::File::create(&tmp).await?);
    f.write_all(ARCHIVE_MAGIC).await?;
    let ml = u32::try_from(manifest.len()).map_err(|_| StoreError::Protocol("manifest"))?;
    f.write_all(&ml.to_be_bytes()).await?;
    f.write_all(&manifest).await?;
    // The index needs every length first: read each chunk once for its length, then again to
    // copy, so a large backup never sits in memory.
    let mut lens = Vec::with_capacity(names.len());
    for n in &names {
        lens.push(
            u32::try_from(store.get(n).await?.len()).map_err(|_| StoreError::Protocol("chunk"))?,
        );
    }
    let count = u32::try_from(names.len()).map_err(|_| StoreError::Protocol("count"))?;
    f.write_all(&count.to_be_bytes()).await?;
    for (n, l) in names.iter().zip(&lens) {
        f.write_all(&n.0).await?;
        f.write_all(&l.to_be_bytes()).await?;
    }
    let mut total = 0u64;
    for (n, l) in names.iter().zip(&lens) {
        let o = store.get(n).await?;
        if u32::try_from(o.len()).ok() != Some(*l) {
            return Err(StoreError::Protocol("chunk changed during export"));
        }
        f.write_all(&o).await?;
        total += u64::from(*l);
    }
    f.flush().await?;
    f.get_ref().sync_all().await?;
    drop(f);
    tokio::fs::rename(&tmp, path).await?;
    Ok(total)
}

/// A read-only store over an archive file.
#[derive(Debug)]
pub struct ArchiveStore {
    path: PathBuf,
    manifest: Vec<u8>,
    index: std::collections::BTreeMap<ChunkName, (u64, u32)>,
}

impl ArchiveStore {
    /// Reads an archive's manifest and index (not its chunks).
    ///
    /// # Errors
    /// [`StoreError::Protocol`] for a file that is not an archive; the file's errors.
    pub async fn open_file(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        let mut f = tokio::fs::File::open(&path).await?;
        let len = f.metadata().await?.len();
        let mut head = [0u8; 8];
        f.read_exact(&mut head).await?;
        if head.get(..4) != Some(ARCHIVE_MAGIC) {
            return Err(StoreError::Protocol("not a Songbird backup file"));
        }
        let ml = u64::from(u32::from_be_bytes([head[4], head[5], head[6], head[7]]));
        let max = u64::try_from(songbird_backup_format::object::max_manifest_object()).unwrap_or(0);
        if ml > max || ml > len {
            return Err(StoreError::Protocol("archive"));
        }
        let mut manifest =
            vec![0u8; usize::try_from(ml).map_err(|_| StoreError::Protocol("archive"))?];
        f.read_exact(&mut manifest).await?;
        let n = f.read_u32().await?;
        if n > MAX_ARCHIVE_CHUNKS || u64::from(n) * 36 > len {
            return Err(StoreError::Protocol("archive"));
        }
        let mut entries = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
        for _ in 0..n {
            let mut name = [0u8; 32];
            f.read_exact(&mut name).await?;
            entries.push((ChunkName(name), f.read_u32().await?));
        }
        let mut at = f.stream_position().await?;
        let mut index = std::collections::BTreeMap::new();
        let most = songbird_backup_format::object::max_chunk_object();
        for (name, l) in entries {
            // No entry larger than a chunk object can be (a sparse file costs nothing to make).
            if usize::try_from(l).map_or(true, |l| l > most) {
                return Err(StoreError::Protocol("archive"));
            }
            index.insert(name, (at, l));
            at = at
                .checked_add(u64::from(l))
                .ok_or(StoreError::Protocol("archive"))?;
        }
        if at != len {
            // Truncated or extended: the index does not match the file.
            return Err(StoreError::Protocol("archive length"));
        }
        Ok(Self {
            path,
            manifest,
            index,
        })
    }
}

#[async_trait]
impl BackupStore for ArchiveStore {
    fn kind(&self) -> &'static str {
        "archive"
    }

    async fn open(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn put(&self, _: &ChunkName, _: Vec<u8>) -> Result<(), StoreError> {
        Err(StoreError::Protocol("read-only"))
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        let (at, l) = *self.index.get(name).ok_or(StoreError::NotFound)?;
        let mut f = tokio::fs::File::open(&self.path).await?;
        f.seek(SeekFrom::Start(at)).await?;
        let mut v = vec![0u8; usize::try_from(l).map_err(|_| StoreError::Protocol("archive"))?];
        f.read_exact(&mut v).await?;
        Ok(v)
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        Ok(self.index.keys().copied().collect())
    }

    async fn delete(&self, _: &[ChunkName]) -> Result<(), StoreError> {
        Err(StoreError::Protocol("read-only"))
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(Some(self.manifest.clone()))
    }

    async fn swap_manifest(&self, _: u64, _: Vec<u8>) -> Result<(), StoreError> {
        Err(StoreError::Protocol("read-only"))
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        tokio::fs::remove_file(&self.path).await?;
        Ok(())
    }
}
