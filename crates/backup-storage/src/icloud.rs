//! iCloud Drive: the interface the native iOS and macOS adapter must satisfy (Prompt 10 defines
//! it; the app phase builds the native half, D-0119).
//!
//! iCloud Drive has no server API: an app reaches its ubiquity container through the file
//! system, with `NSFileCoordinator` for coordinated reads and writes and `NSFileVersion` for
//! conflicts. So the native side implements the small [`ICloudBridge`] below over its
//! container's `Documents/Songbird/<vault>/` folder, and [`ICloudStore`] turns it into a
//! [`BackupStore`]. The same conformance suite runs against it: here with an in-memory bridge,
//! on a device with the real one.
//!
//! What the native bridge must guarantee:
//! - `write` replaces a file atomically (a coordinated write to a temporary file, then a
//!   coordinated move), and `read` never returns a partial file;
//! - `replace_if` is the compare-and-swap: inside **one** coordinated write it reads the file's
//!   current version token (`NSFileVersion.currentVersionOfItem`'s persistent identifier, or the
//!   content's SHA-256), compares it with `expected` (`None`: the file must not exist), and
//!   writes only if equal, returning the new token; otherwise [`StoreError::Conflict`];
//! - after a merge from another device, unresolved conflict versions of `manifest` are kept as
//!   losers (never auto-merged) and reported through `version` changing, so a writer that lost
//!   sees a conflict on its next `replace_if`;
//! - nothing is evicted while a backup or restore runs (`startDownloadingUbiquitousItem` before
//!   `read`); errors map to [`StoreError`] (`NotFound`, `Full` for an iCloud quota, `Unavailable`
//!   when iCloud is signed out or off).

use std::sync::Arc;

use async_trait::async_trait;
use songbird_backup_format::ChunkName;

use crate::store::{BackupStore, StoreError, check_next, generation_of};

/// The file operations the native iCloud adapter provides, on paths relative to the vault's
/// folder (`chunks/<hex>`, `manifest`).
#[async_trait]
pub trait ICloudBridge: Send + Sync {
    /// Creates the folder (and `chunks/`) if needed.
    async fn create_folder(&self) -> Result<(), StoreError>;
    /// A whole file, or [`StoreError::NotFound`].
    async fn read(&self, path: &str) -> Result<Vec<u8>, StoreError>;
    /// Replaces a file atomically.
    async fn write(&self, path: &str, bytes: Vec<u8>) -> Result<(), StoreError>;
    /// File names directly in `dir`.
    async fn list(&self, dir: &str) -> Result<Vec<String>, StoreError>;
    /// Removes a file (absent is fine).
    async fn remove(&self, path: &str) -> Result<(), StoreError>;
    /// The file's version token, if it exists.
    async fn version(&self, path: &str) -> Result<Option<String>, StoreError>;
    /// Writes only if the version token is `expected` (`None`: absent), in one coordinated
    /// write; the new token.
    async fn replace_if(
        &self,
        path: &str,
        expected: Option<&str>,
        bytes: Vec<u8>,
    ) -> Result<String, StoreError>;
    /// Removes the whole folder.
    async fn remove_folder(&self) -> Result<(), StoreError>;
}

/// A backup in iCloud Drive through a native bridge.
pub struct ICloudStore {
    bridge: Arc<dyn ICloudBridge>,
}

impl std::fmt::Debug for ICloudStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ICloudStore { .. }")
    }
}

impl ICloudStore {
    /// A store over the native bridge.
    #[must_use]
    pub fn new(bridge: Arc<dyn ICloudBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl BackupStore for ICloudStore {
    fn kind(&self) -> &'static str {
        "icloud"
    }

    async fn open(&self) -> Result<(), StoreError> {
        self.bridge.create_folder().await
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        self.bridge
            .write(&format!("chunks/{}", name.to_hex()), object)
            .await
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        self.bridge.read(&format!("chunks/{}", name.to_hex())).await
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        let mut out: Vec<ChunkName> = self
            .bridge
            .list("chunks")
            .await?
            .iter()
            .filter_map(|n| ChunkName::from_hex(n))
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        for n in names {
            self.bridge
                .remove(&format!("chunks/{}", n.to_hex()))
                .await?;
        }
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        match self.bridge.read("manifest").await {
            Ok(b) => Ok(Some(b)),
            Err(StoreError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        check_next(expected, &object)?;
        let version = self.bridge.version("manifest").await?;
        let current = match self.manifest().await? {
            Some(m) => generation_of(&m)?,
            None => 0,
        };
        if current != expected {
            return Err(StoreError::Conflict { current });
        }
        match self
            .bridge
            .replace_if("manifest", version.as_deref(), object)
            .await
        {
            Ok(_) => Ok(()),
            Err(StoreError::Conflict { .. }) => Err(StoreError::Conflict {
                current: match self.manifest().await? {
                    Some(m) => generation_of(&m)?,
                    None => 0,
                },
            }),
            Err(e) => Err(e),
        }
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        self.bridge.remove_folder().await
    }
}

/// An in-memory bridge with the semantics the native one must have: the reference for the
/// conformance suite (and for the Swift implementation's own tests).
#[derive(Default)]
pub struct MemoryBridge {
    files: std::sync::Mutex<std::collections::BTreeMap<String, (Vec<u8>, u64)>>,
    counter: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for MemoryBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryBridge { .. }")
    }
}

impl MemoryBridge {
    fn with<T>(
        &self,
        f: impl FnOnce(&mut std::collections::BTreeMap<String, (Vec<u8>, u64)>) -> T,
    ) -> T {
        f(&mut self
            .files
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
    fn next(&self) -> u64 {
        self.counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1
    }
}

#[async_trait]
impl ICloudBridge for MemoryBridge {
    async fn create_folder(&self) -> Result<(), StoreError> {
        Ok(())
    }
    async fn read(&self, path: &str) -> Result<Vec<u8>, StoreError> {
        self.with(|f| f.get(path).map(|(b, _)| b.clone()))
            .ok_or(StoreError::NotFound)
    }
    async fn write(&self, path: &str, bytes: Vec<u8>) -> Result<(), StoreError> {
        let v = self.next();
        self.with(|f| f.insert(path.to_owned(), (bytes, v)));
        Ok(())
    }
    async fn list(&self, dir: &str) -> Result<Vec<String>, StoreError> {
        let p = format!("{dir}/");
        Ok(self.with(|f| {
            f.keys()
                .filter_map(|k| k.strip_prefix(&p).map(str::to_owned))
                .collect()
        }))
    }
    async fn remove(&self, path: &str) -> Result<(), StoreError> {
        self.with(|f| f.remove(path));
        Ok(())
    }
    async fn version(&self, path: &str) -> Result<Option<String>, StoreError> {
        Ok(self.with(|f| f.get(path).map(|(_, v)| v.to_string())))
    }
    async fn replace_if(
        &self,
        path: &str,
        expected: Option<&str>,
        bytes: Vec<u8>,
    ) -> Result<String, StoreError> {
        let v = self.next();
        self.with(|f| {
            let current = f.get(path).map(|(_, v)| v.to_string());
            if current.as_deref() != expected {
                return Err(StoreError::Conflict { current: 0 });
            }
            f.insert(path.to_owned(), (bytes, v));
            Ok(v.to_string())
        })
    }
    async fn remove_folder(&self) -> Result<(), StoreError> {
        self.with(std::collections::BTreeMap::clear);
        Ok(())
    }
}
