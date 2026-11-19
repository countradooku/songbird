//! A store in memory: the reference every other adapter is compared with, and the test double.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use songbird_backup_format::ChunkName;

use crate::store::{BackupStore, StoreError, check_next, generation_of};

#[derive(Default)]
struct State {
    chunks: BTreeMap<ChunkName, Vec<u8>>,
    manifest: Option<Vec<u8>>,
}

/// A store in memory.
#[derive(Default)]
pub struct MemoryStore {
    state: Mutex<State>,
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryStore { .. }")
    }
}

impl MemoryStore {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        let mut g = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Changes a stored chunk (tests of damaged stores).
    pub fn tamper(&self, name: &ChunkName, f: impl FnOnce(&mut Vec<u8>)) {
        self.with(|s| {
            if let Some(o) = s.chunks.get_mut(name) {
                f(o);
            }
        });
    }

    /// Replaces the manifest without any check (tests of rollback).
    pub fn force_manifest(&self, object: Option<Vec<u8>>) {
        self.with(|s| s.manifest = object);
    }

    /// Object bytes stored.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.with(|s| {
            s.chunks
                .values()
                .map(|o| u64::try_from(o.len()).unwrap_or(0))
                .sum()
        })
    }
}

#[async_trait]
impl BackupStore for MemoryStore {
    fn kind(&self) -> &'static str {
        "memory"
    }

    async fn open(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        self.with(|s| s.chunks.insert(*name, object));
        Ok(())
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        self.with(|s| s.chunks.get(name).cloned())
            .ok_or(StoreError::NotFound)
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        Ok(self.with(|s| s.chunks.keys().copied().collect()))
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        self.with(|s| {
            for n in names {
                s.chunks.remove(n);
            }
        });
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.with(|s| s.manifest.clone()))
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        check_next(expected, &object)?;
        self.with(|s| {
            let current = match &s.manifest {
                Some(m) => generation_of(m)?,
                None => 0,
            };
            if current != expected {
                return Err(StoreError::Conflict { current });
            }
            s.manifest = Some(object);
            Ok(())
        })
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        self.with(|s| *s = State::default());
        Ok(())
    }
}
