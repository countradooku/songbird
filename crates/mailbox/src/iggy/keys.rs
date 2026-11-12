//! Puncturable keys: deletion on acknowledgement for an append-only log (D-0031).
//!
//! Iggy cannot remove one message from a segment, so every mailbox record is sealed with keys
//! that can be destroyed. Each **window** (a few minutes of records) has:
//!
//! - a **metadata key** (random, 32 bytes) sealing the record-level metadata (idempotency tag and
//!   fingerprint, timestamps, ACK checkpoints, snapshots). It is destroyed with the window once all
//!   of the window's records are below the low-water offset;
//! - a **GGM key tree** (Goldreich–Goldwasser–Micali) of depth [`DEPTH`]: one leaf key per message
//!   slot, sealing that message's envelope and its `(device, seq)`. Acknowledging a message
//!   **punctures** its leaf: the leaf's key is discarded and only the keys of the sibling subtrees
//!   on its path are kept, so nothing can derive the punctured leaf again. With acknowledgements
//!   arriving roughly in order, the kept set (the frontier) stays at about `DEPTH` keys.
//!
//! The tree's PRG is AES-256 over four distinct counter blocks (AES-256 in counter form, aws-lc-rs
//! ECB on blocks 0..3): a node's key expands into its two children's keys. Leaf keys seal exactly
//! one plaintext each, so their AES-256-GCM nonce is constant.
//!
//! The key state lives in memory and in a key file per partition, sealed with the node's master
//! key (AES-256-GCM, random nonce) and replaced atomically (write, fsync, rename, fsync of the
//! directory). A window is in the file before any record sealed with it is appended; punctures are
//! written with the ACK checkpoint that caused them.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::cipher::{AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};

/// Depth of each window's tree: `2^DEPTH` message slots per window.
pub(crate) const DEPTH: u8 = 24;
/// Slots per window.
pub(crate) const SLOTS: u32 = 1 << DEPTH;

const FILE_VERSION: u8 = 1;
const FILE_AAD: &[u8] = b"songbird-mailbox-keys-v1";

/// A 32-byte key, wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Key(pub(crate) [u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        // Best effort: the compiler may keep copies, but the live value is cleared.
        self.0.iter_mut().for_each(|b| *b = 0);
        std::hint::black_box(&self.0);
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

/// Key-state errors. Carry no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum KeyError {
    /// The key file is missing, unreadable or not sealed by this master key.
    #[error("mailbox key file unreadable")]
    File,
    /// Writing the key file failed.
    #[error("mailbox key file write failed")]
    Write,
    /// Randomness or a cipher failed.
    #[error("mailbox key operation failed")]
    Crypto,
}

fn random_key() -> Result<Key, KeyError> {
    let mut k = [0u8; 32];
    aws_lc_rs::rand::fill(&mut k).map_err(|_| KeyError::Crypto)?;
    Ok(Key(k))
}

/// PRG: a node key expands into (left child, right child).
fn expand(seed: &Key) -> Result<(Key, Key), KeyError> {
    let key = UnboundCipherKey::new(&AES_256, &seed.0).map_err(|_| KeyError::Crypto)?;
    let aes = EncryptingKey::ecb(key).map_err(|_| KeyError::Crypto)?;
    // Four distinct counter blocks (0, 1, 2, 3 in their first byte).
    let mut buf = [0u8; 64];
    for (i, b) in [(16usize, 1u8), (32, 2), (48, 3)] {
        if let Some(x) = buf.get_mut(i) {
            *x = b;
        }
    }
    aes.less_safe_encrypt(&mut buf, EncryptionContext::None)
        .map_err(|_| KeyError::Crypto)?;
    let mut l = [0u8; 32];
    let mut r = [0u8; 32];
    l.copy_from_slice(buf.get(..32).ok_or(KeyError::Crypto)?);
    r.copy_from_slice(buf.get(32..).ok_or(KeyError::Crypto)?);
    buf.fill(0);
    Ok((Key(l), Key(r)))
}

/// One window's tree: the frontier of maximal subtrees whose leaves are still derivable.
#[derive(Debug, Clone)]
pub(crate) struct Tree {
    /// (depth, prefix) -> node key; the subtrees are disjoint.
    frontier: BTreeMap<(u8, u32), Key>,
}

impl Tree {
    fn new(root: Key) -> Self {
        let mut frontier = BTreeMap::new();
        frontier.insert((0, 0), root);
        Self { frontier }
    }

    fn covering(&self, slot: u32) -> Option<(u8, u32)> {
        (0..=DEPTH).find_map(|d| {
            let prefix = slot.checked_shr(u32::from(DEPTH - d)).unwrap_or(0);
            self.frontier
                .contains_key(&(d, prefix))
                .then_some((d, prefix))
        })
    }

    /// The key of leaf `slot`, unless punctured.
    pub(crate) fn leaf(&self, slot: u32) -> Result<Option<Key>, KeyError> {
        let Some((d, prefix)) = self.covering(slot) else {
            return Ok(None);
        };
        let mut key = self
            .frontier
            .get(&(d, prefix))
            .cloned()
            .ok_or(KeyError::Crypto)?;
        for depth in d..DEPTH {
            let bit = slot.checked_shr(u32::from(DEPTH - depth - 1)).unwrap_or(0) & 1;
            let (l, r) = expand(&key)?;
            key = if bit == 0 { l } else { r };
        }
        Ok(Some(key))
    }

    /// Makes leaf `slot` underivable; returns whether it was still derivable.
    pub(crate) fn puncture(&mut self, slot: u32) -> Result<bool, KeyError> {
        let Some((d, prefix)) = self.covering(slot) else {
            return Ok(false);
        };
        let mut key = self.frontier.remove(&(d, prefix)).ok_or(KeyError::Crypto)?;
        let mut cur = prefix;
        for depth in d..DEPTH {
            let bit = slot.checked_shr(u32::from(DEPTH - depth - 1)).unwrap_or(0) & 1;
            let (l, r) = expand(&key)?;
            let left = cur << 1;
            if bit == 0 {
                self.frontier.insert((depth + 1, left | 1), r);
                key = l;
                cur = left;
            } else {
                self.frontier.insert((depth + 1, left), l);
                key = r;
                cur = left | 1;
            }
        }
        Ok(true)
    }

    /// Frontier size (keys kept).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.frontier.len()
    }
}

/// A window: its metadata key and its tree.
#[derive(Debug, Clone)]
pub(crate) struct Window {
    pub(crate) meta: Key,
    pub(crate) tree: Tree,
    /// Next unused slot.
    pub(crate) next_slot: u32,
    /// When it was opened (ms).
    pub(crate) opened_ms: u64,
}

/// All live windows of one partition.
#[derive(Debug, Default)]
pub(crate) struct KeyRing {
    pub(crate) windows: BTreeMap<u64, Window>,
    /// Punctures not yet written to the key file.
    pub(crate) dirty: bool,
}

impl KeyRing {
    /// Opens a new window with fresh keys; returns its id.
    pub(crate) fn open_window(&mut self, now_ms: u64) -> Result<u64, KeyError> {
        let id = self.windows.keys().next_back().map_or(1, |w| w + 1);
        self.windows.insert(
            id,
            Window {
                meta: random_key()?,
                tree: Tree::new(random_key()?),
                next_slot: 0,
                opened_ms: now_ms,
            },
        );
        self.dirty = true;
        Ok(id)
    }

    /// The window records are sealed with now: the newest, unless it is older than `max_age_ms`
    /// or has fewer than `needed` slots left (then `None`: open a new one first).
    pub(crate) fn current(&self, now_ms: u64, max_age_ms: u64, needed: u32) -> Option<u64> {
        let (id, w) = self.windows.iter().next_back()?;
        let fresh = w.opened_ms.saturating_add(max_age_ms) > now_ms;
        let room = SLOTS.saturating_sub(w.next_slot) >= needed;
        (fresh && room).then_some(*id)
    }

    /// Reserves `n` consecutive slots in window `id`; returns the first.
    pub(crate) fn reserve(&mut self, id: u64, n: u32) -> Option<u32> {
        let w = self.windows.get_mut(&id)?;
        let first = w.next_slot;
        w.next_slot = first.checked_add(n).filter(|e| *e <= SLOTS)?;
        Some(first)
    }

    pub(crate) fn meta(&self, id: u64) -> Option<&Key> {
        self.windows.get(&id).map(|w| &w.meta)
    }

    pub(crate) fn leaf(&self, id: u64, slot: u32) -> Result<Option<Key>, KeyError> {
        match self.windows.get(&id) {
            Some(w) => w.tree.leaf(slot),
            None => Ok(None),
        }
    }

    /// Punctures a slot (no-op if the window is gone or the slot already punctured).
    pub(crate) fn puncture(&mut self, id: u64, slot: u32) -> Result<(), KeyError> {
        if let Some(w) = self.windows.get_mut(&id)
            && w.tree.puncture(slot)?
        {
            self.dirty = true;
        }
        Ok(())
    }

    /// Destroys window `id` entirely.
    pub(crate) fn destroy(&mut self, id: u64) {
        if self.windows.remove(&id).is_some() {
            self.dirty = true;
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![FILE_VERSION];
        out.extend_from_slice(
            &u32::try_from(self.windows.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for (id, w) in &self.windows {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&w.opened_ms.to_be_bytes());
            out.extend_from_slice(&w.next_slot.to_be_bytes());
            out.extend_from_slice(&w.meta.0);
            out.extend_from_slice(
                &u32::try_from(w.tree.frontier.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            for ((d, p), k) in &w.tree.frontier {
                out.push(*d);
                out.extend_from_slice(&p.to_be_bytes());
                out.extend_from_slice(&k.0);
            }
        }
        out
    }

    #[allow(clippy::many_single_char_names, reason = "a flat decoder")]
    fn decode(b: &[u8]) -> Result<Self, KeyError> {
        let mut r = Rd { b, pos: 0 };
        if r.u8()? != FILE_VERSION {
            return Err(KeyError::File);
        }
        let n = r.u32()?;
        let mut windows = BTreeMap::new();
        for _ in 0..n {
            let id = r.u64()?;
            let opened_ms = r.u64()?;
            let next_slot = r.u32()?;
            let meta = Key(r.arr()?);
            let m = r.u32()?;
            if usize::try_from(m)
                .map_err(|_| KeyError::File)?
                .saturating_mul(37)
                > b.len()
            {
                return Err(KeyError::File);
            }
            let mut frontier = BTreeMap::new();
            for _ in 0..m {
                let d = r.u8()?;
                let p = r.u32()?;
                if d > DEPTH {
                    return Err(KeyError::File);
                }
                frontier.insert((d, p), Key(r.arr()?));
            }
            windows.insert(
                id,
                Window {
                    meta,
                    tree: Tree { frontier },
                    next_slot,
                    opened_ms,
                },
            );
        }
        if r.pos != b.len() {
            return Err(KeyError::File);
        }
        Ok(Self {
            windows,
            dirty: false,
        })
    }
}

struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Rd<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], KeyError> {
        let end = self.pos.checked_add(n).ok_or(KeyError::File)?;
        let s = self.b.get(self.pos..end).ok_or(KeyError::File)?;
        self.pos = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], KeyError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, KeyError> {
        Ok(self.arr::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, KeyError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, KeyError> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
}

/// The key file of one partition, sealed with the master key.
#[derive(Debug)]
pub(crate) struct KeyFile {
    path: PathBuf,
    master: Key,
    /// Binds the file to its stream, topic and partition.
    aad: Vec<u8>,
}

impl KeyFile {
    pub(crate) fn new(
        dir: &Path,
        stream: &str,
        topic: &str,
        partition: u32,
        master: [u8; 32],
    ) -> Self {
        let mut aad = FILE_AAD.to_vec();
        for part in [
            stream.as_bytes(),
            topic.as_bytes(),
            &partition.to_be_bytes(),
        ] {
            aad.extend_from_slice(&u32::try_from(part.len()).unwrap_or(0).to_be_bytes());
            aad.extend_from_slice(part);
        }
        Self {
            path: dir.join(format!("{stream}.{topic}.{partition}.keys")),
            master: Key(master),
            aad,
        }
    }

    fn sealing_key(&self) -> Result<LessSafeKey, KeyError> {
        let k = UnboundKey::new(&AES_256_GCM, &self.master.0).map_err(|_| KeyError::Crypto)?;
        Ok(LessSafeKey::new(k))
    }

    /// Loads the ring; a missing file is an empty ring (a new partition).
    pub(crate) fn load(&self) -> Result<KeyRing, KeyError> {
        let data = match std::fs::read(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(KeyRing::default()),
            Err(_) => return Err(KeyError::File),
        };
        let (nonce, ct) = data.split_at_checked(NONCE_LEN).ok_or(KeyError::File)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| KeyError::File)?;
        let mut buf = ct.to_vec();
        let plain = self
            .sealing_key()?
            .open_in_place(nonce, Aad::from(self.aad.as_slice()), &mut buf)
            .map_err(|_| KeyError::File)?;
        let ring = KeyRing::decode(plain);
        buf.fill(0);
        ring
    }

    /// The ring sealed for the file (cheap; done under the state lock).
    pub(crate) fn seal(&self, ring: &KeyRing) -> Result<Vec<u8>, KeyError> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| KeyError::Crypto)?;
        let mut buf = ring.encode();
        self.sealing_key()?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(self.aad.as_slice()),
                &mut buf,
            )
            .map_err(|_| KeyError::Crypto)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Replaces the file atomically (write, fsync, rename, fsync of the directory). Blocking.
    pub(crate) fn write(&self, sealed: &[u8]) -> Result<(), KeyError> {
        let tmp = self.path.with_extension("keys.tmp");
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new();
            f.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                f.mode(0o600);
            }
            let mut file = f.open(&tmp)?;
            file.write_all(sealed)?;
            file.sync_all()?;
            std::fs::rename(&tmp, &self.path)?;
            if let Some(dir) = self.path.parent() {
                std::fs::File::open(dir)?.sync_all()?;
            }
            Ok(())
        };
        write().map_err(|_| KeyError::Write)
    }

    /// Seals and writes (tests).
    #[cfg(test)]
    pub(crate) fn store(&self, ring: &KeyRing) -> Result<(), KeyError> {
        self.write(&self.seal(ring)?)
    }
}

/// Seals `plain` with a leaf key (used once: constant nonce).
pub(crate) fn seal_leaf(key: &Key, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, KeyError> {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| KeyError::Crypto)?);
    let mut buf = plain.to_vec();
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0; NONCE_LEN]),
        Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| KeyError::Crypto)?;
    Ok(buf)
}

/// Opens a leaf-sealed value.
pub(crate) fn open_leaf(key: &Key, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, KeyError> {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| KeyError::Crypto)?);
    let mut buf = sealed.to_vec();
    let n = k
        .open_in_place(
            Nonce::assume_unique_for_key([0; NONCE_LEN]),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| KeyError::Crypto)?
        .len();
    buf.truncate(n);
    Ok(buf)
}

/// Seals metadata with a window's metadata key (random nonce, prepended).
pub(crate) fn seal_meta(key: &Key, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, KeyError> {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| KeyError::Crypto)?);
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| KeyError::Crypto)?;
    let mut buf = plain.to_vec();
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| KeyError::Crypto)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Opens window-sealed metadata.
pub(crate) fn open_meta(key: &Key, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, KeyError> {
    let (nonce, ct) = sealed.split_at_checked(NONCE_LEN).ok_or(KeyError::Crypto)?;
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key.0).map_err(|_| KeyError::Crypto)?);
    let mut buf = ct.to_vec();
    let n = k
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| KeyError::Crypto)?,
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| KeyError::Crypto)?
        .len();
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punctured_leaves_cannot_be_derived_and_others_still_can() {
        let mut t = Tree::new(Key([7; 32]));
        let before: Vec<Key> = (0..64).map(|s| t.leaf(s).unwrap().unwrap()).collect();
        assert!(t.puncture(5).unwrap());
        assert!(!t.puncture(5).unwrap(), "already punctured");
        assert_eq!(t.leaf(5).unwrap(), None);
        for s in (0..64).filter(|s| *s != 5) {
            assert_eq!(
                t.leaf(s).unwrap().as_ref(),
                Some(&before[usize::try_from(s).unwrap()]),
                "slot {s}"
            );
        }
        // No kept key derives the punctured leaf: expanding every frontier node to all its
        // leaves (in the low range) never yields it.
        for ((d, p), k) in &t.frontier {
            if u32::from(DEPTH - d) > 8 {
                continue; // large subtrees cover only slots >= 256, far from slot 5
            }
            let span = 1u32 << (DEPTH - d);
            let sub = Tree {
                frontier: BTreeMap::from([((*d, *p), k.clone())]),
            };
            for s in p * span..(p + 1) * span {
                assert_ne!(sub.leaf(s).unwrap().as_ref(), Some(&before[5]));
            }
        }
        // Distinct leaves.
        assert_ne!(before[0], before[1]);
    }

    #[test]
    fn in_order_punctures_keep_the_frontier_small() {
        let mut t = Tree::new(Key([1; 32]));
        for s in 0..10_000 {
            t.puncture(s).unwrap();
        }
        assert!(t.len() <= usize::from(DEPTH), "{}", t.len());
        assert!(t.leaf(9_999).unwrap().is_none());
        assert!(t.leaf(10_000).unwrap().is_some());
    }

    #[test]
    fn ring_file_round_trips_and_binds_its_partition() {
        let dir = std::env::temp_dir().join(format!("sb-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = KeyFile::new(&dir, "s", "t", 0, [9; 32]);
        let mut ring = KeyRing::default();
        let w = ring.open_window(1000).unwrap();
        let first = ring.reserve(w, 10).unwrap();
        let leaf3 = ring.leaf(w, first + 3).unwrap().unwrap();
        ring.puncture(w, first + 2).unwrap();
        file.store(&ring).unwrap();
        let back = file.load().unwrap();
        assert_eq!(back.leaf(w, first + 3).unwrap(), Some(leaf3));
        assert_eq!(back.leaf(w, first + 2).unwrap(), None);
        assert_eq!(back.windows[&w].next_slot, 10);
        // Another partition's file name and binding, or another master key, do not open it.
        let other = KeyFile::new(&dir, "s", "t", 0, [8; 32]);
        assert_eq!(other.load().unwrap_err(), KeyError::File);
        std::fs::rename(dir.join("s.t.0.keys"), dir.join("s.t.1.keys")).unwrap();
        assert_eq!(
            KeyFile::new(&dir, "s", "t", 1, [9; 32]).load().unwrap_err(),
            KeyError::File
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn seal_and_open() {
        let k = Key([3; 32]);
        let s = seal_leaf(&k, b"aad", b"hello").unwrap();
        assert_eq!(open_leaf(&k, b"aad", &s).unwrap(), b"hello");
        assert!(open_leaf(&k, b"other", &s).is_err());
        let m = seal_meta(&k, b"a", b"meta").unwrap();
        assert_eq!(open_meta(&k, b"a", &m).unwrap(), b"meta");
        assert!(open_meta(&Key([4; 32]), b"a", &m).is_err());
    }
}
