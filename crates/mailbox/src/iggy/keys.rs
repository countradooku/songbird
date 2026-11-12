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
//! The key state lives in memory and in a key store per partition ([`KeyFile`]): a head (windows,
//! trees, marks, the list of pages) and pages of individual keys ([`PAGE_SLOTS`] slots each),
//! every file sealed with the node's master key (AES-256-GCM, random nonce). Writes are
//! copy-on-write and replace only the pages that changed, so their cost follows the changes, not
//! the number of pending messages. A window is in the store before any record sealed with it is
//! appended; punctures reach it within the key interval (the log's ACK records are the authority:
//! replay punctures again after a crash).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::cipher::{AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};

/// Depth of each window's tree: `2^DEPTH` message slots per window.
pub(crate) const DEPTH: u8 = 24;
/// Slots per window.
pub(crate) const SLOTS: u32 = 1 << DEPTH;

const FILE_VERSION: u8 = 3;
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
    /// The key store (its head or a page it lists) is missing, unreadable or not sealed by this master key.
    #[error("mailbox key store unreadable")]
    File,
    /// Writing the key store failed.
    #[error("mailbox key store write failed")]
    Write,
    /// Randomness or a cipher failed.
    #[error("mailbox key operation failed")]
    Crypto,
    /// A writer with a newer producer epoch owns the key store: this one is fenced.
    #[error("mailbox key store owned by a newer writer")]
    Fenced,
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

    /// Every leaf in `[start, end)` still derivable, with its key: each node on the way is
    /// expanded once (about two expansions per leaf for a range).
    pub(crate) fn range(&self, start: u32, end: u32) -> Result<Vec<(u32, Key)>, KeyError> {
        let mut out = Vec::new();
        let mut stack: Vec<(u8, u32, Key)> = self
            .frontier
            .iter()
            .filter(|((d, p), _)| {
                let (a, b) = span(*d, *p);
                a < u64::from(end) && b > u64::from(start)
            })
            .map(|((d, p), k)| (*d, *p, k.clone()))
            .collect();
        while let Some((d, p, k)) = stack.pop() {
            if d == DEPTH {
                out.push((p, k));
                continue;
            }
            let (l, r) = expand(&k)?;
            for (child, key) in [(p << 1, l), ((p << 1) | 1, r)] {
                let (a, b) = span(d + 1, child);
                if a < u64::from(end) && b > u64::from(start) {
                    stack.push((d + 1, child, key));
                }
            }
        }
        out.sort_unstable_by_key(|(s, _)| *s);
        Ok(out)
    }

    /// Makes every leaf below `mark` underivable from the tree (their keys, if still needed,
    /// are kept individually by the window): nodes entirely below go; a node straddling `mark` is
    /// split down the path to it, keeping only the halves entirely at or above it.
    pub(crate) fn drop_below(&mut self, mark: u32) -> Result<(), KeyError> {
        let m = u64::from(mark);
        let below: Vec<(u8, u32)> = self
            .frontier
            .keys()
            .filter(|(d, p)| span(*d, *p).0 < m)
            .copied()
            .collect();
        for (d, p) in below {
            let Some(mut key) = self.frontier.remove(&(d, p)) else {
                continue;
            };
            let (mut depth, mut prefix) = (d, p);
            // Only a node that straddles the mark has anything to keep.
            while span(depth, prefix).1 > m && depth < DEPTH {
                let (l, r) = expand(&key)?;
                depth += 1;
                let (left, right) = (prefix << 1, (prefix << 1) | 1);
                if span(depth, left).1 <= m {
                    // Left half entirely below: drop it, go right.
                    prefix = right;
                    key = r;
                } else {
                    // Right half entirely at or above: keep it, go left.
                    self.frontier.insert((depth, right), r);
                    prefix = left;
                    key = l;
                }
                if span(depth, prefix).0 >= m {
                    self.frontier.insert((depth, prefix), key);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Frontier size (keys kept).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.frontier.len()
    }
}

/// The leaves `[a, b)` under node `(depth, prefix)`.
fn span(depth: u8, prefix: u32) -> (u64, u64) {
    let shift = u32::from(DEPTH - depth);
    let a = u64::from(prefix) << shift;
    (a, a + (1u64 << shift))
}

/// A window: its metadata key, its tree for recent slots and the individual keys of older slots
/// still pending.
#[derive(Debug, Clone)]
pub(crate) struct Window {
    pub(crate) meta: Key,
    /// Derives the slots at or above `mark`.
    pub(crate) tree: Tree,
    /// Slots below it are not derivable from the tree.
    pub(crate) mark: u32,
    /// Keys of slots below `mark` still needed (pending); deleting one deletes the slot.
    pub(crate) explicit: BTreeMap<u32, Key>,
    /// Next unused slot.
    pub(crate) next_slot: u32,
    /// When it was opened (ms).
    pub(crate) opened_ms: u64,
}

/// Slots per key page. A window's individual keys are written in pages of this many slots, and a
/// write replaces only the pages that changed (at most `PAGE_SLOTS` keys, 36 KiB, each).
pub(crate) const PAGE_SLOTS: u32 = 1024;

fn page_of(slot: u32) -> u32 {
    slot / PAGE_SLOTS
}

fn page_slots(page: u32) -> std::ops::Range<u32> {
    page.saturating_mul(PAGE_SLOTS)..page.saturating_add(1).saturating_mul(PAGE_SLOTS)
}

/// A page as the head lists it: the generation of its file and how many keys it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PageRef {
    epoch: u16,
    generation: u64,
    count: u32,
}

/// All live windows of one partition.
#[derive(Debug, Default)]
pub(crate) struct KeyRing {
    pub(crate) windows: BTreeMap<u64, Window>,
    /// The head (windows, trees, marks) changed since the last write.
    pub(crate) dirty: bool,
    /// Pages whose keys changed since the last write.
    dirty_pages: BTreeSet<(u64, u32)>,
    /// Pages on disk, as the last head written lists them: (window, page) -> file.
    pages: BTreeMap<(u64, u32), PageRef>,
    /// Generation of the last write attempted (file names are never reused).
    generation: u64,
}

/// What one write puts on disk (plaintext until [`KeyFile::write`] seals it).
pub(crate) struct Changes {
    epoch: u16,
    generation: u64,
    head: Vec<u8>,
    pages: Vec<((u64, u32), Vec<u8>)>,
    /// Files the new head no longer lists (deleted once it is on disk).
    obsolete: Vec<((u64, u32), PageRef)>,
    /// The page list once written ([`KeyRing::committed`]).
    pub(crate) manifest: BTreeMap<(u64, u32), PageRef>,
    /// The pages taken (marked dirty again if the write fails, [`KeyRing::failed`]).
    pub(crate) taken: Vec<(u64, u32)>,
}

impl Drop for Changes {
    fn drop(&mut self) {
        self.head.fill(0);
        for (_, p) in &mut self.pages {
            p.fill(0);
        }
    }
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
                mark: 0,
                explicit: BTreeMap::new(),
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

    /// Records that slots below `end` of window `id` are used (a record replayed from the log):
    /// slots are never handed out twice, even when the key store was last written before them.
    pub(crate) fn note_used(&mut self, id: u64, end: u32) {
        if let Some(w) = self.windows.get_mut(&id)
            && end > w.next_slot
        {
            w.next_slot = end.min(SLOTS);
            self.dirty = true;
        }
    }

    pub(crate) fn meta(&self, id: u64) -> Option<&Key> {
        self.windows.get(&id).map(|w| &w.meta)
    }

    pub(crate) fn leaf(&self, id: u64, slot: u32) -> Result<Option<Key>, KeyError> {
        match self.windows.get(&id) {
            Some(w) if slot < w.mark => Ok(w.explicit.get(&slot).cloned()),
            Some(w) => w.tree.leaf(slot),
            None => Ok(None),
        }
    }

    /// The keys of slots `[first, first + n)` (`None`: punctured), derived in one pass.
    pub(crate) fn leaves(&self, id: u64, first: u32, n: u32) -> Result<Vec<Option<Key>>, KeyError> {
        let w = self.windows.get(&id).ok_or(KeyError::Crypto)?;
        let end = first.checked_add(n).ok_or(KeyError::Crypto)?;
        let mut out: Vec<Option<Key>> =
            vec![None; usize::try_from(n).map_err(|_| KeyError::Crypto)?];
        for s in first..end.min(w.mark) {
            if let (Some(k), Some(o)) = (w.explicit.get(&s), out.get_mut(idx(s - first))) {
                *o = Some(k.clone());
            }
        }
        if end > w.mark {
            for (s, k) in w.tree.range(first.max(w.mark), end)? {
                if let Some(o) = out.get_mut(idx(s - first)) {
                    *o = Some(k);
                }
            }
        }
        Ok(out)
    }

    /// Punctures a slot (no-op if the window is gone or the slot already punctured).
    pub(crate) fn puncture(&mut self, id: u64, slot: u32) -> Result<(), KeyError> {
        let Some(w) = self.windows.get_mut(&id) else {
            return Ok(());
        };
        if slot < w.mark {
            if w.explicit.remove(&slot).is_some() {
                self.dirty_pages.insert((id, page_of(slot)));
            }
        } else if w.tree.puncture(slot)? {
            self.dirty = true;
        }
        Ok(())
    }

    /// Moves every window's mark to its next unused slot: the slots written since the last
    /// call that are still derivable get individual keys, and the tree is cut so it derives
    /// nothing below the mark. Keeps the key state proportional to the pending entries,
    /// whatever order they are acknowledged in. Called before every key-file write.
    pub(crate) fn advance(&mut self) -> Result<(), KeyError> {
        for (id, w) in &mut self.windows {
            if w.next_slot <= w.mark {
                continue;
            }
            for (s, k) in w.tree.range(w.mark, w.next_slot)? {
                w.explicit.insert(s, k);
                self.dirty_pages.insert((*id, page_of(s)));
            }
            w.tree.drop_below(w.next_slot)?;
            w.mark = w.next_slot;
            self.dirty = true;
        }
        Ok(())
    }

    /// Destroys window `id` entirely.
    pub(crate) fn destroy(&mut self, id: u64) {
        if self.windows.remove(&id).is_some() {
            self.dirty = true;
            for (w, p) in self.pages.keys() {
                if *w == id {
                    self.dirty_pages.insert((*w, *p));
                }
            }
        }
    }

    /// Whether anything needs writing.
    pub(crate) fn needs_write(&self) -> bool {
        self.dirty || !self.dirty_pages.is_empty()
    }

    /// Takes what changed since the last write: the new head and the changed pages, as
    /// plaintext (cheap; done under the state lock). `None` when nothing changed.
    pub(crate) fn take_changes(&mut self, epoch: u16) -> Option<Changes> {
        if !self.needs_write() {
            return None;
        }
        self.generation += 1;
        let generation = self.generation;
        self.dirty = false;
        let taken: Vec<(u64, u32)> = std::mem::take(&mut self.dirty_pages).into_iter().collect();
        let mut manifest = self.pages.clone();
        let mut pages = Vec::new();
        let mut obsolete = Vec::new();
        // Pages of destroyed windows (also one destroyed while a write was in flight).
        let windows = &self.windows;
        manifest.retain(|(w, p), r| {
            let keep = windows.contains_key(w);
            if !keep {
                obsolete.push(((*w, *p), *r));
            }
            keep
        });
        for &(w, p) in &taken {
            if let Some(old) = manifest.remove(&(w, p)) {
                obsolete.push(((w, p), old));
            }
            let keys: Vec<(u32, &Key)> = self
                .windows
                .get(&w)
                .map(|win| {
                    win.explicit
                        .range(page_slots(p))
                        .map(|(s, k)| (*s, k))
                        .collect()
                })
                .unwrap_or_default();
            if keys.is_empty() {
                continue;
            }
            let count = u32::try_from(keys.len()).unwrap_or(u32::MAX);
            let mut b = Vec::with_capacity(17 + 36 * keys.len() + 16);
            b.push(FILE_VERSION);
            b.extend_from_slice(&w.to_be_bytes());
            b.extend_from_slice(&p.to_be_bytes());
            b.extend_from_slice(&count.to_be_bytes());
            for (s, k) in keys {
                b.extend_from_slice(&s.to_be_bytes());
                b.extend_from_slice(&k.0);
            }
            pages.push(((w, p), b));
            manifest.insert(
                (w, p),
                PageRef {
                    epoch,
                    generation,
                    count,
                },
            );
        }
        let head = self.encode_head(generation, &manifest);
        Some(Changes {
            epoch,
            generation,
            head,
            pages,
            obsolete,
            manifest,
            taken,
        })
    }

    /// Records a successful write.
    pub(crate) fn committed(&mut self, manifest: BTreeMap<(u64, u32), PageRef>) {
        self.pages = manifest;
    }

    /// Records a failed write: everything it carried is written again next time.
    pub(crate) fn failed(&mut self, taken: Vec<(u64, u32)>) {
        self.dirty = true;
        self.dirty_pages.extend(taken);
    }

    fn encode_head(&self, generation: u64, manifest: &BTreeMap<(u64, u32), PageRef>) -> Vec<u8> {
        let mut out = vec![FILE_VERSION];
        out.extend_from_slice(&generation.to_be_bytes());
        out.extend_from_slice(&len32(self.windows.len()).to_be_bytes());
        for (id, w) in &self.windows {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&w.opened_ms.to_be_bytes());
            out.extend_from_slice(&w.next_slot.to_be_bytes());
            out.extend_from_slice(&w.mark.to_be_bytes());
            out.extend_from_slice(&w.meta.0);
            out.extend_from_slice(&len32(w.tree.frontier.len()).to_be_bytes());
            for ((d, p), k) in &w.tree.frontier {
                out.push(*d);
                out.extend_from_slice(&p.to_be_bytes());
                out.extend_from_slice(&k.0);
            }
        }
        out.extend_from_slice(&len32(manifest.len()).to_be_bytes());
        for ((w, p), r) in manifest {
            out.extend_from_slice(&w.to_be_bytes());
            out.extend_from_slice(&p.to_be_bytes());
            out.extend_from_slice(&r.epoch.to_be_bytes());
            out.extend_from_slice(&r.generation.to_be_bytes());
            out.extend_from_slice(&r.count.to_be_bytes());
        }
        out
    }

    /// Decodes a head: the windows (without their individual keys) and the page list.
    #[allow(clippy::many_single_char_names, reason = "a flat decoder")]
    fn decode_head(b: &[u8]) -> Result<Self, KeyError> {
        let mut r = Rd { b, pos: 0 };
        if r.u8()? != FILE_VERSION {
            return Err(KeyError::File);
        }
        let generation = r.u64()?;
        let n = r.u32()?;
        let mut windows = BTreeMap::new();
        for _ in 0..n {
            let id = r.u64()?;
            let opened_ms = r.u64()?;
            let next_slot = r.u32()?;
            let mark = r.u32()?;
            let meta = Key(r.arr()?);
            let m = r.u32()?;
            r.fits(m, 37)?;
            let mut frontier = BTreeMap::new();
            for _ in 0..m {
                let d = r.u8()?;
                let p = r.u32()?;
                if d > DEPTH || mark > next_slot || next_slot > SLOTS {
                    return Err(KeyError::File);
                }
                frontier.insert((d, p), Key(r.arr()?));
            }
            windows.insert(
                id,
                Window {
                    meta,
                    tree: Tree { frontier },
                    mark,
                    explicit: BTreeMap::new(),
                    next_slot,
                    opened_ms,
                },
            );
        }
        let n = r.u32()?;
        r.fits(n, 26)?;
        let mut pages = BTreeMap::new();
        for _ in 0..n {
            let w = r.u64()?;
            let p = r.u32()?;
            let epoch = r.u16()?;
            let generation = r.u64()?;
            let count = r.u32()?;
            if !windows.contains_key(&w) || count == 0 || count > PAGE_SLOTS {
                return Err(KeyError::File);
            }
            pages.insert(
                (w, p),
                PageRef {
                    epoch,
                    generation,
                    count,
                },
            );
        }
        if r.pos != b.len() {
            return Err(KeyError::File);
        }
        Ok(Self {
            windows,
            dirty: false,
            dirty_pages: BTreeSet::new(),
            pages,
            generation,
        })
    }

    /// Adds a page's keys (checked against what the head says about it).
    #[allow(clippy::many_single_char_names, reason = "a flat decoder")]
    fn add_page(&mut self, w: u64, p: u32, b: &[u8]) -> Result<(), KeyError> {
        let mut r = Rd { b, pos: 0 };
        let want = self.pages.get(&(w, p)).copied().ok_or(KeyError::File)?;
        if r.u8()? != FILE_VERSION || r.u64()? != w || r.u32()? != p || r.u32()? != want.count {
            return Err(KeyError::File);
        }
        let win = self.windows.get_mut(&w).ok_or(KeyError::File)?;
        let range = page_slots(p);
        for _ in 0..want.count {
            let s = r.u32()?;
            if !range.contains(&s) || s >= win.mark {
                return Err(KeyError::File);
            }
            win.explicit.insert(s, Key(r.arr()?));
        }
        if r.pos != b.len() {
            return Err(KeyError::File);
        }
        Ok(())
    }
}

/// Runs the key-store decoders on arbitrary bytes (the `iggy_record` fuzz target): they never
/// panic and stay bounded. Their input is authenticated in production; this is defence in depth.
pub(crate) fn fuzz_decode(data: &[u8]) {
    if let Ok(mut ring) = KeyRing::decode_head(data) {
        let pages: Vec<(u64, u32)> = ring.pages.keys().copied().collect();
        for (w, p) in pages {
            let _ = ring.add_page(w, p, data);
        }
    }
    // A page against a head that expects whatever count the page claims.
    let claimed = data
        .get(13..17)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_be_bytes);
    let page = data
        .get(9..13)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_be_bytes);
    let mut ring = KeyRing::default();
    ring.windows.insert(
        1,
        Window {
            meta: Key([0; 32]),
            tree: Tree {
                frontier: BTreeMap::new(),
            },
            mark: SLOTS,
            explicit: BTreeMap::new(),
            next_slot: SLOTS,
            opened_ms: 0,
        },
    );
    ring.pages.insert(
        (1, page),
        PageRef {
            epoch: 0,
            generation: 1,
            count: claimed.min(PAGE_SLOTS),
        },
    );
    let _ = ring.add_page(1, page, data);
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
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
    fn u16(&mut self) -> Result<u16, KeyError> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32, KeyError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, KeyError> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    /// Refuses a count of `size`-byte items longer than what is left.
    fn fits(&self, n: u32, size: usize) -> Result<(), KeyError> {
        let n = usize::try_from(n).map_err(|_| KeyError::File)?;
        if n.saturating_mul(size) > self.b.len().saturating_sub(self.pos) {
            return Err(KeyError::File);
        }
        Ok(())
    }
}

/// The key store of one partition: a directory holding a **head** (the windows, their trees and
/// the list of pages) and **pages** of individual keys, every file sealed with the master key.
///
/// A write is copy-on-write: changed pages go to new files (named by the write's generation),
/// then the head that lists them replaces the old head atomically, then the files it no longer
/// lists are deleted. A crash at any point leaves a consistent store (the old head and its pages,
/// or the new ones); loading checks every listed page (present, sealed for its place and
/// generation, the expected number of keys) and refuses the store otherwise, so a lost page can
/// never pass for acknowledged messages.
#[derive(Debug)]
pub(crate) struct KeyFile {
    dir: PathBuf,
    master: Key,
    /// Binds every file to its stream, topic and partition.
    aad: Vec<u8>,
    /// Producer epoch of this process's writer: a store written by a newer epoch is never
    /// overwritten (the older writer is fenced, as Iggy fences its appends).
    epoch: std::sync::atomic::AtomicU16,
    /// Files to delete after the next successful write (left by a failed one).
    leftover: std::sync::Mutex<Vec<PathBuf>>,
}

impl KeyFile {
    /// The store of one partition, in a directory of `dir` named after the partition and a hash
    /// of its stream and topic.
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
            aad.extend_from_slice(&len32(part.len()).to_be_bytes());
            aad.extend_from_slice(part);
        }
        let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &aad);
        let tag = hash
            .as_ref()
            .iter()
            .take(8)
            .fold(String::new(), |mut t, b| {
                use std::fmt::Write as _;
                let _ = write!(t, "{b:02x}");
                t
            });
        Self {
            dir: dir.join(format!("p{partition}-{tag}")),
            master: Key(master),
            aad,
            epoch: std::sync::atomic::AtomicU16::new(0),
            leftover: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn sealing_key(&self) -> Result<LessSafeKey, KeyError> {
        let k = UnboundKey::new(&AES_256_GCM, &self.master.0).map_err(|_| KeyError::Crypto)?;
        Ok(LessSafeKey::new(k))
    }

    /// Sets the producer epoch this process writes with.
    pub(crate) fn set_epoch(&self, epoch: u16) {
        self.epoch
            .store(epoch, std::sync::atomic::Ordering::Release);
    }

    /// The producer epoch this process writes with.
    pub(crate) fn epoch(&self) -> u16 {
        self.epoch.load(std::sync::atomic::Ordering::Acquire)
    }

    fn head_path(&self) -> PathBuf {
        self.dir.join("head")
    }

    /// A page file: named by its window, page, writer epoch and write generation, so two
    /// writers (an old one being fenced) never write the same name.
    fn page_path(&self, w: u64, p: u32, r: PageRef) -> PathBuf {
        self.dir
            .join(format!("w{w}.p{p}.e{}.g{}", r.epoch, r.generation))
    }

    fn head_aad(&self, epoch: u16) -> Vec<u8> {
        let mut a = self.aad.clone();
        a.extend_from_slice(b"head");
        a.extend_from_slice(&epoch.to_be_bytes());
        a
    }

    fn page_aad(&self, w: u64, p: u32, generation: u64, epoch: u16) -> Vec<u8> {
        let mut a = self.aad.clone();
        a.extend_from_slice(b"page");
        a.extend_from_slice(&w.to_be_bytes());
        a.extend_from_slice(&p.to_be_bytes());
        a.extend_from_slice(&generation.to_be_bytes());
        a.extend_from_slice(&epoch.to_be_bytes());
        a
    }

    /// `epoch | nonce | ciphertext` -> plaintext (written by `want`, if given).
    fn open_file(
        &self,
        data: &[u8],
        want: Option<u16>,
        aad: impl Fn(u16) -> Vec<u8>,
    ) -> Result<Vec<u8>, KeyError> {
        let (epoch, rest) = data.split_at_checked(2).ok_or(KeyError::File)?;
        let epoch = u16::from_be_bytes(epoch.try_into().map_err(|_| KeyError::File)?);
        if want.is_some_and(|w| w != epoch) {
            return Err(KeyError::File);
        }
        let (nonce, ct) = rest.split_at_checked(NONCE_LEN).ok_or(KeyError::File)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| KeyError::File)?;
        let mut buf = ct.to_vec();
        let n = self
            .sealing_key()?
            .open_in_place(nonce, Aad::from(aad(epoch).as_slice()), &mut buf)
            .map_err(|_| KeyError::File)?
            .len();
        buf.truncate(n);
        Ok(buf)
    }

    /// plaintext -> `epoch | nonce | ciphertext` (the plaintext buffer is sealed in place).
    fn seal_file(&self, epoch: u16, aad: &[u8], plain: &mut Vec<u8>) -> Result<Vec<u8>, KeyError> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| KeyError::Crypto)?;
        plain.reserve(AES_256_GCM.tag_len());
        self.sealing_key()?
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), plain)
            .map_err(|_| KeyError::Crypto)?;
        let mut out = Vec::with_capacity(2 + NONCE_LEN + plain.len());
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);
        Ok(out)
    }

    /// Loads the ring; no head is an empty ring (a new partition). Every page the head lists
    /// must be there and intact; files it does not list are deleted.
    pub(crate) fn load(&self) -> Result<KeyRing, KeyError> {
        // Not while another process writes (its new pages are not listed yet).
        let _lock = match std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("lock"))
        {
            Ok(f) => {
                f.lock().map_err(|_| KeyError::File)?;
                Some(f)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(KeyError::File),
        };
        let data = match std::fs::read(self.head_path()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.remove_unlisted(&BTreeMap::new());
                return Ok(KeyRing::default());
            }
            Err(_) => return Err(KeyError::File),
        };
        let mut plain = self.open_file(&data, None, |e| self.head_aad(e))?;
        let ring = KeyRing::decode_head(&plain);
        plain.fill(0);
        let mut ring = ring?;
        let listed: Vec<((u64, u32), PageRef)> = ring.pages.iter().map(|(k, v)| (*k, *v)).collect();
        for ((w, p), r) in listed {
            let data = std::fs::read(self.page_path(w, p, r)).map_err(|_| KeyError::File)?;
            let mut plain = self.open_file(&data, Some(r.epoch), |e| {
                self.page_aad(w, p, r.generation, e)
            })?;
            let added = ring.add_page(w, p, &plain);
            plain.fill(0);
            added?;
        }
        self.remove_unlisted(&ring.pages);
        Ok(ring)
    }

    /// Deletes page and temporary files the head does not list (left by an interrupted write).
    fn remove_unlisted(&self, pages: &BTreeMap<(u64, u32), PageRef>) {
        let keep: std::collections::HashSet<PathBuf> = pages
            .iter()
            .map(|((w, p), r)| self.page_path(*w, *p, *r))
            .collect();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in entries.flatten() {
            let path = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            let ours = name.starts_with('w') || name.ends_with(".tmp");
            if ours && !keep.contains(&path) {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// Seals and writes a change set (blocking): new pages, then the head, then deletes the
    /// files it replaced.
    pub(crate) fn write(&self, mut changes: Changes) -> Result<(), KeyError> {
        let epoch = changes.epoch;
        let generation = changes.generation;
        let mut pages = Vec::with_capacity(changes.pages.len());
        for ((w, p), plain) in &mut changes.pages {
            let aad = self.page_aad(*w, *p, generation, epoch);
            let at = changes
                .manifest
                .get(&(*w, *p))
                .copied()
                .ok_or(KeyError::Crypto)?;
            pages.push((
                self.page_path(*w, *p, at),
                self.seal_file(epoch, &aad, plain)?,
            ));
        }
        let head = self.seal_file(epoch, &self.head_aad(epoch), &mut changes.head)?;
        std::fs::create_dir_all(&self.dir).map_err(|_| KeyError::Write)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        // One writer at a time, and never over a newer epoch's store.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("lock"))
            .map_err(|_| KeyError::Write)?;
        lock.lock().map_err(|_| KeyError::Write)?;
        if let Ok(current) = std::fs::read(self.head_path())
            && let Some(e) = current.get(..2).and_then(|e| e.try_into().ok())
            && u16::from_be_bytes(e) > epoch
        {
            return Err(KeyError::Fenced);
        }
        let commit = || -> std::io::Result<()> {
            for (path, bytes) in &pages {
                write_file(path, bytes)?;
            }
            sync_dir(&self.dir)?;
            write_file(&self.head_path(), &head)?;
            sync_dir(&self.dir)
        };
        let mut leftover = self
            .leftover
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if commit().is_err() {
            // The new pages may be on disk: delete them once a later head (which will not list
            // them) is written.
            leftover.extend(pages.into_iter().map(|(p, _)| p));
            return Err(KeyError::Write);
        }
        let mut gone: Vec<PathBuf> = changes
            .obsolete
            .iter()
            .map(|((w, p), r)| self.page_path(*w, *p, *r))
            .collect();
        gone.append(&mut leftover);
        for path in gone {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => leftover.push(path),
            }
        }
        let _ = sync_dir(&self.dir);
        drop(lock);
        Ok(())
    }

    /// Advances, writes and commits (tests).
    #[cfg(test)]
    pub(crate) fn store(&self, ring: &mut KeyRing) -> Result<(), KeyError> {
        ring.dirty = true;
        let Some(c) = ring.take_changes(self.epoch()) else {
            return Ok(());
        };
        let manifest = c.manifest.clone();
        self.write(c)?;
        ring.committed(manifest);
        Ok(())
    }

    /// Files in the store (tests).
    #[cfg(test)]
    fn files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

/// Writes a file atomically: temporary file, fsync, rename (the caller syncs the directory).
fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = std::fs::OpenOptions::new();
    f.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        f.mode(0o600);
    }
    let mut file = f.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

fn idx(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
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
    fn range_matches_single_leaves_and_skips_punctured() {
        let mut t = Tree::new(Key([5; 32]));
        t.puncture(7).unwrap();
        let r = t.range(3, 12).unwrap();
        let slots: Vec<u32> = r.iter().map(|(s, _)| *s).collect();
        assert_eq!(slots, vec![3, 4, 5, 6, 8, 9, 10, 11]);
        for (s, k) in r {
            assert_eq!(t.leaf(s).unwrap(), Some(k));
        }
    }

    #[test]
    fn advance_keeps_only_pending_keys_and_cuts_the_tree() {
        let mut ring = KeyRing::default();
        let w = ring.open_window(0).unwrap();
        ring.reserve(w, 1000).unwrap();
        let before: Vec<Key> = (0..1000)
            .map(|s| ring.leaf(w, s).unwrap().unwrap())
            .collect();
        // Acknowledgements in a scattered order.
        for s in (0..1000).filter(|s| s % 3 != 0) {
            ring.puncture(w, s).unwrap();
        }
        ring.advance().unwrap();
        let win = &ring.windows[&w];
        assert_eq!(win.mark, 1000);
        assert_eq!(win.explicit.len(), 334, "one key per pending slot");
        assert!(
            win.tree.len() <= usize::from(DEPTH) + 1,
            "{}",
            win.tree.len()
        );
        // Nothing below the mark is derivable from the tree any more.
        assert_eq!(win.tree.range(0, 1000).unwrap(), Vec::new());
        for s in 0..1000u32 {
            let want = (s % 3 == 0).then(|| before[usize::try_from(s).unwrap()].clone());
            assert_eq!(ring.leaf(w, s).unwrap(), want, "slot {s}");
        }
        ring.puncture(w, 3).unwrap();
        assert!(ring.leaf(w, 3).unwrap().is_none());
        // New slots above the mark still come from the tree, and match a batch derivation.
        let first = ring.reserve(w, 10).unwrap();
        let batch = ring.leaves(w, first, 10).unwrap();
        for (i, k) in batch.iter().enumerate() {
            let s = first + u32::try_from(i).unwrap();
            assert_eq!(k.as_ref(), ring.leaf(w, s).unwrap().as_ref());
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sb-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A ring with one window of `n` pending slots, written once.
    fn stored(file: &KeyFile, n: u32) -> (KeyRing, u64) {
        let mut ring = KeyRing::default();
        let w = ring.open_window(1000).unwrap();
        ring.reserve(w, n).unwrap();
        ring.advance().unwrap();
        file.store(&mut ring).unwrap();
        (ring, w)
    }

    #[test]
    fn store_round_trips_and_binds_its_partition() {
        let dir = temp_dir("keys");
        let file = KeyFile::new(&dir, "s", "t", 0, [9; 32]);
        let mut ring = KeyRing::default();
        let w = ring.open_window(1000).unwrap();
        ring.reserve(w, 3000).unwrap();
        let leaf3 = ring.leaf(w, 3).unwrap().unwrap();
        let leaf2500 = ring.leaf(w, 2500).unwrap().unwrap();
        ring.puncture(w, 2).unwrap();
        ring.advance().unwrap();
        // More slots above the mark stay in the tree (the head).
        ring.reserve(w, 10).unwrap();
        let leaf3005 = ring.leaf(w, 3005).unwrap().unwrap();
        file.store(&mut ring).unwrap();
        let back = file.load().unwrap();
        assert_eq!(back.leaf(w, 3).unwrap(), Some(leaf3));
        assert_eq!(back.leaf(w, 2500).unwrap(), Some(leaf2500));
        assert_eq!(back.leaf(w, 3005).unwrap(), Some(leaf3005));
        assert_eq!(back.leaf(w, 2).unwrap(), None);
        assert_eq!(back.windows[&w].next_slot, 3010);
        assert_eq!(
            file.files(),
            vec!["head", "lock", "w1.p0.e0.g1", "w1.p1.e0.g1", "w1.p2.e0.g1"]
        );
        // Another master key does not open it.
        let other = KeyFile::new(&dir, "s", "t", 0, [8; 32]);
        assert_eq!(other.load().unwrap_err(), KeyError::File);
        // Nor does another partition, given this one's files.
        let p1 = KeyFile::new(&dir, "s", "t", 1, [9; 32]);
        std::fs::create_dir_all(&p1.dir).unwrap();
        for f in ["head", "w1.p0.e0.g1", "w1.p1.e0.g1", "w1.p2.e0.g1"] {
            std::fs::copy(file.dir.join(f), p1.dir.join(f)).unwrap();
        }
        assert_eq!(p1.load().unwrap_err(), KeyError::File);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_write_replaces_only_the_pages_that_changed() {
        let dir = temp_dir("pages");
        let file = KeyFile::new(&dir, "s", "t", 0, [9; 32]);
        let (mut ring, w) = stored(&file, 3000);
        let keep = ring.leaf(w, 1501).unwrap().unwrap();
        ring.puncture(w, 1500).unwrap();
        file.store(&mut ring).unwrap();
        // Page 1 rewritten (generation 2), its old file deleted; pages 0 and 2 untouched.
        assert_eq!(
            file.files(),
            vec!["head", "lock", "w1.p0.e0.g1", "w1.p1.e0.g2", "w1.p2.e0.g1"]
        );
        // Emptying a page deletes its file.
        for s in 2048..3000 {
            ring.puncture(w, s).unwrap();
        }
        file.store(&mut ring).unwrap();
        assert_eq!(
            file.files(),
            vec!["head", "lock", "w1.p0.e0.g1", "w1.p1.e0.g2"]
        );
        let back = file.load().unwrap();
        assert_eq!(back.leaf(w, 1500).unwrap(), None);
        assert_eq!(back.leaf(w, 1501).unwrap(), Some(keep));
        assert_eq!(back.leaf(w, 2500).unwrap(), None);
        assert_eq!(back.windows[&w].explicit.len(), 2047);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_or_misplaced_page_refuses_the_store() {
        let dir = temp_dir("lost");
        let file = KeyFile::new(&dir, "s", "t", 0, [9; 32]);
        let (_ring, _w) = stored(&file, 3000);
        let page = file.dir.join("w1.p1.e0.g1");
        let saved = std::fs::read(&page).unwrap();
        // Lost: pending keys would pass for acknowledged messages, so the store is refused.
        std::fs::remove_file(&page).unwrap();
        assert_eq!(file.load().unwrap_err(), KeyError::File);
        // Another page's file in its place does not open either.
        std::fs::copy(file.dir.join("w1.p2.e0.g1"), &page).unwrap();
        assert_eq!(file.load().unwrap_err(), KeyError::File);
        std::fs::write(&page, saved).unwrap();
        assert!(file.load().is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_interrupted_write_leaves_the_previous_store() {
        let dir = temp_dir("crash");
        let file = KeyFile::new(&dir, "s", "t", 0, [9; 32]);
        let (mut ring, w) = stored(&file, 3000);
        let before = ring.leaf(w, 1500).unwrap().unwrap();
        // A write that stopped after its pages, before its head: new page files exist, the head
        // still lists the old ones.
        ring.puncture(w, 1500).unwrap();
        let c = ring.take_changes(0).unwrap();
        for ((pw, pp), plain) in &c.pages {
            let mut plain = plain.clone();
            let aad = file.page_aad(*pw, *pp, c.generation, 0);
            let bytes = file.seal_file(0, &aad, &mut plain).unwrap();
            write_file(&file.page_path(*pw, *pp, c.manifest[&(*pw, *pp)]), &bytes).unwrap();
        }
        std::fs::write(file.dir.join("head.tmp"), b"partial").unwrap();
        let back = file.load().unwrap();
        // The previous store, whole (the log's ACK record punctures again on replay); the
        // unlisted files are gone.
        assert_eq!(back.leaf(w, 1500).unwrap(), Some(before));
        assert_eq!(
            file.files(),
            vec!["head", "lock", "w1.p0.e0.g1", "w1.p1.e0.g1", "w1.p2.e0.g1"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn destroying_a_window_deletes_its_pages() {
        let dir = temp_dir("destroy");
        let file = KeyFile::new(&dir, "s", "t", 0, [9; 32]);
        let (mut ring, w1) = stored(&file, 1500);
        let w2 = ring.open_window(2000).unwrap();
        ring.reserve(w2, 10).unwrap();
        ring.advance().unwrap();
        file.store(&mut ring).unwrap();
        ring.destroy(w1);
        file.store(&mut ring).unwrap();
        assert_eq!(file.files(), vec!["head", "lock", "w2.p0.e0.g2"]);
        let back = file.load().unwrap();
        assert!(!back.windows.contains_key(&w1));
        assert_eq!(back.windows[&w2].explicit.len(), 10);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_older_writer_cannot_overwrite_a_newer_one() {
        let dir = temp_dir("fence");
        let old = KeyFile::new(&dir, "s", "t", 0, [9; 32]);
        let new = KeyFile::new(&dir, "s", "t", 0, [9; 32]);
        old.set_epoch(1);
        new.set_epoch(2);
        let mut ring = KeyRing::default();
        old.store(&mut ring).unwrap();
        new.store(&mut ring).unwrap();
        assert_eq!(old.store(&mut ring).unwrap_err(), KeyError::Fenced);
        assert!(new.load().is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn replayed_records_move_the_next_slot() {
        let mut ring = KeyRing::default();
        let w = ring.open_window(0).unwrap();
        ring.reserve(w, 10).unwrap();
        ring.note_used(w, 25);
        ring.note_used(w, 5);
        assert_eq!(ring.reserve(w, 1), Some(25));
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
