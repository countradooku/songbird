//! Key transparency (Prompt 3, M6, D-0055): an append-only Merkle log (RFC 9162, "Certificate
//! Transparency Version 2.0", §2.1) of what the server vouches for about each account: its
//! identity key, its device lists and its username.
//!
//! - **Leaves** ([`Leaf`]) name an account only through `subject = HMAC-SHA256(salt, context ||
//!   account)`. The per-account salt is given to whoever asks about the account and deleted with
//!   it, so a deleted account's leaves become unlinkable (the log itself is append-only).
//! - **Hashes**: `leaf = SHA-256(0x00 || leaf bytes)`, `node = SHA-256(0x01 || left || right)`.
//! - **Proofs**: inclusion (`PATH`) and consistency (`PROOF`) as RFC 9162 §2.1.3 and §2.1.4
//!   define them, with their verification algorithms.
//! - **Signed tree heads** ([`TreeHead`]): Ed25519 by the log key over
//!   `"songbird.v1/kt-head\0" || version || size || root || time`.
//! - **Storage** ([`Store`]): only the hashes of perfect subtrees are kept; any range's hash is
//!   assembled from them in O(log² n) lookups.
//!
//! A client keeps the last head it verified per log and checks every newer one is consistent with
//! it; an account's owner checks the log lists exactly the keys and lists it published. A server
//! that shows two people different logs (a fork) must sign two heads that no consistency proof
//! can join.
#![forbid(unsafe_code)]

use aws_lc_rs::digest::{Context, SHA256};
use aws_lc_rs::hmac;

/// Hash length.
pub const HASH_LEN: usize = 32;
/// A hash.
pub type Hash = [u8; HASH_LEN];
/// Leaf format version.
pub const LEAF_VERSION: u8 = 1;
/// Leaf length.
pub const LEAF_LEN: usize = 1 + 1 + HASH_LEN + HASH_LEN + 8;
/// Tree-head length.
pub const HEAD_LEN: usize = 1 + 8 + HASH_LEN + 8 + 64;
/// Domain separation of tree-head signatures.
pub const HEAD_CONTEXT: &[u8] = b"songbird.v1/kt-head\0";
/// Domain separation of subjects.
pub const SUBJECT_CONTEXT: &[u8] = b"songbird.v1/kt-subject\0";
/// Longest proof (a tree of 2^64 leaves).
pub const MAX_PROOF: usize = 64;

/// Proof verification or decoding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KtError {
    /// Malformed bytes or arguments (index beyond size, sizes out of order).
    #[error("malformed")]
    Malformed,
    /// The proof does not lead to the root.
    #[error("proof does not verify")]
    Proof,
    /// The store lacks a hash it should have.
    #[error("store incomplete")]
    Store,
}

/// What a leaf records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The account identity key (value: SHA-256 of the key).
    Identity,
    /// A device list (value: SHA-256 of the signed list).
    DeviceList,
    /// The account's username hash (value: the hash; 32 zero bytes once released).
    Username,
}

impl Kind {
    /// Wire value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Identity => 1,
            Self::DeviceList => 2,
            Self::Username => 3,
        }
    }

    /// From a wire value.
    #[must_use]
    pub const fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(Self::Identity),
            2 => Some(Self::DeviceList),
            3 => Some(Self::Username),
            _ => None,
        }
    }
}

/// A log entry: `version u8 | kind u8 | subject [32] | value [32] | time_ms u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf {
    /// What it records.
    pub kind: Kind,
    /// `HMAC-SHA256(salt, SUBJECT_CONTEXT || account)` ([`subject`]).
    pub subject: Hash,
    /// The recorded value's hash.
    pub value: Hash,
    /// When it was logged (Unix milliseconds).
    pub time_ms: u64,
}

impl Leaf {
    /// The bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; LEAF_LEN] {
        let mut b = [0u8; LEAF_LEN];
        b[0] = LEAF_VERSION;
        b[1] = self.kind.code();
        b[2..34].copy_from_slice(&self.subject);
        b[34..66].copy_from_slice(&self.value);
        b[66..].copy_from_slice(&self.time_ms.to_be_bytes());
        b
    }

    /// Decodes exactly [`LEAF_LEN`] bytes.
    ///
    /// # Errors
    /// [`KtError::Malformed`].
    pub fn decode(b: &[u8]) -> Result<Self, KtError> {
        let b: &[u8; LEAF_LEN] = b.try_into().map_err(|_| KtError::Malformed)?;
        if b[0] != LEAF_VERSION {
            return Err(KtError::Malformed);
        }
        let mut subject = [0u8; HASH_LEN];
        subject.copy_from_slice(&b[2..34]);
        let mut value = [0u8; HASH_LEN];
        value.copy_from_slice(&b[34..66]);
        let mut t = [0u8; 8];
        t.copy_from_slice(&b[66..]);
        Ok(Self {
            kind: Kind::from_code(b[1]).ok_or(KtError::Malformed)?,
            subject,
            value,
            time_ms: u64::from_be_bytes(t),
        })
    }

    /// Its leaf hash.
    #[must_use]
    pub fn hash(&self) -> Hash {
        leaf_hash(&self.encode())
    }
}

/// The subject naming an account in the log.
#[must_use]
pub fn subject(salt: &[u8; 32], account: &[u8; 16]) -> Hash {
    let k = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(SUBJECT_CONTEXT);
    ctx.update(account);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// SHA-256 of some bytes (a leaf's value).
#[must_use]
pub fn sha256(b: &[u8]) -> Hash {
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(aws_lc_rs::digest::digest(&SHA256, b).as_ref());
    out
}

/// `SHA-256(0x00 || bytes)`.
#[must_use]
pub fn leaf_hash(bytes: &[u8]) -> Hash {
    let mut c = Context::new(&SHA256);
    c.update(&[0]);
    c.update(bytes);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(c.finish().as_ref());
    out
}

/// `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut c = Context::new(&SHA256);
    c.update(&[1]);
    c.update(left);
    c.update(right);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(c.finish().as_ref());
    out
}

/// The root of the empty tree: `SHA-256("")`.
#[must_use]
pub fn empty_root() -> Hash {
    sha256(b"")
}

/// Where the log keeps the hashes of perfect subtrees: `(level, index)` covers leaves
/// `[index · 2^level, (index + 1) · 2^level)`.
pub trait Store {
    /// A stored perfect-subtree hash.
    fn node(&self, level: u32, index: u64) -> Option<Hash>;
}

/// The nodes appending one leaf to a tree of `size` leaves completes: `(level, index, hash)`,
/// level 0 (the leaf) first. `sibling` reads existing perfect-subtree hashes.
///
/// # Errors
/// [`KtError::Store`] if a sibling is missing.
pub fn append_nodes(
    store: &impl Store,
    size: u64,
    leaf: Hash,
) -> Result<Vec<(u32, u64, Hash)>, KtError> {
    let mut out = vec![(0, size, leaf)];
    let (mut level, mut index, mut h) = (0u32, size, leaf);
    while index % 2 == 1 {
        let left = store.node(level, index - 1).ok_or(KtError::Store)?;
        h = node_hash(&left, &h);
        level += 1;
        index /= 2;
        out.push((level, index, h));
    }
    Ok(out)
}

fn largest_power_of_two_below(n: u64) -> u64 {
    // n >= 2: the largest power of two strictly less than n.
    1u64 << (n - 1).ilog2()
}

/// `MTH(D[start:end])` assembled from perfect subtrees (RFC 9162 §2.1.1: the left part is the
/// largest power of two). `start` is always aligned to the size of the range's left part.
///
/// # Errors
/// [`KtError::Store`], [`KtError::Malformed`] for an empty range.
pub fn range_hash(store: &impl Store, start: u64, end: u64) -> Result<Hash, KtError> {
    let n = end.checked_sub(start).ok_or(KtError::Malformed)?;
    if n == 0 {
        return Err(KtError::Malformed);
    }
    if n.is_power_of_two() && start.is_multiple_of(n) {
        return store
            .node(n.trailing_zeros(), start >> n.trailing_zeros())
            .ok_or(KtError::Store);
    }
    let k = largest_power_of_two_below(n);
    Ok(node_hash(
        &range_hash(store, start, start + k)?,
        &range_hash(store, start + k, end)?,
    ))
}

/// The root of a tree of `size` leaves.
///
/// # Errors
/// [`KtError::Store`].
pub fn root(store: &impl Store, size: u64) -> Result<Hash, KtError> {
    if size == 0 {
        return Ok(empty_root());
    }
    range_hash(store, 0, size)
}

/// `PATH(m, D[start:end])` (RFC 9162 §2.1.3.1), leaf-side first.
fn path(
    store: &impl Store,
    m: u64,
    start: u64,
    end: u64,
    out: &mut Vec<Hash>,
) -> Result<(), KtError> {
    let n = end - start;
    if n <= 1 {
        return Ok(());
    }
    let k = largest_power_of_two_below(n);
    if m < k {
        path(store, m, start, start + k, out)?;
        out.push(range_hash(store, start + k, end)?);
    } else {
        path(store, m - k, start + k, end, out)?;
        out.push(range_hash(store, start, start + k)?);
    }
    Ok(())
}

/// The inclusion proof of leaf `index` in a tree of `size` leaves.
///
/// # Errors
/// [`KtError::Malformed`] for an index beyond the size; [`KtError::Store`].
pub fn inclusion_proof(store: &impl Store, index: u64, size: u64) -> Result<Vec<Hash>, KtError> {
    if index >= size {
        return Err(KtError::Malformed);
    }
    let mut out = Vec::new();
    path(store, index, 0, size, &mut out)?;
    Ok(out)
}

/// `SUBPROOF(m, D[start:end], b)` (RFC 9162 §2.1.4.1).
fn subproof(
    store: &impl Store,
    m: u64,
    start: u64,
    end: u64,
    complete: bool,
    out: &mut Vec<Hash>,
) -> Result<(), KtError> {
    let n = end - start;
    if m == n {
        if !complete {
            out.push(range_hash(store, start, end)?);
        }
        return Ok(());
    }
    let k = largest_power_of_two_below(n);
    if m <= k {
        subproof(store, m, start, start + k, complete, out)?;
        out.push(range_hash(store, start + k, end)?);
    } else {
        subproof(store, m - k, start + k, end, false, out)?;
        out.push(range_hash(store, start, start + k)?);
    }
    Ok(())
}

/// The consistency proof between sizes `old` and `new` (`0 < old <= new`).
///
/// # Errors
/// [`KtError::Malformed`]; [`KtError::Store`].
pub fn consistency_proof(store: &impl Store, old: u64, new: u64) -> Result<Vec<Hash>, KtError> {
    if old == 0 || old > new {
        return Err(KtError::Malformed);
    }
    let mut out = Vec::new();
    if old < new {
        subproof(store, old, 0, new, true, &mut out)?;
    }
    Ok(out)
}

/// Verifies an inclusion proof (RFC 9162 §2.1.3.2).
///
/// # Errors
/// [`KtError::Malformed`], [`KtError::Proof`].
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), KtError> {
    if index >= size || proof.len() > MAX_PROOF {
        return Err(KtError::Malformed);
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return Err(KtError::Proof);
        }
        if fn_ % 2 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ % 2 == 0 {
                while fn_ % 2 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if sn == 0 && &r == root {
        Ok(())
    } else {
        Err(KtError::Proof)
    }
}

/// Verifies a consistency proof (RFC 9162 §2.1.4.2).
///
/// # Errors
/// [`KtError::Malformed`], [`KtError::Proof`].
pub fn verify_consistency(
    old: u64,
    new: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<(), KtError> {
    if old == 0 || old > new || proof.len() > MAX_PROOF {
        return Err(KtError::Malformed);
    }
    if old == new {
        return if proof.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err(KtError::Proof)
        };
    }
    let mut path: Vec<Hash> = proof.to_vec();
    if old.is_power_of_two() {
        path.insert(0, *old_root);
    }
    let (mut fn_, mut sn) = (old - 1, new - 1);
    while fn_ % 2 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (first, rest) = path.split_first().ok_or(KtError::Proof)?;
    let (mut fr, mut sr) = (*first, *first);
    for c in rest {
        if sn == 0 {
            return Err(KtError::Proof);
        }
        if fn_ % 2 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_ % 2 == 0 {
                while fn_ % 2 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if &fr == old_root && &sr == new_root && sn == 0 {
        Ok(())
    } else {
        Err(KtError::Proof)
    }
}

/// A signed tree head: `version u8 (1) | size u64 | root [32] | time_ms u64 | signature [64]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeHead {
    /// Leaves in the tree.
    pub size: u64,
    /// Its root.
    pub root: Hash,
    /// When it was signed (Unix milliseconds).
    pub time_ms: u64,
    /// Ed25519 by the log key over [`TreeHead::signed_bytes`].
    pub signature: [u8; 64],
}

impl TreeHead {
    fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEAD_LEN);
        b.push(1);
        b.extend_from_slice(&self.size.to_be_bytes());
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&self.time_ms.to_be_bytes());
        b
    }

    /// What the signature covers.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut b = HEAD_CONTEXT.to_vec();
        b.extend_from_slice(&self.body());
        b
    }

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decodes exactly [`HEAD_LEN`] bytes.
    ///
    /// # Errors
    /// [`KtError::Malformed`].
    pub fn decode(b: &[u8]) -> Result<Self, KtError> {
        if b.len() != HEAD_LEN || b.first() != Some(&1) {
            return Err(KtError::Malformed);
        }
        let get = |a: usize, z: usize| b.get(a..z).ok_or(KtError::Malformed);
        let mut size = [0u8; 8];
        size.copy_from_slice(get(1, 9)?);
        let mut root = [0u8; HASH_LEN];
        root.copy_from_slice(get(9, 41)?);
        let mut t = [0u8; 8];
        t.copy_from_slice(get(41, 49)?);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(get(49, 113)?);
        Ok(Self {
            size: u64::from_be_bytes(size),
            root,
            time_ms: u64::from_be_bytes(t),
            signature,
        })
    }
}

/// An in-memory store (tests, tools, clients replaying a log).
#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    nodes: std::collections::HashMap<(u32, u64), Hash>,
    size: u64,
}

impl Store for MemoryStore {
    fn node(&self, level: u32, index: u64) -> Option<Hash> {
        self.nodes.get(&(level, index)).copied()
    }
}

impl MemoryStore {
    /// Appends a leaf hash; returns its index.
    ///
    /// # Errors
    /// [`KtError::Store`] (never for a store built only by `append`).
    pub fn append(&mut self, leaf: Hash) -> Result<u64, KtError> {
        let index = self.size;
        for (l, i, h) in append_nodes(self, self.size, leaf)? {
            self.nodes.insert((l, i), h);
        }
        self.size += 1;
        Ok(index)
    }

    /// Leaves appended.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
}
