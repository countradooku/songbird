//! Sealed records: what the mailbox writes to Iggy (record format version 3, D-0031).
//!
//! ```text
//! u8 version (3) | u8 kind | u64 window | u32 first_leaf | u32 slots |
//! u32 meta_len | meta (AES-256-GCM, window metadata key, random nonce) |
//! slots × (u32 len | sealed slot (AES-256-GCM, leaf key first_leaf + i, constant nonce))
//! ```
//!
//! The header is the AAD of every part, with the partition and, for a slot, its index: a part
//! cannot be moved to another record, slot or partition. What goes where:
//!
//! | Kind | Metadata (window key) | Slots (leaf keys, punctured on ACK) |
//! | --- | --- | --- |
//! | Store | flags, tag and fingerprint, `at_ms`, MLS group and epoch, local count, remote partitions | each local entry (`device`, `seq`, envelope; shared: `device`, `seq`), the shared body, each remote part |
//! | Relocate | count | each entry (`device`, `seq`, `at_ms`, envelope) |
//! | Ack, Owner, Snapshot | the record | none |

use bytes::{BufMut, Bytes, BytesMut};
use songbird_types::DeviceId;

use super::keys::{KeyError, KeyRing, open_leaf, open_meta, seal_leaf, seal_meta};
use super::record::{Local, Record, Remote};

/// Sealed record format version.
pub(crate) const VERSION: u8 = 3;

const KIND_STORE: u8 = 1;
const KIND_ACK: u8 = 2;
const KIND_RELOCATE: u8 = 3;
const KIND_OWNER: u8 = 4;
const KIND_SNAPSHOT: u8 = 5;

const FLAG_TAG: u8 = 0x01;
const FLAG_MLS: u8 = 0x02;
const FLAG_SHARED: u8 = 0x04;

const HEADER: usize = 1 + 1 + 8 + 4 + 4;
/// Largest record accepted.
const MAX_RECORD: usize = 64 << 20;

/// Why a sealed record does not open. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OpenError {
    /// Not a well-formed sealed record of this version.
    #[error("sealed record malformed or of another version")]
    Malformed,
    /// Its window's keys are gone (destroyed, or a lost key store).
    #[error("sealed record's window keys are gone")]
    NoWindow,
    /// Authentication failed (wrong keys or tampering).
    #[error("sealed record failed authentication")]
    Auth,
}

/// A parsed sealed record (nothing decrypted yet).
#[derive(Debug, Clone)]
pub(crate) struct Sealed {
    kind: u8,
    pub(crate) window: u64,
    pub(crate) first_leaf: u32,
    header: [u8; HEADER],
    meta: Bytes,
    slots: Vec<Bytes>,
}

fn aad(header: &[u8; HEADER], partition: u32, slot: Option<u32>) -> Vec<u8> {
    let mut a = Vec::with_capacity(HEADER + 9);
    a.extend_from_slice(header);
    a.extend_from_slice(&partition.to_be_bytes());
    match slot {
        Some(i) => {
            a.push(1);
            a.extend_from_slice(&i.to_be_bytes());
        }
        None => a.push(0),
    }
    a
}

fn put_bytes(buf: &mut BytesMut, b: &[u8]) {
    buf.put_u32(u32::try_from(b.len()).unwrap_or(u32::MAX));
    buf.put_slice(b);
}

/// Opened store metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreMeta {
    pub(crate) tag: Option<([u8; 32], [u8; 16])>,
    pub(crate) at_ms: u64,
    pub(crate) mls: Option<([u8; 16], u64)>,
    pub(crate) shared: bool,
    pub(crate) n_local: u32,
    /// Remote parts' partitions, in slot order.
    pub(crate) remotes: Vec<u32>,
}

impl StoreMeta {
    /// Slot index of the shared body.
    pub(crate) fn body_slot(&self) -> Option<u32> {
        self.shared.then_some(self.n_local)
    }

    /// Slot index of remote part `i`.
    pub(crate) fn remote_slot(&self, i: usize) -> u32 {
        self.n_local + u32::from(self.shared) + u32::try_from(i).unwrap_or(u32::MAX)
    }
}

/// Opened metadata of any record.
#[derive(Debug, Clone)]
pub(crate) enum Meta {
    Store(StoreMeta),
    Relocate {
        n: u32,
    },
    /// Ack, Owner, Snapshot.
    Plain(Record),
}

/// A local or relocated entry decoded from its slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntrySlot {
    pub(crate) device: DeviceId,
    pub(crate) seq: u64,
    /// Relocated entries carry their original time.
    pub(crate) at_ms: Option<u64>,
    /// Per-device envelope (absent for shared entries: see the body slot).
    pub(crate) envelope: Option<Bytes>,
}

/// Seals a record into the current window; returns the payload and the first leaf.
#[cfg(test)]
pub(crate) fn seal(
    rec: &Record,
    ring: &mut KeyRing,
    window: u64,
    partition: u32,
) -> Result<(Bytes, u32), KeyError> {
    seal_batch(std::slice::from_ref(rec), ring, window, partition)?
        .pop()
        .ok_or(KeyError::Crypto)
}

/// Seals a batch into the current window: the slots of all records are reserved together and
/// their keys derived in one pass over the tree. Returns each record's payload and first leaf.
pub(crate) fn seal_batch(
    records: &[Record],
    ring: &mut KeyRing,
    window: u64,
    partition: u32,
) -> Result<Vec<(Bytes, u32)>, KeyError> {
    let parts: Vec<(u8, BytesMut, Vec<BytesMut>)> = records.iter().map(parts_of).collect();
    let total: u32 = parts
        .iter()
        .map(|(_, _, sl)| u32::try_from(sl.len()).unwrap_or(u32::MAX))
        .sum();
    let first = ring.reserve(window, total).ok_or(KeyError::Crypto)?;
    let leaves = ring.leaves(window, first, total)?;
    let meta_key = ring.meta(window).ok_or(KeyError::Crypto)?;
    let mut out = Vec::with_capacity(records.len());
    let mut next = 0usize;
    for (kind, meta, slots) in parts {
        let n = u32::try_from(slots.len()).map_err(|_| KeyError::Crypto)?;
        let first_leaf = first + u32::try_from(next).map_err(|_| KeyError::Crypto)?;
        let mut header = [0u8; HEADER];
        header[0] = VERSION;
        header[1] = kind;
        header[2..10].copy_from_slice(&window.to_be_bytes());
        header[10..14].copy_from_slice(&first_leaf.to_be_bytes());
        header[14..18].copy_from_slice(&n.to_be_bytes());
        let meta_ct = seal_meta(meta_key, &aad(&header, partition, None), &meta)?;
        let mut buf = BytesMut::with_capacity(
            HEADER + 4 + meta_ct.len() + slots.iter().map(|s| s.len() + 20).sum::<usize>(),
        );
        buf.put_slice(&header);
        put_bytes(&mut buf, &meta_ct);
        for (i, plain) in slots.iter().enumerate() {
            let leaf = leaves
                .get(next + i)
                .and_then(Option::as_ref)
                .ok_or(KeyError::Crypto)?;
            let i = u32::try_from(i).map_err(|_| KeyError::Crypto)?;
            let ct = seal_leaf(leaf, &aad(&header, partition, Some(i)), plain)?;
            put_bytes(&mut buf, &ct);
        }
        next += slots.len();
        out.push((buf.freeze(), first_leaf));
    }
    Ok(out)
}

/// A record's kind, metadata plaintext and slot plaintexts.
#[allow(
    clippy::too_many_lines,
    reason = "one flat match over every record kind"
)]
fn parts_of(rec: &Record) -> (u8, BytesMut, Vec<BytesMut>) {
    let mut meta = BytesMut::new();
    let mut slots: Vec<BytesMut> = Vec::new();
    let kind = match rec {
        Record::Store {
            tag,
            at_ms,
            mls,
            local,
            remote,
        } => {
            let shared = matches!(local, Local::Shared { .. });
            let mut flags = 0;
            if tag.is_some() {
                flags |= FLAG_TAG;
            }
            if mls.is_some() {
                flags |= FLAG_MLS;
            }
            if shared {
                flags |= FLAG_SHARED;
            }
            meta.put_u8(flags);
            if let Some((t, fp)) = tag {
                meta.put_slice(t);
                meta.put_slice(fp);
            }
            meta.put_u64(*at_ms);
            if let Some((g, e)) = mls {
                meta.put_slice(g);
                meta.put_u64(*e);
            }
            meta.put_u32(u32::try_from(local.len()).unwrap_or(u32::MAX));
            meta.put_u32(u32::try_from(remote.len()).unwrap_or(u32::MAX));
            for r in remote {
                meta.put_u32(r.partition);
            }
            match local {
                Local::PerDevice(items) => {
                    for (d, s, env) in items {
                        let mut b = BytesMut::with_capacity(24 + env.len());
                        b.put_slice(d.as_bytes());
                        b.put_u64(*s);
                        b.put_slice(env);
                        slots.push(b);
                    }
                }
                Local::Shared { entries, body } => {
                    for (d, s) in entries {
                        let mut b = BytesMut::with_capacity(24);
                        b.put_slice(d.as_bytes());
                        b.put_u64(*s);
                        slots.push(b);
                    }
                    slots.push(BytesMut::from(&body[..]));
                }
            }
            for r in remote {
                let mut b = BytesMut::new();
                b.put_u8(u8::from(r.shared.is_some()));
                b.put_u32(u32::try_from(r.items.len()).unwrap_or(u32::MAX));
                for (d, env) in &r.items {
                    b.put_slice(d.as_bytes());
                    if r.shared.is_none() {
                        put_bytes(&mut b, env);
                    }
                }
                if let Some(body) = &r.shared {
                    put_bytes(&mut b, body);
                }
                slots.push(b);
            }
            KIND_STORE
        }
        Record::Relocate(items) => {
            meta.put_u32(u32::try_from(items.len()).unwrap_or(u32::MAX));
            for (d, s, at, env) in items {
                let mut b = BytesMut::with_capacity(32 + env.len());
                b.put_slice(d.as_bytes());
                b.put_u64(*s);
                b.put_u64(*at);
                b.put_slice(env);
                slots.push(b);
            }
            KIND_RELOCATE
        }
        Record::Ack(_) => {
            meta.put_slice(&rec.encode());
            KIND_ACK
        }
        Record::Owner { .. } => {
            meta.put_slice(&rec.encode());
            KIND_OWNER
        }
        Record::Snapshot { .. } => {
            meta.put_slice(&rec.encode());
            KIND_SNAPSHOT
        }
    };
    (kind, meta, slots)
}

impl Sealed {
    /// Parses the outer layout (bounded; nothing decrypted).
    pub(crate) fn parse(payload: &Bytes) -> Result<Self, OpenError> {
        if payload.len() > MAX_RECORD || payload.len() < HEADER {
            return Err(OpenError::Malformed);
        }
        let mut header = [0u8; HEADER];
        header.copy_from_slice(payload.get(..HEADER).ok_or(OpenError::Malformed)?);
        if header[0] != VERSION || !(KIND_STORE..=KIND_SNAPSHOT).contains(&header[1]) {
            return Err(OpenError::Malformed);
        }
        let u64_at = |i: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(header.get(i..i + 8).unwrap_or(&[0; 8]));
            u64::from_be_bytes(a)
        };
        let u32_at = |i: usize| {
            let mut a = [0u8; 4];
            a.copy_from_slice(header.get(i..i + 4).unwrap_or(&[0; 4]));
            u32::from_be_bytes(a)
        };
        let window = u64_at(2);
        let first_leaf = u32_at(10);
        let n = u32_at(14);
        let mut pos = HEADER;
        let take = |pos: &mut usize| -> Result<Bytes, OpenError> {
            let len_b = payload.get(*pos..*pos + 4).ok_or(OpenError::Malformed)?;
            let mut a = [0u8; 4];
            a.copy_from_slice(len_b);
            let len = usize::try_from(u32::from_be_bytes(a)).map_err(|_| OpenError::Malformed)?;
            let start = *pos + 4;
            let end = start.checked_add(len).ok_or(OpenError::Malformed)?;
            if end > payload.len() {
                return Err(OpenError::Malformed);
            }
            *pos = end;
            Ok(payload.slice(start..end))
        };
        let meta = take(&mut pos)?;
        // Every slot is at least its length and a 16-byte tag.
        let n_usize = usize::try_from(n).map_err(|_| OpenError::Malformed)?;
        if n_usize.saturating_mul(20) > payload.len().saturating_sub(pos) {
            return Err(OpenError::Malformed);
        }
        let mut slots = Vec::with_capacity(n_usize);
        for _ in 0..n {
            slots.push(take(&mut pos)?);
        }
        if pos != payload.len() {
            return Err(OpenError::Malformed);
        }
        Ok(Self {
            kind: header[1],
            window,
            first_leaf,
            header,
            meta,
            slots,
        })
    }

    /// Number of slots.
    pub(crate) fn slots(&self) -> u32 {
        u32::try_from(self.slots.len()).unwrap_or(u32::MAX)
    }

    /// Opens the metadata.
    pub(crate) fn meta(&self, ring: &KeyRing, partition: u32) -> Result<Meta, OpenError> {
        let key = ring.meta(self.window).ok_or(OpenError::NoWindow)?;
        let plain = open_meta(key, &aad(&self.header, partition, None), &self.meta)
            .map_err(|_| OpenError::Auth)?;
        let mut r = Rd { b: &plain, pos: 0 };
        let meta = match self.kind {
            KIND_STORE => {
                let flags = r.u8()?;
                if flags & !(FLAG_TAG | FLAG_MLS | FLAG_SHARED) != 0 {
                    return Err(OpenError::Malformed);
                }
                let tag = if flags & FLAG_TAG == 0 {
                    None
                } else {
                    Some((r.arr::<32>()?, r.arr::<16>()?))
                };
                let at_ms = r.u64()?;
                let mls = if flags & FLAG_MLS == 0 {
                    None
                } else {
                    Some((r.arr::<16>()?, r.u64()?))
                };
                let n_local = r.u32()?;
                let n_remote = r.u32()?;
                let mut remotes = Vec::new();
                for _ in 0..n_remote {
                    remotes.push(r.u32()?);
                }
                let shared = flags & FLAG_SHARED != 0;
                let m = StoreMeta {
                    tag,
                    at_ms,
                    mls,
                    shared,
                    n_local,
                    remotes,
                };
                if u64::from(m.n_local) + u64::from(shared) + u64::from(n_remote)
                    != u64::from(self.slots())
                {
                    return Err(OpenError::Malformed);
                }
                Meta::Store(m)
            }
            KIND_RELOCATE => {
                let n = r.u32()?;
                if n != self.slots() {
                    return Err(OpenError::Malformed);
                }
                Meta::Relocate { n }
            }
            _ => {
                let rec = Record::decode(&Bytes::copy_from_slice(&plain))
                    .map_err(|_| OpenError::Malformed)?;
                r.pos = plain.len();
                Meta::Plain(rec)
            }
        };
        if r.pos != plain.len() {
            return Err(OpenError::Malformed);
        }
        Ok(meta)
    }

    /// Opens slot `i`: `None` when its leaf is punctured (acknowledged, expired or moved).
    pub(crate) fn slot(
        &self,
        ring: &KeyRing,
        partition: u32,
        i: u32,
    ) -> Result<Option<Vec<u8>>, OpenError> {
        let ct = self
            .slots
            .get(usize::try_from(i).map_err(|_| OpenError::Malformed)?)
            .ok_or(OpenError::Malformed)?;
        let Some(leaf) = ring
            .leaf(self.window, self.first_leaf + i)
            .map_err(|_| OpenError::Auth)?
        else {
            return Ok(None);
        };
        open_leaf(&leaf, &aad(&self.header, partition, Some(i)), ct)
            .map(Some)
            .map_err(|_| OpenError::Auth)
    }
}

/// Decodes a local entry slot of a store record.
pub(crate) fn decode_entry(plain: &[u8], shared: bool) -> Result<EntrySlot, OpenError> {
    let mut r = Rd { b: plain, pos: 0 };
    let device = DeviceId::from_bytes(r.arr()?);
    let seq = r.u64()?;
    let envelope = if shared {
        if r.pos != plain.len() {
            return Err(OpenError::Malformed);
        }
        None
    } else {
        Some(Bytes::copy_from_slice(
            plain.get(r.pos..).unwrap_or_default(),
        ))
    };
    Ok(EntrySlot {
        device,
        seq,
        at_ms: None,
        envelope,
    })
}

/// Decodes a relocated entry slot.
pub(crate) fn decode_relocated(plain: &[u8]) -> Result<EntrySlot, OpenError> {
    let mut r = Rd { b: plain, pos: 0 };
    let device = DeviceId::from_bytes(r.arr()?);
    let seq = r.u64()?;
    let at = r.u64()?;
    Ok(EntrySlot {
        device,
        seq,
        at_ms: Some(at),
        envelope: Some(Bytes::copy_from_slice(
            plain.get(r.pos..).unwrap_or_default(),
        )),
    })
}

/// Decodes a remote part slot.
pub(crate) fn decode_remote(plain: &[u8], partition: u32) -> Result<Remote, OpenError> {
    let mut r = Rd { b: plain, pos: 0 };
    let shared = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(OpenError::Malformed),
    };
    let k = r.u32()?;
    if usize::try_from(k)
        .map_err(|_| OpenError::Malformed)?
        .saturating_mul(16)
        > plain.len()
    {
        return Err(OpenError::Malformed);
    }
    let mut items = Vec::new();
    for _ in 0..k {
        let d = DeviceId::from_bytes(r.arr()?);
        let env = if shared { Bytes::new() } else { r.bytes()? };
        items.push((d, env));
    }
    let body = if shared { Some(r.bytes()?) } else { None };
    if r.pos != plain.len() {
        return Err(OpenError::Malformed);
    }
    Ok(Remote {
        partition,
        items,
        shared: body,
    })
}

struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Rd<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], OpenError> {
        let end = self.pos.checked_add(n).ok_or(OpenError::Malformed)?;
        let s = self.b.get(self.pos..end).ok_or(OpenError::Malformed)?;
        self.pos = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], OpenError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, OpenError> {
        Ok(self.arr::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, OpenError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, OpenError> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    fn bytes(&mut self) -> Result<Bytes, OpenError> {
        let n = usize::try_from(self.u32()?).map_err(|_| OpenError::Malformed)?;
        Ok(Bytes::copy_from_slice(self.take(n)?))
    }
}

#[cfg(test)]
#[allow(clippy::many_single_char_names, reason = "tests")]
mod tests {
    use super::*;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn store() -> Record {
        Record::Store {
            tag: Some(([7; 32], [8; 16])),
            at_ms: 42,
            mls: Some(([9; 16], 3)),
            local: Local::PerDevice(vec![
                (d(1), 5, Bytes::from_static(b"one")),
                (d(2), 6, Bytes::from_static(b"two")),
            ]),
            remote: vec![Remote {
                partition: 3,
                items: vec![(d(4), Bytes::from_static(b"far"))],
                shared: None,
            }],
        }
    }

    #[test]
    fn sealed_store_opens_until_punctured() {
        let mut ring = KeyRing::default();
        let w = ring.open_window(0).unwrap();
        let (payload, first) = seal(&store(), &mut ring, w, 2).unwrap();
        let s = Sealed::parse(&payload).unwrap();
        assert_eq!((s.window, s.first_leaf, s.slots()), (w, first, 3));
        let Meta::Store(m) = s.meta(&ring, 2).unwrap() else {
            panic!()
        };
        assert_eq!(m.tag, Some(([7; 32], [8; 16])));
        assert_eq!(m.remotes, vec![3]);
        let e = decode_entry(&s.slot(&ring, 2, 1).unwrap().unwrap(), false).unwrap();
        assert_eq!(
            (e.device, e.seq, e.envelope.as_deref()),
            (d(2), 6, Some(&b"two"[..]))
        );
        let r = decode_remote(&s.slot(&ring, 2, m.remote_slot(0)).unwrap().unwrap(), 3).unwrap();
        assert_eq!(r.items, vec![(d(4), Bytes::from_static(b"far"))]);
        // Acknowledging entry 1 makes it unreadable, with the current key state.
        ring.puncture(w, first + 1).unwrap();
        assert_eq!(s.slot(&ring, 2, 1).unwrap(), None);
        assert!(s.slot(&ring, 2, 0).unwrap().is_some());
        // Destroying the window makes even the metadata unreadable.
        ring.destroy(w);
        assert_eq!(s.meta(&ring, 2).unwrap_err(), OpenError::NoWindow);
    }

    #[test]
    fn parts_are_bound_to_their_record_and_partition() {
        let mut ring = KeyRing::default();
        let w = ring.open_window(0).unwrap();
        let (payload, _) = seal(&store(), &mut ring, w, 2).unwrap();
        let s = Sealed::parse(&payload).unwrap();
        assert_eq!(s.meta(&ring, 5).unwrap_err(), OpenError::Auth);
        assert_eq!(s.slot(&ring, 5, 0).unwrap_err(), OpenError::Auth);
        // Swapping two slots' ciphertexts fails authentication.
        let mut swapped = s.clone();
        swapped.slots.swap(0, 1);
        assert_eq!(swapped.slot(&ring, 2, 0).unwrap_err(), OpenError::Auth);
    }

    #[test]
    fn plain_kinds_and_relocate_round_trip() {
        let mut ring = KeyRing::default();
        let w = ring.open_window(0).unwrap();
        let ack = Record::Ack(vec![(d(1), 9)]);
        let (p, _) = seal(&ack, &mut ring, w, 0).unwrap();
        let Meta::Plain(back) = Sealed::parse(&p).unwrap().meta(&ring, 0).unwrap() else {
            panic!()
        };
        assert_eq!(back, ack);
        let rel = Record::Relocate(vec![(d(3), 4, 77, Bytes::from_static(b"x"))]);
        let (p, _) = seal(&rel, &mut ring, w, 0).unwrap();
        let s = Sealed::parse(&p).unwrap();
        let e = decode_relocated(&s.slot(&ring, 0, 0).unwrap().unwrap()).unwrap();
        assert_eq!((e.device, e.seq, e.at_ms), (d(3), 4, Some(77)));
    }

    #[test]
    fn parse_is_bounded() {
        let mut ring = KeyRing::default();
        let w = ring.open_window(0).unwrap();
        let (p, _) = seal(&store(), &mut ring, w, 0).unwrap();
        for cut in 0..p.len() {
            assert!(Sealed::parse(&p.slice(..cut)).is_err());
        }
        let mut huge = BytesMut::from(&p[..HEADER]);
        huge[14..18].copy_from_slice(&u32::MAX.to_be_bytes());
        huge.put_u32(0);
        assert_eq!(
            Sealed::parse(&huge.freeze()).unwrap_err(),
            OpenError::Malformed
        );
    }
}
