//! The mailbox's records in the Iggy log (one record per Iggy message payload).
//!
//! Every record starts with a version byte and a kind byte. All integers are big-endian. The
//! decoder is bounded: every count and length is checked against the bytes that remain before
//! anything is allocated, and trailing bytes are refused (fuzz target `iggy_record`).
//!
//! | Kind | Content |
//! | --- | --- |
//! | 1 `Store` | `tag?`, `at_ms`, `mls?`, local entries (`device`, `seq`, envelope or one shared body), remote parts not yet stored on their own partitions |
//! | 2 `Ack` | (`device`, acknowledged `seq`)* |
//! | 3 `Relocate` | (`device`, `seq`, `at_ms`, envelope)*: pending entries copied forward by compaction |
//! | 4 `Owner` | the writer's producer epoch, written when a writer starts |
//! | 5 `Snapshot` | producer epoch, (`device`, last `seq`, acknowledged `seq`)*, (`group`, epoch)*: counters, so compaction may drop old records |

use bytes::{BufMut, Bytes, BytesMut};
use songbird_types::DeviceId;

/// Record format version. Bump it on every change to the encoding: start-up refuses a log with
/// records it cannot read (version 1, before the recipient-set fingerprint, was never deployed).
pub(crate) const VERSION: u8 = 2;

const KIND_STORE: u8 = 1;
const KIND_ACK: u8 = 2;
const KIND_RELOCATE: u8 = 3;
const KIND_OWNER: u8 = 4;
const KIND_SNAPSHOT: u8 = 5;

const FLAG_TAG: u8 = 0x01;
const FLAG_MLS: u8 = 0x02;
const FLAG_SHARED: u8 = 0x04;

/// Largest record accepted by the decoder.
pub(crate) const MAX_RECORD: usize = 64 << 20;

/// Why a record does not decode. Carries no record content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RecordError {
    /// Too short, a length past the end, or trailing bytes.
    #[error("record truncated or malformed")]
    Malformed,
    /// Unknown version or kind.
    #[error("unknown record version or kind")]
    Unknown,
}

/// What a store record holds for its own partition.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Local {
    /// One envelope per device.
    PerDevice(Vec<(DeviceId, u64, Bytes)>),
    /// One body for every device.
    Shared {
        /// (device, seq).
        entries: Vec<(DeviceId, u64)>,
        /// The ciphertext.
        body: Bytes,
    },
}

impl Local {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::PerDevice(e) => e.len(),
            Self::Shared { entries, .. } => entries.len(),
        }
    }

    /// (device, seq) of entry `slot`.
    pub(crate) fn entry(&self, slot: usize) -> Option<(DeviceId, u64)> {
        match self {
            Self::PerDevice(e) => e.get(slot).map(|(d, s, _)| (*d, *s)),
            Self::Shared { entries, .. } => entries.get(slot).copied(),
        }
    }

    /// The ciphertext of entry `slot`.
    #[cfg(test)]
    pub(crate) fn envelope(&self, slot: usize) -> Option<Bytes> {
        match self {
            Self::PerDevice(e) => e.get(slot).map(|(_, _, b)| b.clone()),
            Self::Shared { entries, body } => (slot < entries.len()).then(|| body.clone()),
        }
    }
}

/// A part of a send for another partition, recorded in the home partition until it is stored
/// there (the re-driver completes it after a failure or a restart).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Remote {
    /// The partition.
    pub(crate) partition: u32,
    /// Devices with their envelopes (per device) ...
    pub(crate) items: Vec<(DeviceId, Bytes)>,
    /// ... or one shared body (`items` envelopes are then empty).
    pub(crate) shared: Option<Bytes>,
}

/// One record.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Record {
    /// A send's entries for this partition.
    Store {
        /// Keyed hash of the idempotency key, and a fingerprint of the send's whole recipient
        /// set (a reused key is a replay only when both match).
        tag: Option<([u8; 32], [u8; 16])>,
        /// When the send was accepted (ms since the Unix epoch).
        at_ms: u64,
        /// MLS commit: group and the epoch it moves the group to.
        mls: Option<([u8; 16], u64)>,
        /// Entries for this partition.
        local: Local,
        /// Parts for other partitions (home record of a multi-partition send).
        remote: Vec<Remote>,
    },
    /// Acknowledged `seq`s.
    Ack(Vec<(DeviceId, u64)>),
    /// Pending entries copied forward: (device, seq, `at_ms`, envelope).
    Relocate(Vec<(DeviceId, u64, u64, Bytes)>),
    /// A writer started with this producer epoch.
    Owner {
        /// The epoch.
        epoch: u16,
    },
    /// Counters: the writer's producer epoch, (device, last, acked) and (group, epoch).
    Snapshot {
        /// Producer epoch of the writer that wrote it.
        owner: u16,
        /// Devices.
        devices: Vec<(DeviceId, u64, u64)>,
        /// MLS groups.
        groups: Vec<([u8; 16], u64)>,
    },
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store { local, remote, .. } => f
                .debug_struct("Store")
                .field("local", &local.len())
                .field("remote", &remote.len())
                .finish_non_exhaustive(),
            Self::Ack(a) => f.debug_tuple("Ack").field(&a.len()).finish(),
            Self::Relocate(r) => f.debug_tuple("Relocate").field(&r.len()).finish(),
            Self::Owner { epoch } => f.debug_struct("Owner").field("epoch", epoch).finish(),
            Self::Snapshot {
                devices, groups, ..
            } => f
                .debug_struct("Snapshot")
                .field("devices", &devices.len())
                .field("groups", &groups.len())
                .finish(),
        }
    }
}

fn put_len(buf: &mut BytesMut, n: usize) {
    buf.put_u32(u32::try_from(n).unwrap_or(u32::MAX));
}

fn put_bytes(buf: &mut BytesMut, b: &[u8]) {
    put_len(buf, b.len());
    buf.put_slice(b);
}

impl Record {
    /// Encodes the record.
    #[allow(
        clippy::too_many_lines,
        reason = "one flat match over every record kind"
    )]
    pub(crate) fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.size_hint());
        buf.put_u8(VERSION);
        match self {
            Self::Store {
                tag,
                at_ms,
                mls,
                local,
                remote,
            } => {
                buf.put_u8(KIND_STORE);
                let mut flags = 0;
                if tag.is_some() {
                    flags |= FLAG_TAG;
                }
                if mls.is_some() {
                    flags |= FLAG_MLS;
                }
                if matches!(local, Local::Shared { .. }) {
                    flags |= FLAG_SHARED;
                }
                buf.put_u8(flags);
                if let Some((t, fp)) = tag {
                    buf.put_slice(t);
                    buf.put_slice(fp);
                }
                buf.put_u64(*at_ms);
                if let Some((g, e)) = mls {
                    buf.put_slice(g);
                    buf.put_u64(*e);
                }
                match local {
                    Local::PerDevice(items) => {
                        put_len(&mut buf, items.len());
                        for (d, s, env) in items {
                            buf.put_slice(d.as_bytes());
                            buf.put_u64(*s);
                            put_bytes(&mut buf, env);
                        }
                    }
                    Local::Shared { entries, body } => {
                        put_len(&mut buf, entries.len());
                        for (d, s) in entries {
                            buf.put_slice(d.as_bytes());
                            buf.put_u64(*s);
                        }
                        put_bytes(&mut buf, body);
                    }
                }
                put_len(&mut buf, remote.len());
                for r in remote {
                    buf.put_u32(r.partition);
                    buf.put_u8(u8::from(r.shared.is_some()));
                    put_len(&mut buf, r.items.len());
                    for (d, env) in &r.items {
                        buf.put_slice(d.as_bytes());
                        if r.shared.is_none() {
                            put_bytes(&mut buf, env);
                        }
                    }
                    if let Some(b) = &r.shared {
                        put_bytes(&mut buf, b);
                    }
                }
            }
            Self::Ack(items) => {
                buf.put_u8(KIND_ACK);
                put_len(&mut buf, items.len());
                for (d, s) in items {
                    buf.put_slice(d.as_bytes());
                    buf.put_u64(*s);
                }
            }
            Self::Relocate(items) => {
                buf.put_u8(KIND_RELOCATE);
                put_len(&mut buf, items.len());
                for (d, s, at, env) in items {
                    buf.put_slice(d.as_bytes());
                    buf.put_u64(*s);
                    buf.put_u64(*at);
                    put_bytes(&mut buf, env);
                }
            }
            Self::Owner { epoch } => {
                buf.put_u8(KIND_OWNER);
                buf.put_u16(*epoch);
            }
            Self::Snapshot {
                owner,
                devices,
                groups,
            } => {
                buf.put_u8(KIND_SNAPSHOT);
                buf.put_u16(*owner);
                put_len(&mut buf, devices.len());
                for (d, last, acked) in devices {
                    buf.put_slice(d.as_bytes());
                    buf.put_u64(*last);
                    buf.put_u64(*acked);
                }
                put_len(&mut buf, groups.len());
                for (g, e) in groups {
                    buf.put_slice(g);
                    buf.put_u64(*e);
                }
            }
        }
        buf.freeze()
    }

    fn size_hint(&self) -> usize {
        match self {
            Self::Store { local, remote, .. } => {
                let l = match local {
                    Local::PerDevice(items) => items.iter().map(|(_, _, e)| 28 + e.len()).sum(),
                    Local::Shared { entries, body } => entries.len() * 24 + body.len() + 4,
                };
                let r: usize = remote
                    .iter()
                    .map(|r| {
                        9 + r.items.iter().map(|(_, e)| 20 + e.len()).sum::<usize>()
                            + r.shared.as_ref().map_or(0, |b| b.len() + 4)
                    })
                    .sum();
                80 + l + r
            }
            Self::Ack(a) => 8 + a.len() * 24,
            Self::Relocate(r) => 8 + r.iter().map(|(_, _, _, e)| 36 + e.len()).sum::<usize>(),
            Self::Owner { .. } => 4,
            Self::Snapshot {
                devices, groups, ..
            } => 14 + devices.len() * 32 + groups.len() * 24,
        }
    }

    /// Decodes a record (bounded; refuses trailing bytes).
    #[allow(
        clippy::too_many_lines,
        clippy::many_single_char_names,
        reason = "one flat match over every record kind"
    )]
    pub(crate) fn decode(input: &Bytes) -> Result<Self, RecordError> {
        if input.len() > MAX_RECORD {
            return Err(RecordError::Malformed);
        }
        let mut r = Reader { buf: input, pos: 0 };
        if r.u8()? != VERSION {
            return Err(RecordError::Unknown);
        }
        let rec = match r.u8()? {
            KIND_STORE => {
                let flags = r.u8()?;
                if flags & !(FLAG_TAG | FLAG_MLS | FLAG_SHARED) != 0 {
                    return Err(RecordError::Malformed);
                }
                let tag = if flags & FLAG_TAG == 0 {
                    None
                } else {
                    Some((r.array::<32>()?, r.array::<16>()?))
                };
                let at_ms = r.u64()?;
                let mls = if flags & FLAG_MLS == 0 {
                    None
                } else {
                    Some((r.array::<16>()?, r.u64()?))
                };
                let n = r.count(24)?;
                let local = if flags & FLAG_SHARED == 0 {
                    let mut items = Vec::with_capacity(n);
                    for _ in 0..n {
                        items.push((r.device()?, r.u64()?, r.bytes()?));
                    }
                    Local::PerDevice(items)
                } else {
                    let mut entries = Vec::with_capacity(n);
                    for _ in 0..n {
                        entries.push((r.device()?, r.u64()?));
                    }
                    Local::Shared {
                        entries,
                        body: r.bytes()?,
                    }
                };
                let m = r.count(9)?;
                let mut remote = Vec::with_capacity(m);
                for _ in 0..m {
                    let partition = r.u32()?;
                    let shared = match r.u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err(RecordError::Malformed),
                    };
                    let k = r.count(16)?;
                    let mut items = Vec::with_capacity(k);
                    for _ in 0..k {
                        let d = r.device()?;
                        let env = if shared { Bytes::new() } else { r.bytes()? };
                        items.push((d, env));
                    }
                    let shared = if shared { Some(r.bytes()?) } else { None };
                    remote.push(Remote {
                        partition,
                        items,
                        shared,
                    });
                }
                Self::Store {
                    tag,
                    at_ms,
                    mls,
                    local,
                    remote,
                }
            }
            KIND_ACK => {
                let n = r.count(24)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push((r.device()?, r.u64()?));
                }
                Self::Ack(items)
            }
            KIND_RELOCATE => {
                let n = r.count(36)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push((r.device()?, r.u64()?, r.u64()?, r.bytes()?));
                }
                Self::Relocate(items)
            }
            KIND_OWNER => Self::Owner { epoch: r.u16()? },
            KIND_SNAPSHOT => {
                let owner = r.u16()?;
                let n = r.count(32)?;
                let mut devices = Vec::with_capacity(n);
                for _ in 0..n {
                    devices.push((r.device()?, r.u64()?, r.u64()?));
                }
                let m = r.count(24)?;
                let mut groups = Vec::with_capacity(m);
                for _ in 0..m {
                    groups.push((r.array::<16>()?, r.u64()?));
                }
                Self::Snapshot {
                    owner,
                    devices,
                    groups,
                }
            }
            _ => return Err(RecordError::Unknown),
        };
        if r.pos != input.len() {
            return Err(RecordError::Malformed);
        }
        Ok(rec)
    }
}

struct Reader<'a> {
    buf: &'a Bytes,
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], RecordError> {
        let end = self.pos.checked_add(n).ok_or(RecordError::Malformed)?;
        let s = self.buf.get(self.pos..end).ok_or(RecordError::Malformed)?;
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, RecordError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, RecordError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, RecordError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RecordError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn device(&mut self) -> Result<DeviceId, RecordError> {
        Ok(DeviceId::from_bytes(self.array()?))
    }

    /// A count of items each at least `min_item` bytes long: refused if they cannot fit.
    fn count(&mut self, min_item: usize) -> Result<usize, RecordError> {
        let n = usize::try_from(self.u32()?).map_err(|_| RecordError::Malformed)?;
        let remaining = self.buf.len().saturating_sub(self.pos);
        if n.saturating_mul(min_item) > remaining {
            return Err(RecordError::Malformed);
        }
        Ok(n)
    }

    fn bytes(&mut self) -> Result<Bytes, RecordError> {
        let n = usize::try_from(self.u32()?).map_err(|_| RecordError::Malformed)?;
        let start = self.pos;
        self.take(n)?;
        Ok(self.buf.slice(start..start + n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn samples() -> Vec<Record> {
        vec![
            Record::Store {
                tag: Some(([7; 32], [8; 16])),
                at_ms: 1_700_000_000_000,
                mls: Some(([9; 16], 4)),
                local: Local::PerDevice(vec![
                    (d(1), 3, Bytes::from_static(b"abc")),
                    (d(2), 1, Bytes::from_static(b"z")),
                ]),
                remote: vec![
                    Remote {
                        partition: 2,
                        items: vec![(d(3), Bytes::from_static(b"q"))],
                        shared: None,
                    },
                    Remote {
                        partition: 3,
                        items: vec![(d(4), Bytes::new()), (d(5), Bytes::new())],
                        shared: Some(Bytes::from_static(b"body")),
                    },
                ],
            },
            Record::Store {
                tag: None,
                at_ms: 5,
                mls: None,
                local: Local::Shared {
                    entries: vec![(d(1), 1), (d(2), 9)],
                    body: Bytes::from_static(b"grp"),
                },
                remote: vec![],
            },
            Record::Ack(vec![(d(1), 3), (d(2), 1)]),
            Record::Relocate(vec![(d(1), 4, 77, Bytes::from_static(b"x"))]),
            Record::Owner { epoch: 12 },
            Record::Snapshot {
                owner: 3,
                devices: vec![(d(1), 9, 4)],
                groups: vec![([2; 16], 5)],
            },
        ]
    }

    #[test]
    fn round_trips() {
        for rec in samples() {
            let enc = rec.encode();
            assert_eq!(Record::decode(&enc).unwrap(), rec, "{rec:?}");
        }
    }

    #[test]
    fn refuses_truncation_trailing_bytes_and_unknown_kinds() {
        for rec in samples() {
            let enc = rec.encode();
            for cut in 0..enc.len() {
                assert!(Record::decode(&enc.slice(..cut)).is_err());
            }
            let mut long = BytesMut::from(&enc[..]);
            long.put_u8(0);
            assert_eq!(Record::decode(&long.freeze()), Err(RecordError::Malformed));
        }
        assert_eq!(
            Record::decode(&Bytes::from_static(&[3, 1])),
            Err(RecordError::Unknown)
        );
        assert_eq!(
            Record::decode(&Bytes::from_static(&[2, 99])),
            Err(RecordError::Unknown)
        );
        // A huge count with no bytes behind it is refused before allocating.
        assert_eq!(
            Record::decode(&Bytes::from_static(&[2, 2, 0xff, 0xff, 0xff, 0xff])),
            Err(RecordError::Malformed)
        );
    }

    #[test]
    fn local_accessors() {
        let shared = Local::Shared {
            entries: vec![(d(1), 2), (d(3), 4)],
            body: Bytes::from_static(b"b"),
        };
        assert_eq!(shared.entry(1), Some((d(3), 4)));
        assert_eq!(shared.envelope(1).as_deref(), Some(&b"b"[..]));
        assert_eq!(shared.envelope(2), None);
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = Record::decode(&Bytes::from(bytes));
        }

        #[test]
        fn per_device_round_trip(
            items in proptest::collection::vec((any::<[u8; 16]>(), any::<u64>(), proptest::collection::vec(any::<u8>(), 0..40)), 0..20),
            tag in proptest::option::of((any::<[u8; 32]>(), any::<[u8; 16]>())),
            at in any::<u64>(),
        ) {
            let rec = Record::Store {
                tag,
                at_ms: at,
                mls: None,
                local: Local::PerDevice(items.into_iter().map(|(d, s, e)| (DeviceId::from_bytes(d), s, Bytes::from(e))).collect()),
                remote: vec![],
            };
            prop_assert_eq!(Record::decode(&rec.encode()).unwrap(), rec);
        }
    }
}
