//! Partition operations between nodes (D-0034): what a node asks the owner of a partition, and
//! the answers. Carried by node links (mutual TLS); decoded with every count checked against the
//! bytes left before anything is allocated (fuzz target `iggy_record` covers it).

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use songbird_types::DeviceId;

use super::LocalReq;
use super::record::Remote;
use crate::{MailboxError, MlsCommit, Stored};

/// A store for one partition (a send's home part, or one of its remote parts).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct JobData {
    pub(crate) tag: Option<([u8; 32], [u8; 16])>,
    pub(crate) mls: Option<MlsCommit>,
    pub(crate) local: LocalReq,
    pub(crate) remote: Vec<Remote>,
}

/// One request to a partition's owner.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Request {
    Store {
        p: u32,
        job: JobData,
    },
    Ack {
        p: u32,
        device: DeviceId,
        seq: u64,
    },
    Fetch {
        p: u32,
        device: DeviceId,
        after: u64,
        limit: u32,
    },
    Count {
        p: u32,
        device: DeviceId,
    },
    Expire {
        p: u32,
        age_ms: u64,
    },
    PartDone {
        p: u32,
        tag: [u8; 32],
        part: u32,
    },
    /// A key-store write of partition `p`, for its standby (D-0034).
    KeyStore {
        p: u32,
        files: Vec<(String, Bytes)>,
        remove: Vec<String>,
        /// The whole store: the standby deletes every key file it holds that is not listed.
        full: bool,
    },
}

/// Longest file name in a key-store write.
const MAX_NAME: usize = 96;

/// The owner's answer.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Response {
    Store(Result<(Vec<(DeviceId, u64)>, bool), MailboxError>),
    Fetch(Result<Vec<Stored>, MailboxError>),
    Count(Result<u64, MailboxError>),
    Done(Result<(), MailboxError>),
    /// This node does not own the partition (any more): ask the current owner.
    NotOwner,
}

// Debug shows the kind only: devices and envelopes never reach logs (invariant 6).
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Store { .. } => "Store",
            Self::Ack { .. } => "Ack",
            Self::Fetch { .. } => "Fetch",
            Self::Count { .. } => "Count",
            Self::Expire { .. } => "Expire",
            Self::PartDone { .. } => "PartDone",
            Self::KeyStore { .. } => "KeyStore",
        };
        f.debug_struct("Request")
            .field("kind", &kind)
            .field("partition", &self.partition())
            .finish()
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Store(r) => {
                if r.is_ok() {
                    "Store"
                } else {
                    "StoreError"
                }
            }
            Self::Fetch(r) => {
                if r.is_ok() {
                    "Fetch"
                } else {
                    "FetchError"
                }
            }
            Self::Count(r) => {
                if r.is_ok() {
                    "Count"
                } else {
                    "CountError"
                }
            }
            Self::Done(r) => {
                if r.is_ok() {
                    "Done"
                } else {
                    "DoneError"
                }
            }
            Self::NotOwner => "NotOwner",
        };
        f.debug_struct("Response").field("kind", &kind).finish()
    }
}

const VERSION: u8 = 1;

fn put_err(b: &mut BytesMut, e: &MailboxError) {
    b.put_u8(match e {
        MailboxError::Full => 1,
        MailboxError::IdempotencyConflict => 2,
        MailboxError::StaleEpoch => 3,
        MailboxError::Unavailable => 4,
    });
}

fn put_bytes(b: &mut BytesMut, v: &[u8]) {
    b.put_u32(u32::try_from(v.len()).unwrap_or(u32::MAX));
    b.put_slice(v);
}

fn put_local(b: &mut BytesMut, l: &LocalReq) {
    match l {
        LocalReq::PerDevice(items) => {
            b.put_u8(0);
            b.put_u32(u32::try_from(items.len()).unwrap_or(u32::MAX));
            for (d, e) in items {
                b.put_slice(d.as_bytes());
                put_bytes(b, e);
            }
        }
        LocalReq::Shared { devices, body } => {
            b.put_u8(1);
            b.put_u32(u32::try_from(devices.len()).unwrap_or(u32::MAX));
            for d in devices {
                b.put_slice(d.as_bytes());
            }
            put_bytes(b, body);
        }
    }
}

impl Request {
    pub(crate) fn encode(&self) -> Bytes {
        let mut b = BytesMut::with_capacity(64);
        b.put_u8(VERSION);
        match self {
            Self::Store { p, job } => {
                b.put_u8(1);
                b.put_u32(*p);
                match &job.tag {
                    Some((t, fp)) => {
                        b.put_u8(1);
                        b.put_slice(t);
                        b.put_slice(fp);
                    }
                    None => b.put_u8(0),
                }
                match &job.mls {
                    Some(m) => {
                        b.put_u8(1);
                        b.put_slice(&m.group);
                        b.put_u64(m.epoch);
                    }
                    None => b.put_u8(0),
                }
                put_local(&mut b, &job.local);
                b.put_u32(u32::try_from(job.remote.len()).unwrap_or(u32::MAX));
                for r in &job.remote {
                    b.put_u32(r.partition);
                    b.put_u32(u32::try_from(r.items.len()).unwrap_or(u32::MAX));
                    for (d, e) in &r.items {
                        b.put_slice(d.as_bytes());
                        put_bytes(&mut b, e);
                    }
                    match &r.shared {
                        Some(body) => {
                            b.put_u8(1);
                            put_bytes(&mut b, body);
                        }
                        None => b.put_u8(0),
                    }
                }
            }
            Self::Ack { p, device, seq } => {
                b.put_u8(2);
                b.put_u32(*p);
                b.put_slice(device.as_bytes());
                b.put_u64(*seq);
            }
            Self::Fetch {
                p,
                device,
                after,
                limit,
            } => {
                b.put_u8(3);
                b.put_u32(*p);
                b.put_slice(device.as_bytes());
                b.put_u64(*after);
                b.put_u32(*limit);
            }
            Self::Count { p, device } => {
                b.put_u8(4);
                b.put_u32(*p);
                b.put_slice(device.as_bytes());
            }
            Self::Expire { p, age_ms } => {
                b.put_u8(5);
                b.put_u32(*p);
                b.put_u64(*age_ms);
            }
            Self::PartDone { p, tag, part } => {
                b.put_u8(6);
                b.put_u32(*p);
                b.put_slice(tag);
                b.put_u32(*part);
            }
            Self::KeyStore {
                p,
                files,
                remove,
                full,
            } => {
                b.put_u8(7);
                b.put_u32(*p);
                b.put_u32(u32::try_from(files.len()).unwrap_or(u32::MAX));
                for (n, f) in files {
                    put_bytes(&mut b, n.as_bytes());
                    put_bytes(&mut b, f);
                }
                b.put_u32(u32::try_from(remove.len()).unwrap_or(u32::MAX));
                for n in remove {
                    put_bytes(&mut b, n.as_bytes());
                }
                b.put_u8(u8::from(*full));
            }
        }
        b.freeze()
    }

    fn decode_key_store(r: &mut Rd) -> Option<Self> {
        let p = r.u32()?;
        let n = r.count(8)?;
        let mut files = Vec::with_capacity(n);
        for _ in 0..n {
            files.push((r.name()?, r.bytes()?));
        }
        let n = r.count(4)?;
        let mut remove = Vec::with_capacity(n);
        for _ in 0..n {
            remove.push(r.name()?);
        }
        let full = match r.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some(Self::KeyStore {
            p,
            files,
            remove,
            full,
        })
    }

    pub(crate) fn decode(src: &Bytes) -> Option<Self> {
        let mut r = Rd(src.clone());
        if r.u8()? != VERSION {
            return None;
        }
        let out = match r.u8()? {
            1 => {
                let p = r.u32()?;
                let tag = match r.u8()? {
                    0 => None,
                    1 => Some((r.arr::<32>()?, r.arr::<16>()?)),
                    _ => return None,
                };
                let mls = match r.u8()? {
                    0 => None,
                    1 => Some(MlsCommit {
                        group: r.arr::<16>()?,
                        epoch: r.u64()?,
                    }),
                    _ => return None,
                };
                let local = r.local()?;
                let n = r.count(4 + 4 + 1)?;
                let mut remote = Vec::with_capacity(n);
                for _ in 0..n {
                    let partition = r.u32()?;
                    let k = r.count(16 + 4)?;
                    let mut items = Vec::with_capacity(k);
                    for _ in 0..k {
                        items.push((r.device()?, r.bytes()?));
                    }
                    let shared = match r.u8()? {
                        0 => None,
                        1 => Some(r.bytes()?),
                        _ => return None,
                    };
                    remote.push(Remote {
                        partition,
                        items,
                        shared,
                    });
                }
                Self::Store {
                    p,
                    job: JobData {
                        tag,
                        mls,
                        local,
                        remote,
                    },
                }
            }
            2 => Self::Ack {
                p: r.u32()?,
                device: r.device()?,
                seq: r.u64()?,
            },
            3 => Self::Fetch {
                p: r.u32()?,
                device: r.device()?,
                after: r.u64()?,
                limit: r.u32()?,
            },
            4 => Self::Count {
                p: r.u32()?,
                device: r.device()?,
            },
            5 => Self::Expire {
                p: r.u32()?,
                age_ms: r.u64()?,
            },
            6 => Self::PartDone {
                p: r.u32()?,
                tag: r.arr::<32>()?,
                part: r.u32()?,
            },
            7 => Self::decode_key_store(&mut r)?,
            _ => return None,
        };
        r.done().then_some(out)
    }

    /// The partition it is for.
    pub(crate) fn partition(&self) -> u32 {
        match self {
            Self::Store { p, .. }
            | Self::Ack { p, .. }
            | Self::Fetch { p, .. }
            | Self::Count { p, .. }
            | Self::Expire { p, .. }
            | Self::PartDone { p, .. }
            | Self::KeyStore { p, .. } => *p,
        }
    }
}

impl Response {
    pub(crate) fn encode(&self) -> Bytes {
        let mut b = BytesMut::with_capacity(32);
        b.put_u8(VERSION);
        match self {
            Self::Store(Ok((seqs, replayed))) => {
                b.put_u8(1);
                b.put_u8(u8::from(*replayed));
                b.put_u32(u32::try_from(seqs.len()).unwrap_or(u32::MAX));
                for (d, s) in seqs {
                    b.put_slice(d.as_bytes());
                    b.put_u64(*s);
                }
            }
            Self::Fetch(Ok(items)) => {
                b.put_u8(2);
                b.put_u32(u32::try_from(items.len()).unwrap_or(u32::MAX));
                for s in items {
                    b.put_u64(s.seq);
                    put_bytes(&mut b, &s.envelope);
                }
            }
            Self::Count(Ok(n)) => {
                b.put_u8(3);
                b.put_u64(*n);
            }
            Self::Done(Ok(())) => b.put_u8(4),
            Self::NotOwner => b.put_u8(5),
            Self::Store(Err(e)) => {
                b.put_u8(11);
                put_err(&mut b, e);
            }
            Self::Fetch(Err(e)) => {
                b.put_u8(12);
                put_err(&mut b, e);
            }
            Self::Count(Err(e)) => {
                b.put_u8(13);
                put_err(&mut b, e);
            }
            Self::Done(Err(e)) => {
                b.put_u8(14);
                put_err(&mut b, e);
            }
        }
        b.freeze()
    }

    pub(crate) fn decode(src: &Bytes) -> Option<Self> {
        let mut r = Rd(src.clone());
        if r.u8()? != VERSION {
            return None;
        }
        let out = match r.u8()? {
            1 => {
                let replayed = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return None,
                };
                let n = r.count(16 + 8)?;
                let mut seqs = Vec::with_capacity(n);
                for _ in 0..n {
                    seqs.push((r.device()?, r.u64()?));
                }
                Self::Store(Ok((seqs, replayed)))
            }
            2 => {
                let n = r.count(8 + 4)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(Stored {
                        seq: r.u64()?,
                        envelope: r.bytes()?,
                    });
                }
                Self::Fetch(Ok(items))
            }
            3 => Self::Count(Ok(r.u64()?)),
            4 => Self::Done(Ok(())),
            5 => Self::NotOwner,
            11 => Self::Store(Err(r.err()?)),
            12 => Self::Fetch(Err(r.err()?)),
            13 => Self::Count(Err(r.err()?)),
            14 => Self::Done(Err(r.err()?)),
            _ => return None,
        };
        r.done().then_some(out)
    }
}

/// A bounded reader: every length and count is checked against what is left.
struct Rd(Bytes);

impl Rd {
    fn u8(&mut self) -> Option<u8> {
        (self.0.remaining() >= 1).then(|| self.0.get_u8())
    }
    fn u32(&mut self) -> Option<u32> {
        (self.0.remaining() >= 4).then(|| self.0.get_u32())
    }
    fn u64(&mut self) -> Option<u64> {
        (self.0.remaining() >= 8).then(|| self.0.get_u64())
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        if self.0.remaining() < N {
            return None;
        }
        let mut a = [0u8; N];
        self.0.copy_to_slice(&mut a);
        Some(a)
    }
    fn device(&mut self) -> Option<DeviceId> {
        Some(DeviceId::from_bytes(self.arr::<16>()?))
    }
    fn bytes(&mut self) -> Option<Bytes> {
        let n = usize::try_from(self.u32()?).ok()?;
        (self.0.remaining() >= n).then(|| self.0.split_to(n))
    }
    /// A count of items of at least `min` bytes each, refused if they cannot fit.
    fn count(&mut self, min: usize) -> Option<usize> {
        let n = usize::try_from(self.u32()?).ok()?;
        (n.saturating_mul(min) <= self.0.remaining()).then_some(n)
    }
    fn name(&mut self) -> Option<String> {
        let b = self.bytes()?;
        if b.len() > MAX_NAME {
            return None;
        }
        String::from_utf8(b.to_vec()).ok()
    }
    fn err(&mut self) -> Option<MailboxError> {
        Some(match self.u8()? {
            1 => MailboxError::Full,
            2 => MailboxError::IdempotencyConflict,
            3 => MailboxError::StaleEpoch,
            4 => MailboxError::Unavailable,
            _ => return None,
        })
    }
    fn local(&mut self) -> Option<LocalReq> {
        Some(match self.u8()? {
            0 => {
                let n = self.count(16 + 4)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push((self.device()?, self.bytes()?));
                }
                LocalReq::PerDevice(items)
            }
            1 => {
                let n = self.count(16)?;
                let mut devices = Vec::with_capacity(n);
                for _ in 0..n {
                    devices.push(self.device()?);
                }
                LocalReq::Shared {
                    devices,
                    body: self.bytes()?,
                }
            }
            _ => return None,
        })
    }
    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// The wire decoders on arbitrary bytes: they never panic and stay bounded, and what they
/// accept re-encodes to the same bytes (canonical).
pub(crate) fn fuzz(data: &[u8]) {
    let src = Bytes::copy_from_slice(data);
    if let Some(r) = Request::decode(&src) {
        assert_eq!(r.encode(), src, "request encoding is canonical");
    }
    if let Some(r) = Response::decode(&src) {
        assert_eq!(r.encode(), src, "response encoding is canonical");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    #[test]
    fn requests_round_trip() {
        let all = [
            Request::Store {
                p: 3,
                job: JobData {
                    tag: Some(([1; 32], [2; 16])),
                    mls: Some(MlsCommit {
                        group: [9; 16],
                        epoch: 4,
                    }),
                    local: LocalReq::PerDevice(vec![(d(1), Bytes::from_static(b"a"))]),
                    remote: vec![
                        Remote {
                            partition: 1,
                            items: vec![(d(2), Bytes::from_static(b"b"))],
                            shared: None,
                        },
                        Remote {
                            partition: 2,
                            items: vec![(d(3), Bytes::new())],
                            shared: Some(Bytes::from_static(b"body")),
                        },
                    ],
                },
            },
            Request::Store {
                p: 0,
                job: JobData {
                    tag: None,
                    mls: None,
                    local: LocalReq::Shared {
                        devices: vec![d(4), d(5)],
                        body: Bytes::from_static(b"group"),
                    },
                    remote: vec![],
                },
            },
            Request::Ack {
                p: 1,
                device: d(1),
                seq: 7,
            },
            Request::Fetch {
                p: 2,
                device: d(2),
                after: 3,
                limit: 100,
            },
            Request::Count { p: 2, device: d(2) },
            Request::Expire { p: 1, age_ms: 99 },
            Request::PartDone {
                p: 0,
                tag: [7; 32],
                part: 3,
            },
            Request::KeyStore {
                p: 2,
                files: vec![
                    ("w1.p0.e1.g2".into(), Bytes::from_static(b"page")),
                    ("head".into(), Bytes::from_static(b"head")),
                ],
                remove: vec!["w1.p0.e1.g1".into()],
                full: false,
            },
            Request::KeyStore {
                p: 1,
                files: vec![("head".into(), Bytes::from_static(b"head"))],
                remove: Vec::new(),
                full: true,
            },
        ];
        for r in all {
            let b = r.encode();
            assert_eq!(Request::decode(&b), Some(r));
            // Truncated anywhere: refused, never a panic.
            for cut in 0..b.len() {
                assert_eq!(Request::decode(&b.slice(..cut)), None);
            }
        }
    }

    #[test]
    fn responses_round_trip() {
        let all = [
            Response::Store(Ok((vec![(d(1), 5), (d(2), 6)], true))),
            Response::Store(Err(MailboxError::IdempotencyConflict)),
            Response::Fetch(Ok(vec![Stored {
                seq: 1,
                envelope: Bytes::from_static(b"env"),
            }])),
            Response::Fetch(Err(MailboxError::Unavailable)),
            Response::Count(Ok(42)),
            Response::Count(Err(MailboxError::Full)),
            Response::Done(Ok(())),
            Response::Done(Err(MailboxError::StaleEpoch)),
            Response::NotOwner,
        ];
        for r in all {
            let b = r.encode();
            assert_eq!(Response::decode(&b), Some(r));
        }
    }

    #[test]
    fn huge_counts_are_refused_before_allocating() {
        let mut b = BytesMut::new();
        b.put_u8(VERSION);
        b.put_u8(2);
        b.put_u32(u32::MAX);
        assert_eq!(Response::decode(&b.freeze()), None);
    }
}
