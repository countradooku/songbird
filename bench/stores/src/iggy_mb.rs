//! Mailbox on Apache Iggy: the durable truth is an append-only log, one partition per writer
//! (one per Iggy shard). Each device belongs to one partition; that partition's writer, in this
//! process, owns the device's `seq` counter and its in-memory index of un-acknowledged entries.
//! A batch of sends is one `persisted` append (fsynced before Iggy replies); the writer assigns
//! `seq`s before appending and records them in the log, so replaying the partition rebuilds the
//! counters and the index. ACKs are merged and written as one checkpoint record per partition
//! every `ack_interval`.
//!
//! Not in this comparison (needed for production): replay on start, copy-forward compaction so
//! old segments can expire while un-acknowledged entries survive 30 days, MLS epochs, partition
//! ownership across nodes.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::hmac;
use bytes::{BufMut, BytesMut};
use iggy::prelude::*;
use songbird_mailbox::{
    Mailbox, MailboxError, Payload, StoreOutcome, StoreRequest, Stored,
};
use songbird_types::DeviceId;
use tokio::sync::{mpsc, oneshot};

const STREAM: &str = "songbird";
const TOPIC: &str = "mailbox";

/// Settings.
pub struct IggyConfig {
    pub url: String,
    pub partitions: u32,
    pub max_batch: usize,
    pub max_per_device: u64,
    pub ack_interval: Duration,
    pub idempotency_secret: [u8; 32],
}

struct Part {
    devices: Vec<(usize, DeviceId)>,
    payload: Arc<Payload>,
    tag: Option<[u8; 32]>,
    reply: oneshot::Sender<Result<(Vec<(usize, u64)>, bool), MailboxError>>,
}

#[derive(Default)]
struct Index {
    last: HashMap<DeviceId, u64>,
    pending: HashMap<DeviceId, VecDeque<Stored>>,
    idem: HashMap<[u8; 32], (Vec<DeviceId>, Vec<u64>)>,
}

struct Shard {
    tx: mpsc::Sender<Part>,
    acks: mpsc::UnboundedSender<(DeviceId, u64)>,
    index: Arc<Mutex<Index>>,
}

/// The Iggy mailbox.
pub struct IggyMailbox {
    shards: Vec<Shard>,
    idem: hmac::Key,
}

fn shard_of(d: &DeviceId, n: usize) -> usize {
    let b = d.as_bytes();
    (u64::from_le_bytes(b[..8].try_into().unwrap()) % n as u64) as usize
}

impl IggyMailbox {
    pub async fn connect(cfg: IggyConfig) -> Result<Self, IggyError> {
        let admin = IggyClient::from_connection_string(&cfg.url)?;
        admin.connect().await?;
        let stream = Identifier::named(STREAM)?;
        let topic = Identifier::named(TOPIC)?;
        if admin.get_stream(&stream).await?.is_none() {
            admin.create_stream(STREAM, &StreamCreateOptions::default()).await?;
        }
        if std::env::var("RESET").is_ok() && admin.get_topic(&stream, &topic).await?.is_some() {
            admin.delete_topic(&stream, &topic).await?;
        }
        if admin.get_topic(&stream, &topic).await?.is_none() {
            let opts = TopicCreateOptions {
                partitions_count: Some(cfg.partitions),
                durability: Durability::Persisted,
                consumer_offset_durability: Durability::Persisted,
                ..TopicCreateOptions::default()
            };
            admin.create_topic(&stream, TOPIC, &opts).await?;
        }
        let mut shards = Vec::new();
        for p in 0..cfg.partitions {
            let client = IggyClient::from_connection_string(&cfg.url)?;
            client.connect().await?;
            let client = Arc::new(client);
            let (tx, rx) = mpsc::channel(65536);
            let (atx, arx) = mpsc::unbounded_channel();
            let index = Arc::new(Mutex::new(Index::default()));
            tokio::spawn(writer(
                client.clone(),
                p,
                rx,
                arx,
                index.clone(),
                cfg.max_batch,
                cfg.max_per_device,
                cfg.ack_interval,
            ));
            shards.push(Shard { tx, acks: atx, index });
        }
        Ok(Self {
            shards,
            idem: hmac::Key::new(hmac::HMAC_SHA256, &cfg.idempotency_secret),
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn writer(
    client: Arc<IggyClient>,
    partition: u32,
    mut rx: mpsc::Receiver<Part>,
    mut acks: mpsc::UnboundedReceiver<(DeviceId, u64)>,
    index: Arc<Mutex<Index>>,
    max_batch: usize,
    max_per_device: u64,
    ack_interval: Duration,
) {
    let stream = Identifier::named(STREAM).unwrap();
    let topic = Identifier::named(TOPIC).unwrap();
    let partitioning = Partitioning::partition_id(partition);
    let mut pending_acks: HashMap<DeviceId, u64> = HashMap::new();
    let mut tick = tokio::time::interval(ack_interval);
    let mut batch: Vec<Part> = Vec::with_capacity(max_batch);
    loop {
        tokio::select! {
            biased;
            _ = tick.tick() => {
                while let Ok((d, s)) = acks.try_recv() {
                    let e = pending_acks.entry(d).or_default();
                    *e = (*e).max(s);
                }
                if pending_acks.is_empty() { continue; }
                // One checkpoint record: kind 3, count, (device, acked)*.
                let mut buf = BytesMut::with_capacity(5 + 24 * pending_acks.len());
                buf.put_u8(3);
                buf.put_u32(pending_acks.len() as u32);
                for (d, s) in &pending_acks { buf.put_slice(d.as_bytes()); buf.put_u64(*s); }
                let mut msgs = vec![IggyMessage::builder().payload(buf.freeze()).build().unwrap()];
                if client.send_messages(&stream, &topic, &partitioning, &mut msgs).await.is_ok() {
                    let mut ix = index.lock().unwrap();
                    for (d, s) in pending_acks.drain() {
                        if let Some(q) = ix.pending.get_mut(&d) {
                            while q.front().is_some_and(|e| e.seq <= s) { q.pop_front(); }
                            if q.is_empty() { ix.pending.remove(&d); }
                        }
                    }
                }
            }
            first = rx.recv() => {
                let Some(first) = first else { return };
                batch.push(first);
                while batch.len() < max_batch {
                    match rx.try_recv() { Ok(p) => batch.push(p), Err(_) => break }
                }
                commit(&client, &stream, &topic, &partitioning, &index, &mut batch, max_per_device).await;
            }
        }
    }
}

async fn commit(
    client: &IggyClient,
    stream: &Identifier,
    topic: &Identifier,
    partitioning: &Partitioning,
    index: &Mutex<Index>,
    batch: &mut Vec<Part>,
    max_per_device: u64,
) {
    // Assign seqs from the cached counters, encode one log message per send.
    let mut msgs = Vec::with_capacity(batch.len());
    let mut results: Vec<Option<Result<(Vec<(usize, u64)>, bool), MailboxError>>> =
        Vec::with_capacity(batch.len());
    let mut new_entries: Vec<(DeviceId, Stored)> = Vec::new();
    let mut new_idem: Vec<([u8; 32], Vec<DeviceId>, Vec<u64>)> = Vec::new();
    {
        let mut ix = index.lock().unwrap();
        let mut provisional: HashMap<DeviceId, u64> = HashMap::new();
        'parts: for part in batch.iter() {
            let devs: Vec<DeviceId> = part.devices.iter().map(|(_, d)| *d).collect();
            if let Some(tag) = &part.tag {
                if let Some((d0, s0)) = ix.idem.get(tag) {
                    if *d0 == devs {
                        let seqs = part.devices.iter().zip(s0).map(|((i, _), s)| (*i, *s)).collect();
                        results.push(Some(Ok((seqs, true))));
                    } else {
                        results.push(Some(Err(MailboxError::IdempotencyConflict)));
                    }
                    continue 'parts;
                }
            }
            for d in &devs {
                if ix.pending.get(d).map_or(0, |q| q.len() as u64) >= max_per_device {
                    results.push(Some(Err(MailboxError::Full)));
                    continue 'parts;
                }
            }
            let mut buf = BytesMut::new();
            let shared = matches!(*part.payload, Payload::Shared { .. });
            buf.put_u8(if shared { 2 } else { 1 });
            buf.put_slice(part.tag.as_ref().map_or(&[0u8; 32][..], |t| &t[..]));
            buf.put_u16(part.devices.len() as u16);
            let mut seqs = Vec::with_capacity(part.devices.len());
            for (i, d) in &part.devices {
                let last = provisional
                    .get(d)
                    .copied()
                    .or_else(|| ix.last.get(d).copied())
                    .unwrap_or(0);
                let s = last + 1;
                provisional.insert(*d, s);
                buf.put_slice(d.as_bytes());
                buf.put_u64(s);
                let env = part.payload.envelope(*i).cloned().unwrap_or_default();
                if !shared {
                    buf.put_u32(env.len() as u32);
                    buf.put_slice(&env);
                }
                new_entries.push((*d, Stored { seq: s, envelope: env }));
                seqs.push((*i, s));
            }
            if let Payload::Shared { body, .. } = &*part.payload {
                buf.put_u32(body.len() as u32);
                buf.put_slice(body);
            }
            if let Some(tag) = part.tag {
                new_idem.push((tag, devs, seqs.iter().map(|(_, s)| *s).collect()));
            }
            msgs.push(IggyMessage::builder().payload(buf.freeze()).build().unwrap());
            results.push(Some(Ok((seqs, false))));
        }
    }
    let ok = msgs.is_empty()
        || client.send_messages(stream, topic, partitioning, &mut msgs).await.is_ok();
    if ok {
        let mut ix = index.lock().unwrap();
        for (d, e) in new_entries {
            let s = e.seq;
            ix.pending.entry(d).or_default().push_back(e);
            let l = ix.last.entry(d).or_default();
            *l = (*l).max(s);
        }
        for (t, d, s) in new_idem {
            ix.idem.insert(t, (d, s));
        }
    }
    for (part, r) in batch.drain(..).zip(results) {
        let r = r.unwrap();
        let r = match r {
            Ok((s, replayed)) if ok || replayed => Ok((s, replayed)),
            Ok(_) => Err(MailboxError::Unavailable),
            Err(e) => Err(e),
        };
        let _ = part.reply.send(r);
    }
}

impl Mailbox for IggyMailbox {
    async fn store(&self, req: StoreRequest) -> Result<StoreOutcome, MailboxError> {
        let n = self.shards.len();
        let tag = req.idempotency_key.map(|k| {
            let mut t = [0u8; 32];
            t.copy_from_slice(&hmac::sign(&self.idem, &k).as_ref()[..32]);
            t
        });
        let mut groups: Vec<Vec<(usize, DeviceId)>> = vec![Vec::new(); n];
        for (i, d) in req.payload.devices().enumerate() {
            groups[shard_of(d, n)].push((i, *d));
        }
        let payload = Arc::new(req.payload);
        let mut waits = Vec::new();
        for (s, devices) in groups.into_iter().enumerate() {
            if devices.is_empty() {
                continue;
            }
            let (tx, rx) = oneshot::channel();
            self.shards[s]
                .tx
                .send(Part { devices, payload: payload.clone(), tag, reply: tx })
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            waits.push(rx);
        }
        let mut seqs = vec![0u64; payload.len()];
        let mut replayed = true;
        for w in waits {
            let (part, r) = w.await.map_err(|_| MailboxError::Unavailable)??;
            replayed &= r;
            for (i, s) in part {
                seqs[i] = s;
            }
        }
        Ok(StoreOutcome { seqs, replayed })
    }

    async fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Stored>, MailboxError> {
        let s = &self.shards[shard_of(device, self.shards.len())];
        let ix = s.index.lock().unwrap();
        Ok(ix
            .pending
            .get(device)
            .map(|q| q.iter().filter(|e| e.seq > after_seq).take(limit).cloned().collect())
            .unwrap_or_default())
    }

    async fn ack_up_to(&self, device: &DeviceId, up_to_seq: u64) -> Result<(), MailboxError> {
        self.shards[shard_of(device, self.shards.len())]
            .acks
            .send((*device, up_to_seq))
            .map_err(|_| MailboxError::Unavailable)
    }

    async fn expire_older_than(&self, _age: Duration) -> Result<u64, MailboxError> {
        Ok(0)
    }

    async fn store_generation(&self) -> Result<u64, MailboxError> {
        Ok(1)
    }

    async fn count_pending(&self, device: &DeviceId) -> Result<u64, MailboxError> {
        let s = &self.shards[shard_of(device, self.shards.len())];
        Ok(s.index.lock().unwrap().pending.get(device).map_or(0, |q| q.len() as u64))
    }
}
