//! Several single-node mailboxes behind one, split by device (the way a single-threaded store
//! such as Valkey uses more than one core). A send to devices of several shards becomes one store
//! per shard; each part is atomic, the whole send is completed by an idempotent retry.

use std::time::Duration;

use songbird_mailbox::{
    Mailbox, MailboxError, NewEnvelope, Payload, StoreOutcome, StoreRequest, Stored,
};
use songbird_types::DeviceId;

pub struct Sharded<M> {
    pub shards: Vec<M>,
}

pub fn shard_of(d: &DeviceId, n: usize) -> usize {
    let b = d.as_bytes();
    (u64::from_le_bytes(b[..8].try_into().unwrap()) % n as u64) as usize
}

impl<M: Mailbox> Mailbox for Sharded<M> {
    async fn store(&self, req: StoreRequest) -> Result<StoreOutcome, MailboxError> {
        let n = self.shards.len();
        let mut idx: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, d) in req.payload.devices().enumerate() {
            idx[shard_of(d, n)].push(i);
        }
        let mut seqs = vec![0u64; req.payload.len()];
        let mut replayed = true;
        let mut futs = Vec::new();
        for (s, ids) in idx.iter().enumerate() {
            if ids.is_empty() {
                continue;
            }
            let payload = match &req.payload {
                Payload::PerDevice(items) => Payload::PerDevice(
                    ids.iter()
                        .map(|i| NewEnvelope {
                            device: items[*i].device,
                            envelope: items[*i].envelope.clone(),
                        })
                        .collect(),
                ),
                Payload::Shared { devices, body } => Payload::Shared {
                    devices: ids.iter().map(|i| devices[*i]).collect(),
                    body: body.clone(),
                },
            };
            let part = StoreRequest { idempotency_key: req.idempotency_key, mls: req.mls, payload };
            futs.push((s, self.shards[s].store(part)));
        }
        for (s, f) in futs {
            let out = f.await?;
            replayed &= out.replayed;
            for (i, q) in idx[s].iter().zip(out.seqs) {
                seqs[*i] = q;
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
        self.shards[shard_of(device, self.shards.len())].fetch_after(device, after_seq, limit).await
    }

    async fn ack_up_to(&self, device: &DeviceId, up_to_seq: u64) -> Result<(), MailboxError> {
        self.shards[shard_of(device, self.shards.len())].ack_up_to(device, up_to_seq).await
    }

    async fn expire_older_than(&self, _age: Duration) -> Result<u64, MailboxError> {
        Ok(0)
    }

    async fn store_generation(&self) -> Result<u64, MailboxError> {
        Ok(1)
    }

    async fn count_pending(&self, device: &DeviceId) -> Result<u64, MailboxError> {
        self.shards[shard_of(device, self.shards.len())].count_pending(device).await
    }
}
