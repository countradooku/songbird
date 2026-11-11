//! Mailbox on Valkey: one stream per device (`XADD` with the `seq` as the entry ID), a counter
//! per device, idempotency records with a TTL, shared bodies with a reference count, MLS epochs.
//! Every store is one atomic function call; durability comes from AOF `appendfsync always`
//! (Valkey fsyncs before replying, once per event-loop pass: group commit across clients).
//! ACKs are merged per device and applied every `ack_interval` with one function call
//! (`XTRIM MINID`).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aws_lc_rs::hmac;
use bytes::Bytes;
use redis::aio::MultiplexedConnection;
use songbird_mailbox::{
    IDEMPOTENCY_RETENTION, Mailbox, MailboxError, Payload, StoreOutcome, StoreRequest, Stored,
};
use songbird_types::DeviceId;
use tokio::sync::mpsc;

const LIBRARY: &str = r#"#!lua name=sb
-- KEYS: idem, body, mls, then n counters (q:dev), then n streams (m:dev)
-- ARGV: flags ('i' idem, 's' shared, 'g' mls), devices blob, max_per_device, idem ttl, epoch,
--       then the body (shared) or n envelopes
local function store(keys, args)
  local flags = args[1]
  local n = (#keys - 3) / 2
  local idem = string.find(flags, 'i', 1, true)
  local shared = string.find(flags, 's', 1, true)
  local mls = string.find(flags, 'g', 1, true)
  if idem then
    local prev = redis.call('GET', keys[1])
    if prev then
      local sep = string.find(prev, '|', 1, true)
      if string.sub(prev, 1, sep - 1) ~= args[2] then return {2} end
      local out = {1}
      for s in string.gmatch(string.sub(prev, sep + 1), '[^,]+') do out[#out + 1] = tonumber(s) end
      return out
    end
  end
  local max = tonumber(args[3])
  for i = 1, n do
    if redis.call('XLEN', keys[3 + n + i]) >= max then return {3} end
  end
  if mls then
    local cur = tonumber(redis.call('GET', keys[3]) or '0')
    if cur ~= tonumber(args[5]) then return {4} end
    redis.call('SET', keys[3], cur + 1)
  end
  if shared then
    redis.call('HSET', keys[2], 'd', args[6], 'r', n)
  end
  local out = {0}
  for i = 1, n do
    local s = redis.call('INCR', keys[3 + i])
    if shared then
      redis.call('XADD', keys[3 + n + i], s .. '-1', 'b', keys[2])
    else
      redis.call('XADD', keys[3 + n + i], s .. '-1', 'e', args[5 + i])
    end
    out[#out + 1] = s
  end
  if idem then
    local seqs = {}
    for i = 2, #out do seqs[#seqs + 1] = out[i] end
    redis.call('SET', keys[1], args[2] .. '|' .. table.concat(seqs, ','), 'EX', args[4])
  end
  return out
end

-- KEYS: streams; ARGV: the seq to delete up to, per stream
local function ack(keys, args)
  for i = 1, #keys do
    local up = args[i]
    local items = redis.call('XRANGE', keys[i], '-', up .. '-1')
    for _, it in ipairs(items) do
      local f = it[2]
      if f[1] == 'b' then
        if redis.call('HINCRBY', f[2], 'r', -1) <= 0 then redis.call('DEL', f[2]) end
      end
    end
    redis.call('XTRIM', keys[i], 'MINID', (tonumber(up) + 1) .. '-1')
  end
  return #keys
end

redis.register_function('sb_store', store)
redis.register_function('sb_ack', ack)
"#;

fn key(prefix: u8, id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + id.len());
    k.push(prefix);
    k.extend_from_slice(id);
    k
}

/// Settings.
pub struct ValkeyConfig {
    pub url: String,
    pub connections: usize,
    pub max_per_device: u64,
    pub ack_interval: Duration,
    pub idempotency_secret: [u8; 32],
}

/// The Valkey mailbox.
pub struct ValkeyMailbox {
    conns: Vec<MultiplexedConnection>,
    next: AtomicUsize,
    idem: hmac::Key,
    max_per_device: u64,
    acks: mpsc::UnboundedSender<(DeviceId, u64)>,
    body_counter: AtomicUsize,
    pub ack_calls: Arc<AtomicUsize>,
}

impl ValkeyMailbox {
    pub async fn connect(cfg: ValkeyConfig) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(cfg.url.as_str())?;
        let mut conns = Vec::with_capacity(cfg.connections);
        for _ in 0..cfg.connections.max(1) {
            let cc = redis::AsyncConnectionConfig::new()
                .set_response_timeout(Some(Duration::from_secs(5)));
            conns.push(client.get_multiplexed_async_connection_with_config(&cc).await?);
        }
        let mut c = conns[0].clone();
        if std::env::var("RESET").is_ok() {
            let _: () = redis::cmd("FLUSHALL").query_async(&mut c).await?;
            let _: String = redis::cmd("BGREWRITEAOF").query_async(&mut c).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let _: String = redis::cmd("FUNCTION")
            .arg("LOAD")
            .arg("REPLACE")
            .arg(LIBRARY)
            .query_async(&mut c)
            .await?;
        let (tx, rx) = mpsc::unbounded_channel();
        let ack_calls = Arc::new(AtomicUsize::new(0));
        tokio::spawn(ack_task(conns[0].clone(), rx, cfg.ack_interval, ack_calls.clone()));
        Ok(Self {
            conns,
            next: AtomicUsize::new(0),
            idem: hmac::Key::new(hmac::HMAC_SHA256, &cfg.idempotency_secret),
            max_per_device: cfg.max_per_device,
            acks: tx,
            body_counter: AtomicUsize::new(0),
            ack_calls,
        })
    }

    fn conn(&self) -> MultiplexedConnection {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.conns.len();
        self.conns[i].clone()
    }
}

async fn ack_task(
    mut conn: MultiplexedConnection,
    mut rx: mpsc::UnboundedReceiver<(DeviceId, u64)>,
    every: Duration,
    calls: Arc<AtomicUsize>,
) {
    let mut pending: HashMap<DeviceId, u64> = HashMap::new();
    let mut tick = tokio::time::interval(every);
    loop {
        tokio::select! {
            m = rx.recv() => match m {
                Some((d, s)) => { let e = pending.entry(d).or_default(); *e = (*e).max(s); }
                None => return,
            },
            _ = tick.tick() => {
                while let Ok((d, s)) = rx.try_recv() { let e = pending.entry(d).or_default(); *e = (*e).max(s); }
                if pending.is_empty() { continue; }
                let batch: Vec<(DeviceId, u64)> = pending.drain().collect();
                for chunk in batch.chunks(1000) {
                    let mut cmd = redis::cmd("FCALL");
                    cmd.arg("sb_ack").arg(chunk.len());
                    for (d, _) in chunk { cmd.arg(key(b'm', d.as_bytes())); }
                    for (_, s) in chunk { cmd.arg(*s); }
                    let r: Result<i64, _> = cmd.query_async(&mut conn).await;
                    if r.is_err() {
                        for (d, s) in chunk { pending.insert(*d, *s); }
                    }
                    calls.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

impl Mailbox for ValkeyMailbox {
    async fn store(&self, req: StoreRequest) -> Result<StoreOutcome, MailboxError> {
        let n = req.payload.len();
        let mut flags = String::new();
        let idem_key = match req.idempotency_key {
            Some(k) => {
                flags.push('i');
                let tag = hmac::sign(&self.idem, &k);
                key(b'i', &tag.as_ref()[..32])
            }
            None => b"-".to_vec(),
        };
        let body_key = if matches!(req.payload, Payload::Shared { .. }) {
            flags.push('s');
            let c = self.body_counter.fetch_add(1, Ordering::Relaxed) as u64;
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&c.to_be_bytes());
            id[8..].copy_from_slice(&std::process::id().to_be_bytes().repeat(2));
            key(b'b', &id)
        } else {
            b"-".to_vec()
        };
        let (mls_key, epoch) = match req.mls {
            Some(m) => {
                flags.push('g');
                (key(b'g', &m.group), m.epoch)
            }
            None => (b"-".to_vec(), 0),
        };
        let mut blob = Vec::with_capacity(16 * n);
        for d in req.payload.devices() {
            blob.extend_from_slice(d.as_bytes());
        }
        let mut cmd = redis::cmd("FCALL");
        cmd.arg("sb_store").arg(3 + 2 * n);
        cmd.arg(idem_key).arg(body_key).arg(mls_key);
        for d in req.payload.devices() {
            cmd.arg(key(b'q', d.as_bytes()));
        }
        for d in req.payload.devices() {
            cmd.arg(key(b'm', d.as_bytes()));
        }
        cmd.arg(if flags.is_empty() { "-".to_owned() } else { flags })
            .arg(blob)
            .arg(self.max_per_device)
            .arg(IDEMPOTENCY_RETENTION.as_secs())
            .arg(epoch);
        match &req.payload {
            Payload::PerDevice(items) => {
                for it in items {
                    cmd.arg(it.envelope.as_ref());
                }
            }
            Payload::Shared { body, .. } => {
                cmd.arg(body.as_ref());
            }
        }
        let r: Vec<i64> = cmd
            .query_async(&mut self.conn())
            .await
            .map_err(|e| {
                if std::env::var("DEBUG_ERRORS").is_ok() {
                    eprintln!("valkey store error: {e:?}");
                }
                MailboxError::Unavailable
            })?;
        match r.first().copied() {
            Some(0) | Some(1) => Ok(StoreOutcome {
                seqs: r[1..].iter().map(|s| *s as u64).collect(),
                replayed: r[0] == 1,
            }),
            Some(2) => Err(MailboxError::IdempotencyConflict),
            Some(3) => Err(MailboxError::Full),
            Some(4) => Err(MailboxError::StaleEpoch),
            _ => Err(MailboxError::Unavailable),
        }
    }

    async fn fetch_after(
        &self,
        device: &DeviceId,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Stored>, MailboxError> {
        let mut c = self.conn();
        let items: Vec<(String, Vec<Vec<u8>>)> = redis::cmd("XRANGE")
            .arg(key(b'm', device.as_bytes()))
            .arg(format!("({after_seq}-1"))
            .arg("+")
            .arg("COUNT")
            .arg(limit)
            .query_async(&mut c)
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        let mut out = Vec::with_capacity(items.len());
        for (id, fields) in items {
            let seq = id.split('-').next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let envelope = match (fields.first().map(Vec::as_slice), fields.get(1)) {
                (Some(b"e"), Some(v)) => Bytes::copy_from_slice(v),
                (Some(b"b"), Some(k)) => {
                    let body: Vec<u8> = redis::cmd("HGET")
                        .arg(k.as_slice())
                        .arg("d")
                        .query_async(&mut c)
                        .await
                        .map_err(|_| MailboxError::Unavailable)?;
                    Bytes::from(body)
                }
                _ => return Err(MailboxError::Unavailable),
            };
            out.push(Stored { seq, envelope });
        }
        Ok(out)
    }

    async fn ack_up_to(&self, device: &DeviceId, up_to_seq: u64) -> Result<(), MailboxError> {
        self.acks
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
        let n: u64 = redis::cmd("XLEN")
            .arg(key(b'm', device.as_bytes()))
            .query_async(&mut self.conn())
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        Ok(n)
    }
}
