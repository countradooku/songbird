//! Cross-node routing over Valkey pub/sub that learns nothing about who talks to whom (D-0034).
//!
//! - **One channel per device; the subscriptions are the registry.** A node subscribes to the
//!   channel of every device it holds. A send publishes on the recipient's channel; `PUBLISH`
//!   answers how many nodes received it, and zero means the device is offline. A device attaching
//!   publishes a `close` on its channel first (any older connection elsewhere drops, invariant 4),
//!   then subscribes, and only then drains its mailbox, so nothing stored meanwhile is missed.
//! - **Valkey sees no identifiers and no content.** Channel names are keyed hashes of the device
//!   ID (HMAC-SHA256 under a cluster secret); every payload is sealed with a cluster key
//!   (AES-256-GCM-SIV, nonce-misuse resistant, so random nonces stay safe at millions of messages
//!   per second) and bound to its channel and kind. A `close` older than [`CLOSE_MAX_AGE`] is
//!   ignored, so replaying captured traffic cannot disconnect anyone.
//! - **Local first.** A device held on this node is routed in memory ([`LocalRouter`]), with no
//!   Valkey hop.
//! - **Self-healing.** A pool of subscriber connections (channels assigned by hash) reconnects
//!   with backoff, re-subscribes every channel it held, and marks local sessions lagged so they
//!   recover anything published while it was away from their mailboxes (routing is never the
//!   source of truth).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::{hkdf, hmac};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt as _;
use songbird_types::DeviceId;
use tokio::sync::{mpsc, oneshot};

use crate::{Inbox, InboxSizes, Live, LocalRouter, Routed, Router};

/// A `close` older than this is ignored (replay protection; clocks within seconds).
pub const CLOSE_MAX_AGE: Duration = Duration::from_secs(30);

/// Subscriber connections are pinged this often; one that does not answer within
/// [`PING_TIMEOUT`] is treated as dead and replaced (a half-open connection would otherwise miss
/// messages silently; the approach Sockudo's Redis Cluster transport takes).
pub const PING_INTERVAL: Duration = Duration::from_secs(5);
/// See [`PING_INTERVAL`].
pub const PING_TIMEOUT: Duration = Duration::from_secs(3);

const KIND_LIVE: u8 = 1;
const KIND_EPHEMERAL: u8 = 2;
const KIND_CLOSE: u8 = 3;

/// Why the router could not start.
#[derive(Debug, thiserror::Error)]
pub enum ValkeyRouterError {
    /// Valkey refused or failed.
    #[error("valkey: {0}")]
    Valkey(String),
    /// A key could not be derived.
    #[error("router key derivation failed")]
    Crypto,
}

/// Settings.
#[derive(Clone)]
pub struct ValkeyRouterConfig {
    /// `redis://` or `rediss://` URL, with credentials.
    pub url: String,
    /// PEM root certificate for `rediss://` (the internal CA).
    pub tls_ca_pem: Option<Vec<u8>>,
    /// PEM client certificate chain and key, when Valkey requires client certificates (D-0012).
    pub tls_client: Option<(Vec<u8>, Vec<u8>)>,
    /// Cluster secret: channel names and payload sealing keys derive from it (every node the
    /// same).
    pub cluster_secret: [u8; 32],
    /// Subscriber connections (channels spread over them by hash).
    pub subscribers: usize,
    /// This node's identifier (random per process start is enough: it tells a node's own
    /// `close` apart).
    pub node_id: u64,
}

impl std::fmt::Debug for ValkeyRouterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyRouterConfig")
            .field("subscribers", &self.subscribers)
            .finish_non_exhaustive()
    }
}

/// Counters.
#[derive(Debug, Default)]
pub struct ValkeyRouterStats {
    /// Envelopes and events published to other nodes.
    pub published: AtomicU64,
    /// Publishes that failed (Valkey unreachable): treated as offline.
    pub publish_errors: AtomicU64,
    /// Messages received from other nodes.
    pub received: AtomicU64,
    /// Received messages that did not open (wrong key, tampering, garbage): dropped.
    pub rejected: AtomicU64,
    /// Subscriber reconnects.
    pub reconnects: AtomicU64,
    /// Sessions closed because the device connected on another node.
    pub evicted: AtomicU64,
}

/// Channel naming and payload sealing (pure; unit-tested).
struct Seal {
    channel_key: hmac::Key,
    aead: LessSafeKey,
}

impl Seal {
    fn new(secret: &[u8; 32]) -> Result<Self, ValkeyRouterError> {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-router-v1").extract(secret);
        let mut channel = [0u8; 32];
        let mut seal = [0u8; 32];
        prk.expand(&[b"channel"], hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(&mut channel))
            .map_err(|_| ValkeyRouterError::Crypto)?;
        prk.expand(&[b"seal"], hkdf::HKDF_SHA256)
            .and_then(|o| o.fill(&mut seal))
            .map_err(|_| ValkeyRouterError::Crypto)?;
        let aead = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM_SIV, &seal).map_err(|_| ValkeyRouterError::Crypto)?,
        );
        let out = Self {
            channel_key: hmac::Key::new(hmac::HMAC_SHA256, &channel),
            aead,
        };
        channel.fill(0);
        seal.fill(0);
        Ok(out)
    }

    /// The device's channel: `r:` and 32 hex characters of a keyed hash (no identifier).
    fn channel(&self, device: &DeviceId) -> String {
        let tag = hmac::sign(&self.channel_key, device.as_bytes());
        let mut out = String::with_capacity(34);
        out.push_str("r:");
        out.push_str(&hex::encode(tag.as_ref().get(..16).unwrap_or_default()));
        out
    }

    fn aad(channel: &str, kind: u8) -> Vec<u8> {
        let mut a = Vec::with_capacity(channel.len() + 1);
        a.extend_from_slice(channel.as_bytes());
        a.push(kind);
        a
    }

    /// `kind | nonce | sealed(body)`.
    fn seal(&self, channel: &str, kind: u8, body: &[u8]) -> Option<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).ok()?;
        let mut buf = Vec::with_capacity(1 + NONCE_LEN + body.len() + 16);
        buf.push(kind);
        buf.extend_from_slice(&nonce);
        let mut sealed = body.to_vec();
        self.aead
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(Self::aad(channel, kind).as_slice()),
                &mut sealed,
            )
            .ok()?;
        buf.extend_from_slice(&sealed);
        Some(buf)
    }

    fn open(&self, channel: &str, msg: &[u8]) -> Option<(u8, Vec<u8>)> {
        let (&kind, rest) = msg.split_first()?;
        let (nonce, ct) = rest.split_at_checked(NONCE_LEN)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buf = ct.to_vec();
        let n = self
            .aead
            .open_in_place(
                nonce,
                Aad::from(Self::aad(channel, kind).as_slice()),
                &mut buf,
            )
            .ok()?
            .len();
        buf.truncate(n);
        Some((kind, buf))
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

enum Cmd {
    Sub(String, DeviceId, oneshot::Sender<bool>),
    Unsub(String),
}

/// Routes across nodes through Valkey (D-0034); within the node through [`LocalRouter`].
pub struct ValkeyRouter {
    local: Arc<LocalRouter>,
    seal: Arc<Seal>,
    publisher: crate::conn::ValkeyConn,
    shards: Vec<mpsc::UnboundedSender<Cmd>>,
    node_id: u64,
    stats: Arc<ValkeyRouterStats>,
}

impl std::fmt::Debug for ValkeyRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyRouter")
            .field("shards", &self.shards.len())
            .finish_non_exhaustive()
    }
}

fn client(cfg: &ValkeyRouterConfig) -> Result<redis::Client, ValkeyRouterError> {
    let r = match &cfg.tls_ca_pem {
        Some(ca) => redis::Client::build_with_tls(
            cfg.url.as_str(),
            redis::TlsCertificates {
                client_tls: cfg
                    .tls_client
                    .as_ref()
                    .map(|(cert, key)| redis::ClientTlsConfig {
                        client_cert: cert.clone(),
                        client_key: key.clone(),
                    }),
                root_cert: Some(ca.clone()),
            },
        ),
        None => redis::Client::open(cfg.url.as_str()),
    };
    // No details: the URL holds credentials.
    r.map_err(|e| ValkeyRouterError::Valkey(format!("{:?}", e.kind())))
}

impl ValkeyRouter {
    /// Connects the publisher and starts the subscriber tasks (on the current runtime).
    ///
    /// # Errors
    /// [`ValkeyRouterError`]: Valkey unreachable or refused, or key derivation failed.
    pub async fn connect(cfg: ValkeyRouterConfig) -> Result<Self, ValkeyRouterError> {
        let seal = Arc::new(Seal::new(&cfg.cluster_secret)?);
        let client = client(&cfg)?;
        let publisher = crate::conn::ValkeyConn::connect(client.clone())
            .await
            .map_err(|e| ValkeyRouterError::Valkey(format!("{:?}", e.kind())))?;
        let local = Arc::new(LocalRouter::new());
        let stats = Arc::new(ValkeyRouterStats::default());
        let mut shards = Vec::new();
        for _ in 0..cfg.subscribers.max(1) {
            let (tx, rx) = mpsc::unbounded_channel();
            tokio::spawn(subscriber(
                client.clone(),
                rx,
                Arc::clone(&local),
                Arc::clone(&seal),
                Arc::clone(&stats),
                cfg.node_id,
            ));
            shards.push(tx);
        }
        Ok(Self {
            local,
            seal,
            publisher,
            shards,
            node_id: cfg.node_id,
            stats,
        })
    }

    /// A router that only publishes (`api`, D-0037): it holds no sessions, so it opens no
    /// subscriber connections; [`Router::attach`] on it subscribes nothing and must not be used.
    /// Routing seals and names channels exactly like a delivery node.
    ///
    /// # Errors
    /// [`ValkeyRouterError`]: Valkey unreachable or refused, or key derivation failed.
    pub async fn publisher(
        client: redis::Client,
        cluster_secret: &[u8; 32],
    ) -> Result<Self, ValkeyRouterError> {
        let seal = Arc::new(Seal::new(cluster_secret)?);
        let publisher = crate::conn::ValkeyConn::connect(client)
            .await
            .map_err(|e| ValkeyRouterError::Valkey(format!("{:?}", e.kind())))?;
        let mut node_id = [0u8; 8];
        aws_lc_rs::rand::fill(&mut node_id).map_err(|_| ValkeyRouterError::Crypto)?;
        Ok(Self {
            local: Arc::new(LocalRouter::new()),
            seal,
            publisher,
            shards: Vec::new(),
            node_id: u64::from_be_bytes(node_id),
            stats: Arc::new(ValkeyRouterStats::default()),
        })
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> Arc<ValkeyRouterStats> {
        Arc::clone(&self.stats)
    }

    fn shard(&self, channel: &str) -> Option<&mpsc::UnboundedSender<Cmd>> {
        // The channel is already a keyed hash: its bytes spread evenly.
        let h = channel
            .bytes()
            .skip(2)
            .take(8)
            .fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)));
        let n = u64::try_from(self.shards.len()).unwrap_or(1).max(1);
        self.shards.get(usize::try_from(h % n).unwrap_or(0))
    }

    async fn publish(&self, channel: &str, payload: Vec<u8>) -> Option<i64> {
        if let Ok(n) = self
            .publisher
            .query::<i64>(redis::cmd("PUBLISH").arg(channel).arg(payload))
            .await
        {
            self.stats.published.fetch_add(1, Ordering::Relaxed);
            Some(n)
        } else {
            self.stats.publish_errors.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    async fn remote(&self, device: &DeviceId, kind: u8, body: &[u8]) -> Routed {
        let channel = self.seal.channel(device);
        let Some(payload) = self.seal.seal(&channel, kind, body) else {
            return Routed::Offline;
        };
        match self.publish(&channel, payload).await {
            Some(n) if n > 0 => Routed::Queued,
            // Nobody holds it (or Valkey is unreachable): offline; the mailbox keeps it.
            _ => Routed::Offline,
        }
    }
}

impl ValkeyRouter {
    /// Tells every other node to close its session for `device` (a `close` message carrying
    /// this node's ID, which this node's own subscriber ignores).
    async fn publish_close(&self, channel: &str) {
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&self.node_id.to_be_bytes());
        body.extend_from_slice(&now_ms().to_be_bytes());
        if let Some(p) = self.seal.seal(channel, KIND_CLOSE, &body) {
            let _ = self.publish(channel, p).await;
        }
    }
}

impl Router for ValkeyRouter {
    async fn close_everywhere(&self, device: &DeviceId) {
        self.publish_close(&self.seal.channel(device)).await;
        self.local.evict(device);
    }

    async fn attach(&self, device: DeviceId, sizes: InboxSizes) -> Inbox {
        {
            let channel = self.seal.channel(&device);
            // 1. Any older connection on another node closes (invariant 4).
            self.publish_close(&channel).await;
            // 2. Held here (a local older session is replaced by the local router).
            let inbox = self.local.attach(device, sizes).await;
            // 3. Subscribed (confirmed) before the session drains its mailbox, so an envelope
            //    stored meanwhile is either fetched by the drain or routed here.
            if let Some(shard) = self.shard(&channel) {
                let (tx, rx) = oneshot::channel();
                if shard.send(Cmd::Sub(channel, device, tx)).is_ok() {
                    let _ = tokio::time::timeout(Duration::from_secs(5), rx).await;
                }
            }
            inbox
        }
    }

    async fn detach(&self, device: &DeviceId, conn: u64) {
        {
            self.local.detach(device, conn).await;
            if !self.local.holds(device) {
                let channel = self.seal.channel(device);
                if let Some(shard) = self.shard(&channel) {
                    let _ = shard.send(Cmd::Unsub(channel));
                }
            }
        }
    }

    async fn route(&self, device: &DeviceId, live: Live) -> Routed {
        {
            if self.local.holds(device) {
                return self.local.route(device, live).await;
            }
            let mut body = Vec::with_capacity(8 + live.envelope.len());
            body.extend_from_slice(&live.seq.to_be_bytes());
            body.extend_from_slice(&live.envelope);
            self.remote(device, KIND_LIVE, &body).await
        }
    }

    async fn route_ephemeral(&self, device: &DeviceId, payload: Bytes) -> Routed {
        {
            if self.local.holds(device) {
                return self.local.route_ephemeral(device, payload).await;
            }
            self.remote(device, KIND_EPHEMERAL, &payload).await
        }
    }
}

/// One subscriber connection: keeps its channels subscribed across reconnects and hands what
/// arrives to the local router.
async fn subscriber(
    client: redis::Client,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    local: Arc<LocalRouter>,
    seal: Arc<Seal>,
    stats: Arc<ValkeyRouterStats>,
    node_id: u64,
) {
    let mut wanted: HashMap<String, DeviceId> = HashMap::new();
    let mut backoff = Duration::from_millis(50);
    let mut first = true;
    loop {
        let Ok(pubsub) = client.get_async_pubsub().await else {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(2));
            continue;
        };
        let (mut sink, mut stream) = pubsub.split();
        // Re-subscribe everything this connection held, in batches.
        let channels: Vec<String> = wanted.keys().cloned().collect();
        let mut ok = true;
        for batch in channels.chunks(512) {
            if sink.subscribe(batch).await.is_err() {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        if !first {
            stats.reconnects.fetch_add(1, Ordering::Relaxed);
            // Anything published while this connection was down is in the mailboxes.
            local.lag_all();
        }
        first = false;
        backoff = Duration::from_millis(50);
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    let alive = tokio::time::timeout(PING_TIMEOUT, sink.ping::<String>()).await;
                    if !matches!(alive, Ok(Ok(_))) { break; }
                }
                cmd = cmds.recv() => match cmd {
                    None => return,
                    Some(Cmd::Sub(ch, device, done)) => {
                        let r = sink.subscribe(&ch).await.is_ok();
                        wanted.insert(ch, device);
                        let _ = done.send(r);
                        if !r { break; }
                    }
                    Some(Cmd::Unsub(ch)) => {
                        wanted.remove(&ch);
                        if sink.unsubscribe(&ch).await.is_err() { break; }
                    }
                },
                msg = stream.next() => {
                    let Some(msg) = msg else { break };
                    stats.received.fetch_add(1, Ordering::Relaxed);
                    let channel = msg.get_channel_name();
                    let Some(device) = wanted.get(channel).copied() else { continue };
                    let Some((kind, body)) = seal.open(channel, msg.get_payload_bytes()) else {
                        stats.rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    deliver(&local, &stats, node_id, device, kind, body).await;
                }
            }
        }
    }
}

async fn deliver(
    local: &LocalRouter,
    stats: &ValkeyRouterStats,
    node_id: u64,
    device: DeviceId,
    kind: u8,
    body: Vec<u8>,
) {
    match kind {
        KIND_LIVE => {
            let Some((seq, env)) = body.split_at_checked(8) else {
                return;
            };
            let seq = u64::from_be_bytes(seq.try_into().unwrap_or([0; 8]));
            let envelope = BytesMut::from(env).freeze();
            let _ = local.route(&device, Live { seq, envelope }).await;
        }
        KIND_EPHEMERAL => {
            let _ = local.route_ephemeral(&device, Bytes::from(body)).await;
        }
        KIND_CLOSE => {
            let (Some(origin), Some(at)) = (
                body.get(..8).and_then(|b| b.try_into().ok()),
                body.get(8..16).and_then(|b| b.try_into().ok()),
            ) else {
                return;
            };
            let fresh = now_ms().saturating_sub(u64::from_be_bytes(at))
                < u64::try_from(CLOSE_MAX_AGE.as_millis()).unwrap_or(u64::MAX);
            if u64::from_be_bytes(origin) != node_id && fresh && local.evict(&device) {
                stats.evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
    use super::*;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    #[test]
    fn channels_hide_the_device_and_depend_on_the_secret() {
        let a = Seal::new(&[1; 32]).unwrap();
        let b = Seal::new(&[2; 32]).unwrap();
        let ch = a.channel(&d(7));
        assert_eq!(ch.len(), 34);
        assert!(ch.starts_with("r:"));
        assert!(!ch.contains(&d(7).to_hex_unredacted()[..8]));
        assert_eq!(ch, a.channel(&d(7)), "stable");
        assert_ne!(ch, a.channel(&d(8)));
        assert_ne!(ch, b.channel(&d(7)), "another cluster secret, another name");
    }

    #[test]
    fn sealed_payloads_open_only_on_their_channel_kind_and_key() {
        let a = Seal::new(&[1; 32]).unwrap();
        let other = Seal::new(&[2; 32]).unwrap();
        let ch = a.channel(&d(1));
        let msg = a.seal(&ch, KIND_LIVE, b"hello").unwrap();
        assert!(
            !msg.windows(5).any(|w| w == b"hello"),
            "nothing in the clear"
        );
        assert_eq!(a.open(&ch, &msg), Some((KIND_LIVE, b"hello".to_vec())));
        assert_eq!(
            a.open(&a.channel(&d(2)), &msg),
            None,
            "moved to another channel"
        );
        let mut wrong_kind = msg.clone();
        wrong_kind[0] = KIND_CLOSE;
        assert_eq!(a.open(&ch, &wrong_kind), None, "kind is authenticated");
        assert_eq!(other.open(&ch, &msg), None, "another cluster key");
        let mut flipped = msg.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(a.open(&ch, &flipped), None);
        assert_eq!(a.open(&ch, &[]), None);
        assert_ne!(
            a.seal(&ch, KIND_LIVE, b"hello").unwrap(),
            msg,
            "fresh nonce"
        );
    }
}
