//! Cluster mode (D-0034): several delivery nodes share the mailbox topic; each partition has one
//! owner node, which runs its writer, and two standby nodes, which receive every key-store write.
//!
//! - **Membership**: each node keeps itself in a Valkey sorted set whose scores are expiry times
//!   on Valkey's clock (no node clock is trusted).
//! - **Leases**: partition `p` is owned by whoever holds `lease:<p>` (`SET NX PX`, renewed and
//!   released by compare-and-set scripts). Iggy's producer epochs still fence a writer that lost
//!   its lease but has not noticed yet (D-0029): a lease is an optimisation, not the guard.
//! - **Placement**: rendezvous hashing over the live members; the owner should be the first, its
//!   standbys the next one and the next one in another zone.
//! - **Copies**: a window seals records only once a standby holds its keys; a new standby gets
//!   the whole store; a node that is no longer a standby deletes its copy.
//! - **Failover**: the owner dies; its lease and membership expire; its first live standby takes
//!   the partition at once (the next standby a lease period later, anyone else after three),
//!   replays the log and fences the old writer.
//! - **Rebalancing**: an owner hands a partition to the node that should own it once that node
//!   holds a full copy (one partition per round), so a node that joins takes its share.
//! - Everything crosses nodes over node links (mutual TLS, internal CA). Delivery nodes
//!   (`delivery.`) may ask for every operation; nodes that only send (`api.`, when listed in
//!   [`ClusterConfig::senders`], D-0044) may ask for one: the store of a send.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use songbird_link::{Handler, LinkClient, LinkStats, LinkTls};
use tokio::sync::watch;

use super::keys::{KeyFile, Replica};
use super::partitions::{self, Peer, Replicator, Slot};
use super::wire::{Request, Response};
use super::{Ctx, start_partition};
use crate::MailboxError;

/// Cluster settings.
#[derive(Clone)]
pub struct ClusterConfig {
    /// This node's name, the one its certificate is for (`delivery.<host>.songbird.internal`).
    pub node_name: String,
    /// Where this node's link listener binds.
    pub link_listen: SocketAddr,
    /// The address other nodes reach it at.
    pub link_advertise: SocketAddr,
    /// TLS for links.
    pub link_tls: LinkTls,
    /// Valkey for leases and membership (`redis://` or `rediss://`, with credentials).
    pub valkey_url: String,
    /// PEM root of the internal CA, for `rediss://`.
    pub valkey_tls_ca_pem: Option<Vec<u8>>,
    /// PEM client certificate chain and key for Valkey (D-0012).
    pub valkey_tls_client: Option<(Vec<u8>, Vec<u8>)>,
    /// Lease length; renewed every third of it.
    pub lease_ttl: Duration,
    /// This node's failure domain (a zone or rack, `[a-z0-9-]`, empty for none): a partition's
    /// second standby is in a zone neither its owner nor its first standby is in.
    pub zone: String,
    /// Certificate-name prefixes of nodes that only send (`api.`, D-0044), admitted to this
    /// node's link listener for one request, the store of a send; anything else they ask is
    /// refused and counted. Empty: delivery nodes only. `delivery.` here is ignored.
    pub senders: Vec<String>,
}

impl std::fmt::Debug for ClusterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterConfig")
            .field("lease_ttl", &self.lease_ttl)
            .finish_non_exhaustive()
    }
}

/// Standby nodes per partition: three copies of every key store.
const STANDBYS: usize = 2;

/// A live node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) id: u64,
    zone: String,
    pub(crate) name: String,
    pub(crate) addr: SocketAddr,
}

impl Member {
    fn encode(&self) -> String {
        format!("{:016x}|{}|{}|{}", self.id, self.zone, self.name, self.addr)
    }

    pub(crate) fn decode(s: &str) -> Option<Self> {
        let mut it = s.splitn(4, '|');
        let id = u64::from_str_radix(it.next()?, 16).ok()?;
        let zone = it.next()?.to_owned();
        let name = it.next()?.to_owned();
        let addr = it.next()?.parse().ok()?;
        Some(Self {
            id,
            zone,
            name,
            addr,
        })
    }
}

/// Whether `zone` is a valid zone name (`[a-z0-9-]`, at most 32 bytes, possibly empty).
pub(crate) fn zone_ok(zone: &str) -> bool {
    zone.len() <= 32
        && zone
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Rendezvous weight of `member` for partition `p`.
fn weight(member: u64, p: u32) -> u64 {
    let mut input = [0u8; 12];
    input[..8].copy_from_slice(&member.to_be_bytes());
    input[8..].copy_from_slice(&p.to_be_bytes());
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &input);
    d.as_ref()
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_be_bytes)
}

/// Members in preference order for partition `p` (the first should own it).
fn ranked(members: &[Member], p: u32) -> Vec<&Member> {
    let mut v: Vec<&Member> = members.iter().collect();
    v.sort_by_key(|m| std::cmp::Reverse((weight(m.id, p), m.id)));
    v
}

/// The standbys of `p` while `owner` holds it, in takeover order: the best-ranked other member,
/// then the best-ranked remaining one in a zone neither of them is in (the next one if there is
/// none).
fn standbys(members: &[Member], p: u32, owner: u64) -> Vec<&Member> {
    let rest: Vec<&Member> = ranked(members, p)
        .into_iter()
        .filter(|m| m.id != owner)
        .collect();
    let Some(first) = rest.first().copied() else {
        return Vec::new();
    };
    let owner_zone = members
        .iter()
        .find(|m| m.id == owner)
        .map(|m| m.zone.as_str());
    let others = rest.get(1..).unwrap_or_default();
    let second = others
        .iter()
        .find(|m| Some(m.zone.as_str()) != owner_zone && m.zone != first.zone)
        .or_else(|| others.first())
        .copied();
    std::iter::once(first)
        .chain(second)
        .take(STANDBYS)
        .collect()
}

/// A node link to another member, as a [`Peer`].
pub(crate) struct LinkPeer {
    pub(crate) client: LinkClient,
    pub(crate) timeout: Duration,
}

impl Peer for LinkPeer {
    fn call(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response, MailboxError>> + Send + '_>> {
        Box::pin(async move {
            let resp = self
                .client
                .call(&req.encode(), self.timeout)
                .await
                .map_err(|_| MailboxError::Unavailable)?;
            Response::decode(&resp).ok_or(MailboxError::Unavailable)
        })
    }
}

/// Members and links, shared by the manager and the replicator.
struct Peers {
    me: Member,
    tls: LinkTls,
    timeout: Duration,
    members: RwLock<Vec<Member>>,
    links: Mutex<HashMap<u64, Arc<LinkPeer>>>,
    /// Key-store writes that did not reach a standby.
    replica_failures: std::sync::atomic::AtomicU64,
    /// The standbys holding everything each partition's store has written.
    synced: Mutex<HashMap<u32, HashSet<u64>>>,
    /// Opens a partition's key store (to copy it whole to a new standby).
    store_of: Box<dyn Fn(u32) -> KeyFile + Send + Sync>,
}

impl Peers {
    fn link(&self, m: &Member) -> Arc<LinkPeer> {
        let mut links = self
            .links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(links.entry(m.id).or_insert_with(|| {
            Arc::new(LinkPeer {
                client: LinkClient::new(m.addr, &m.name, self.tls.clone()),
                timeout: self.timeout,
            })
        }))
    }

    fn members(&self) -> Vec<Member> {
        self.members
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The standbys of `p` while this node owns it.
    fn standbys(&self, p: u32) -> Vec<Member> {
        let members = self.members();
        standbys(&members, p, self.me.id)
            .into_iter()
            .cloned()
            .collect()
    }

    fn synced(&self, p: u32) -> HashSet<u64> {
        self.synced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p)
            .cloned()
            .unwrap_or_default()
    }

    /// Whether every standby of `p` holds its whole store.
    fn all_synced(&self, p: u32) -> bool {
        let synced = self.synced(p);
        self.standbys(p).iter().all(|s| synced.contains(&s.id))
    }
}

fn key_store_request(p: u32, r: &Replica, full: bool) -> Request {
    Request::KeyStore {
        p,
        files: r
            .files
            .iter()
            .map(|(n, b)| (n.clone(), Bytes::copy_from_slice(b)))
            .collect(),
        remove: r.remove.clone(),
        full,
    }
}

impl Replicator for Peers {
    fn replicate(
        &self,
        p: u32,
        replica: Replica,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            let standbys = self.standbys(p);
            if standbys.is_empty() {
                // Alone: nobody to copy to (fewer live nodes than copies).
                return true;
            }
            let before = self.synced(p);
            // A standby without the whole store gets all of it (it includes this write).
            let full: Result<Option<Replica>, ()> =
                if standbys.iter().all(|s| before.contains(&s.id)) {
                    Ok(None)
                } else {
                    let file = (self.store_of)(p);
                    match tokio::task::spawn_blocking(move || file.snapshot()).await {
                        Ok(Ok(full)) => Ok(full),
                        _ => Err(()),
                    }
                };
            let empty = replica.files.is_empty() && replica.remove.is_empty();
            let full_sent = matches!(full, Ok(Some(_)));
            let sends = standbys.iter().map(|s| {
                let was_synced = before.contains(&s.id);
                let job = if was_synced {
                    Ok((!empty).then(|| key_store_request(p, &replica, false)))
                } else {
                    match &full {
                        Ok(Some(f)) => Ok(Some(key_store_request(p, f, true))),
                        // No store yet: nothing to hold.
                        Ok(None) => Ok(None),
                        Err(()) => Err(()),
                    }
                };
                async move {
                    let ok = match job {
                        Ok(None) => true,
                        Ok(Some(req)) => {
                            matches!(self.link(s).call(req).await, Ok(Response::Done(Ok(()))))
                        }
                        Err(()) => false,
                    };
                    // Success leaves it holding everything if it did before or got it all now.
                    let holds = ok && (was_synced || full_sent);
                    (s.id, ok, holds)
                }
            });
            let results = futures_util::future::join_all(sends).await;
            let failed = results.iter().filter(|(_, ok, _)| !ok).count();
            let mut synced = self
                .synced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            synced.insert(
                p,
                results
                    .iter()
                    .filter(|(_, _, holds)| *holds)
                    .map(|(id, _, _)| *id)
                    .collect(),
            );
            drop(synced);
            if failed > 0 {
                // Copied whole next time.
                self.replica_failures.fetch_add(
                    u64::try_from(failed).unwrap_or(u64::MAX),
                    std::sync::atomic::Ordering::Relaxed,
                );
                tracing::warn!(
                    partition = p,
                    "mailbox key store not replicated to a standby"
                );
            }
            results.iter().any(|(_, ok, _)| *ok)
        })
    }
}

/// Keeps this node in the members set and lists the live ones, on Valkey's clock: returns
/// whether this node was added (rather than renewed) and the members.
const MEMBERS: &str = "local t = redis.call('time') \
     local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) \
     local added = redis.call('zadd', KEYS[1], string.format('%.0f', now + tonumber(ARGV[2])), ARGV[1]) \
     redis.call('zremrangebyscore', KEYS[1], '-inf', '(' .. string.format('%.0f', now)) \
     return {added, redis.call('zrangebyscore', KEYS[1], string.format('%.0f', now), '+inf')}";

/// Renews the lease only if this node still holds it.
const RENEW: &str = "if redis.call('get', KEYS[1]) == ARGV[1] then \
     return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end";
/// Releases the lease only if this node holds it.
const RELEASE: &str = "if redis.call('get', KEYS[1]) == ARGV[1] then \
     return redis.call('del', KEYS[1]) else return 0 end";

/// The cluster manager of one node.
pub(crate) struct Cluster {
    peers: Arc<Peers>,
    ctx: Arc<Ctx>,
    conn: songbird_router::conn::ValkeyConn,
    prefix: String,
    ttl: Duration,
    /// Partitions being started here (lease held, writer not up yet).
    starting: Mutex<HashSet<u32>>,
    /// When each partition was first seen without an owner.
    free_since: Mutex<HashMap<u32, Instant>>,
    /// The member each remote slot points at (the partition's last known owner).
    remote_of: Mutex<HashMap<u32, Member>>,
    /// When this node first saw each live member (a node must have been up a while before
    /// partitions are handed to it).
    first_seen: Mutex<HashMap<u64, Instant>>,
    /// When this node, holding a copy of a partition's key store, stopped being its standby.
    not_standby_since: Mutex<HashMap<u32, Instant>>,
    /// This node has registered at least once (to tell a Valkey that lost everything).
    joined: std::sync::atomic::AtomicBool,
    /// When this node last found its registration gone (Valkey lost its data).
    reset_at: Mutex<Option<Instant>>,
    link_stats: Arc<LinkStats>,
    /// Requests from send-only nodes refused for asking more than a store.
    sender_refused: std::sync::atomic::AtomicU64,
    stop: watch::Sender<bool>,
}

/// What cluster mode adds to a mailbox: the replicator (to put in the start context) and how to
/// finish setting up once the context exists.
pub(crate) struct Prepared {
    peers: Arc<Peers>,
    cfg: ClusterConfig,
    timeout: Duration,
}

impl Prepared {
    pub(crate) fn new(
        cfg: ClusterConfig,
        timeout: Duration,
        store_of: Box<dyn Fn(u32) -> KeyFile + Send + Sync>,
    ) -> Result<Self, MailboxError> {
        let mut id = [0u8; 8];
        aws_lc_rs::rand::fill(&mut id).map_err(|_| MailboxError::Unavailable)?;
        if !zone_ok(&cfg.zone) {
            return Err(MailboxError::Unavailable);
        }
        let me = Member {
            id: u64::from_be_bytes(id),
            zone: cfg.zone.clone(),
            name: cfg.node_name.clone(),
            addr: cfg.link_advertise,
        };
        let peers = Arc::new(Peers {
            me,
            tls: cfg.link_tls.clone(),
            timeout,
            members: RwLock::new(Vec::new()),
            links: Mutex::new(HashMap::new()),
            replica_failures: std::sync::atomic::AtomicU64::new(0),
            synced: Mutex::new(HashMap::new()),
            store_of,
        });
        Ok(Self {
            peers,
            cfg,
            timeout,
        })
    }

    pub(crate) fn replicator(&self) -> Arc<dyn Replicator> {
        let r: Arc<dyn Replicator> = self.peers.clone();
        r
    }

    /// Connects to Valkey, starts the link listener and the manager, and waits until every
    /// partition has a known owner (or `wait` passes).
    pub(crate) async fn start(
        self,
        ctx: Arc<Ctx>,
        wait: Duration,
    ) -> Result<Arc<Cluster>, MailboxError> {
        let client = match &self.cfg.valkey_tls_ca_pem {
            Some(ca) => redis::Client::build_with_tls(
                self.cfg.valkey_url.as_str(),
                redis::TlsCertificates {
                    client_tls: self.cfg.valkey_tls_client.as_ref().map(|(cert, key)| {
                        redis::ClientTlsConfig {
                            client_cert: cert.clone(),
                            client_key: key.clone(),
                        }
                    }),
                    root_cert: Some(ca.clone()),
                },
            ),
            None => redis::Client::open(self.cfg.valkey_url.as_str()),
        }
        .map_err(|_| MailboxError::Unavailable)?;
        let conn = songbird_router::conn::ValkeyConn::connect(client)
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        let listener = tokio::net::TcpListener::bind(self.cfg.link_listen)
            .await
            .map_err(|_| MailboxError::Unavailable)?;
        let (stop, stop_rx) = watch::channel(false);
        let cluster = Arc::new(Cluster {
            peers: self.peers,
            prefix: format!("songbird:{}:{}", ctx.cfg.stream, ctx.cfg.topic),
            ctx,
            conn,
            ttl: self.cfg.lease_ttl,
            starting: Mutex::new(HashSet::new()),
            free_since: Mutex::new(HashMap::new()),
            remote_of: Mutex::new(HashMap::new()),
            first_seen: Mutex::new(HashMap::new()),
            not_standby_since: Mutex::new(HashMap::new()),
            joined: std::sync::atomic::AtomicBool::new(false),
            reset_at: Mutex::new(None),
            link_stats: Arc::new(LinkStats::default()),
            sender_refused: std::sync::atomic::AtomicU64::new(0),
            stop,
        });
        let mut admit = vec![songbird_link::Admit {
            prefix: "delivery.".into(),
            handler: Cluster::handler(&cluster),
        }];
        for prefix in self.cfg.senders.iter().filter(|p| *p != "delivery.") {
            admit.push(songbird_link::Admit {
                prefix: prefix.clone(),
                handler: Cluster::sender_handler(&cluster),
            });
        }
        tokio::spawn(songbird_link::serve_admitting(
            listener,
            self.cfg.link_tls,
            admit,
            Arc::clone(&cluster.link_stats),
            stop_rx.clone(),
        ));
        let _ = self.timeout;
        let deadline = Instant::now() + wait;
        let mut tick = tokio::time::interval(cluster.ttl / 3);
        loop {
            tick.tick().await;
            cluster.round().await;
            let parts = &cluster.ctx.parts;
            let known = (0..parts.count()).all(|p| !matches!(parts.get(p), Slot::Unknown));
            if known || Instant::now() >= deadline {
                break;
            }
        }
        let c = Arc::clone(&cluster);
        tokio::spawn(async move {
            let mut stop = stop_rx;
            let mut tick = tokio::time::interval(c.ttl / 3);
            loop {
                tokio::select! {
                    _ = tick.tick() => c.round().await,
                    _ = async { stop.wait_for(|s| *s).await.is_ok() } => return,
                }
            }
        });
        Ok(cluster)
    }
}

impl Cluster {
    /// Serves partition requests and key-store writes from other nodes.
    fn handler(cluster: &Arc<Self>) -> Handler {
        let c = Arc::clone(cluster);
        Arc::new(move |raw: Bytes| {
            let c = Arc::clone(&c);
            Box::pin(async move {
                let Some(req) = Request::decode(&raw) else {
                    return Response::Done(Err(MailboxError::Unavailable)).encode();
                };
                let resp = match req {
                    Request::KeyStore {
                        p,
                        files,
                        remove,
                        full,
                    } => c.apply_replica(p, files, remove, full).await,
                    other => partitions::serve(&c.ctx.parts, other).await,
                };
                resp.encode()
            })
        })
    }

    /// Serves nodes that only send (D-0044): the store of a send, nothing else. Fetches, ACKs,
    /// forgets, key-store copies and the rest are refused (and counted), so a compromised `api`
    /// can neither read nor delete anyone's messages, nor touch a key store. `PartDone` is
    /// refused too: a sender leaves a multi-partition send's bookkeeping to the home partition's
    /// re-driver, so it cannot mark another send's part stored before it is.
    fn sender_handler(cluster: &Arc<Self>) -> Handler {
        let c = Arc::clone(cluster);
        Arc::new(move |raw: Bytes| {
            let c = Arc::clone(&c);
            Box::pin(async move {
                let resp = if let Some(req @ Request::Store { .. }) = Request::decode(&raw) {
                    partitions::serve(&c.ctx.parts, req).await
                } else {
                    c.sender_refused
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Response::Done(Err(MailboxError::Unavailable))
                };
                resp.encode()
            })
        })
    }

    /// Requests from send-only nodes refused for asking more than a store.
    pub(crate) fn sender_refused(&self) -> u64 {
        self.sender_refused
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn apply_replica(
        &self,
        p: u32,
        files: Vec<(String, Bytes)>,
        remove: Vec<String>,
        full: bool,
    ) -> Response {
        // Never over a partition this node runs or is starting (that store is live here).
        let starting = self
            .starting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&p);
        if starting || self.ctx.parts.local(p).is_some() || p >= self.ctx.parts.count() {
            return Response::Done(Err(MailboxError::Unavailable));
        }
        let cfg = &self.ctx.cfg;
        let file = KeyFile::new(&cfg.key_dir, &cfg.stream, &cfg.topic, p, cfg.master_key);
        let replica = Replica {
            files: files.into_iter().map(|(n, b)| (n, b.to_vec())).collect(),
            remove,
            full,
        };
        match tokio::task::spawn_blocking(move || file.apply_replica(&replica)).await {
            Ok(Ok(())) => Response::Done(Ok(())),
            _ => Response::Done(Err(MailboxError::Unavailable)),
        }
    }

    fn lease_key(&self, p: u32) -> String {
        format!("{}:lease:{p}", self.prefix)
    }

    /// Set for a lease period when an owner hands a partition back on purpose (graceful
    /// shutdown): others take it at once instead of waiting out a lease period.
    fn released_key(&self, p: u32) -> String {
        format!("{}:released:{p}", self.prefix)
    }

    fn members_key(&self) -> String {
        format!("{}:members", self.prefix)
    }

    fn ttl_ms(&self) -> i64 {
        i64::try_from(self.ttl.as_millis()).unwrap_or(10_000)
    }

    /// One round: heartbeat, then every partition's lease.
    async fn round(self: &Arc<Self>) {
        let me = self.peers.me.encode();
        let listed: Result<(i64, Vec<String>), _> = self
            .conn
            .query(
                redis::cmd("EVAL")
                    .arg(MEMBERS)
                    .arg(1)
                    .arg(self.members_key())
                    .arg(&me)
                    .arg(self.ttl_ms()),
            )
            .await;
        let Ok((added, members)) = listed else {
            // Valkey unreachable: keep running what this node owns; renewals resume when it is
            // back (a lease that lapses meanwhile is fenced by Iggy's epochs anyway).
            return;
        };
        let was_member = self.joined.swap(true, std::sync::atomic::Ordering::Relaxed);
        if added == 1 && was_member {
            // Registered before, gone now: Valkey lost its data (or this node stalled for a
            // lease period). Owners may not have re-registered yet: nobody counts as dead for a
            // while.
            *self
                .reset_at
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
        }
        let members: Vec<Member> = members.iter().filter_map(|s| Member::decode(s)).collect();
        {
            let mut seen = self
                .first_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            seen.retain(|id, _| members.iter().any(|m| m.id == *id));
            for m in &members {
                seen.entry(m.id).or_insert_with(Instant::now);
            }
        }
        self.peers
            .members
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&members);
        for p in 0..self.ctx.parts.count() {
            self.lease_round(&self.conn, &members, p, &me).await;
            // A partition whose standbys changed is copied to them now, not at its next write.
            if let Some(part) = self.ctx.parts.local(p)
                && !self.peers.all_synced(p)
            {
                let peers = Arc::clone(&self.peers);
                tokio::spawn(async move {
                    let _serial = part.shared.persist_lock.lock().await;
                    peers.replicate(p, Replica::default()).await;
                });
            }
        }
        self.drop_stale_copies(&members).await;
        self.rebalance(&members, &me).await;
    }

    /// Deletes this node's copies of key stores it is no longer a standby for (after three lease
    /// periods, so a passing change of members deletes nothing): keys nobody needs here must not
    /// stay on disk.
    async fn drop_stale_copies(&self, members: &[Member]) {
        let me = self.peers.me.id;
        for p in 0..self.ctx.parts.count() {
            let owner = self
                .remote_of
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&p)
                .cloned();
            let running = self.ctx.parts.local(p).is_some()
                || self
                    .starting
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&p);
            // Only for a partition with a live owner elsewhere that does not count on this node.
            let stale = !running
                && owner.is_some_and(|o| {
                    members.iter().any(|m| m.id == o.id)
                        && !standbys(members, p, o.id).iter().any(|m| m.id == me)
                });
            let t = {
                let mut since = self
                    .not_standby_since
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !stale {
                    since.remove(&p);
                    continue;
                }
                *since.entry(p).or_insert_with(Instant::now)
            };
            if t.elapsed() < self.ttl * 3 {
                continue;
            }
            let file = (self.peers.store_of)(p);
            let removed = tokio::task::spawn_blocking(move || {
                if file.has_store() {
                    file.remove_all().map(|()| true)
                } else {
                    Ok(false)
                }
            })
            .await;
            match removed {
                Ok(Ok(true)) => {
                    tracing::info!(
                        partition = p,
                        "mailbox key store copy deleted (no longer a standby)"
                    );
                }
                Ok(Ok(false)) => {}
                _ => tracing::warn!(partition = p, "mailbox key store copy could not be deleted"),
            }
            self.not_standby_since
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&p);
        }
    }

    /// Hands at most one partition per round to the node that should own it, once that node
    /// has been up two lease periods and holds the whole store (it is this partition's first
    /// standby): a node that joins takes its share; ownership never moves to a node without the
    /// keys.
    async fn rebalance(&self, members: &[Member], me: &str) {
        let busy = !self
            .starting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty();
        if busy {
            return;
        }
        for p in 0..self.ctx.parts.count() {
            if self.ctx.parts.local(p).is_none() {
                continue;
            }
            let Some(preferred) = ranked(members, p).first().map(|m| m.id) else {
                continue;
            };
            if preferred == self.peers.me.id || !self.peers.synced(p).contains(&preferred) {
                continue;
            }
            let settled = self
                .first_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&preferred)
                .is_some_and(|t| t.elapsed() >= self.ttl * 2);
            if !settled {
                continue;
            }
            if self.hand_over(p, me, true).await {
                tracing::info!(
                    partition = p,
                    "mailbox partition handed to its preferred node"
                );
            }
            return;
        }
    }

    /// Hands partition `p` over: its key store written and copied, its writer stopped, its
    /// lease released with a marker so the next owner takes it at once. With `strict`, nothing
    /// changes (false) unless a standby confirmed the copy.
    async fn hand_over(&self, p: u32, me: &str, strict: bool) -> bool {
        let Some(part) = self.ctx.parts.local(p) else {
            return false;
        };
        if part.shared.persist_keys().await.is_err() && strict {
            return false;
        }
        part.stop();
        self.ctx.parts.set(p, Slot::Unknown);
        // What the writer changed while it stopped (best effort: the next owner replays the log).
        let _ = part.shared.persist_keys().await;
        let _: Result<(), _> = self
            .conn
            .query(
                redis::cmd("SET")
                    .arg(self.released_key(p))
                    .arg(1)
                    .arg("PX")
                    .arg(self.ttl_ms()),
            )
            .await;
        let _: Result<i64, _> = self
            .conn
            .query(
                redis::cmd("EVAL")
                    .arg(RELEASE)
                    .arg(1)
                    .arg(self.lease_key(p))
                    .arg(me),
            )
            .await;
        true
    }

    async fn lease_round(
        self: &Arc<Self>,
        conn: &songbird_router::conn::ValkeyConn,
        members: &[Member],
        p: u32,
        me: &str,
    ) {
        let key = self.lease_key(p);
        let holder: Option<String> = conn.query(redis::cmd("GET").arg(&key)).await.ok().flatten();
        match holder {
            Some(h) if h == me => {
                let renewed: i64 = conn
                    .query(
                        redis::cmd("EVAL")
                            .arg(RENEW)
                            .arg(1)
                            .arg(&key)
                            .arg(me)
                            .arg(self.ttl_ms()),
                    )
                    .await
                    .unwrap_or(1);
                if renewed == 0 {
                    // Gone or taken. Gone (Valkey lost it): take it back and keep running. Taken
                    // by another node: stop (Iggy fences this writer anyway).
                    let retaken: Option<String> = conn
                        .query(
                            redis::cmd("SET")
                                .arg(&key)
                                .arg(me)
                                .arg("NX")
                                .arg("PX")
                                .arg(self.ttl_ms()),
                        )
                        .await
                        .ok()
                        .flatten();
                    if retaken.is_none() {
                        let now: Option<String> =
                            conn.query(redis::cmd("GET").arg(&key)).await.ok().flatten();
                        if now.as_deref().is_some_and(|h| h != me) {
                            self.give_up(p);
                        }
                    }
                }
            }
            Some(h) => {
                if let Some(owner) = Member::decode(&h) {
                    self.give_up(p);
                    self.point_at(p, &owner);
                }
                self.free_since
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&p);
            }
            None if self.ctx.parts.local(p).is_some() => {
                // Running here but the lease is gone (Valkey restarted without persistence):
                // take it back without restarting anything; if another node got it first, the
                // next round sees its holder and stops this writer (Iggy fences it anyway).
                let _: Option<String> = conn
                    .query(
                        redis::cmd("SET")
                            .arg(&key)
                            .arg(me)
                            .arg("NX")
                            .arg("PX")
                            .arg(self.ttl_ms()),
                    )
                    .await
                    .ok()
                    .flatten();
            }
            None => self.take_free(conn, members, p, key, me).await,
        }
    }

    /// Partition `p` has no lease: take it if this node should.
    async fn take_free(
        self: &Arc<Self>,
        conn: &songbird_router::conn::ValkeyConn,
        members: &[Member],
        p: u32,
        key: String,
        me: &str,
    ) {
        let first_free = *self
            .free_since
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(p)
            .or_insert_with(Instant::now);
        let old_owner = self
            .remote_of
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p)
            .cloned();
        let wait = match old_owner {
            // No owner seen since this node started (a new cluster, or this node just joined):
            // the first-ranked member takes it.
            None => {
                let preferred = ranked(members, p)
                    .first()
                    .is_none_or(|m| m.id == self.peers.me.id);
                if preferred {
                    Duration::ZERO
                } else {
                    self.ttl * 3
                }
            }
            Some(owner) => {
                let alive = members.iter().any(|m| m.id == owner.id);
                let released = conn
                    .query::<bool>(redis::cmd("EXISTS").arg(self.released_key(p)))
                    .await
                    .unwrap_or(false);
                // The owner's standbys hold its key store: the first live one goes first, the
                // next one a lease period later (if the first cannot), anyone else after three.
                let mut all = members.to_vec();
                if !alive {
                    all.push(owner.clone());
                }
                let file = (self.peers.store_of)(p);
                let has_copy = tokio::task::spawn_blocking(move || file.has_store())
                    .await
                    .unwrap_or(false);
                let rank = standbys(&all, p, owner.id)
                    .iter()
                    .position(|m| m.id == self.peers.me.id)
                    .filter(|_| has_copy);
                let base = match rank {
                    Some(0) => Duration::ZERO,
                    Some(_) => self.ttl,
                    None => self.ttl * 3,
                };
                // Not handed over on purpose and the owner may be alive (still a member, or
                // Valkey just lost everything and it has not registered again): it gets a lease
                // period to take its lease back.
                let reset = self
                    .reset_at
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_some_and(|t| t.elapsed() < self.ttl * 2);
                if !released && (alive || reset) {
                    base + self.ttl
                } else {
                    base
                }
            }
        };
        if first_free.elapsed() < wait {
            return;
        }
        let took: Option<String> = conn
            .query(
                redis::cmd("SET")
                    .arg(&key)
                    .arg(me)
                    .arg("NX")
                    .arg("PX")
                    .arg(self.ttl_ms()),
            )
            .await
            .ok()
            .flatten();
        if took.is_some() {
            self.take(p, key, me.to_owned());
        }
    }

    /// Points partition `p` at its owner on another node.
    fn point_at(&self, p: u32, owner: &Member) {
        let mut remote = self
            .remote_of
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if remote.get(&p).map(|m| m.id) != Some(owner.id) {
            let link: Arc<dyn Peer> = self.peers.link(owner);
            self.ctx.parts.set(p, Slot::Remote(link));
            remote.insert(p, owner.clone());
        }
    }

    /// This node lost (or never had) partition `p`: its writer stops.
    fn give_up(&self, p: u32) {
        if let Some(part) = self.ctx.parts.local(p) {
            part.stop();
            self.ctx.parts.set(p, Slot::Unknown);
            tracing::warn!(
                partition = p,
                "mailbox partition lease lost; writer stopped"
            );
        }
    }

    /// Starts partition `p` (this node holds its lease now).
    fn take(self: &Arc<Self>, p: u32, key: String, me: String) {
        if !self
            .starting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(p)
        {
            return;
        }
        let c = Arc::clone(self);
        tokio::spawn(async move {
            match start_partition(&c.ctx, p).await {
                Ok((part, homes)) => {
                    c.ctx.parts.set(p, Slot::Local(part));
                    c.remote_of
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&p);
                    super::resume_parts(&c.ctx.parts, vec![(p, homes)]).await;
                    tracing::info!(partition = p, "mailbox partition taken over");
                }
                Err(e) => {
                    tracing::error!(partition = p, error = %e, "mailbox partition could not start");
                    let _: Result<i64, _> = c
                        .conn
                        .query(redis::cmd("EVAL").arg(RELEASE).arg(1).arg(&key).arg(&me))
                        .await;
                }
            }
            c.starting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&p);
        });
    }

    /// Graceful shutdown: every owned partition's key store is written (and replicated), its
    /// writer stopped and its lease released, so the standby takes over at once.
    pub(crate) async fn shutdown(&self) {
        let me = self.peers.me.encode();
        for p in 0..self.ctx.parts.count() {
            self.hand_over(p, &me, false).await;
        }
        let _: Result<i64, _> = self
            .conn
            .query(redis::cmd("ZREM").arg(self.members_key()).arg(&me))
            .await;
        let _ = self.stop.send(true);
    }

    /// Stops everything at once without writing or releasing (tests: a killed node).
    pub(crate) fn crash(&self) {
        let _ = self.stop.send(true);
        for p in 0..self.ctx.parts.count() {
            if let Some(part) = self.ctx.parts.local(p) {
                part.stop();
                self.ctx.parts.set(p, Slot::Unknown);
            }
        }
    }

    /// Live members this node sees (itself included).
    pub(crate) fn members(&self) -> usize {
        self.peers.members().len()
    }

    /// Whether every partition this node owns has its key store on its current standby (true
    /// when there is no other node).
    pub(crate) fn standbys_synced(&self) -> bool {
        (0..self.ctx.parts.count())
            .filter(|p| self.ctx.parts.local(*p).is_some())
            .all(|p| self.peers.all_synced(p))
    }

    /// Key-store writes that did not reach a standby.
    pub(crate) fn replica_failures(&self) -> u64 {
        self.peers
            .replica_failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    fn m(id: u64) -> Member {
        mz(id, "")
    }

    fn mz(id: u64, zone: &str) -> Member {
        Member {
            id,
            zone: zone.into(),
            name: format!("delivery.n{id}.songbird.internal"),
            addr: "127.0.0.1:1".parse().unwrap(),
        }
    }

    #[test]
    fn members_round_trip() {
        let a = mz(42, "fsn1-dc14");
        assert_eq!(Member::decode(&a.encode()), Some(a));
        assert_eq!(Member::decode(&m(7).encode()), Some(m(7)));
        assert_eq!(Member::decode("zz|x|y|z"), None);
        assert_eq!(Member::decode("00000000000000ff|z|name"), None);
    }

    #[test]
    fn zone_names() {
        assert!(zone_ok(""));
        assert!(zone_ok("fsn1-dc14"));
        assert!(!zone_ok("A"));
        assert!(!zone_ok("a|b"));
        assert!(!zone_ok(&"a".repeat(33)));
    }

    #[test]
    fn two_standbys_never_the_owner_and_the_second_in_another_zone() {
        let ms = [
            mz(1, "a"),
            mz(2, "a"),
            mz(3, "a"),
            mz(4, "b"),
            mz(5, "b"),
            mz(6, "c"),
        ];
        let zone = |id: u64| ms.iter().find(|m| m.id == id).unwrap().zone.clone();
        for p in 0..500 {
            let owner = ranked(&ms, p)[0].id;
            let sb = standbys(&ms, p, owner);
            assert_eq!(sb.len(), 2);
            assert!(sb.iter().all(|m| m.id != owner));
            assert_ne!(sb[0].id, sb[1].id);
            // The first standby is the next-ranked node: with the owner gone it ranks first, so
            // the node that takes over holds the keys.
            let without: Vec<Member> = ms.iter().filter(|m| m.id != owner).cloned().collect();
            assert_eq!(ranked(&without, p)[0].id, sb[0].id);
            // The second is in a third zone whenever one exists.
            assert_ne!(sb[1].zone, zone(owner), "p={p}");
            assert_ne!(sb[1].zone, sb[0].zone, "p={p}");
        }
        // Fewer nodes than copies: as many standbys as there are other nodes.
        assert_eq!(standbys(&[m(1), m(2)], 0, 1).len(), 1);
        assert_eq!(standbys(&[m(1)], 0, 1), Vec::<&Member>::new());
        // No other zone: the next-ranked node.
        assert_eq!(standbys(&[m(1), m(2), m(3)], 0, 1).len(), 2);
    }

    #[test]
    fn rendezvous_spreads_partitions_and_moves_few_when_a_node_leaves() {
        let three = [m(1), m(2), m(3)];
        let two = [m(1), m(2)];
        let owner = |ms: &[Member], p| ranked(ms, p)[0].id;
        let mut counts = HashMap::new();
        let mut moved = 0;
        for p in 0..300 {
            *counts.entry(owner(&three, p)).or_insert(0) += 1;
            if owner(&three, p) != 3 && owner(&three, p) != owner(&two, p) {
                moved += 1;
            }
            // The standby is never the owner.
            let r = ranked(&three, p);
            assert_ne!(r[0].id, r[1].id);
        }
        assert!(counts.values().all(|c| *c > 60), "{counts:?}");
        // Only node 3's partitions move when it leaves.
        assert_eq!(moved, 0);
    }
}
