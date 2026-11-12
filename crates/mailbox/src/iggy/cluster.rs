//! Cluster mode (D-0034): several delivery nodes share the mailbox topic; each partition has one
//! owner node, which runs its writer, and one standby node, which receives every key-store write.
//!
//! - **Membership**: each node keeps itself in a Valkey sorted set with an expiry score.
//! - **Leases**: partition `p` is owned by whoever holds `lease:<p>` (`SET NX PX`, renewed and
//!   released by compare-and-set scripts). Iggy's producer epochs still fence a writer that lost
//!   its lease but has not noticed yet (D-0029): a lease is an optimisation, not the guard.
//! - **Who takes a free partition**: its preferred node by rendezvous hashing over the live
//!   members; any other node takes it after a lease period if the preferred one does not. The
//!   second choice is the standby. Ownership is sticky: a partition stays with its owner while it
//!   lives (no handover of live partitions yet).
//! - **Failover**: the owner dies; its lease expires; the standby (which holds the replicated key
//!   store) takes the lease, replays the log and fences the old writer.
//! - Everything crosses nodes over node links (mutual TLS, `delivery.` identities only).

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
}

impl std::fmt::Debug for ClusterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterConfig")
            .field("lease_ttl", &self.lease_ttl)
            .finish_non_exhaustive()
    }
}

/// A live node.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    id: u64,
    name: String,
    addr: SocketAddr,
}

impl Member {
    fn encode(&self) -> String {
        format!("{:016x}|{}|{}", self.id, self.name, self.addr)
    }

    fn decode(s: &str) -> Option<Self> {
        let mut it = s.splitn(3, '|');
        let id = u64::from_str_radix(it.next()?, 16).ok()?;
        let name = it.next()?.to_owned();
        let addr = it.next()?.parse().ok()?;
        Some(Self { id, name, addr })
    }
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

/// Members in preference order for partition `p` (owner first, standby second).
fn ranked(members: &[Member], p: u32) -> Vec<&Member> {
    let mut v: Vec<&Member> = members.iter().collect();
    v.sort_by_key(|m| std::cmp::Reverse((weight(m.id, p), m.id)));
    v
}

/// A node link to another member, as a [`Peer`].
struct LinkPeer {
    client: LinkClient,
    timeout: Duration,
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
    /// The standby each partition's store was last copied to in full.
    synced: Mutex<HashMap<u32, u64>>,
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

    /// The standby of `p`: the best-ranked live member other than this node.
    fn standby(&self, p: u32) -> Option<Member> {
        let members = self.members();
        ranked(&members, p)
            .into_iter()
            .find(|m| m.id != self.me.id)
            .cloned()
    }
}

impl Replicator for Peers {
    fn replicate(&self, p: u32, replica: Replica) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let Some(standby) = self.standby(p) else {
                // Alone: nothing to replicate to (the cluster has one node).
                return;
            };
            let synced = self
                .synced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&p)
                == Some(&standby.id);
            // A new standby gets the whole store first (it already holds this write's files).
            let replica = if synced {
                replica
            } else {
                let file = (self.store_of)(p);
                match tokio::task::spawn_blocking(move || file.snapshot()).await {
                    Ok(Ok(Some(full))) => full,
                    _ => replica,
                }
            };
            let req = Request::KeyStore {
                p,
                files: replica
                    .files
                    .into_iter()
                    .map(|(n, b)| (n, Bytes::from(b)))
                    .collect(),
                remove: replica.remove,
            };
            let ok = matches!(
                self.link(&standby).call(req).await,
                Ok(Response::Done(Ok(())))
            );
            let mut s = self
                .synced
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if ok {
                s.insert(p, standby.id);
            } else {
                // Copied whole next time.
                s.remove(&p);
                drop(s);
                self.replica_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    partition = p,
                    "mailbox key store not replicated to its standby"
                );
            }
        })
    }
}

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
    /// The member each remote slot points at.
    remote_of: Mutex<HashMap<u32, u64>>,
    link_stats: Arc<LinkStats>,
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
        let me = Member {
            id: u64::from_be_bytes(id),
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
            link_stats: Arc::new(LinkStats::default()),
            stop,
        });
        let handler = Cluster::handler(&cluster);
        tokio::spawn(songbird_link::serve(
            listener,
            self.cfg.link_tls,
            "delivery.".into(),
            handler,
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
                    Request::KeyStore { p, files, remove } => {
                        c.apply_replica(p, files, remove).await
                    }
                    other => partitions::serve(&c.ctx.parts, other).await,
                };
                resp.encode()
            })
        })
    }

    async fn apply_replica(
        &self,
        p: u32,
        files: Vec<(String, Bytes)>,
        remove: Vec<String>,
    ) -> Response {
        // Never over a partition this node runs (that store is live here).
        if self.ctx.parts.local(p).is_some() || p >= self.ctx.parts.count() {
            return Response::Done(Err(MailboxError::Unavailable));
        }
        let cfg = &self.ctx.cfg;
        let file = KeyFile::new(&cfg.key_dir, &cfg.stream, &cfg.topic, p, cfg.master_key);
        let replica = Replica {
            files: files.into_iter().map(|(n, b)| (n, b.to_vec())).collect(),
            remove,
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

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }

    fn ttl_ms(&self) -> i64 {
        i64::try_from(self.ttl.as_millis()).unwrap_or(10_000)
    }

    /// One round: heartbeat, then every partition's lease.
    async fn round(self: &Arc<Self>) {
        let now = Self::now_ms();
        let me = self.peers.me.encode();
        let members: Result<Vec<String>, _> = self
            .conn
            .query_pipe::<(Vec<String>,)>(
                redis::pipe()
                    .cmd("ZADD")
                    .arg(self.members_key())
                    .arg(now + self.ttl_ms())
                    .arg(&me)
                    .ignore()
                    .cmd("ZREMRANGEBYSCORE")
                    .arg(self.members_key())
                    .arg("-inf")
                    .arg(now)
                    .ignore()
                    .cmd("ZRANGEBYSCORE")
                    .arg(self.members_key())
                    .arg(now)
                    .arg("+inf"),
            )
            .await
            .map(|(m,)| m);
        let Ok(members) = members else {
            // Valkey unreachable: keep running what this node owns; renewals resume when it is
            // back (a lease that lapses meanwhile is fenced by Iggy's epochs anyway).
            return;
        };
        let members: Vec<Member> = members.iter().filter_map(|s| Member::decode(s)).collect();
        self.peers
            .members
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&members);
        for p in 0..self.ctx.parts.count() {
            self.lease_round(&self.conn, &members, p, &me).await;
            // A partition whose standby changed is copied to it now, not at its next write.
            if let Some(part) = self.ctx.parts.local(p) {
                let synced = self.peers.standby(p).is_none_or(|s| {
                    self.peers
                        .synced
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(&p)
                        == Some(&s.id)
                });
                if !synced {
                    let peers = Arc::clone(&self.peers);
                    tokio::spawn(async move {
                        let _serial = part.shared.persist_lock.lock().await;
                        peers.replicate(p, Replica::default()).await;
                    });
                }
            }
        }
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
        let preferred = ranked(members, p)
            .first()
            .is_none_or(|m| m.id == self.peers.me.id);
        // A partition with a known owner that suddenly looks free (Valkey lost the
        // lease) waits a lease period: its owner takes it back first, instead of a
        // needless handover.
        let had_owner = self
            .remote_of
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&p);
        let released = had_owner
            && conn
                .query::<bool>(redis::cmd("EXISTS").arg(self.released_key(p)))
                .await
                .unwrap_or(false);
        if (!preferred || (had_owner && !released)) && first_free.elapsed() < self.ttl {
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
        if remote.get(&p) != Some(&owner.id) {
            let link: Arc<dyn Peer> = self.peers.link(owner);
            self.ctx.parts.set(p, Slot::Remote(link));
            remote.insert(p, owner.id);
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
            if let Some(part) = self.ctx.parts.local(p) {
                let _ = part.shared.persist_keys().await;
                part.stop();
                self.ctx.parts.set(p, Slot::Unknown);
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
                            .arg(&me),
                    )
                    .await;
            }
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
        let synced = self
            .peers
            .synced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        (0..self.ctx.parts.count())
            .filter(|p| self.ctx.parts.local(*p).is_some())
            .all(|p| {
                self.peers
                    .standby(p)
                    .is_none_or(|s| synced.get(&p) == Some(&s.id))
            })
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
        Member {
            id,
            name: format!("delivery.n{id}.songbird.internal"),
            addr: "127.0.0.1:1".parse().unwrap(),
        }
    }

    #[test]
    fn members_round_trip() {
        let a = m(42);
        assert_eq!(Member::decode(&a.encode()), Some(a));
        assert_eq!(Member::decode("zz|x|y"), None);
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
