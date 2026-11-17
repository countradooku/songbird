//! Songbird `worker`: background jobs (D-0036).
//!
//! - **Account deletion** (`j:deletion`, written through the outbox when `api` accepts the
//!   request), every step idempotent, so a crash or a retry repeats it safely:
//!   1. the account's devices (disabled by `api` already, so no new session authenticates);
//!   2. `delivery` closes their sessions on every node and forgets their mailboxes (pending
//!      envelopes acknowledged, so their keys are punctured; counters dropped);
//!   3. their push registrations, pending upload grants and the grants' partial objects go;
//!   4. after the directory has propagated to every delivery node, the mailboxes are forgotten
//!      again (a send that raced the deletion stored nothing that survives);
//!   5. verification: the mailbox knows none of the devices and no object of a grant is left;
//!      then the device and account rows go, and the registry is checked to hold nothing of
//!      them. Anything left fails the job, which is retried, then dead-lettered (alert).
//!
//!   Attachments already sent are not linked to the account (the threat model's attachment row);
//!   they go when fetched or after 30 days. Backups are M6's.
//! - **Attachment cleanup** (`j:cleanup`): an object fetched by every recipient is deleted with
//!   its record.
//! - **Sweeps** (every minute): attachments past 30 days or fully fetched, expired upload grants
//!   with their partial objects, and the outbox relay.
//!
//! Nothing here logs identifiers or object names (invariant 6).
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use songbird_accounts::{Registry, push_index};
use songbird_jobs::{Job, ObjectKey, Outcome, Queue, Work};
use songbird_link::devices::{DeviceRequest, decode_response};
use songbird_link::{Handler, LinkClient};
use songbird_service::telemetry::sharded::ShardedCounter as Counter;
use songbird_types::{AccountId, DeviceId};

/// How long one delivery request may take.
const LINK_TIMEOUT: Duration = Duration::from_secs(10);
/// Items handled per sweep pass.
const SWEEP_BATCH: usize = 500;

/// How `worker` reaches `delivery`'s device link.
pub enum DeliveryLink {
    /// Node links (mutual TLS); any node forwards to the partition owners, so the first that
    /// answers is enough.
    Nodes(Vec<LinkClient>),
    /// In process (tests).
    Direct(Handler),
}

impl std::fmt::Debug for DeliveryLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nodes(n) => f.debug_tuple("Nodes").field(&n.len()).finish(),
            Self::Direct(_) => f.write_str("Direct"),
        }
    }
}

impl DeliveryLink {
    async fn call(&self, req: &DeviceRequest, n: usize) -> Result<Vec<bool>, ()> {
        let payload = req.encode();
        match self {
            Self::Direct(h) => {
                let r = h(Bytes::from(payload)).await;
                decode_response(&r, n).unwrap_or(Err(()))
            }
            Self::Nodes(nodes) => {
                for node in nodes {
                    if let Ok(r) = node.call(&payload, LINK_TIMEOUT).await
                        && let Some(Ok(v)) = decode_response(&r, n)
                    {
                        return Ok(v);
                    }
                }
                Err(())
            }
        }
    }

    /// Closes the devices' sessions and forgets their mailboxes.
    ///
    /// # Errors
    /// No delivery node did it.
    pub async fn forget(&self, devices: &[DeviceId]) -> Result<(), Left> {
        if devices.is_empty() {
            return Ok(());
        }
        self.call(&DeviceRequest::Forget(devices.to_vec()), 0)
            .await
            .map(|_| ())
            .map_err(|()| Left::Unavailable)
    }

    /// Whether the mailbox still holds anything of any of the devices.
    ///
    /// # Errors
    /// No delivery node answered.
    pub async fn any_known(&self, devices: &[DeviceId]) -> Result<bool, Left> {
        if devices.is_empty() {
            return Ok(false);
        }
        let known = self
            .call(&DeviceRequest::Known(devices.to_vec()), devices.len())
            .await
            .map_err(|()| Left::Unavailable)?;
        Ok(known.iter().any(|k| *k))
    }
}

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct WorkerMetrics {
    /// Accounts deleted and verified gone from every store.
    pub deletions_verified: Counter,
    /// Deletion attempts that found something left or a store unreachable (retried).
    pub deletion_retries: Counter,
    /// Attachment objects deleted.
    pub objects_deleted: Counter,
    /// Expired upload grants removed.
    pub grants_expired: Counter,
    /// Multipart uploads aborted because their grant is gone (Prompt 6, M2).
    pub uploads_aborted: Counter,
    /// Removed devices deleted and verified gone (one per job).
    pub devices_deleted: Counter,
    /// Accounts whose deletion started for inactivity.
    pub inactive_deleted: Counter,
}

impl WorkerMetrics {
    /// Registers every metric.
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            (
                "worker_deletions_verified",
                "Accounts deleted and verified gone from every store",
                &self.deletions_verified,
            ),
            (
                "worker_deletion_retries",
                "Account deletion attempts retried",
                &self.deletion_retries,
            ),
            (
                "worker_objects_deleted",
                "Attachment objects deleted",
                &self.objects_deleted,
            ),
            (
                "worker_inactive_deleted",
                "Account deletions started for inactivity",
                &self.inactive_deleted,
            ),
            (
                "worker_devices_deleted",
                "Removed devices deleted and verified gone",
                &self.devices_deleted,
            ),
            (
                "worker_grants_expired",
                "Expired upload grants removed",
                &self.grants_expired,
            ),
            (
                "worker_uploads_aborted",
                "Multipart uploads aborted after their grant was gone",
                &self.uploads_aborted,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// Everything the jobs need.
#[derive(Debug)]
pub struct Worker {
    /// Account registry.
    pub registry: Arc<Registry>,
    /// Attachment store (the worker's own credential).
    pub s3: songbird_s3::Client,
    /// Job queue.
    pub queue: Arc<Queue>,
    /// Delivery's device link.
    pub delivery: DeliveryLink,
    /// Push-token row key.
    pub push_index_secret: [u8; 32],
    /// The deletion journal (D-0041); `None` only in development.
    pub journal: Option<Journal>,
    /// How long every delivery node takes to drop a disabled device (its directory poll
    /// interval with a margin).
    pub propagation: Duration,
    /// The akd writer (Prompt 3, D-0057); `None` publishes nothing.
    pub kt: Option<Arc<songbird_akd::Publisher>>,
    /// The keys of block rows (Prompt 4, D-0062): an account's blocks are found by its keyed
    /// owner tag. `None` only in development (no blocks exist without `[api.requests]`).
    pub block_keys: Option<songbird_accounts::blocks::GateKeys>,
    /// Metrics.
    pub metrics: WorkerMetrics,
}

/// The deletion journal's writer (D-0041): before an account is deleted, an empty, write-once
/// tombstone named by its keyed tag goes to the off-site backup bucket, so a restore of an older
/// backup deletes it again. Its credential can only put under `deletions/`.
#[derive(Debug)]
pub struct Journal {
    /// The backup bucket (the journal's own put-only credential).
    pub s3: songbird_s3::Client,
    /// The journal key (tags are HMAC-SHA256 under it).
    pub key: [u8; 32],
}

impl Journal {
    /// Writes the account's tombstone, locked for the longest backup retention.
    ///
    /// # Errors
    /// The bucket refused or was unreachable: the deletion must not proceed.
    pub async fn record(&self, account: &AccountId) -> Result<(), songbird_s3::Error> {
        use songbird_accounts::journal;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let name = journal::tombstone_name(
            &songbird_s3::sigv4::amz_date(now),
            &journal::tag(&self.key, account),
        );
        let mut empty_sha = [0u8; 32];
        empty_sha
            .copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"").as_ref());
        self.s3
            .put_object_with(
                &name,
                0,
                futures_util::stream::empty::<Result<Bytes, std::convert::Infallible>>(),
                songbird_s3::PutOptions {
                    retain_until: Some(now + journal::RETENTION.as_secs()),
                    sha256: Some(empty_sha),
                },
            )
            .await
    }
}

/// What a deletion step found wrong (never an identifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Left {
    /// A store was unreachable.
    Unavailable,
    /// The mailbox still knows a device.
    Mailbox,
    /// An upload object is still stored.
    Objects,
    /// Registry rows remain.
    Rows,
}

/// An avatar's object name (as `api` writes it, `songbird_api::profiles::avatar_name`).
fn avatar_name(id: &[u8; 32]) -> String {
    let mut name = String::with_capacity(66);
    name.push_str("p/");
    name.push_str(&ObjectKey(*id).to_hex_unredacted());
    name
}

/// An attachment's object name (as `api` writes it).
fn object_name(o: &ObjectKey) -> String {
    let mut name = String::with_capacity(66);
    name.push_str("a/");
    name.push_str(&o.to_hex_unredacted());
    name
}

impl Worker {
    /// Runs one job.
    pub async fn handle(&self, job: Job) -> Outcome {
        match job.work {
            Work::DeleteAccount { account } => match self.delete_account(&account).await {
                Ok(()) => {
                    self.metrics.deletions_verified.inc();
                    Outcome::Done
                }
                Err(left) => {
                    self.metrics.deletion_retries.inc();
                    tracing::warn!(?left, "account deletion incomplete; retrying");
                    Outcome::Retry(None)
                }
            },
            Work::DeleteDevices { account } => match self.delete_devices(&account).await {
                Ok(()) => {
                    self.metrics.devices_deleted.inc();
                    Outcome::Done
                }
                Err(left) => {
                    self.metrics.deletion_retries.inc();
                    tracing::warn!(?left, "device deletion incomplete; retrying");
                    Outcome::Retry(None)
                }
            },
            Work::DeleteObject { object } => match self.delete_object(&object).await {
                Ok(()) => Outcome::Done,
                Err(_) => Outcome::Retry(None),
            },
            // Not this service's stream.
            Work::Push { .. } => Outcome::Dead,
        }
    }

    /// Deletes an account from every store and verifies it (see the module documentation).
    ///
    /// # Errors
    /// [`Left`]: what is still there; the job is retried.
    pub async fn delete_account(&self, account: &AccountId) -> Result<(), Left> {
        let unavailable = |_| Left::Unavailable;
        // First, before anything is gone: the tombstone that keeps it gone after a restore.
        if let Some(j) = &self.journal {
            j.record(account).await.map_err(|_| Left::Unavailable)?;
        }
        let devices = self
            .registry
            .account_devices(account)
            .await
            .map_err(unavailable)?;
        let index: Vec<[u8; 32]> = devices
            .iter()
            .map(|d| push_index(&self.push_index_secret, d))
            .collect();
        self.delivery.forget(&devices).await?;
        self.registry
            .delete_push_tokens(&index)
            .await
            .map_err(unavailable)?;
        let grants = self
            .registry
            .grants_of(&devices)
            .await
            .map_err(unavailable)?;
        for g in &grants {
            self.s3
                .delete_object(&object_name(g))
                .await
                .map_err(|_| Left::Unavailable)?;
            self.registry.delete_grant(g).await.map_err(unavailable)?;
        }
        // Encrypted avatars (Prompt 3, M5): every object the account uploaded.
        let avatars = self
            .registry
            .avatars_of(account)
            .await
            .map_err(unavailable)?;
        for a in &avatars {
            self.s3
                .delete_object(&avatar_name(a))
                .await
                .map_err(|_| Left::Unavailable)?;
        }
        // Every delivery node has dropped the devices: forget again what a racing send stored.
        tokio::time::sleep(self.propagation).await;
        self.delivery.forget(&devices).await?;
        if self.delivery.any_known(&devices).await? {
            return Err(Left::Mailbox);
        }
        for name in grants
            .iter()
            .map(object_name)
            .chain(avatars.iter().map(avatar_name))
        {
            if self
                .s3
                .head_object(&name)
                .await
                .map_err(|_| Left::Unavailable)?
                .is_some()
            {
                return Err(Left::Objects);
            }
        }
        // The account's blocks (Prompt 4): rows named by keyed hashes, found by its owner tag.
        if let Some(k) = &self.block_keys {
            let owner = k.owner(account);
            self.registry
                .delete_blocks(&owner)
                .await
                .map_err(unavailable)?;
            if self
                .registry
                .block_count(&owner)
                .await
                .map_err(unavailable)?
                != 0
            {
                return Err(Left::Rows);
            }
        }
        self.registry
            .delete_account_rows(account)
            .await
            .map_err(unavailable)?;
        let r = self
            .registry
            .remnants(account, &devices, &index)
            .await
            .map_err(unavailable)?;
        if !r.is_empty() {
            return Err(Left::Rows);
        }
        Ok(())
    }

    /// Deletes an account's removed devices (Prompt 3, M4, D-0052) from every store and
    /// verifies it, as an account deletion does for all its devices: the mailbox forgets them
    /// (twice, around the directory's propagation, for a racing send), their push tokens and
    /// upload grants go, then their rows, prekeys and KeyPackages. The account and its enabled
    /// devices are untouched; nothing to do is success (the job repeats harmlessly).
    ///
    /// # Errors
    /// [`Left`]: what is still there; the job is retried.
    pub async fn delete_devices(&self, account: &AccountId) -> Result<(), Left> {
        let unavailable = |_| Left::Unavailable;
        let devices = self
            .registry
            .removed_devices(account)
            .await
            .map_err(unavailable)?;
        if devices.is_empty() {
            return Ok(());
        }
        let index: Vec<[u8; 32]> = devices
            .iter()
            .map(|d| push_index(&self.push_index_secret, d))
            .collect();
        self.delivery.forget(&devices).await?;
        self.registry
            .delete_push_tokens(&index)
            .await
            .map_err(unavailable)?;
        let grants = self
            .registry
            .grants_of(&devices)
            .await
            .map_err(unavailable)?;
        for g in &grants {
            self.s3
                .delete_object(&object_name(g))
                .await
                .map_err(|_| Left::Unavailable)?;
            self.registry.delete_grant(g).await.map_err(unavailable)?;
        }
        tokio::time::sleep(self.propagation).await;
        self.delivery.forget(&devices).await?;
        if self.delivery.any_known(&devices).await? {
            return Err(Left::Mailbox);
        }
        for g in &grants {
            if self
                .s3
                .head_object(&object_name(g))
                .await
                .map_err(|_| Left::Unavailable)?
                .is_some()
            {
                return Err(Left::Objects);
            }
        }
        self.registry
            .delete_device_rows(&devices)
            .await
            .map_err(unavailable)?;
        let left = self
            .registry
            .device_remnants(&devices)
            .await
            .map_err(unavailable)?;
        let tokens = self
            .registry
            .remnants(account, &[], &index)
            .await
            .map_err(unavailable)?
            .push_tokens;
        let grants_left = self
            .registry
            .grants_of(&devices)
            .await
            .map_err(unavailable)?;
        if left != 0 || tokens != 0 || !grants_left.is_empty() {
            return Err(Left::Rows);
        }
        Ok(())
    }

    /// Inactivity deletion (Prompt 3, M7, D-0056): a wake-up push to every device of an
    /// account a month and a week before its period ends (the app wakes, makes a request and
    /// the account counts as used again), then the account's deletion through the outbox, as if
    /// it had asked itself.
    pub async fn inactivity(&self) {
        let found = match self.registry.inactive(SWEEP_BATCH).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "inactivity pass failed");
                return;
            }
        };
        for (level, list) in [(1u8, &found.warn_month), (2u8, &found.warn_week)] {
            for (account, devices) in list {
                let jobs: Vec<Job> = devices
                    .iter()
                    .filter_map(|d| {
                        Job::new(Work::Push {
                            device: *d,
                            call: false,
                        })
                        .ok()
                    })
                    .collect();
                if self.queue.enqueue(&jobs).await.is_ok() {
                    let _ = self.registry.mark_warned(account, level).await;
                }
            }
        }
        for account in &found.expired {
            let Ok(job) = Job::new(Work::DeleteAccount { account: *account }) else {
                continue;
            };
            if let Err(e) = self.registry.begin_account_deletion(account, &job).await {
                tracing::warn!(error = %e, "inactive account deletion not started");
            }
        }
        if !found.expired.is_empty() {
            self.metrics
                .inactive_deleted
                .inc_by(u64::try_from(found.expired.len()).unwrap_or(u64::MAX));
        }
    }

    /// Deletes an attachment object, then its record (idempotent).
    ///
    /// # Errors
    /// The store or the registry failed.
    pub async fn delete_object(&self, object: &ObjectKey) -> Result<(), Left> {
        self.s3
            .delete_object(&object_name(object))
            .await
            .map_err(|_| Left::Unavailable)?;
        self.registry
            .delete_attachment(object)
            .await
            .map_err(|_| Left::Unavailable)?;
        self.metrics.objects_deleted.inc();
        Ok(())
    }

    /// Aborts multipart uploads whose grant is gone: expired, completed, or its device or
    /// account deleted (Prompt 6, M2, D-0081). No part outlives its grant by more than a sweep.
    ///
    /// An upload whose grant still exists without a recorded upload is left alone: `api` may be
    /// between creating it and recording it. Once the grant expires, the next sweep aborts it.
    pub async fn abort_abandoned_uploads(&self) {
        let uploads = match self.s3.list_multipart_uploads("a/").await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "multipart sweep failed");
                return;
            }
        };
        for u in uploads {
            let Some(object) = u.key.strip_prefix("a/").and_then(ObjectKey::parse_hex) else {
                continue;
            };
            let keep = match self.registry.pending_upload(&object).await {
                Ok(Some(p)) => p.upload.as_deref().is_none_or(|id| id == u.upload_id),
                Ok(None) => false,
                Err(_) => true,
            };
            if !keep
                && self
                    .s3
                    .abort_multipart_upload(&u.key, &u.upload_id)
                    .await
                    .is_ok()
            {
                self.metrics.uploads_aborted.inc();
            }
        }
    }

    /// One sweep:attachments past 30 days or fully fetched, expired grants, expired invite
    /// codes, expired KeyPackages, expired link tokens, released usernames whose hold ended, the outbox.
    pub async fn sweep(&self) {
        // Queued reports past their retention (Prompt 4, D-0063).
        if let Ok(n) = self.registry.sweep_reports().await
            && n > 0
        {
            tracing::info!(n, "expired reports deleted");
        }
        match self.registry.expired_attachments(SWEEP_BATCH).await {
            Ok(objects) => {
                for o in objects {
                    let _ = self.delete_object(&o).await;
                }
            }
            Err(e) => tracing::warn!(error = %e, "attachment sweep failed"),
        }
        match self.registry.expired_grants(SWEEP_BATCH).await {
            Ok(grants) => {
                for g in grants {
                    if self.s3.delete_object(&object_name(&g)).await.is_ok()
                        && self.registry.delete_grant(&g).await.is_ok()
                    {
                        self.metrics.grants_expired.inc();
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "grant sweep failed"),
        }
        self.abort_abandoned_uploads().await;
        // Expired codes are refused already; this only stops them taking space.
        if let Err(e) = self.registry.delete_expired_invites(SWEEP_BATCH).await {
            tracing::warn!(error = %e, "invite sweep failed");
        }
        // Expired KeyPackages are never served; this only stops them taking space.
        if let Err(e) = self.registry.delete_expired_key_packages(SWEEP_BATCH).await {
            tracing::warn!(error = %e, "key package sweep failed");
        }
        // Replaced avatars (Prompt 3, M5): objects that are no account's current one.
        match self.registry.stale_avatars(SWEEP_BATCH).await {
            Ok(ids) => {
                for id in ids {
                    if self.s3.delete_object(&avatar_name(&id)).await.is_ok() {
                        let _ = self.registry.delete_avatar(&id).await;
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "avatar sweep failed"),
        }
        self.inactivity().await;
        // Key transparency (Prompt 3, D-0057): publish what changed as one akd epoch.
        if let Some(kt) = &self.kt
            && let Err(e) = kt.publish_pending(&self.registry, SWEEP_BATCH).await
        {
            tracing::warn!(error = %e, "transparency publish failed");
        }
        // Expired link tokens are refused already; this only stops them taking space.
        if let Err(e) = self.registry.delete_expired_link_tokens(SWEEP_BATCH).await {
            tracing::warn!(error = %e, "link token sweep failed");
        }
        // Released usernames whose hold ended become claimable again.
        if let Err(e) = self.registry.delete_released_usernames(SWEEP_BATCH).await {
            tracing::warn!(error = %e, "username sweep failed");
        }
        if let Err(e) = songbird_jobs::relay(self.registry.as_ref(), &self.queue).await {
            tracing::warn!(error = %e, "outbox relay failed");
        }
    }
}
