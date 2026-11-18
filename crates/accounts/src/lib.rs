//! The account registry in SurrealDB (D-0036).
//!
//! A minimal registry until Prompt 3 builds identity on top of it: accounts, their devices
//! (Ed25519 authentication keys), a directory version that delivery nodes poll, and the rows M5
//! adds, each holding only what the threat model lists:
//!
//! | Table | Key | Holds | Gone |
//! | --- | --- | --- | --- |
//! | `account` | account ID | creation time, `deleting`, identity key, invites left | with the account |
//! | `device` | device ID | account ID, auth key, `disabled` | with the device |
//! | `push_token` | keyed hash of the device ID | the token sealed to `push`'s public key | unregistered, or with the device |
//! | `upload_grant` | object key | uploading device, exact size, fetches due, expiry | at upload, expiry, or with the device |
//! | `attachment` | object key | size, fetches left, expiry (30 days) | at the last fetch or expiry |
//! | `outbox` | job ID | the job (IDs only) | relayed to the queue |
//! | `invite` | SHA-256 of the code | uses left, expiry; **no issuer** (D-0038, D-0047) | at its last use, revocation, or expiry |
//! | `username` | username hash (Ristretto, D-0049) | its account, or none while held after release | held [`USERNAME_HOLD`] after release, then swept |
//! | `ulink` | random link handle | its account, the link's ciphertext | replaced, deleted, at a username change, or with the account |
//! | `device` (M3 fields) | device ID | identity key, signed prekey, last-resort ML-KEM prekey | replaced (prekeys), or with the device |
//! | `otpk`, `otkem` | (device, key ID) | one one-time X25519 or ML-KEM-1024 prekey | claimed by one fetch, or with the device |
//! | `mlskp` | (device, `KeyPackageRef`) | one single-use MLS KeyPackage and its expiry; the device's last-resort package on the device row | claimed by one fetch, expired (swept), or with the device |
//!
//! An attachment row has no link to the account that uploaded it (owner-approved threat-model
//! row, D-0036).
#![forbid(unsafe_code)]

/// `SurrealQL`, inside a transaction that disables or deletes the devices in `$gone`: marks every
/// group holding one of them with those of its devices, so `api` proposes their removal as the
/// groups' external sender (D-0075, `groups::Registry::groups_to_prune`). The mark lives until
/// `api` has proposed (seconds).
macro_rules! mark_prune {
    () => {
        "FOR $pg IN (SELECT meta::id(id)[0] AS g, devs FROM grp WHERE devs CONTAINSANY $gone) {
           UPSERT grp_prune:[$pg.g] SET n = (n ?? 0) + 1, at = time::now(),
             gone = array::union(gone ?? [], array::intersect($pg.devs, $gone)) RETURN NONE;
         };"
    };
}

mod db;
pub mod push_token;

use std::time::Duration;

use bytes::Bytes;
use songbird_jobs::{Job, ObjectKey};
use songbird_surreal::Value;
use songbird_types::{AccountId, DeviceId, JobId};

pub mod blocks;
pub mod call_links;
pub mod communities;
pub mod devices;
pub mod gdpr;
pub mod groups;
pub mod journal;
pub mod kt;
pub mod packs;
pub mod profile;
pub mod reports;
pub use db::{Db, DbError, SurrealSettings};

/// Ed25519 public key length.
pub const AUTH_KEY_LEN: usize = 32;

/// Attachments live at most this long (invariant 3).
pub const ATTACHMENT_MAX_AGE: Duration = Duration::from_hours(30 * 24);
/// A resumable upload grant lives at most this long, however often its parts keep it alive
/// (Prompt 6, M2, D-0081).
pub const GRANT_MAX_AGE: Duration = Duration::from_hours(24);

const SCHEMA: &str = "
DEFINE TABLE IF NOT EXISTS account SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS at ON account TYPE datetime;
DEFINE FIELD IF NOT EXISTS deleting ON account TYPE bool;
DEFINE FIELD IF NOT EXISTS identity ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS invites ON account TYPE option<int>;
DEFINE TABLE IF NOT EXISTS invite SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS uses ON invite TYPE int;
DEFINE FIELD IF NOT EXISTS expires ON invite TYPE datetime;
DEFINE INDEX IF NOT EXISTS invite_expires ON invite FIELDS expires;
DEFINE FIELD IF NOT EXISTS username ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS ukey ON account TYPE option<bytes>;
DEFINE TABLE IF NOT EXISTS username SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS account ON username TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS held_until ON username TYPE option<datetime>;
DEFINE INDEX IF NOT EXISTS username_account ON username FIELDS account;
DEFINE INDEX IF NOT EXISTS username_held ON username FIELDS held_until;
DEFINE FIELD IF NOT EXISTS ik ON device TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS spk ON device TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS lrk ON device TYPE option<bytes>;
DEFINE TABLE IF NOT EXISTS otpk SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS device ON otpk TYPE bytes;
DEFINE FIELD IF NOT EXISTS blob ON otpk TYPE bytes;
DEFINE INDEX IF NOT EXISTS otpk_device ON otpk FIELDS device;
DEFINE TABLE IF NOT EXISTS otkem SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS device ON otkem TYPE bytes;
DEFINE FIELD IF NOT EXISTS blob ON otkem TYPE bytes;
DEFINE INDEX IF NOT EXISTS otkem_device ON otkem FIELDS device;
DEFINE FIELD IF NOT EXISTS mlslr ON device TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS mlslr_exp ON device TYPE option<datetime>;
DEFINE TABLE IF NOT EXISTS mlskp SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS device ON mlskp TYPE bytes;
DEFINE FIELD IF NOT EXISTS blob ON mlskp TYPE bytes;
DEFINE FIELD IF NOT EXISTS expires ON mlskp TYPE datetime;
DEFINE INDEX IF NOT EXISTS mlskp_device ON mlskp FIELDS device;
DEFINE INDEX IF NOT EXISTS mlskp_expires ON mlskp FIELDS expires;
DEFINE FIELD IF NOT EXISTS mlslr_ref ON device TYPE option<bytes>;
DEFINE TABLE IF NOT EXISTS mlskp_used SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS device ON mlskp_used TYPE bytes;
DEFINE FIELD IF NOT EXISTS expires ON mlskp_used TYPE datetime;
DEFINE INDEX IF NOT EXISTS mlskp_used_device ON mlskp_used FIELDS device;
DEFINE INDEX IF NOT EXISTS mlskp_used_expires ON mlskp_used FIELDS expires;
DEFINE TABLE IF NOT EXISTS ulink SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS account ON ulink TYPE bytes;
DEFINE FIELD IF NOT EXISTS blob ON ulink TYPE bytes;
DEFINE INDEX IF NOT EXISTS ulink_account ON ulink FIELDS account;
DEFINE TABLE IF NOT EXISTS device SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS account ON device TYPE bytes;
DEFINE FIELD IF NOT EXISTS key ON device TYPE bytes;
DEFINE FIELD IF NOT EXISTS disabled ON device TYPE bool;
DEFINE FIELD IF NOT EXISTS at ON device TYPE datetime;
DEFINE INDEX IF NOT EXISTS device_account ON device FIELDS account;
DEFINE FIELD IF NOT EXISTS prim ON device TYPE option<bool>;
DEFINE FIELD IF NOT EXISTS pending ON device TYPE option<bool>;
DEFINE FIELD IF NOT EXISTS lconf ON device TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS dlist ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS dlist_v ON account TYPE option<int>;
DEFINE FIELD IF NOT EXISTS dgen ON account TYPE option<int>;
DEFINE TABLE IF NOT EXISTS ltoken SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS account ON ltoken TYPE bytes;
DEFINE FIELD IF NOT EXISTS device ON ltoken TYPE bytes;
DEFINE FIELD IF NOT EXISTS expires ON ltoken TYPE datetime;
DEFINE INDEX IF NOT EXISTS ltoken_account ON ltoken FIELDS account;
DEFINE INDEX IF NOT EXISTS ltoken_expires ON ltoken FIELDS expires;
DEFINE FIELD IF NOT EXISTS pin ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS pin_tries ON account TYPE option<int>;
DEFINE FIELD IF NOT EXISTS pin_lock ON account TYPE option<datetime>;
DEFINE TABLE IF NOT EXISTS passkey SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS account ON passkey TYPE bytes;
DEFINE FIELD IF NOT EXISTS cid ON passkey TYPE bytes;
DEFINE FIELD IF NOT EXISTS key ON passkey TYPE bytes;
DEFINE FIELD IF NOT EXISTS count ON passkey TYPE int;
DEFINE FIELD IF NOT EXISTS at ON passkey TYPE datetime;
DEFINE INDEX IF NOT EXISTS passkey_account ON passkey FIELDS account;
DEFINE FIELD IF NOT EXISTS profile ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS profile_v ON account TYPE option<int>;
DEFINE FIELD IF NOT EXISTS uak ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS uak_open ON account TYPE option<bool>;
DEFINE FIELD IF NOT EXISTS avatar ON account TYPE option<bytes>;
DEFINE TABLE IF NOT EXISTS avatar SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS account ON avatar TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON avatar TYPE datetime;
DEFINE FIELD IF NOT EXISTS replaced_at ON avatar TYPE option<datetime>;
DEFINE INDEX IF NOT EXISTS avatar_replaced ON avatar FIELDS replaced_at;
DEFINE INDEX IF NOT EXISTS avatar_account ON avatar FIELDS account;
DEFINE INDEX IF NOT EXISTS avatar_at ON avatar FIELDS at;
DEFINE FIELD IF NOT EXISTS kt_gen ON account TYPE option<int>;
DEFINE FIELD IF NOT EXISTS kt_logged ON account TYPE option<int>;
DEFINE FIELD IF NOT EXISTS kt_salt ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS kt_v1 ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS kt_v2 ON account TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS kt_v3 ON account TYPE option<bytes>;
DEFINE INDEX IF NOT EXISTS account_kt ON account FIELDS kt_gen;
DEFINE FIELD IF NOT EXISTS last_seen ON account TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS inactive_months ON account TYPE option<int>;
DEFINE FIELD IF NOT EXISTS inact_warned ON account TYPE option<int>;
DEFINE INDEX IF NOT EXISTS account_last_seen ON account FIELDS last_seen;
DEFINE FIELD IF NOT EXISTS requests_off ON account TYPE option<bool>;
DEFINE TABLE IF NOT EXISTS block SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS owner ON block TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON block TYPE datetime;
DEFINE INDEX IF NOT EXISTS block_owner ON block FIELDS owner;
DEFINE TABLE IF NOT EXISTS pin SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS v ON pin TYPE bytes;
DEFINE TABLE IF NOT EXISTS blockctr SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS n ON blockctr TYPE int;
DEFINE TABLE IF NOT EXISTS report SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS sealed ON report TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON report TYPE datetime;
DEFINE FIELD IF NOT EXISTS expires ON report TYPE datetime;
DEFINE INDEX IF NOT EXISTS report_expires ON report FIELDS expires;
DEFINE TABLE IF NOT EXISTS directory SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS version ON directory TYPE int;
DEFINE TABLE IF NOT EXISTS push_token SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS sealed ON push_token TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON push_token TYPE datetime;
DEFINE TABLE IF NOT EXISTS upload_grant SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS device ON upload_grant TYPE bytes;
DEFINE FIELD IF NOT EXISTS size ON upload_grant TYPE int;
DEFINE FIELD IF NOT EXISTS fetches ON upload_grant TYPE int;
DEFINE FIELD IF NOT EXISTS expires ON upload_grant TYPE datetime;
DEFINE FIELD IF NOT EXISTS deadline ON upload_grant TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS upload ON upload_grant TYPE option<string>;
DEFINE FIELD IF NOT EXISTS sent ON upload_grant TYPE int DEFAULT 0;
DEFINE INDEX IF NOT EXISTS upload_grant_device ON upload_grant FIELDS device;
DEFINE INDEX IF NOT EXISTS upload_grant_expires ON upload_grant FIELDS expires;
DEFINE TABLE IF NOT EXISTS attachment SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS size ON attachment TYPE int;
DEFINE FIELD IF NOT EXISTS left ON attachment TYPE int;
DEFINE FIELD IF NOT EXISTS expires ON attachment TYPE datetime;
DEFINE INDEX IF NOT EXISTS attachment_expires ON attachment FIELDS expires;
DEFINE TABLE IF NOT EXISTS outbox SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS job ON outbox TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON outbox TYPE datetime;
DEFINE INDEX IF NOT EXISTS outbox_at ON outbox FIELDS at;
DEFINE TABLE IF NOT EXISTS grp SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS epoch ON grp TYPE int;
DEFINE FIELD IF NOT EXISTS state ON grp TYPE bytes;
DEFINE FIELD IF NOT EXISTS roster ON grp TYPE bytes;
DEFINE FIELD IF NOT EXISTS last ON grp TYPE bytes;
DEFINE TABLE IF NOT EXISTS grp_fanout SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS body ON grp_fanout TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON grp_fanout TYPE datetime;
DEFINE INDEX IF NOT EXISTS grp_fanout_at ON grp_fanout FIELDS at;
DEFINE FIELD IF NOT EXISTS rev ON grp TYPE int;
DEFINE FIELD IF NOT EXISTS meta ON grp TYPE bytes;
DEFINE FIELD IF NOT EXISTS meta_v ON grp TYPE int;
DEFINE FIELD IF NOT EXISTS devs ON grp TYPE array<bytes> DEFAULT [];
DEFINE INDEX IF NOT EXISTS grp_devs ON grp FIELDS devs;
DEFINE TABLE IF NOT EXISTS grp_log SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS entry ON grp_log TYPE bytes;
DEFINE FIELD IF NOT EXISTS at ON grp_log TYPE datetime;
DEFINE FIELD IF NOT EXISTS grp ON grp_log TYPE bytes;
DEFINE INDEX IF NOT EXISTS grp_log_grp ON grp_log FIELDS grp;
DEFINE TABLE IF NOT EXISTS grp_link SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS grp ON grp_link TYPE bytes;
DEFINE FIELD IF NOT EXISTS sha ON grp_link TYPE bytes;
DEFINE FIELD IF NOT EXISTS max ON grp_link TYPE int;
DEFINE FIELD IF NOT EXISTS uses ON grp_link TYPE int;
DEFINE FIELD IF NOT EXISTS approval ON grp_link TYPE bool;
DEFINE FIELD IF NOT EXISTS expires ON grp_link TYPE option<datetime>;
DEFINE INDEX IF NOT EXISTS grp_link_grp ON grp_link FIELDS grp;
DEFINE TABLE IF NOT EXISTS grp_req SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS at ON grp_req TYPE datetime;
DEFINE FIELD IF NOT EXISTS grp ON grp_req TYPE bytes;
DEFINE INDEX IF NOT EXISTS grp_req_grp ON grp_req FIELDS grp;
DEFINE INDEX IF NOT EXISTS grp_req_at ON grp_req FIELDS at;
DEFINE FIELD IF NOT EXISTS acct ON grp_req TYPE bytes;
DEFINE INDEX IF NOT EXISTS grp_req_acct ON grp_req FIELDS acct;
DEFINE INDEX IF NOT EXISTS grp_link_expires ON grp_link FIELDS expires;
DEFINE TABLE IF NOT EXISTS pack SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS objects ON pack TYPE array<bytes>;
DEFINE FIELD IF NOT EXISTS sizes ON pack TYPE array<int>;
DEFINE FIELD IF NOT EXISTS device ON pack TYPE option<bytes>;
DEFINE FIELD IF NOT EXISTS token ON pack TYPE bytes;
DEFINE FIELD IF NOT EXISTS done ON pack TYPE bool;
DEFINE FIELD IF NOT EXISTS created ON pack TYPE datetime;
DEFINE FIELD IF NOT EXISTS used ON pack TYPE datetime;
DEFINE FIELD IF NOT EXISTS puts ON pack TYPE int DEFAULT 0;
DEFINE INDEX IF NOT EXISTS pack_used ON pack FIELDS used;
DEFINE INDEX IF NOT EXISTS pack_device ON pack FIELDS device;
DEFINE TABLE IF NOT EXISTS call_link SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS room ON call_link TYPE bytes;
DEFINE FIELD IF NOT EXISTS admin ON call_link TYPE bytes;
DEFINE FIELD IF NOT EXISTS media ON call_link TYPE int;
DEFINE FIELD IF NOT EXISTS lobby ON call_link TYPE bool;
DEFINE FIELD IF NOT EXISTS expires ON call_link TYPE datetime;
DEFINE INDEX IF NOT EXISTS call_link_expires ON call_link FIELDS expires;
DEFINE TABLE IF NOT EXISTS cmty SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS ann ON cmty TYPE bytes;
DEFINE FIELD IF NOT EXISTS meta ON cmty TYPE bytes;
DEFINE FIELD IF NOT EXISTS meta_v ON cmty TYPE int;
DEFINE TABLE IF NOT EXISTS cmty_grp SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS cmty ON cmty_grp TYPE bytes;
DEFINE FIELD IF NOT EXISTS ann ON cmty_grp TYPE bool;
DEFINE INDEX IF NOT EXISTS cmty_grp_cmty ON cmty_grp FIELDS cmty;
DEFINE TABLE IF NOT EXISTS grp_prune SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS n ON grp_prune TYPE int;
DEFINE FIELD IF NOT EXISTS at ON grp_prune TYPE datetime;
DEFINE FIELD IF NOT EXISTS gone ON grp_prune TYPE array<bytes> DEFAULT [];
DEFINE INDEX IF NOT EXISTS grp_prune_at ON grp_prune FIELDS at;
UPSERT directory:v SET version = version ?? 1 RETURN NONE;
DEFINE TABLE IF NOT EXISTS store SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS generation ON store TYPE int;
UPSERT store:g SET generation = generation ?? 1 RETURN NONE;
";

/// Registry failures. They carry no identifiers.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The database is unreachable or failed.
    #[error(transparent)]
    Db(#[from] DbError),
    /// The account or a device already exists.
    #[error("already exists")]
    Exists,
    /// A row did not have the expected shape.
    #[error("unexpected row shape")]
    Shape,
    /// The invite code is unknown, used up or expired (one answer for all three).
    #[error("invite refused")]
    Invite,
    /// The account has no invites left.
    #[error("no invites left")]
    Allowance,
    /// The username belongs to another account, or is held after its release.
    #[error("username taken")]
    Taken,
    /// The account has no username (a link needs one).
    #[error("no username")]
    NoUsername,
    /// The upload names another identity key than the device's (set once, never replaced).
    #[error("identity key differs")]
    IdentityMismatch,
    /// The device would hold more one-time prekeys than allowed.
    #[error("too many one-time prekeys")]
    Full,
    /// A one-time prekey ID the device already holds.
    #[error("duplicate prekey id")]
    Duplicate,
    /// The device has no identity key or prekeys yet (a first upload must carry them).
    #[error("keys incomplete")]
    Incomplete,
    /// Only the primary device may do this.
    #[error("not the primary device")]
    NotPrimary,
    /// The account has as many devices (and outstanding link tokens) as allowed.
    #[error("device limit reached")]
    DeviceLimit,
    /// The link token is unknown, used or expired, or names another device (one answer).
    #[error("link token refused")]
    LinkToken,
    /// A device list whose version does not grow.
    #[error("device list version does not grow")]
    Rollback,
    /// A device list naming a device that is not an enabled device of the account with those
    /// keys, or another primary.
    #[error("device list does not match the account's devices")]
    ListMismatch,
    /// An MLS commit made from an epoch the group is no longer at (another commit won), or for
    /// a group that does not exist.
    #[error("stale group epoch")]
    StaleEpoch,
    /// An invite link that is unknown, of another group, used up or expired (one answer).
    #[error("group link refused")]
    GroupLink,
    /// No such community (Prompt 5, M4).
    #[error("not found")]
    NotFound,
    /// The transaction kept losing write conflicts to concurrent changes of the same rows for
    /// longer than the retry budget (D-0093). Nothing was written; the caller may retry later
    /// (the API answers 503).
    #[error("busy: concurrent changes, retry later")]
    Busy,
}

/// One device's stored keys (opaque stored forms, `songbird_proto::keys`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceKeys {
    /// Identity key, `0x05 || u`.
    pub identity: Option<[u8; 33]>,
    /// Signed prekey, stored form.
    pub signed: Option<Bytes>,
    /// Last-resort ML-KEM-1024 prekey, stored form.
    pub last_resort: Option<Bytes>,
}

/// What an upload changes (already verified by the caller).
#[derive(Debug, Clone, Default)]
pub struct KeysUpdate {
    /// Identity key, on the first upload.
    pub identity: Option<[u8; 33]>,
    /// A new signed prekey.
    pub signed: Option<Vec<u8>>,
    /// A new last-resort prekey.
    pub last_resort: Option<Vec<u8>>,
    /// One-time X25519 prekeys: (ID, stored form).
    pub one_time_ec: Vec<(u32, Vec<u8>)>,
    /// One-time ML-KEM prekeys: (ID, stored form).
    pub one_time_kem: Vec<(u32, Vec<u8>)>,
}

/// What one fetch claims for one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedKeys {
    /// The device.
    pub device: DeviceId,
    /// Identity key.
    pub identity: [u8; 33],
    /// Signed prekey, stored form.
    pub signed: Bytes,
    /// A one-time X25519 prekey, stored form, removed from the store by this claim.
    pub one_time_ec: Option<Bytes>,
    /// A one-time ML-KEM prekey removed by this claim, or the last-resort one.
    pub kem: Bytes,
    /// Whether `kem` is one-time.
    pub kem_one_time: bool,
}

/// A checked KeyPackage to store (`songbird_keys::mls::check`).
#[derive(Debug, Clone)]
pub struct StoredKeyPackage {
    /// Its `KeyPackageRef`.
    pub reference: [u8; 32],
    /// The package.
    pub package: Vec<u8>,
    /// When it expires (Unix seconds).
    pub not_after: u64,
}

/// A device's KeyPackage, as one fetch claims it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedKeyPackage {
    /// The device.
    pub device: DeviceId,
    /// The package.
    pub package: Bytes,
    /// Whether it is single use (removed by this claim), not the last-resort one.
    pub one_time: bool,
}

/// Which one-time pool a claim draws from.
#[derive(Debug, Clone, Copy)]
enum Pool {
    Ec,
    Kem,
    KeyPackage,
}

/// Candidates a claim picks among at random, so concurrent claims rarely aim at one key.
const CLAIM_CANDIDATES: i64 = 16;
/// Attempts a claim makes before giving up on a one-time key (it then serves none).
const CLAIM_ATTEMPTS: u32 = 32;

/// How long a released username stays unavailable to everyone (impersonation of its previous
/// owner by whoever grabs it first). The held row names no account.
pub const USERNAME_HOLD: Duration = Duration::from_hours(30 * 24);

/// A username as lookup sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernameRow {
    /// Its account.
    pub account: AccountId,
    /// The account's username key verifier (salt and Argon2id output), if it set one.
    pub key: Option<Bytes>,
}

/// A new account as registration creates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewAccount {
    /// Server-chosen account ID.
    pub account: AccountId,
    /// Account identity public key (Ed25519, already checked).
    pub identity: [u8; 32],
    /// Server-chosen ID of the first device.
    pub device: DeviceId,
    /// Its authentication public key (Ed25519, already checked).
    pub auth_key: [u8; AUTH_KEY_LEN],
    /// Invites the account may create.
    pub allowance: u32,
}

/// How many times a transaction that lost a write conflict is retried, at most (D-0093).
const CONFLICT_RETRIES: u32 = 20;

/// How long one call may spend retrying lost write conflicts before it answers
/// [`RegistryError::Busy`] (D-0093).
const CONFLICT_BUDGET: Duration = Duration::from_millis(1500);

/// Lost write conflicts retried, process-wide: aggregates only, no labels (invariant 6).
static CONFLICT_RETRIED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Calls answered [`RegistryError::Busy`], process-wide.
static CONFLICT_BUSY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A process-wide counter a service exports: (name, help, its value at scrape).
pub type CounterSpec = (&'static str, &'static str, fn() -> u64);

/// The registry's conflict counters, for a service to export (`songbird_registry_*`, runbook
/// "Registry busy" in `docs/RUNBOOKS/jobs-push-api-worker.md`): (name, help, read at scrape).
pub const METRICS: [CounterSpec; 2] = [
    (
        "registry_conflict_retries",
        "Registry transactions retried after losing a write conflict",
        || CONFLICT_RETRIED.load(std::sync::atomic::Ordering::Relaxed),
    ),
    (
        "registry_busy",
        "Registry calls answered busy: write conflicts outlasted the retry budget",
        || CONFLICT_BUSY.load(std::sync::atomic::Ordering::Relaxed),
    ),
];

/// Backoff between retries of a transaction that lost a write conflict (D-0093): full jitter
/// (a uniformly random wait up to an exponentially growing cap, 2 ms doubling to 128 ms), bounded
/// by [`CONFLICT_RETRIES`] attempts and [`CONFLICT_BUDGET`] of time. Without the jitter, racing
/// writers that lost to the same commit all wake at the same instant and collide again, round
/// after round, until one of them runs out of attempts. How often a call loses is not bounded by
/// the number of competing winners: `SurrealKV` counts commits still in flight or awaiting their
/// fsync as conflicts, so the bound is a time budget (D-0093).
pub(crate) struct Backoff {
    attempt: u32,
    started: std::time::Instant,
}

impl Backoff {
    pub(crate) fn new() -> Self {
        Self {
            attempt: 0,
            started: std::time::Instant::now(),
        }
    }

    /// The upper bound of the wait before retry `attempt` (1-based).
    fn cap(attempt: u32) -> Duration {
        Duration::from_millis(1u64 << attempt.clamp(1, 7))
    }

    /// Waits before the next attempt after a lost conflict; [`RegistryError::Busy`] once the
    /// attempts or the time budget are spent.
    pub(crate) async fn conflicted(&mut self) -> Result<(), RegistryError> {
        if self.attempt >= CONFLICT_RETRIES || self.started.elapsed() >= CONFLICT_BUDGET {
            CONFLICT_BUSY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                attempts = self.attempt,
                "registry busy: write conflicts outlasted the retry budget"
            );
            return Err(RegistryError::Busy);
        }
        CONFLICT_RETRIED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.attempt += 1;
        let cap = u64::try_from(Self::cap(self.attempt).as_micros()).unwrap_or(u64::MAX);
        let mut r = [0u8; 8];
        // No randomness only loses the jitter, never the bound.
        let wait = if getrandom::fill(&mut r).is_ok() {
            u64::from_le_bytes(r) % (cap + 1)
        } else {
            cap
        };
        tokio::time::sleep(Duration::from_micros(wait)).await;
        Ok(())
    }
}

/// Whether a failure is SurrealDB's "transaction conflict, retry" (as a statement kind or an RPC
/// error code; which one depends on where the conflict is detected).
fn is_conflict(e: &DbError) -> bool {
    match e {
        DbError::Rpc(songbird_surreal::RpcError::Server { code, .. }) => {
            *code == songbird_surreal::CODE_TRANSACTION_CONFLICT
        }
        DbError::Statement(kind) => kind == db::TRANSACTION_CONFLICT,
        _ => false,
    }
}

/// A device as authentication sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRow {
    /// Its account.
    pub account: AccountId,
    /// Ed25519 authentication public key.
    pub key: [u8; AUTH_KEY_LEN],
    /// Disabled: the account is being deleted (or the device removed).
    pub disabled: bool,
    /// Holds the account identity key (Prompt 3, M4).
    pub primary: bool,
    /// Linked, not yet in a signed device list (Prompt 3, M4): no account-wide changes.
    pub pending: bool,
}

/// A pending upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// The device allowed to upload.
    pub device: DeviceId,
    /// Exact (padded) size in bytes.
    pub size: u64,
    /// Recipient fetches due once uploaded.
    pub fetches: u32,
}

/// A pending upload with its resumable state (Prompt 6, M2, D-0081). `Debug` hides the upload ID.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingUpload {
    /// The grant.
    pub grant: Grant,
    /// The object store's multipart upload ID, once the first part arrived.
    pub upload: Option<String>,
}

impl std::fmt::Debug for PendingUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingUpload")
            .field("grant", &self.grant)
            .field("resumable", &self.upload.is_some())
            .finish()
    }
}

/// How an upload ended ([`Registry::finish_upload`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadEnd {
    /// The grant became the attachment.
    Completed,
    /// The object already is an attachment (a retried completion).
    Attached,
    /// No live grant: what was stored belongs to nothing.
    Gone,
}

/// An uploaded attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attachment {
    /// Size in bytes.
    pub size: u64,
    /// Fetches still due.
    pub left: u32,
}

/// What is left of an account after deletion (all zero when it is gone everywhere here).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Remnants {
    /// The account row.
    pub account: u64,
    /// Device rows.
    pub devices: u64,
    /// Push tokens of the devices.
    pub push_tokens: u64,
    /// Upload grants and unfinished packs of the devices (Prompt 6).
    pub grants: u64,
    /// Usernames still naming the account.
    pub usernames: u64,
    /// Username links, link tokens, passkeys and avatar records of the account.
    pub links: u64,
    /// One-time prekeys (both kinds) and single-use KeyPackages of the devices.
    pub prekeys: u64,
    /// Pending requests to join groups (Prompt 5, D-0073).
    pub group_requests: u64,
    /// Group prune marks still naming the devices (D-0075).
    pub group_marks: u64,
}

impl Remnants {
    /// Nothing left.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(Bytes::copy_from_slice(b))
}

fn var(name: &str, v: Value) -> (String, Value) {
    (name.to_owned(), v)
}

fn int(v: u64) -> Value {
    Value::Int(i64::try_from(v).unwrap_or(i64::MAX))
}

fn first_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        Value::Array(a) => a.first().and_then(Value::as_i64),
        _ => None,
    }
}

fn id16(v: &Value) -> Option<[u8; 16]> {
    v.as_bytes().and_then(|b| b.as_ref().try_into().ok())
}

fn id32(v: &Value) -> Option<[u8; 32]> {
    v.as_bytes().and_then(|b| b.as_ref().try_into().ok())
}

fn rows(v: Value) -> Vec<Value> {
    v.into_array().unwrap_or_default()
}

/// The account registry.
#[derive(Debug)]
pub struct Registry {
    db: Db,
}

impl Registry {
    /// Connects and creates the schema if missing.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn connect(db: Db) -> Result<Self, RegistryError> {
        db.exec(SCHEMA, Vec::new()).await?;
        Ok(Self { db })
    }

    /// The database handle (for tests and verification).
    #[must_use]
    pub fn db(&self) -> &Db {
        &self.db
    }

    // ----- accounts and devices -----

    /// Creates an account with its first devices (registration stand-in until Prompt 3).
    ///
    /// # Errors
    /// [`RegistryError::Exists`] if the account or a device exists.
    pub async fn create_account(
        &self,
        account: &AccountId,
        devices: &[(DeviceId, [u8; AUTH_KEY_LEN])],
    ) -> Result<(), RegistryError> {
        // The first device is the primary (it holds the account identity key).
        let list: Vec<Value> = devices
            .iter()
            .enumerate()
            .map(|(i, (d, k))| {
                Value::Array(vec![bytes(d.as_bytes()), bytes(k), Value::Bool(i == 0)])
            })
            .collect();
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 CREATE account:[$a] SET at = time::now(), deleting = false, last_seen = time::now()
                   RETURN NONE;
                 FOR $d IN $devices {
                   CREATE device:[$d[0]] SET account = $a, key = $d[1], disabled = false,
                     prim = $d[2], at = time::now() RETURN NONE;
                 };
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("devices", Value::Array(list)),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(kind)) if kind.contains("AlreadyExists") => {
                Err(RegistryError::Exists)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Registers an account and its first device (`POST /v1/registration`), consuming one use of
    /// `invite` (the SHA-256 of a code) when given, all in one transaction: two registrations
    /// racing for a code's last use write the same invite row, so SurrealDB lets one commit and
    /// the other retries and finds the code used up. Nothing links the account to the code or to
    /// whoever created it (D-0038).
    ///
    /// # Errors
    /// [`RegistryError::Invite`] for an unknown, used-up or expired code;
    /// [`RegistryError::Exists`] if an ID is taken (the caller draws new ones).
    pub async fn register(
        &self,
        new: &NewAccount,
        invite: Option<&[u8; 32]>,
    ) -> Result<(), RegistryError> {
        let invite_sql = if invite.is_some() {
            "LET $u = invite:[$code].uses;
             LET $e = invite:[$code].expires;
             IF $u == NONE OR $u < 1 OR $e <= time::now() { THROW 'invite' };
             IF $u == 1 { DELETE invite:[$code] RETURN NONE; }
             ELSE { UPDATE invite:[$code] SET uses -= 1 RETURN NONE; };"
        } else {
            ""
        };
        let sql = format!(
            "BEGIN TRANSACTION;
             {invite_sql}
             CREATE account:[$a] SET at = time::now(), deleting = false, identity = $identity,
               invites = $allowance, kt_gen = 1, last_seen = time::now() RETURN NONE;
             CREATE device:[$d] SET account = $a, key = $k, disabled = false, prim = true,
               at = time::now() RETURN NONE;
             UPDATE directory:v SET version += 1 RETURN NONE;
             COMMIT TRANSACTION;"
        );
        let vars = || {
            vec![
                var("a", bytes(new.account.as_bytes())),
                var("identity", bytes(&new.identity)),
                var("allowance", int(u64::from(new.allowance))),
                var("d", bytes(new.device.as_bytes())),
                var("k", bytes(&new.auth_key)),
                var("code", bytes(invite.map_or(&[0u8; 32][..], |c| &c[..]))),
            ]
        };
        let mut backoff = Backoff::new();
        loop {
            match self.db.query(&sql, vars()).await {
                Ok(_) => return Ok(()),
                Err(DbError::Statement(kind)) if kind == "Thrown" => {
                    return Err(RegistryError::Invite);
                }
                Err(DbError::Statement(kind)) if kind.contains("AlreadyExists") => {
                    return Err(RegistryError::Exists);
                }
                Err(e) if is_conflict(&e) => backoff.conflicted().await?,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// A user's invite: takes one from the account's allowance and stores the code's hash, single
    /// use, until `expires_in`. The row says nothing about who created it.
    ///
    /// # Errors
    /// [`RegistryError::Allowance`] when none is left (or the account does not exist).
    pub async fn create_user_invite(
        &self,
        account: &AccountId,
        code: &[u8; 32],
        expires_in: Duration,
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             LET $n = account:[$a].invites;
             IF $n == NONE OR $n < 1 { THROW 'allowance' };
             UPDATE account:[$a] SET invites -= 1 RETURN NONE;
             CREATE invite:[$code] SET uses = 1, expires = time::now() + duration::from_secs($ttl) RETURN NONE;
             COMMIT TRANSACTION;";
        let vars = || {
            vec![
                var("a", bytes(account.as_bytes())),
                var("code", bytes(code)),
                var("ttl", int(expires_in.as_secs())),
            ]
        };
        let mut backoff = Backoff::new();
        loop {
            match self.db.query(sql, vars()).await {
                Ok(_) => return Ok(()),
                Err(DbError::Statement(kind)) if kind == "Thrown" => {
                    return Err(RegistryError::Allowance);
                }
                Err(DbError::Statement(kind)) if kind.contains("AlreadyExists") => {
                    return Err(RegistryError::Exists);
                }
                Err(e) if is_conflict(&e) => backoff.conflicted().await?,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// An operator's batch of invites (`songbird-admin invites create`): each code hash with
    /// `uses` uses until `expires_in`.
    ///
    /// # Errors
    /// [`RegistryError::Exists`] if a hash is already stored (the caller draws new codes).
    pub async fn create_invites(
        &self,
        codes: &[[u8; 32]],
        uses: u32,
        expires_in: Duration,
    ) -> Result<(), RegistryError> {
        let list: Vec<Value> = codes.iter().map(|c| bytes(c)).collect();
        let r = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 FOR $c IN $codes {
                   CREATE invite:[$c] SET uses = $uses, expires = time::now() + duration::from_secs($ttl) RETURN NONE;
                 };
                 COMMIT TRANSACTION;",
                vec![
                    var("codes", Value::Array(list)),
                    var("uses", int(u64::from(uses))),
                    var("ttl", int(expires_in.as_secs())),
                ],
            )
            .await;
        match r {
            Ok(_) => Ok(()),
            Err(DbError::Statement(kind)) if kind.contains("AlreadyExists") => {
                Err(RegistryError::Exists)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Revokes a code (whoever holds it may; nothing records who created it).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn revoke_invite(&self, code: &[u8; 32]) -> Result<(), RegistryError> {
        self.db
            .exec(
                "DELETE invite:[$code] RETURN NONE;",
                vec![var("code", bytes(code))],
            )
            .await?;
        Ok(())
    }

    /// Uses left on a code that has not expired (tests and operators); `None` if unknown,
    /// used up or expired.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn invite_uses(&self, code: &[u8; 32]) -> Result<Option<u32>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE uses FROM invite WHERE id = invite:[$code] AND expires > time::now();",
                vec![var("code", bytes(code))],
            )
            .await?;
        Ok(first_int(&v).and_then(|n| u32::try_from(n).ok()))
    }

    /// Invites an account may still create (0 for an account without an allowance).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn invite_allowance(&self, account: &AccountId) -> Result<u32, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN account:[$a].invites;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(first_int(&v)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0))
    }

    /// Adds to an account's allowance (`songbird-admin invites grant`). Returns false if the
    /// account does not exist.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn add_invite_allowance(
        &self,
        account: &AccountId,
        add: u32,
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF !record::exists(account:[$a]) { THROW 'no_account' };
                 UPDATE account:[$a] SET invites = (invites ?? 0) + $n RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("n", int(u64::from(add))),
                ],
            )
            .await;
        match v {
            Ok(_) => Ok(true),
            Err(DbError::Statement(kind)) if kind == "Thrown" => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes up to `limit` expired invites (the worker's sweep); returns how many.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_expired_invites(&self, limit: usize) -> Result<usize, RegistryError> {
        let v = self
            .db
            .query1(
                "DELETE (SELECT VALUE id FROM invite WHERE expires <= time::now() LIMIT $n)
                   RETURN BEFORE;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        Ok(rows(v).len())
    }

    /// An account's identity key (`None` for an account created without one by the admin link).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn identity_key(
        &self,
        account: &AccountId,
    ) -> Result<Option<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN account:[$a].identity;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(id32(&v))
    }

    // ----- usernames (Prompt 3, M2, D-0049) -----

    /// Gives an account the username with this hash, in one transaction: refused if another
    /// account holds it or it is held after a release; the account's previous username (if
    /// another) becomes held for [`USERNAME_HOLD`] with no account named; its link goes (the
    /// link's ciphertext names the old username). Setting the username the account already has
    /// changes nothing. Racing claims write the same row, so one commits and the others retry and
    /// find it taken.
    ///
    /// # Errors
    /// [`RegistryError::Taken`].
    pub async fn set_username(
        &self,
        account: &AccountId,
        hash: &[u8; 32],
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             LET $owner = username:[$h].account;
             LET $held = username:[$h].held_until;
             IF record::exists(username:[$h]) AND $owner != $a
                AND ($owner != NONE OR $held > time::now()) { THROW 'taken' };
             LET $old = account:[$a].username;
             IF $old != NONE AND $old != $h {
               UPDATE username:[$old] SET account = NONE,
                 held_until = time::now() + duration::from_secs($hold) RETURN NONE;
               DELETE ulink WHERE account = $a RETURN NONE;
             };
             UPSERT username:[$h] SET account = $a, held_until = NONE RETURN NONE;
             UPDATE account:[$a] SET username = $h, kt_gen = (kt_gen ?? 0) + 1 RETURN NONE;
             COMMIT TRANSACTION;";
        self.retrying(sql, || {
            vec![
                var("a", bytes(account.as_bytes())),
                var("h", bytes(hash)),
                var("hold", int(USERNAME_HOLD.as_secs())),
            ]
        })
        .await
        .map_err(|e| match e {
            RegistryError::Invite => RegistryError::Taken,
            other => other,
        })
    }

    /// Removes the account's username (held for [`USERNAME_HOLD`], naming no account) and its
    /// link. Nothing to remove is not an error.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_username(&self, account: &AccountId) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             LET $old = account:[$a].username;
             IF $old != NONE {
               UPDATE username:[$old] SET account = NONE,
                 held_until = time::now() + duration::from_secs($hold) RETURN NONE;
             };
             DELETE ulink WHERE account = $a RETURN NONE;
             UPDATE account:[$a] SET username = NONE, kt_gen = (kt_gen ?? 0) + 1 RETURN NONE;
             COMMIT TRANSACTION;";
        self.retrying(sql, || {
            vec![
                var("a", bytes(account.as_bytes())),
                var("hold", int(USERNAME_HOLD.as_secs())),
            ]
        })
        .await
    }

    /// The account a username hash names, with its username key verifier; `None` for an unknown
    /// or held username, or one whose account is being deleted.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn lookup_username(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<UsernameRow>, RegistryError> {
        // One statement, the same work whether or not the username exists: an absent username
        // reads the key of an account ID that cannot exist (all zeros), so the answer's timing
        // does not depend on existence.
        let v = self
            .db
            .query1(
                "RETURN [username:[$h].account, account:[username:[$h].account ?? $zero].ukey,
                   account:[username:[$h].account ?? $zero].deleting];",
                vec![var("h", bytes(hash)), var("zero", bytes(&[0u8; 16]))],
            )
            .await?;
        let r = rows(v);
        let Some(account) = r.first().and_then(id16).map(AccountId::from_bytes) else {
            return Ok(None);
        };
        // An account being deleted is found by nobody.
        if matches!(r.get(2), Some(Value::Bool(true))) {
            return Ok(None);
        }
        let key = r.get(1).and_then(|k| k.as_bytes().cloned());
        Ok(Some(UsernameRow { account, key }))
    }

    /// The hash of the account's username, if it has one.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn username_of(
        &self,
        account: &AccountId,
    ) -> Result<Option<[u8; 32]>, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN account:[$a].username;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(id32(&v))
    }

    /// Sets (`Some`) or removes the account's username key verifier.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn set_username_key(
        &self,
        account: &AccountId,
        verifier: Option<&[u8]>,
    ) -> Result<(), RegistryError> {
        let mut vars = vec![var("a", bytes(account.as_bytes()))];
        let sql = match verifier {
            Some(k) => {
                vars.push(var("k", bytes(k)));
                "UPDATE account:[$a] SET ukey = $k RETURN NONE;"
            }
            // An optional field is cleared with NONE (NULL is a value and fails validation).
            None => "UPDATE account:[$a] SET ukey = NONE RETURN NONE;",
        };
        self.db.exec(sql, vars).await?;
        Ok(())
    }

    /// Stores the account's username link under a new handle, replacing any previous link (a
    /// reset: the old handle stops working).
    ///
    /// # Errors
    /// [`RegistryError::NoUsername`] without a username.
    pub async fn put_username_link(
        &self,
        account: &AccountId,
        handle: &[u8; 16],
        blob: &[u8],
    ) -> Result<(), RegistryError> {
        let sql = "BEGIN TRANSACTION;
             IF account:[$a].username = NONE { THROW 'no_username' };
             DELETE ulink WHERE account = $a RETURN NONE;
             CREATE ulink:[$l] SET account = $a, blob = $b RETURN NONE;
             COMMIT TRANSACTION;";
        self.retrying(sql, || {
            vec![
                var("a", bytes(account.as_bytes())),
                var("l", bytes(handle)),
                var("b", bytes(blob)),
            ]
        })
        .await
        .map_err(|e| match e {
            RegistryError::Invite => RegistryError::NoUsername,
            other => other,
        })
    }

    /// A link's ciphertext.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn username_link(&self, handle: &[u8; 16]) -> Result<Option<Bytes>, RegistryError> {
        let v = self
            .db
            .query1("RETURN ulink:[$l].blob;", vec![var("l", bytes(handle))])
            .await?;
        Ok(v.as_bytes().cloned())
    }

    /// Deletes the account's link.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_username_link(&self, account: &AccountId) -> Result<(), RegistryError> {
        self.db
            .exec(
                "DELETE ulink WHERE account = $a RETURN NONE;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        Ok(())
    }

    /// Deletes up to `limit` held usernames whose hold ended (the worker's sweep); returns how
    /// many.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_released_usernames(&self, limit: usize) -> Result<usize, RegistryError> {
        let v = self
            .db
            .query1(
                "DELETE (SELECT VALUE id FROM username
                   WHERE account = NONE AND held_until <= time::now() LIMIT $n) RETURN BEFORE;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        Ok(rows(v).len())
    }

    /// Runs a transaction, retrying lost write conflicts; `THROW` maps to
    /// [`RegistryError::Invite`] for the caller to rename.
    async fn retrying(
        &self,
        sql: &str,
        vars: impl Fn() -> Vec<(String, Value)>,
    ) -> Result<(), RegistryError> {
        let mut backoff = Backoff::new();
        loop {
            match self.db.query(sql, vars()).await {
                Ok(_) => return Ok(()),
                Err(DbError::Statement(kind)) if kind == "Thrown" => {
                    return Err(RegistryError::Invite);
                }
                Err(e) if is_conflict(&e) => backoff.conflicted().await?,
                Err(e) => return Err(e.into()),
            }
        }
    }

    // ----- key directory (Prompt 3, M3, D-0050) -----

    /// A device's stored identity key and prekeys.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn device_keys(&self, device: &DeviceId) -> Result<DeviceKeys, RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN [device:[$d].ik, device:[$d].spk, device:[$d].lrk];",
                vec![var("d", bytes(device.as_bytes()))],
            )
            .await?;
        let r = rows(v);
        let get = |i: usize| r.get(i).and_then(|x| x.as_bytes().cloned());
        Ok(DeviceKeys {
            identity: get(0).and_then(|b| b.as_ref().try_into().ok()),
            signed: get(1),
            last_resort: get(2),
        })
    }

    /// Applies a verified upload in one transaction: the identity key only if the device has
    /// none (another one is refused, never replaced); new signed and last-resort prekeys replace
    /// the current ones; one-time prekeys are added, within `max` of each kind. After it the
    /// device must hold an identity key, a signed prekey and a last-resort prekey.
    ///
    /// # Errors
    /// [`RegistryError::IdentityMismatch`], [`RegistryError::Full`],
    /// [`RegistryError::Duplicate`], [`RegistryError::Incomplete`].
    pub async fn put_keys(
        &self,
        device: &DeviceId,
        update: &KeysUpdate,
        max: usize,
    ) -> Result<(), RegistryError> {
        let mut sql = String::from("BEGIN TRANSACTION;\n");
        let mut vars = vec![
            var("d", bytes(device.as_bytes())),
            var("max", int(u64::try_from(max).unwrap_or(u64::MAX))),
        ];
        if let Some(ik) = &update.identity {
            vars.push(var("ik", bytes(ik)));
            sql.push_str(
                "IF device:[$d].ik != NONE AND device:[$d].ik != $ik { THROW 'songbird:identity' };
                 UPDATE device:[$d] SET ik = $ik RETURN NONE;\n",
            );
        }
        if let Some(k) = &update.signed {
            vars.push(var("spk", bytes(k)));
            sql.push_str("UPDATE device:[$d] SET spk = $spk RETURN NONE;\n");
        }
        if let Some(k) = &update.last_resort {
            vars.push(var("lrk", bytes(k)));
            sql.push_str("UPDATE device:[$d] SET lrk = $lrk RETURN NONE;\n");
        }
        let list = |keys: &[(u32, Vec<u8>)]| {
            Value::Array(
                keys.iter()
                    .map(|(id, b)| Value::Array(vec![int(u64::from(*id)), bytes(b)]))
                    .collect(),
            )
        };
        vars.push(var("ec", list(&update.one_time_ec)));
        vars.push(var("kem", list(&update.one_time_kem)));
        sql.push_str(
            "IF device:[$d].ik = NONE OR device:[$d].spk = NONE OR device:[$d].lrk = NONE
               { THROW 'songbird:incomplete' };
             IF count(SELECT id FROM otpk WHERE device = $d) + array::len($ec) > $max
               { THROW 'songbird:full' };
             IF count(SELECT id FROM otkem WHERE device = $d) + array::len($kem) > $max
               { THROW 'songbird:full' };
             FOR $k IN $ec { CREATE otpk:[$d, $k[0]] SET device = $d, blob = $k[1] RETURN NONE; };
             FOR $k IN $kem { CREATE otkem:[$d, $k[0]] SET device = $d, blob = $k[1] RETURN NONE; };
             COMMIT TRANSACTION;",
        );
        let mut backoff = Backoff::new();
        loop {
            match self.db.query(&sql, vars.clone()).await {
                Ok(_) => return Ok(()),
                Err(DbError::Statement(kind)) => match kind.as_str() {
                    "Thrown:identity" => return Err(RegistryError::IdentityMismatch),
                    "Thrown:full" => return Err(RegistryError::Full),
                    "Thrown:incomplete" => return Err(RegistryError::Incomplete),
                    k if k.contains("AlreadyExists") => return Err(RegistryError::Duplicate),
                    k if k == db::TRANSACTION_CONFLICT => backoff.conflicted().await?,
                    _ => return Err(DbError::Statement(kind).into()),
                },
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// One-time prekeys a device holds: (X25519, ML-KEM-1024).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn prekey_counts(&self, device: &DeviceId) -> Result<(u64, u64), RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN [count(SELECT id FROM otpk WHERE device = $d),
                         count(SELECT id FROM otkem WHERE device = $d)];",
                vec![var("d", bytes(device.as_bytes()))],
            )
            .await?;
        let r = rows(v);
        let n = |i: usize| {
            r.get(i)
                .and_then(Value::as_i64)
                .and_then(|x| u64::try_from(x).ok())
                .unwrap_or(0)
        };
        Ok((n(0), n(1)))
    }

    /// Removes and returns one one-time prekey of the device, or `None` when it holds none.
    /// A key is removed by exactly one claim: each attempt deletes one record and returns what
    /// it deleted, so of two claims racing for one record one gets it and the other gets
    /// nothing (or loses the write conflict) and tries another candidate. Candidates are drawn
    /// at random among the first few, so concurrent claims rarely collide.
    async fn claim_one(
        &self,
        pool: Pool,
        device: &DeviceId,
    ) -> Result<Option<Bytes>, RegistryError> {
        let (list, take) = match pool {
            Pool::Kem => (
                "SELECT VALUE meta::id(id)[1] FROM otkem WHERE device = $d LIMIT $n;",
                "DELETE ONLY otkem:[$d, $id] RETURN BEFORE;",
            ),
            Pool::Ec => (
                "SELECT VALUE meta::id(id)[1] FROM otpk WHERE device = $d LIMIT $n;",
                "DELETE ONLY otpk:[$d, $id] RETURN BEFORE;",
            ),
            // An expired package is never served (the sweep deletes it).
            Pool::KeyPackage => (
                "SELECT VALUE meta::id(id)[1] FROM mlskp
                   WHERE device = $d AND expires > time::now() LIMIT $n;",
                "DELETE ONLY mlskp:[$d, $id] RETURN BEFORE;",
            ),
        };
        for _ in 0..CLAIM_ATTEMPTS {
            let ids = rows(
                self.db
                    .query1(
                        list,
                        vec![
                            var("d", bytes(device.as_bytes())),
                            var("n", Value::Int(CLAIM_CANDIDATES)),
                        ],
                    )
                    .await?,
            );
            if ids.is_empty() {
                return Ok(None);
            }
            let mut pick = [0u8; 8];
            getrandom::fill(&mut pick).map_err(|_| RegistryError::Shape)?;
            let index =
                usize::try_from(u64::from_le_bytes(pick) % u64::try_from(ids.len()).unwrap_or(1))
                    .unwrap_or(0);
            let Some(id) = ids.get(index).cloned() else {
                continue;
            };
            match self
                .db
                .query1(
                    take,
                    vec![var("d", bytes(device.as_bytes())), var("id", id.clone())],
                )
                .await
            {
                Ok(v) => {
                    if let Some(blob) = v.get("blob").and_then(|b| b.as_bytes().cloned()) {
                        // A claimed package's reference is kept until it expires: a commit
                        // may add only a package its device published (D-0074). If this
                        // fails, adding the package is refused later (fail closed).
                        if matches!(pool, Pool::KeyPackage) {
                            self.db
                                .exec(
                                    "UPSERT mlskp_used:[$d, $id] SET device = $d,
                                       expires = $e RETURN NONE;",
                                    vec![
                                        var("d", bytes(device.as_bytes())),
                                        var("id", id),
                                        var("e", v.get("expires").cloned().unwrap_or(Value::Null)),
                                    ],
                                )
                                .await?;
                        }
                        return Ok(Some(blob));
                    }
                    // Someone else claimed it first: try another.
                }
                Err(e) if is_conflict(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }

    /// The bundles of an account's enabled devices that hold keys (except `skip`), each with a
    /// one-time X25519 prekey and a one-time ML-KEM prekey claimed for this fetch when
    /// `one_time` and when any are left (else the last-resort ML-KEM prekey and no X25519 one).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn claim_bundles(
        &self,
        account: &AccountId,
        only: Option<&DeviceId>,
        skip: &DeviceId,
        one_time: bool,
    ) -> Result<Vec<ClaimedKeys>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS d, ik, spk, lrk FROM device
                   WHERE account = $a AND disabled = false AND pending != true
                     AND ik != NONE AND spk != NONE AND lrk != NONE;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let (Some(d), Some(ik), Some(spk), Some(lrk)) = (
                r.get("d").and_then(id16).map(DeviceId::from_bytes),
                r.get("ik")
                    .and_then(|b| b.as_bytes())
                    .and_then(|b| <[u8; 33]>::try_from(b.as_ref()).ok()),
                r.get("spk").and_then(|b| b.as_bytes().cloned()),
                r.get("lrk").and_then(|b| b.as_bytes().cloned()),
            ) else {
                return Err(RegistryError::Shape);
            };
            if &d == skip || only.is_some_and(|o| o != &d) {
                continue;
            }
            let (ec, kem) = if one_time {
                (
                    self.claim_one(Pool::Ec, &d).await?,
                    self.claim_one(Pool::Kem, &d).await?,
                )
            } else {
                (None, None)
            };
            out.push(ClaimedKeys {
                device: d,
                identity: ik,
                signed: spk,
                one_time_ec: ec,
                kem_one_time: kem.is_some(),
                kem: kem.unwrap_or(lrk),
            });
        }
        Ok(out)
    }

    // ----- MLS KeyPackages (Prompt 3, M3b, D-0051) -----

    /// Stores checked KeyPackages for a device in one transaction: single-use ones within `max`
    /// (duplicates by reference refused), a last-resort one replacing the current one.
    ///
    /// # Errors
    /// [`RegistryError::Full`], [`RegistryError::Duplicate`].
    pub async fn put_key_packages(
        &self,
        device: &DeviceId,
        single_use: &[StoredKeyPackage],
        last_resort: Option<&StoredKeyPackage>,
        max: usize,
    ) -> Result<(), RegistryError> {
        let mut sql = String::from("BEGIN TRANSACTION;\n");
        let mut vars = vec![
            var("d", bytes(device.as_bytes())),
            var("max", int(u64::try_from(max).unwrap_or(u64::MAX))),
            var(
                "kps",
                Value::Array(
                    single_use
                        .iter()
                        .map(|k| {
                            Value::Array(vec![
                                bytes(&k.reference),
                                bytes(&k.package),
                                int(k.not_after),
                            ])
                        })
                        .collect(),
                ),
            ),
        ];
        if let Some(lr) = last_resort {
            vars.push(var("lr", bytes(&lr.package)));
            vars.push(var("lrexp", int(lr.not_after)));
            vars.push(var("lrref", bytes(&lr.reference)));
            sql.push_str(
                "UPDATE device:[$d] SET mlslr = $lr, mlslr_ref = $lrref,
                   mlslr_exp = time::from_secs($lrexp) RETURN NONE;\n",
            );
        }
        sql.push_str(
            "IF count(SELECT id FROM mlskp WHERE device = $d) + array::len($kps) > $max
               { THROW 'songbird:full' };
             FOR $k IN $kps {
               CREATE mlskp:[$d, $k[0]] SET device = $d, blob = $k[1],
                 expires = time::from_secs($k[2]) RETURN NONE;
             };
             COMMIT TRANSACTION;",
        );
        let mut backoff = Backoff::new();
        loop {
            match self.db.query(&sql, vars.clone()).await {
                Ok(_) => return Ok(()),
                Err(DbError::Statement(kind)) => match kind.as_str() {
                    "Thrown:full" => return Err(RegistryError::Full),
                    k if k.contains("AlreadyExists") => return Err(RegistryError::Duplicate),
                    k if k == db::TRANSACTION_CONFLICT => backoff.conflicted().await?,
                    _ => return Err(DbError::Statement(kind).into()),
                },
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Unexpired single-use KeyPackages a device holds, and whether it has an unexpired
    /// last-resort one.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn key_package_counts(
        &self,
        device: &DeviceId,
    ) -> Result<(u64, bool), RegistryError> {
        let v = self
            .db
            .query1(
                "RETURN [count(SELECT id FROM mlskp WHERE device = $d AND expires > time::now()),
                         device:[$d].mlslr_exp > time::now()];",
                vec![var("d", bytes(device.as_bytes()))],
            )
            .await?;
        let r = rows(v);
        let n = r
            .first()
            .and_then(Value::as_i64)
            .and_then(|x| u64::try_from(x).ok())
            .unwrap_or(0);
        Ok((n, matches!(r.get(1), Some(Value::Bool(true)))))
    }

    /// A KeyPackage per enabled device of an account (except `skip`): a single-use one claimed
    /// for this fetch when `one_time` and any is left, else the unexpired last-resort one;
    /// devices with neither are left out.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn claim_key_packages(
        &self,
        account: &AccountId,
        only: Option<&DeviceId>,
        skip: &DeviceId,
        one_time: bool,
    ) -> Result<Vec<ClaimedKeyPackage>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS d,
                   (IF mlslr_exp > time::now() THEN mlslr ELSE NONE END) AS lr
                 FROM device WHERE account = $a AND disabled = false AND pending != true;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let Some(d) = r.get("d").and_then(id16).map(DeviceId::from_bytes) else {
                return Err(RegistryError::Shape);
            };
            if &d == skip || only.is_some_and(|o| o != &d) {
                continue;
            }
            let claimed = if one_time {
                self.claim_one(Pool::KeyPackage, &d).await?
            } else {
                None
            };
            let one = claimed.is_some();
            let lr = r.get("lr").and_then(|b| b.as_bytes().cloned());
            if let Some(package) = claimed.or(lr) {
                out.push(ClaimedKeyPackage {
                    device: d,
                    package,
                    one_time: one,
                });
            }
        }
        Ok(out)
    }

    /// Deletes up to `limit` expired single-use KeyPackages (the worker's sweep); returns how
    /// many.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_expired_key_packages(&self, limit: usize) -> Result<usize, RegistryError> {
        let v = self
            .db
            .query1(
                "DELETE (SELECT VALUE id FROM mlskp WHERE expires <= time::now() LIMIT $n)
                   RETURN BEFORE;
                 DELETE (SELECT VALUE id FROM mlskp_used WHERE expires <= time::now() LIMIT $n)
                   RETURN NONE;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        Ok(rows(v).len())
    }

    /// The directory version: bumped by every change to accounts or devices.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn directory_version(&self) -> Result<i64, RegistryError> {
        let v = self
            .db
            .query1("SELECT VALUE version FROM ONLY directory:v;", Vec::new())
            .await?;
        first_int(&v).ok_or(RegistryError::Shape)
    }

    /// The store generation sent to clients in `Hello` (PROTOCOL.md §3.6, D-0040).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn store_generation(&self) -> Result<u64, RegistryError> {
        let v = self
            .db
            .query1("SELECT VALUE generation FROM ONLY store:g;", Vec::new())
            .await?;
        first_int(&v)
            .and_then(|g| u64::try_from(g).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Increments the store generation after a restore or a loss of the mailbox, to at least the
    /// current Unix time in milliseconds: a restored registry carries the generation of its
    /// backup, which can be below one clients have already seen, and `+1` alone could land on it.
    /// Every value issued is at most the wall clock plus the bumps made within one millisecond,
    /// so a bump a millisecond later passes all of them. Returns the new generation.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn bump_store_generation(&self) -> Result<u64, RegistryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let v = self
            .db
            .query1(
                "UPDATE ONLY store:g SET generation = math::max([generation + 1, $now]) RETURN VALUE generation;",
                vec![var("now", int(now))],
            )
            .await?;
        first_int(&v)
            .and_then(|g| u64::try_from(g).ok())
            .ok_or(RegistryError::Shape)
    }

    /// Every enabled device with whether it is pending, in one snapshot: delivery's directory.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn load_directory_full(
        &self,
    ) -> Result<Vec<(DeviceId, AccountId, [u8; AUTH_KEY_LEN], bool)>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS d, account AS a, key AS k, pending AS p FROM device
                   WHERE disabled = false;",
                Vec::new(),
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let (Some(d), Some(a), Some(k)) = (
                r.get("d").and_then(id16),
                r.get("a").and_then(id16),
                r.get("k").and_then(id32),
            ) else {
                return Err(RegistryError::Shape);
            };
            let pending = matches!(r.get("p"), Some(Value::Bool(true)));
            out.push((
                DeviceId::from_bytes(d),
                AccountId::from_bytes(a),
                k,
                pending,
            ));
        }
        Ok(out)
    }

    /// Every enabled device: (device, account, key). Delivery's directory.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn load_directory(
        &self,
    ) -> Result<Vec<(DeviceId, AccountId, [u8; AUTH_KEY_LEN])>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT meta::id(id)[0] AS d, account AS a, key AS k FROM device WHERE disabled = false;",
                Vec::new(),
            )
            .await?;
        let mut out = Vec::new();
        for r in rows(v) {
            let (Some(d), Some(a), Some(k)) = (
                r.get("d").and_then(id16),
                r.get("a").and_then(id16),
                r.get("k").and_then(id32),
            ) else {
                return Err(RegistryError::Shape);
            };
            out.push((DeviceId::from_bytes(d), AccountId::from_bytes(a), k));
        }
        Ok(out)
    }

    /// One device, for request authentication.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn device(&self, device: &DeviceId) -> Result<Option<DeviceRow>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT account AS a, key AS k, disabled, prim, pending FROM ONLY device:[$d];",
                vec![var("d", bytes(device.as_bytes()))],
            )
            .await?;
        if v.is_absent() {
            return Ok(None);
        }
        let (Some(a), Some(k), Some(disabled)) = (
            v.get("a").and_then(id16),
            v.get("k").and_then(id32),
            v.get("disabled").map(|d| matches!(d, Value::Bool(true))),
        ) else {
            return Err(RegistryError::Shape);
        };
        Ok(Some(DeviceRow {
            account: AccountId::from_bytes(a),
            key: k,
            disabled,
            primary: matches!(v.get("prim"), Some(Value::Bool(true))),
            pending: matches!(v.get("pending"), Some(Value::Bool(true))),
        }))
    }

    /// Every device of an account, disabled ones included.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn account_devices(
        &self,
        account: &AccountId,
    ) -> Result<Vec<DeviceId>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM device WHERE account = $a;",
                vec![var("a", bytes(account.as_bytes()))],
            )
            .await?;
        rows(v)
            .iter()
            .map(|d| {
                id16(d)
                    .map(DeviceId::from_bytes)
                    .ok_or(RegistryError::Shape)
            })
            .collect()
    }

    /// A page of account IDs in ID order (the restore runbook's deletion journal pass).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn accounts_page(
        &self,
        start: usize,
        limit: usize,
    ) -> Result<Vec<AccountId>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM account ORDER BY id START $s LIMIT $n;",
                vec![
                    var("s", Value::from(i64::try_from(start).unwrap_or(i64::MAX))),
                    var("n", Value::from(i64::try_from(limit).unwrap_or(i64::MAX))),
                ],
            )
            .await?;
        rows(v)
            .iter()
            .map(|d| {
                id16(d)
                    .map(AccountId::from_bytes)
                    .ok_or(RegistryError::Shape)
            })
            .collect()
    }

    /// Starts deleting an account: in one transaction, marks it, disables its devices (every
    /// delivery node drops them at its next directory reload) and writes the deletion job to the
    /// outbox. Returns false if the account does not exist; repeating it is harmless.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn begin_account_deletion(
        &self,
        account: &AccountId,
        job: &Job,
    ) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query(
                concat!(
                    "BEGIN TRANSACTION;
                 IF !record::exists(account:[$a]) { THROW 'no_account' };
                 UPDATE account:[$a] SET deleting = true RETURN NONE;
                 LET $gone = (SELECT VALUE meta::id(id)[0] FROM device WHERE account = $a);
                 UPDATE device SET disabled = true WHERE account = $a RETURN NONE;",
                    mark_prune!(),
                    "UPDATE directory:v SET version += 1 RETURN NONE;
                 UPSERT outbox:[$j] SET job = $job, at = time::now() RETURN NONE;
                 COMMIT TRANSACTION;"
                ),
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("j", bytes(job.id.as_bytes())),
                    var("job", bytes(&job.to_bytes())),
                ],
            )
            .await;
        match v {
            Ok(_) => Ok(true),
            Err(DbError::Statement(kind)) if kind == "Thrown" => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// [`Registry::begin_account_deletion`] on a device's request: only the account's enabled
    /// primary may delete it, checked inside the same transaction (Prompt 3, M4, D-0052). Returns
    /// the account.
    ///
    /// # Errors
    /// [`RegistryError::NotPrimary`] for any other device.
    pub async fn begin_account_deletion_by(
        &self,
        device: &DeviceId,
        job: impl FnOnce(&AccountId) -> Option<Job>,
    ) -> Result<AccountId, RegistryError> {
        let Some(row) = self.device(device).await? else {
            return Err(RegistryError::NotPrimary);
        };
        if !row.primary || row.disabled {
            return Err(RegistryError::NotPrimary);
        }
        let job = job(&row.account).ok_or(RegistryError::Shape)?;
        let v = self
            .db
            .query(
                concat!(
                    "BEGIN TRANSACTION;
                 LET $row = (SELECT account, disabled, prim FROM ONLY device:[$d]);
                 IF $row = NONE OR $row.disabled OR $row.prim != true OR $row.account != $a
                   { THROW 'songbird:primary' };
                 UPDATE account:[$a] SET deleting = true, dgen = (dgen ?? 0) + 1 RETURN NONE;
                 LET $gone = (SELECT VALUE meta::id(id)[0] FROM device WHERE account = $a);
                 UPDATE device SET disabled = true WHERE account = $a RETURN NONE;",
                    mark_prune!(),
                    "UPDATE directory:v SET version += 1 RETURN NONE;
                 UPSERT outbox:[$j] SET job = $job, at = time::now() RETURN NONE;
                 COMMIT TRANSACTION;"
                ),
                vec![
                    var("d", bytes(device.as_bytes())),
                    var("a", bytes(row.account.as_bytes())),
                    var("j", bytes(job.id.as_bytes())),
                    var("job", bytes(&job.to_bytes())),
                ],
            )
            .await;
        match v {
            Ok(_) => Ok(row.account),
            Err(DbError::Statement(kind)) if kind == "Thrown:primary" => {
                Err(RegistryError::NotPrimary)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes an account's device rows and its account row (last step of deletion); its username
    /// is held for [`USERNAME_HOLD`] with no account named, its link deleted.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_account_rows(&self, account: &AccountId) -> Result<(), RegistryError> {
        self.db
            .query(
                "BEGIN TRANSACTION;
                 LET $devs = (SELECT VALUE meta::id(id)[0] FROM device WHERE account = $a);
                 DELETE otpk WHERE device IN $devs RETURN NONE;
                 DELETE otkem WHERE device IN $devs RETURN NONE;
                 DELETE mlskp WHERE device IN $devs RETURN NONE;
                 DELETE mlskp_used WHERE device IN $devs RETURN NONE;
                 DELETE device WHERE account = $a RETURN NONE;
                 UPDATE username SET account = NONE, held_until = time::now() + duration::from_secs($hold)
                   WHERE account = $a RETURN NONE;
                 DELETE ulink WHERE account = $a RETURN NONE;
                 DELETE ltoken WHERE account = $a RETURN NONE;
                 DELETE passkey WHERE account = $a RETURN NONE;
                 DELETE avatar WHERE account = $a RETURN NONE;
                 DELETE grp_req WHERE acct = $a RETURN NONE;
                 UPDATE grp_prune SET gone = array::complement(gone, $devs)
                   WHERE gone CONTAINSANY $devs RETURN NONE;
                 DELETE account:[$a] RETURN NONE;
                 UPDATE directory:v SET version += 1 RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("hold", int(USERNAME_HOLD.as_secs())),
                ],
            )
            .await?;
        Ok(())
    }

    /// What is left of an account and its devices.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn remnants(
        &self,
        account: &AccountId,
        devices: &[DeviceId],
        push_index: &[[u8; 32]],
    ) -> Result<Remnants, RegistryError> {
        let ds: Vec<Value> = devices.iter().map(|d| bytes(d.as_bytes())).collect();
        let ps: Vec<Value> = push_index.iter().map(|p| bytes(p)).collect();
        let v = self
            .db
            .query(
                "RETURN count(SELECT id FROM account:[$a]);
                 RETURN count(SELECT id FROM device WHERE account = $a OR meta::id(id)[0] IN $ds);
                 RETURN count(SELECT id FROM push_token WHERE meta::id(id)[0] IN $ps);
                 RETURN count(SELECT id FROM upload_grant WHERE device IN $ds)
                   + count(SELECT id FROM pack WHERE device IN $ds);
                 RETURN count(SELECT id FROM username WHERE account = $a);
                 RETURN count(SELECT id FROM ulink WHERE account = $a)
                   + count(SELECT id FROM ltoken WHERE account = $a)
                   + count(SELECT id FROM passkey WHERE account = $a)
                   + count(SELECT id FROM avatar WHERE account = $a);
                 RETURN count(SELECT id FROM otpk WHERE device IN $ds)
                   + count(SELECT id FROM otkem WHERE device IN $ds)
                   + count(SELECT id FROM mlskp WHERE device IN $ds)
                   + count(SELECT id FROM mlskp_used WHERE device IN $ds);
                 RETURN count(SELECT id FROM grp_req WHERE acct = $a);
                 RETURN count(SELECT id FROM grp_prune WHERE gone CONTAINSANY $ds);",
                vec![
                    var("a", bytes(account.as_bytes())),
                    var("ds", Value::Array(ds)),
                    var("ps", Value::Array(ps)),
                ],
            )
            .await?;
        let n = |i: usize| {
            v.get(i)
                .and_then(first_int)
                .and_then(|x| u64::try_from(x).ok())
                .ok_or(RegistryError::Shape)
        };
        Ok(Remnants {
            account: n(0)?,
            devices: n(1)?,
            push_tokens: n(2)?,
            grants: n(3)?,
            usernames: n(4)?,
            links: n(5)?,
            prekeys: n(6)?,
            group_requests: n(7)?,
            group_marks: n(8)?,
        })
    }

    // ----- push tokens -----

    /// Stores (or replaces) a device's sealed push token under its keyed hash.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn put_push_token(
        &self,
        index: &[u8; 32],
        sealed: &[u8],
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPSERT push_token:[$p] SET sealed = $s, at = time::now() RETURN NONE;",
                vec![var("p", bytes(index)), var("s", bytes(sealed))],
            )
            .await?;
        Ok(())
    }

    /// A device's sealed push token.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn push_token(&self, index: &[u8; 32]) -> Result<Option<Bytes>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE sealed FROM ONLY push_token:[$p];",
                vec![var("p", bytes(index))],
            )
            .await?;
        Ok(v.as_bytes().cloned())
    }

    /// Deletes push tokens (unregistered, or their device deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_push_tokens(&self, index: &[[u8; 32]]) -> Result<(), RegistryError> {
        let ps: Vec<Value> = index.iter().map(|p| bytes(p)).collect();
        self.db
            .query(
                "FOR $p IN $ps { DELETE push_token:[$p] RETURN NONE; };",
                vec![var("ps", Value::Array(ps))],
            )
            .await?;
        Ok(())
    }

    // ----- uploads and attachments -----

    /// Records an upload grant.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn create_grant(
        &self,
        object: &ObjectKey,
        grant: &Grant,
        ttl: Duration,
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "CREATE upload_grant:[$o] SET device = $d, size = $n, fetches = $f,
                   expires = time::now() + duration::from_secs($ttl),
                   deadline = time::now() + duration::from_secs($max) RETURN NONE;",
                vec![
                    var("o", bytes(&object.0)),
                    var("d", bytes(grant.device.as_bytes())),
                    var("n", int(grant.size)),
                    var("f", int(u64::from(grant.fetches))),
                    var("ttl", int(ttl.as_secs())),
                    var("max", int(GRANT_MAX_AGE.as_secs().max(ttl.as_secs()))),
                ],
            )
            .await?;
        Ok(())
    }

    /// An unexpired grant with its resumable state (Prompt 6, M2).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn pending_upload(
        &self,
        object: &ObjectKey,
    ) -> Result<Option<PendingUpload>, RegistryError> {
        let Some(grant) = self.grant(object).await? else {
            return Ok(None);
        };
        let v = self
            .db
            .query1(
                "SELECT VALUE upload FROM ONLY upload_grant:[$o] WHERE expires > time::now();",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        let upload = match v {
            Value::Array(a) => a
                .into_iter()
                .next()
                .and_then(|u| u.as_text().map(str::to_owned)),
            other => other.as_text().map(str::to_owned),
        };
        Ok(Some(PendingUpload { grant, upload }))
    }

    /// Records the multipart upload of an unexpired grant, if it has none yet (two first parts
    /// racing: one wins). Returns the upload ID the grant now holds, or `None` if the grant is
    /// gone.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn set_grant_upload(
        &self,
        object: &ObjectKey,
        upload: &str,
    ) -> Result<Option<String>, RegistryError> {
        let v = self
            .db
            .query(
                "UPDATE upload_grant:[$o] SET upload = $u
                   WHERE upload = NONE AND expires > time::now() RETURN NONE;
                 SELECT VALUE upload FROM ONLY upload_grant:[$o] WHERE expires > time::now();",
                vec![var("o", bytes(&object.0)), var("u", Value::from(upload))],
            )
            .await?;
        Ok(match v.into_iter().nth(1).unwrap_or(Value::Null) {
            Value::Array(a) => a
                .into_iter()
                .next()
                .and_then(|u| u.as_text().map(str::to_owned)),
            other => other.as_text().map(str::to_owned),
        })
    }

    /// Counts one part write against an unexpired grant, if fewer than `most` were counted:
    /// retries are allowed, an endless stream of rewrites is not (Prompt 6, D-0084).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn spend_part(&self, object: &ObjectKey, most: u64) -> Result<bool, RegistryError> {
        let v = self
            .db
            .query1(
                "UPDATE upload_grant:[$o] SET sent += 1
                   WHERE expires > time::now() AND (sent ?? 0) < $m RETURN VALUE sent;",
                vec![var("o", bytes(&object.0)), var("m", int(most))],
            )
            .await?;
        Ok(!rows(v).is_empty())
    }

    /// Keeps an unexpired grant alive for `idle` more, never past its deadline
    /// ([`GRANT_MAX_AGE`] after it was issued): a resumable upload that keeps sending parts
    /// keeps its grant.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn touch_grant(
        &self,
        object: &ObjectKey,
        idle: Duration,
    ) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPDATE upload_grant:[$o]
                   SET expires = IF deadline != NONE AND deadline < time::now() + duration::from_secs($t)
                       { deadline } ELSE { time::now() + duration::from_secs($t) }
                   WHERE expires > time::now() RETURN NONE;",
                vec![var("o", bytes(&object.0)), var("t", int(idle.as_secs()))],
            )
            .await?;
        Ok(())
    }

    /// An unexpired grant.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn grant(&self, object: &ObjectKey) -> Result<Option<Grant>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT device, size, fetches FROM ONLY upload_grant:[$o] WHERE expires > time::now();",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        let v = match v {
            Value::Array(mut a) if a.len() == 1 => a.swap_remove(0),
            Value::Array(_) => return Ok(None),
            other => other,
        };
        if v.is_absent() {
            return Ok(None);
        }
        let (Some(d), Some(size), Some(fetches)) = (
            v.get("device").and_then(id16),
            v.get("size")
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok()),
            v.get("fetches")
                .and_then(Value::as_i64)
                .and_then(|n| u32::try_from(n).ok()),
        ) else {
            return Err(RegistryError::Shape);
        };
        Ok(Some(Grant {
            device: DeviceId::from_bytes(d),
            size,
            fetches,
        }))
    }

    /// Turns a used grant into an attachment record (no link to the uploader), in one
    /// transaction. Returns false if the grant is gone (expired or used).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn complete_upload(&self, object: &ObjectKey) -> Result<bool, RegistryError> {
        Ok(self.finish_upload(object).await? == UploadEnd::Completed)
    }

    /// Turns an unexpired grant into an attachment record, and says what happened when it
    /// could not: the object is already an attachment (a retried completion: keep it), or there is
    /// no live grant (the caller may delete what it stored). Prompt 6, D-0084.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn finish_upload(&self, object: &ObjectKey) -> Result<UploadEnd, RegistryError> {
        let v = self
            .db
            .query(
                "BEGIN TRANSACTION;
                 IF record::exists(attachment:[$o]) { THROW 'songbird:attached' };
                 LET $n = (SELECT VALUE size FROM ONLY upload_grant:[$o] WHERE expires > time::now());
                 LET $f = (SELECT VALUE fetches FROM ONLY upload_grant:[$o] WHERE expires > time::now());
                 IF $n = NONE OR $f = NONE { THROW 'songbird:no_grant' };
                 DELETE upload_grant:[$o] RETURN NONE;
                 CREATE attachment:[$o] SET size = $n, left = $f,
                   expires = time::now() + duration::from_secs($age) RETURN NONE;
                 COMMIT TRANSACTION;",
                vec![
                    var("o", bytes(&object.0)),
                    var("age", int(ATTACHMENT_MAX_AGE.as_secs())),
                ],
            )
            .await;
        match v {
            Ok(_) => Ok(UploadEnd::Completed),
            Err(DbError::Statement(kind)) if kind == "Thrown:attached" => Ok(UploadEnd::Attached),
            Err(DbError::Statement(kind)) if kind.starts_with("Thrown") => Ok(UploadEnd::Gone),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes a grant (expired, or its device deleted).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_grant(&self, object: &ObjectKey) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE upload_grant:[$o] RETURN NONE;",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        Ok(())
    }

    /// Pending grants of some devices.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn grants_of(&self, devices: &[DeviceId]) -> Result<Vec<ObjectKey>, RegistryError> {
        let ds: Vec<Value> = devices.iter().map(|d| bytes(d.as_bytes())).collect();
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM upload_grant WHERE device IN $ds;",
                vec![var("ds", Value::Array(ds))],
            )
            .await?;
        objects(v)
    }

    /// Up to `limit` expired grants.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn expired_grants(&self, limit: usize) -> Result<Vec<ObjectKey>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM upload_grant WHERE expires <= time::now() LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        objects(v)
    }

    /// An unexpired attachment.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn attachment(
        &self,
        object: &ObjectKey,
    ) -> Result<Option<Attachment>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT size, left FROM ONLY attachment:[$o] WHERE expires > time::now() AND left > 0;",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        let v = match v {
            Value::Array(mut a) if a.len() == 1 => a.swap_remove(0),
            Value::Array(_) => return Ok(None),
            other => other,
        };
        if v.is_absent() {
            return Ok(None);
        }
        let (Some(size), Some(left)) = (
            v.get("size")
                .and_then(Value::as_i64)
                .and_then(|n| u64::try_from(n).ok()),
            v.get("left")
                .and_then(Value::as_i64)
                .and_then(|n| u32::try_from(n).ok()),
        ) else {
            return Err(RegistryError::Shape);
        };
        Ok(Some(Attachment { size, left }))
    }

    /// Counts one completed fetch; returns the fetches still due (0: the last one; delete the
    /// object), or `None` if there was nothing left to fetch.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn count_fetch(&self, object: &ObjectKey) -> Result<Option<u32>, RegistryError> {
        let v = self
            .db
            .query1(
                "UPDATE attachment:[$o] SET left -= 1 WHERE left > 0 RETURN VALUE left;",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        Ok(first_int(&v).and_then(|n| u32::try_from(n).ok()))
    }

    /// Deletes an attachment record.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn delete_attachment(&self, object: &ObjectKey) -> Result<(), RegistryError> {
        self.db
            .query(
                "DELETE attachment:[$o] RETURN NONE;",
                vec![var("o", bytes(&object.0))],
            )
            .await?;
        Ok(())
    }

    /// Up to `limit` attachments past their 30 days, or fully fetched.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn expired_attachments(&self, limit: usize) -> Result<Vec<ObjectKey>, RegistryError> {
        let v = self
            .db
            .query1(
                "SELECT VALUE meta::id(id)[0] FROM attachment WHERE expires <= time::now() OR left <= 0 LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await?;
        objects(v)
    }

    // ----- outbox -----

    /// Writes a job to the outbox on its own (most outbox rows are written inside the
    /// transaction of the change that needs them).
    ///
    /// # Errors
    /// [`RegistryError`].
    pub async fn outbox_put(&self, job: &Job) -> Result<(), RegistryError> {
        self.db
            .query(
                "UPSERT outbox:[$j] SET job = $job, at = time::now() RETURN NONE;",
                vec![
                    var("j", bytes(job.id.as_bytes())),
                    var("job", bytes(&job.to_bytes())),
                ],
            )
            .await?;
        Ok(())
    }
}

fn objects(v: Value) -> Result<Vec<ObjectKey>, RegistryError> {
    rows(v)
        .iter()
        .map(|o| id32(o).map(ObjectKey).ok_or(RegistryError::Shape))
        .collect()
}

impl songbird_jobs::Outbox for Registry {
    async fn take(&self, limit: usize) -> Result<Vec<Job>, String> {
        let v = self
            .db
            .query1(
                "SELECT VALUE job FROM outbox ORDER BY at LIMIT $n;",
                vec![var("n", int(u64::try_from(limit).unwrap_or(u64::MAX)))],
            )
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for j in rows(v) {
            match j.as_bytes().map(|b| Job::from_bytes(b)) {
                Some(Ok(job)) => out.push(job),
                _ => {
                    // A row that does not decode would block the outbox forever: drop it loudly.
                    tracing::error!("outbox row does not decode; dropped");
                }
            }
        }
        Ok(out)
    }

    async fn remove(&self, ids: &[JobId]) -> Result<(), String> {
        let js: Vec<Value> = ids.iter().map(|j| bytes(j.as_bytes())).collect();
        self.db
            .query(
                "FOR $j IN $js { DELETE outbox:[$j] RETURN NONE; };",
                vec![var("js", Value::Array(js))],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Invite code length (`songbird_proto::registration::INVITE_LEN`).
pub const INVITE_CODE_LEN: usize = 15;

/// What an invite code is stored under: `SHA-256("songbird.v1/invite\0" || code)`. A code is 120
/// random bits, so an unkeyed hash is enough: the table alone gives no code back, and nothing
/// can be precomputed. Comparison is by database key lookup on the hash; guessing is limited by
/// the proof of work and the refused-invite throttles in front of it.
#[must_use]
pub fn invite_hash(code: &[u8; INVITE_CODE_LEN]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ctx.update(b"songbird.v1/invite\0");
    ctx.update(code);
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// The keyed hash a push token is stored under (HMAC-SHA256 of the device ID with the
/// push-index secret): the table alone does not say which device a token belongs to.
#[must_use]
pub fn push_index(secret: &[u8; 32], device: &DeviceId) -> [u8; 32] {
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret);
    let tag = aws_lc_rs::hmac::sign(&key, device.as_bytes());
    let mut out = [0u8; 32];
    if let Some(t) = tag.as_ref().get(..32) {
        out.copy_from_slice(t);
    }
    out
}

#[cfg(test)]
mod backoff_tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use std::time::{Duration, Instant};

    use super::{Backoff, CONFLICT_BUDGET, CONFLICT_RETRIES, RegistryError};

    #[test]
    fn the_cap_doubles_from_2_ms_to_128_ms() {
        let caps: Vec<u64> = (1..=9)
            .map(|a| u64::try_from(Backoff::cap(a).as_millis()).unwrap())
            .collect();
        assert_eq!(caps, [2, 4, 8, 16, 32, 64, 128, 128, 128]);
    }

    #[tokio::test]
    async fn retries_end_in_busy_within_the_budget_plus_one_wait() {
        let start = Instant::now();
        let mut b = Backoff::new();
        let mut retries = 0;
        while b.conflicted().await.is_ok() {
            retries += 1;
        }
        assert!(retries <= CONFLICT_RETRIES);
        // The budget is checked before each wait, and one wait is at most the largest cap.
        assert!(start.elapsed() < CONFLICT_BUDGET + Backoff::cap(7) + Duration::from_millis(250));
    }

    #[tokio::test]
    async fn the_attempt_limit_ends_retries_even_with_time_left() {
        let mut b = Backoff::new();
        b.attempt = CONFLICT_RETRIES;
        assert!(matches!(b.conflicted().await, Err(RegistryError::Busy)));
    }

    #[tokio::test]
    async fn the_time_budget_ends_retries_even_with_attempts_left() {
        let busy = || (super::METRICS[1].2)();
        let before = busy();
        let mut b = Backoff::new();
        b.started = Instant::now().checked_sub(CONFLICT_BUDGET).unwrap();
        assert!(matches!(b.conflicted().await, Err(RegistryError::Busy)));
        // Counted for the runbook's alert (process-wide; other tests may add to it too).
        assert!(busy() > before);
    }
}
