//! Usernames, the username key and username links (Prompt 3, M2, D-0049; `docs/PROTOCOL.md`
//! §4.3). Every endpoint is signed by a device ([`crate::auth`]).
//!
//! | Method and path | What |
//! | --- | --- |
//! | `PUT /v1/username` | `hash [32] \|\| proof [64]`: claim the username (unique; a previous one is held) |
//! | `DELETE /v1/username` | Release it (held, naming nobody) |
//! | `POST /v1/username/lookup` | `{"hash": hex, "key"?: digits}`: the account, or 404 |
//! | `PUT`, `DELETE /v1/username/key` | `{"key": digits}`: require a key from strangers, or stop |
//! | `PUT`, `DELETE /v1/username/link` | A link's ciphertext under a new random handle (a reset), or none |
//! | `GET /v1/username/link/<handle>` | A link's ciphertext |
//!
//! # Lookups leak nothing beyond the answer
//!
//! - One answer, 404, for an unknown username, a held one, a key required but missing, a wrong
//!   key, and a username whose key-guessing budget is spent (the owner's decision, D-0049).
//! - The same work whatever the answer: the registry reads the same rows whether or not the
//!   username exists; a lookup that carries a key always runs one Argon2id verification (against
//!   a dummy verifier when there is nothing to check) and always touches the username's
//!   key-guessing budget; a lookup without a key never runs one.
//! - Exact match only: there is no search, prefix or listing.
//! - Rate-limited per account and per IP range; key guesses limited per username across every
//!   requester (so more accounts do not mean more guesses).
//!
//! # The username key
//!
//! 4 to 10 digits, stored as `salt [16] || Argon2id(m, t, p = 1, secret = pepper)(key, salt)`.
//! The pepper comes from `[api.usernames] secret` (the secrets store, never the database or its
//! backups): a database thief cannot test keys offline. A compromised `api` can; the key only
//! gates finding someone by username, not messaging or any account power.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::{constant_time, hkdf, hmac};
use bytes::Bytes;
use songbird_accounts::{Registry, RegistryError};
use songbird_keys::username::{HASH_LEN, PROOF_LEN, Username, verify_proof};
use songbird_types::AccountId;
use songbird_valkey::ValkeyConn;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::config::UsernameSettings;
use crate::registration::{Registration, range_of};

/// Built-in reserved usernames (configuration adds more): names that would let someone pose as
/// the service. Checked by hash, like every username.
pub const RESERVED: &[&str] = &[
    "abuse",
    "admin",
    "administrator",
    "help",
    "info",
    "legal",
    "moderator",
    "official",
    "privacy",
    "root",
    "security",
    "songbird",
    "songbirdchat",
    "staff",
    "support",
    "system",
    "team",
    "verified",
];

/// The username's key-guessing budget, checked and spent atomically (GCRA on Valkey's clock):
/// `ARGV[1]` interval and `ARGV[2]` burst tolerance in microseconds, `ARGV[3]` 1 if the lookup
/// would find the account. Returns 0 (found: nothing spent), 1 (budget spent: refused, nothing
/// spent) or 2 (not found: one guess spent).
pub const KEY_GUESS: &str = "local t = redis.call('TIME') \
     local now = tonumber(t[1]) * 1000000 + tonumber(t[2]) \
     local tat = tonumber(redis.call('GET', KEYS[1]) or now) \
     if tat < now then tat = now end \
     local new = tat + tonumber(ARGV[1]) \
     if new - tonumber(ARGV[2]) - now > 0 then return 1 end \
     if ARGV[3] == '1' then return 0 end \
     redis.call('SET', KEYS[1], new, 'PX', math.ceil((new - now) / 1000) + 1) \
     return 2";

/// Salt length of a key verifier.
const SALT_LEN: usize = 16;
/// Length of a key verifier.
pub const VERIFIER_LEN: usize = SALT_LEN + 32;
/// Longest link ciphertext.
pub const MAX_LINK_BYTES: usize = 256;

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct UsernameMetrics {
    /// Usernames claimed.
    pub claimed: songbird_service::telemetry::sharded::ShardedCounter,
    /// Claims refused (taken, held or reserved).
    pub taken: songbird_service::telemetry::sharded::ShardedCounter,
    /// Lookups answered.
    pub lookups: songbird_service::telemetry::sharded::ShardedCounter,
    /// Lookups answered 404 (any reason).
    pub not_found: songbird_service::telemetry::sharded::ShardedCounter,
    /// Argon2id key verifications run (one per lookup that carries a key).
    pub key_checks: songbird_service::telemetry::sharded::ShardedCounter,
    /// Requests refused by a throttle.
    pub throttled: songbird_service::telemetry::sharded::ShardedCounter,
}

impl UsernameMetrics {
    /// Registers every metric. Names say "handle" and "guard": the telemetry layer refuses
    /// names with "username" or "key" in them (invariant 6).
    ///
    /// # Errors
    /// A refused name.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            ("api_handles_claimed", "Usernames claimed", &self.claimed),
            (
                "api_handles_taken",
                "Username claims refused (taken, held, reserved)",
                &self.taken,
            ),
            (
                "api_handle_lookups",
                "Username lookups answered",
                &self.lookups,
            ),
            (
                "api_handle_not_found",
                "Username lookups answered not found",
                &self.not_found,
            ),
            (
                "api_handle_guard_checks",
                "Username key verifications run",
                &self.key_checks,
            ),
            (
                "api_handle_throttled",
                "Username requests refused by a throttle",
                &self.throttled,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// What a username endpoint answers (the HTTP layer maps it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 200, no body.
    Done,
    /// 200: the account a lookup found.
    Found(AccountId),
    /// 200: a new link handle.
    Link([u8; 16]),
    /// 200: a link's ciphertext.
    Blob(Bytes),
    /// 400: the request is malformed or its proof is refused.
    Malformed(&'static str),
    /// 404.
    NotFound,
    /// 409: the username is taken, held or reserved.
    Taken,
    /// 409: a link needs a username.
    NoUsername,
    /// 429: wait this long (microseconds).
    Throttled(u64),
    /// 503.
    Unavailable,
}

/// Lookup request body.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupBody {
    /// The username hash, 64 hex characters.
    pub hash: String,
    /// The username key, if the requester has one.
    #[serde(default)]
    pub key: Option<String>,
}

impl std::fmt::Debug for LookupBody {
    // The key is a secret and the hash personal data: neither is printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LookupBody(..)")
    }
}

/// Username key request body.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBody {
    /// 4 to 10 digits.
    pub key: String,
}

impl std::fmt::Debug for KeyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyBody(..)")
    }
}

/// A stored verifier's salt and Argon2id output; `None` for anything not 48 bytes.
fn split_verifier(v: &[u8]) -> Option<([u8; SALT_LEN], [u8; 32])> {
    let (salt, output) = v.split_first_chunk::<SALT_LEN>()?;
    Some((*salt, output.try_into().ok()?))
}

/// Whether a username key has the allowed shape: 4 to 10 ASCII digits.
#[must_use]
pub fn key_ok(key: &str) -> bool {
    (4..=10).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_digit())
}

/// Username state shared by every request.
pub struct Usernames {
    /// Settings.
    pub settings: UsernameSettings,
    pepper: Zeroizing<[u8; 32]>,
    throttle_key: hmac::Key,
    reserved: HashSet<[u8; HASH_LEN]>,
    /// Checked against when a keyed lookup has no verifier to check, so every keyed lookup costs
    /// one Argon2id run. Random per process.
    dummy_salt: [u8; SALT_LEN],
    dummy_output: [u8; 32],
    checks: Arc<Semaphore>,
    /// Counters.
    pub metrics: UsernameMetrics,
}

impl std::fmt::Debug for Usernames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Usernames").finish_non_exhaustive()
    }
}

impl Usernames {
    /// Derives the pepper and the throttle key from the secret; hashes the reserved names.
    ///
    /// # Errors
    /// A reserved name that is not a username, or HKDF refusing a 32-byte output (it does not).
    pub fn new(
        settings: UsernameSettings,
        secret: &[u8; 32],
        metrics: UsernameMetrics,
    ) -> Result<Self, &'static str> {
        let derive = |info: &[u8]| -> Result<[u8; 32], &'static str> {
            let mut k = [0u8; 32];
            hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-usernames-v1")
                .extract(secret)
                .expand(&[info], hkdf::HKDF_SHA256)
                .and_then(|o| o.fill(&mut k))
                .map_err(|_| "hkdf")?;
            Ok(k)
        };
        let pepper = Zeroizing::new(derive(b"username-key-pepper")?);
        let throttle = derive(b"username-throttle")?;
        let mut reserved = HashSet::new();
        for name in RESERVED
            .iter()
            .copied()
            .chain(settings.reserved.iter().map(String::as_str))
        {
            let u = Username::parse(name).map_err(|_| "a reserved name is not a username")?;
            reserved.insert(u.hash());
        }
        let permits = match settings.max_concurrent_key_checks {
            0 => std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).max(1)),
            n => n,
        };
        let mut dummy_salt = [0u8; SALT_LEN];
        getrandom::fill(&mut dummy_salt).map_err(|_| "random source")?;
        let mut dummy_output = [0u8; 32];
        getrandom::fill(&mut dummy_output).map_err(|_| "random source")?;
        Ok(Self {
            dummy_salt,
            dummy_output,
            pepper,
            throttle_key: hmac::Key::new(hmac::HMAC_SHA256, &throttle),
            reserved,
            checks: Arc::new(Semaphore::new(permits)),
            settings,
            metrics,
        })
    }

    fn record(&self, kind: &str, subject: &[u8]) -> String {
        let mut ctx = hmac::Context::with_key(&self.throttle_key);
        ctx.update(kind.as_bytes());
        ctx.update(&[0]);
        ctx.update(subject);
        let tag = ctx.sign();
        let mut k = String::with_capacity(40);
        k.push_str("u:");
        k.push_str(kind);
        k.push(':');
        k.push_str(&hex::encode(tag.as_ref().get(..16).unwrap_or_default()));
        k
    }

    async fn spend(&self, hot: &ValkeyConn, budgets: &[(String, u32, u32)]) -> Result<(), Outcome> {
        for (record, rate, burst) in budgets {
            match Registration::gcra(hot, record, *rate, *burst, false).await {
                Ok(0) => {}
                Ok(wait) => {
                    self.metrics.throttled.inc();
                    return Err(Outcome::Throttled(wait));
                }
                Err(()) => return Err(Outcome::Unavailable),
            }
        }
        Ok(())
    }

    fn lookup_budgets(&self, account: &AccountId, peer: IpAddr) -> [(String, u32, u32); 2] {
        let t = &self.settings.throttle;
        let range = range_of(peer, t.ipv4_prefix, t.ipv6_prefix);
        [
            (
                self.record("l", account.as_bytes()),
                t.lookups_per_hour,
                t.lookup_burst,
            ),
            (
                self.record("r", &range),
                t.range_lookups_per_hour,
                t.range_lookup_burst,
            ),
        ]
    }

    /// Argon2id of a key with a salt and the pepper, off the async runtime, bounded.
    async fn derive(&self, key: Zeroizing<String>, salt: [u8; SALT_LEN]) -> Option<[u8; 32]> {
        let permit = tokio::time::timeout(
            Duration::from_secs(2),
            Arc::clone(&self.checks).acquire_owned(),
        )
        .await
        .ok()?
        .ok()?;
        let pepper = self.pepper.clone();
        let (m, t) = (self.settings.key.memory_kib, self.settings.key.iterations);
        tokio::task::spawn_blocking(move || {
            let params = argon2::Params::new(m, t, 1, Some(32)).ok()?;
            let argon = argon2::Argon2::new_with_secret(
                pepper.as_slice(),
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                params,
            )
            .ok()?;
            let mut out = [0u8; 32];
            argon
                .hash_password_into(key.as_bytes(), &salt, &mut out)
                .ok()?;
            drop(permit);
            Some(out)
        })
        .await
        .ok()
        .flatten()
    }

    /// `PUT /v1/username`.
    pub async fn claim(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        account: &AccountId,
        body: &[u8],
    ) -> Outcome {
        let t = &self.settings.throttle;
        // Every attempt spends: probing which names are taken costs the change budget.
        if let Err(o) = self
            .spend(
                hot,
                &[(
                    self.record("c", account.as_bytes()),
                    t.changes_per_hour,
                    t.change_burst,
                )],
            )
            .await
        {
            return o;
        }
        let Some((hash, proof)) = body
            .split_first_chunk::<HASH_LEN>()
            .filter(|(_, p)| p.len() == PROOF_LEN)
        else {
            return Outcome::Malformed("request");
        };
        if !verify_proof(hash, proof) {
            return Outcome::Malformed("proof");
        }
        if self.reserved.contains(hash) {
            self.metrics.taken.inc();
            return Outcome::Taken;
        }
        match registry.set_username(account, hash).await {
            Ok(()) => {
                self.metrics.claimed.inc();
                Outcome::Done
            }
            Err(RegistryError::Taken) => {
                self.metrics.taken.inc();
                Outcome::Taken
            }
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/username/lookup`.
    pub async fn lookup(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        account: &AccountId,
        peer: IpAddr,
        body: &[u8],
    ) -> Outcome {
        if let Err(o) = self.spend(hot, &self.lookup_budgets(account, peer)).await {
            return o;
        }
        let Ok(req) = serde_json::from_slice::<LookupBody>(body) else {
            return Outcome::Malformed("request");
        };
        let mut hash = [0u8; HASH_LEN];
        if hex::decode_to_slice(&req.hash, &mut hash).is_err() {
            return Outcome::Malformed("hash");
        }
        let key = match req.key {
            Some(k) if key_ok(&k) => Some(Zeroizing::new(k)),
            Some(_) => return Outcome::Malformed("key"),
            None => None,
        };
        self.metrics.lookups.inc();
        let Ok(row) = registry.lookup_username(&hash).await else {
            return Outcome::Unavailable;
        };
        let out = match key {
            None => match row {
                Some(r) if r.key.is_none() => Outcome::Found(r.account),
                _ => Outcome::NotFound,
            },
            Some(key) => self.lookup_with_key(hot, &hash, row, key).await,
        };
        if out == Outcome::NotFound {
            self.metrics.not_found.inc();
        }
        out
    }

    /// The keyed path: always one Argon2id run and one look at the username's guessing budget.
    async fn lookup_with_key(
        &self,
        hot: &ValkeyConn,
        hash: &[u8; HASH_LEN],
        row: Option<songbird_accounts::UsernameRow>,
        key: Zeroizing<String>,
    ) -> Outcome {
        // The verifier to check against: the account's, or the random dummy drawn at start-up
        // (it matches no key: its output part is random bytes, not a hash of one).
        let stored = row.as_ref().and_then(|r| r.key.clone());
        let (salt, expected) = stored
            .as_deref()
            .and_then(split_verifier)
            .unwrap_or((self.dummy_salt, self.dummy_output));
        self.metrics.key_checks.inc();
        let Some(derived) = self.derive(key, salt).await else {
            return Outcome::Unavailable;
        };
        let matches = constant_time::verify_slices_are_equal(&derived, &expected).is_ok();
        let t = &self.settings.throttle;
        let budget = self.record("k", hash);
        let would_find = row
            .as_ref()
            .filter(|_| stored.is_none() || matches)
            .map(|r| r.account);
        // One atomic step, one round trip on every path: a spent budget refuses even the right
        // key; a lookup that finds nothing spends one guess, whether or not the username exists.
        // (Checking then spending in two calls would let concurrent guesses share one token.)
        let verdict: Result<i64, _> = hot
            .query(
                redis::cmd("EVAL")
                    .arg(KEY_GUESS)
                    .arg(1)
                    .arg(&budget)
                    .arg(3_600_000_000 / u64::from(t.key_failures_per_hour.max(1)))
                    .arg(
                        (3_600_000_000 / u64::from(t.key_failures_per_hour.max(1)))
                            .saturating_mul(u64::from(t.key_failure_burst.max(1))),
                    )
                    .arg(i32::from(would_find.is_some())),
            )
            .await;
        match (verdict, would_find) {
            (Ok(0), Some(a)) => Outcome::Found(a),
            (Ok(_), _) => Outcome::NotFound,
            (Err(_), _) => Outcome::Unavailable,
        }
    }

    /// `PUT /v1/username/key`.
    pub async fn set_key(&self, registry: &Registry, account: &AccountId, body: &[u8]) -> Outcome {
        let Ok(req) = serde_json::from_slice::<KeyBody>(body) else {
            return Outcome::Malformed("request");
        };
        let key = Zeroizing::new(req.key);
        if !key_ok(&key) {
            return Outcome::Malformed("key");
        }
        let mut salt = [0u8; SALT_LEN];
        if getrandom::fill(&mut salt).is_err() {
            return Outcome::Unavailable;
        }
        let Some(derived) = self.derive(key, salt).await else {
            return Outcome::Unavailable;
        };
        let mut verifier = [0u8; VERIFIER_LEN];
        verifier[..SALT_LEN].copy_from_slice(&salt);
        verifier[SALT_LEN..].copy_from_slice(&derived);
        match registry.set_username_key(account, Some(&verifier)).await {
            Ok(()) => Outcome::Done,
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `PUT /v1/username/link`: a new handle every time (a reset).
    pub async fn put_link(&self, registry: &Registry, account: &AccountId, body: &[u8]) -> Outcome {
        if body.is_empty() || body.len() > MAX_LINK_BYTES {
            return Outcome::Malformed("link");
        }
        let mut handle = [0u8; 16];
        if getrandom::fill(&mut handle).is_err() {
            return Outcome::Unavailable;
        }
        match registry.put_username_link(account, &handle, body).await {
            Ok(()) => Outcome::Link(handle),
            Err(RegistryError::NoUsername) => Outcome::NoUsername,
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `GET /v1/username/link/<handle>`: spends the lookup budgets like a lookup.
    pub async fn get_link(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        account: &AccountId,
        peer: IpAddr,
        handle: &[u8; 16],
    ) -> Outcome {
        if let Err(o) = self.spend(hot, &self.lookup_budgets(account, peer)).await {
            return o;
        }
        match registry.username_link(handle).await {
            Ok(Some(b)) => Outcome::Blob(b),
            Ok(None) => Outcome::NotFound,
            Err(_) => Outcome::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;

    #[test]
    fn keys_are_four_to_ten_digits() {
        for (k, ok) in [
            ("1234", true),
            ("0000000000", true),
            ("123", false),
            ("12345678901", false),
            ("12a4", false),
            ("１２３４", false),
            ("", false),
        ] {
            assert_eq!(key_ok(k), ok, "{k}");
        }
    }

    #[test]
    fn every_reserved_name_is_a_username() {
        for r in RESERVED {
            assert!(Username::parse(r).is_ok(), "{r}");
        }
    }
}
