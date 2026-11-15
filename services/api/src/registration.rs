//! Registration and invites (Prompt 3, M1, D-0048; `docs/PROTOCOL.md` §4.1–§4.2).
//!
//! | Method and path | What |
//! | --- | --- |
//! | `POST /v1/registration/challenge` | A proof-of-work challenge (51 bytes, `songbird-pow`) |
//! | `POST /v1/registration` | A solved challenge, keys and (invite-only mode) a code: the new account and device IDs |
//! | `POST /v1/invites` | Signed: one invite code from the account's allowance |
//! | `GET /v1/invites` | Signed: the allowance left, and whether registration is invite-only |
//! | `DELETE /v1/invites` | Signed: revokes a code (whoever holds a code may revoke it) |
//!
//! # Order of checks on `POST /v1/registration`, cheapest first
//!
//! 1. Body length, then strict decoding.
//! 2. Throttles: the range's and the deployment's registration budget; in invite-only mode,
//!    whether the range or the deployment has used up its refused-invite budget (peeked, not
//!    spent).
//! 3. The challenge's MAC and age (no state).
//! 4. Both keys canonical and of prime order, different from each other, each signature valid
//!    (`songbird-keys`).
//! 5. The challenge's nonce burnt in `valkey-hot` (single use): a replay, or a second attempt
//!    with the same challenge, stops here.
//! 6. The proof of work, off the async runtime, a bounded number at once. A forged solution
//!    costs the server one Argon2id evaluation per challenge it handed out.
//! 7. The invite (in invite-only mode) and the account, in one transaction. A refused code
//!    spends the range's and the deployment's refused-invite budget.
//!
//! Every invite refusal (unknown, used up, expired, revoked) gets the same answer. Refusals say
//! which step failed only as far as the client must know to recover (solve again, fix the code,
//! wait), never whether a code ever existed.
//!
//! # What is stored
//!
//! The account (random ID, identity key, invites left) and its device (random ID, authentication
//! key). Not stored: the IP address or range (only a keyed hash of the range, in `valkey-hot`,
//! for the throttle window), the challenge (its nonce for its lifetime), and who invited whom
//! (D-0038, D-0047: an invite row holds uses and expiry only and goes at its last use).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::{hkdf, hmac};
use bytes::Bytes;
use songbird_accounts::{NewAccount, Registry, RegistryError, invite_hash};
use songbird_pow::{ChallengeKey, PowError};
use songbird_proto::registration::{
    self, DEVICE_CONTEXT, IDENTITY_CONTEXT, RegisterRequest, invite,
};
use songbird_types::{AccountId, DeviceId};
use songbird_valkey::ValkeyConn;
use tokio::sync::Semaphore;

use crate::config::RegistrationSettings;

/// The client's address, put on every request by the listener.
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub IpAddr);

/// GCRA without recording: 0 if a request would be allowed now, else the wait in microseconds.
/// Same arguments as [`crate::messages::GCRA`].
pub const GCRA_PEEK: &str = "local t = redis.call('TIME') \
     local now = tonumber(t[1]) * 1000000 + tonumber(t[2]) \
     local tat = tonumber(redis.call('GET', KEYS[1]) or now) \
     if tat < now then tat = now end \
     local wait = tat + tonumber(ARGV[1]) - tonumber(ARGV[2]) - now \
     if wait > 0 then return wait end \
     return 0";

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct RegistrationMetrics {
    /// Challenges issued.
    pub challenges: songbird_service::telemetry::sharded::ShardedCounter,
    /// Accounts registered.
    pub registered: songbird_service::telemetry::sharded::ShardedCounter,
    /// Registrations refused (any reason but throttling).
    pub refused: songbird_service::telemetry::sharded::ShardedCounter,
    /// Requests refused by a throttle.
    pub throttled: songbird_service::telemetry::sharded::ShardedCounter,
    /// Registrations refused for their invite code.
    pub invite_refused: songbird_service::telemetry::sharded::ShardedCounter,
    /// Invites users created.
    pub invites_created: songbird_service::telemetry::sharded::ShardedCounter,
}

/// What a registration endpoint answers (the HTTP layer maps it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 200: the challenge bytes.
    Challenge(Bytes),
    /// 201: the new account and device.
    Registered {
        /// Account ID.
        account: AccountId,
        /// Device ID.
        device: DeviceId,
    },
    /// 400: the request does not decode, or its keys or signatures are refused.
    Malformed(&'static str),
    /// 403: the challenge is forged, expired, already used or wrongly solved: get a new one.
    Challenge403,
    /// 403: the invite code is missing, unknown, used up, expired or revoked.
    Invite403,
    /// 429: wait this long (microseconds) and retry.
    Throttled(u64),
    /// 503: a dependency failed (Valkey, the database) or verification is saturated.
    Unavailable,
}

/// Registration state shared by every request.
pub struct Registration {
    /// Settings.
    pub settings: RegistrationSettings,
    challenge_key: ChallengeKey,
    throttle_key: hmac::Key,
    verifications: Arc<Semaphore>,
    /// Counters.
    pub metrics: RegistrationMetrics,
}

impl std::fmt::Debug for Registration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registration")
            .field("invite_only", &self.settings.invite_only)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The IP range an address belongs to: family byte, then the address masked to the prefix.
/// IPv4-mapped IPv6 addresses count as IPv4.
#[must_use]
pub fn range_of(ip: IpAddr, ipv4_prefix: u8, ipv6_prefix: u8) -> [u8; 17] {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    let mut out = [0u8; 17];
    let (family, bytes, prefix): (u8, Vec<u8>, u8) = match ip {
        IpAddr::V4(a) => (4, a.octets().to_vec(), ipv4_prefix),
        IpAddr::V6(a) => (6, a.octets().to_vec(), ipv6_prefix),
    };
    out[0] = family;
    let mut left = u32::from(prefix);
    for (o, b) in out.iter_mut().skip(1).zip(bytes) {
        let keep = left.min(8);
        // keep bits of b, from the top
        let mask = if keep == 0 { 0 } else { u8::MAX << (8 - keep) };
        *o = b & mask;
        left -= keep;
    }
    out
}

/// Request bodies of `POST /v1/invites` and `DELETE /v1/invites`.
#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct InviteBody {
    /// Requested lifetime in days (capped by the configuration).
    #[serde(default)]
    pub ttl_days: Option<u32>,
    /// The code to revoke.
    #[serde(default)]
    pub code: Option<String>,
}

impl std::fmt::Debug for InviteBody {
    // A code is a bearer secret: never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteBody")
            .field("ttl_days", &self.ttl_days)
            .finish_non_exhaustive()
    }
}

impl RegistrationMetrics {
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
                "api_registration_challenges",
                "Proof-of-work challenges issued",
                &self.challenges,
            ),
            ("api_registrations", "Accounts registered", &self.registered),
            (
                "api_registrations_refused",
                "Registrations refused (not throttling)",
                &self.refused,
            ),
            (
                "api_registration_throttled",
                "Registration requests refused by a throttle",
                &self.throttled,
            ),
            (
                "api_registration_invite_refused",
                "Registrations refused for their invite code",
                &self.invite_refused,
            ),
            (
                "api_invites_created",
                "Invite codes users created",
                &self.invites_created,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

impl Registration {
    /// Derives the keys from the registration secret.
    ///
    /// # Errors
    /// Only if HKDF refuses a 32-byte output, which it does not.
    pub fn new(
        settings: RegistrationSettings,
        secret: &[u8; 32],
        metrics: RegistrationMetrics,
    ) -> Result<Self, aws_lc_rs::error::Unspecified> {
        let mut k = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird-registration-v1")
            .extract(secret)
            .expand(&[b"ip-range-throttle"], hkdf::HKDF_SHA256)?
            .fill(&mut k)?;
        let permits = match settings.max_concurrent_verifications {
            0 => std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).max(1)),
            n => n,
        };
        Ok(Self {
            challenge_key: ChallengeKey::derive(secret)?,
            throttle_key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            verifications: Arc::new(Semaphore::new(permits)),
            settings,
            metrics,
        })
    }

    fn record(&self, kind: &str, range: &[u8; 17]) -> String {
        let tag = hmac::sign(&self.throttle_key, range);
        let mut k = String::with_capacity(40);
        k.push_str("t:");
        k.push_str(kind);
        k.push(':');
        k.push_str(&hex::encode(tag.as_ref().get(..16).unwrap_or_default()));
        k
    }

    /// Spends one unit of a budget (`peek`: only asks). 0 if allowed, else microseconds to wait.
    pub(crate) async fn gcra(
        hot: &ValkeyConn,
        record: &str,
        per_hour: u32,
        burst: u32,
        peek: bool,
    ) -> Result<u64, ()> {
        let interval_us = 3_600_000_000 / u64::from(per_hour.max(1));
        let tolerance_us = interval_us.saturating_mul(u64::from(burst.max(1)));
        let script = if peek {
            GCRA_PEEK
        } else {
            crate::messages::GCRA
        };
        hot.query::<i64>(
            redis::cmd("EVAL")
                .arg(script)
                .arg(1)
                .arg(record)
                .arg(interval_us)
                .arg(tolerance_us),
        )
        .await
        .map(|w| u64::try_from(w).unwrap_or(0))
        .map_err(|_| ())
    }

    /// `POST /v1/registration/challenge`.
    pub async fn challenge(&self, hot: &ValkeyConn, peer: IpAddr) -> Outcome {
        let t = self.settings.throttle;
        let range = range_of(peer, t.ipv4_prefix, t.ipv6_prefix);
        match Self::gcra(
            hot,
            &self.record("c", &range),
            t.challenges_per_hour,
            t.challenge_burst,
            false,
        )
        .await
        {
            Ok(0) => {}
            Ok(wait) => {
                self.metrics.throttled.inc();
                return Outcome::Throttled(wait);
            }
            Err(()) => return Outcome::Unavailable,
        }
        match self
            .challenge_key
            .issue(self.settings.pow.params(), now_ms())
        {
            Ok(c) => {
                self.metrics.challenges.inc();
                Outcome::Challenge(Bytes::copy_from_slice(&c.bytes))
            }
            Err(_) => Outcome::Unavailable,
        }
    }

    /// `POST /v1/registration`.
    pub async fn register(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        server_name: &str,
        peer: IpAddr,
        body: &[u8],
    ) -> Outcome {
        let out = self
            .register_inner(registry, hot, server_name, peer, body)
            .await;
        match &out {
            Outcome::Registered { .. } => self.metrics.registered.inc(),
            Outcome::Throttled(_) => self.metrics.throttled.inc(),
            Outcome::Invite403 => {
                self.metrics.refused.inc();
                self.metrics.invite_refused.inc();
            }
            Outcome::Malformed(_) | Outcome::Challenge403 => self.metrics.refused.inc(),
            Outcome::Challenge(_) | Outcome::Unavailable => {}
        }
        out
    }

    async fn register_inner(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        server_name: &str,
        peer: IpAddr,
        body: &[u8],
    ) -> Outcome {
        match self.checked(hot, server_name, peer, body).await {
            Ok((req, range)) => self.create(registry, hot, &req, &range).await,
            Err(refusal) => refusal,
        }
    }

    /// Steps 1 to 6: everything before the database.
    async fn checked(
        &self,
        hot: &ValkeyConn,
        server_name: &str,
        peer: IpAddr,
        body: &[u8],
    ) -> Result<(RegisterRequest, [u8; 17]), Outcome> {
        // 1. Decode.
        let req = RegisterRequest::decode(body).map_err(|_| Outcome::Malformed("request"))?;
        // 2. Throttles.
        let range = range_of(
            peer,
            self.settings.throttle.ipv4_prefix,
            self.settings.throttle.ipv6_prefix,
        );
        self.throttle(hot, &range).await?;
        // Without a code there is nothing to check: refused before any work.
        if self.settings.invite_only && req.invite.is_none() {
            return Err(Outcome::Invite403);
        }
        // 3. The challenge.
        let ttl_ms = self.settings.challenge_ttl_secs.saturating_mul(1_000);
        let Ok(challenge) = self.challenge_key.check(&req.challenge, now_ms(), ttl_ms) else {
            return Err(Outcome::Challenge403);
        };
        // 4. Keys and signatures.
        check_keys(&req, server_name)?;
        // 5. Burn the nonce: a challenge is good for one attempt.
        let burnt: Result<redis::Value, _> = hot
            .query(
                redis::cmd("SET")
                    .arg(nonce_record(&challenge.nonce))
                    .arg(1)
                    .arg("NX")
                    .arg("PX")
                    .arg(ttl_ms.saturating_add(10_000)),
            )
            .await;
        match burnt {
            Ok(redis::Value::Nil) => return Err(Outcome::Challenge403),
            Ok(_) => {}
            Err(_) => return Err(Outcome::Unavailable),
        }
        // 6. The work, off the runtime, a bounded number at once.
        let Ok(Ok(permit)) = tokio::time::timeout(
            Duration::from_secs(2),
            Arc::clone(&self.verifications).acquire_owned(),
        )
        .await
        else {
            return Err(Outcome::Unavailable);
        };
        let solutions = req.solutions.clone();
        let verified = tokio::task::spawn_blocking(move || {
            let r = songbird_pow::verify(&challenge, &solutions);
            drop(permit);
            r
        })
        .await;
        match verified {
            Ok(Ok(())) => Ok((req, range)),
            Ok(Err(
                PowError::Wrong | PowError::Malformed | PowError::Forged | PowError::Expired,
            )) => Err(Outcome::Challenge403),
            Err(_) => Err(Outcome::Unavailable),
        }
    }

    /// The range's and the deployment's registration budgets (spent); in invite-only mode, the
    /// refused-invite budgets (peeked).
    async fn throttle(&self, hot: &ValkeyConn, range: &[u8; 17]) -> Result<(), Outcome> {
        let t = self.settings.throttle;
        let mut budgets = vec![
            (
                self.record("r", range),
                t.registrations_per_hour,
                t.registration_burst,
                false,
            ),
            (
                self.record("R", &[0; 17]),
                t.global_registrations_per_hour,
                (t.global_registrations_per_hour / 60).max(1),
                false,
            ),
        ];
        if self.settings.invite_only {
            budgets.extend(
                self.invite_failure_budgets(range)
                    .into_iter()
                    .map(|(record, rate, burst)| (record, rate, burst, true)),
            );
        }
        for (record, rate, burst, peek) in budgets {
            match Self::gcra(hot, &record, rate, burst, peek).await {
                Ok(0) => {}
                Ok(wait) => return Err(Outcome::Throttled(wait)),
                Err(()) => return Err(Outcome::Unavailable),
            }
        }
        Ok(())
    }

    /// Step 7: the invite and the account, in one transaction.
    async fn create(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        req: &RegisterRequest,
        range: &[u8; 17],
    ) -> Outcome {
        let code = if self.settings.invite_only {
            req.invite.as_ref().map(invite_hash)
        } else {
            None
        };
        for _ in 0..3 {
            let (Ok(account), Ok(device)) = (AccountId::random(), DeviceId::random()) else {
                return Outcome::Unavailable;
            };
            let new = NewAccount {
                account,
                identity: req.identity_key,
                device,
                auth_key: req.auth_key,
                allowance: self.settings.allowance,
            };
            match registry.register(&new, code.as_ref()).await {
                Ok(()) => return Outcome::Registered { account, device },
                // A 128-bit collision: draw again.
                Err(RegistryError::Exists) => {}
                Err(RegistryError::Invite) => {
                    for (record, rate, burst) in self.invite_failure_budgets(range) {
                        // Spent whatever the answer: the refusal stands either way.
                        let _ = Self::gcra(hot, &record, rate, burst, false).await;
                    }
                    return Outcome::Invite403;
                }
                Err(_) => return Outcome::Unavailable,
            }
        }
        Outcome::Unavailable
    }

    fn invite_failure_budgets(&self, range: &[u8; 17]) -> [(String, u32, u32); 2] {
        let t = self.settings.throttle;
        [
            (
                self.record("f", range),
                t.invite_failures_per_hour,
                t.invite_failure_burst,
            ),
            (
                self.record("F", &[0; 17]),
                t.global_invite_failures_per_hour,
                (t.global_invite_failures_per_hour / 60).max(1),
            ),
        ]
    }

    /// `POST /v1/invites`: a code from the account's allowance. `Ok(None)`: none left.
    ///
    /// # Errors
    /// The registry failed.
    pub async fn create_invite(
        &self,
        registry: &Registry,
        account: &AccountId,
        body: &InviteBody,
    ) -> Result<Option<(String, u64)>, RegistryError> {
        let days = body
            .ttl_days
            .unwrap_or(self.settings.invite_ttl_days)
            .clamp(1, self.settings.invite_ttl_days);
        let ttl = Duration::from_secs(u64::from(days) * 86_400);
        for _ in 0..3 {
            let mut code = [0u8; registration::INVITE_LEN];
            getrandom::fill(&mut code).map_err(|_| RegistryError::Shape)?;
            match registry
                .create_user_invite(account, &invite_hash(&code), ttl)
                .await
            {
                Ok(()) => {
                    self.metrics.invites_created.inc();
                    return Ok(Some((invite::format(&code), ttl.as_secs())));
                }
                Err(RegistryError::Allowance) => return Ok(None),
                // A 120-bit collision: draw again.
                Err(RegistryError::Exists) => {}
                Err(e) => return Err(e),
            }
        }
        Err(RegistryError::Exists)
    }
}

/// Step 4: two different keys, each canonical and of prime order, each signing its transcript.
fn check_keys(req: &RegisterRequest, server_name: &str) -> Result<(), Outcome> {
    if req.identity_key == req.auth_key {
        return Err(Outcome::Malformed("keys"));
    }
    for (context, key, sig) in [
        (IDENTITY_CONTEXT, &req.identity_key, &req.identity_sig),
        (DEVICE_CONTEXT, &req.auth_key, &req.auth_sig),
    ] {
        let t = registration::transcript(
            context,
            server_name,
            &req.challenge,
            &req.identity_key,
            &req.auth_key,
        )
        .map_err(|_| Outcome::Malformed("server name"))?;
        if !songbird_keys::ed25519_verify(key, &t, sig) {
            return Err(Outcome::Malformed("keys"));
        }
    }
    Ok(())
}

/// The `valkey-hot` record of a burnt challenge nonce (random, identifies nobody).
#[must_use]
pub fn nonce_record(nonce: &[u8; songbird_pow::NONCE_LEN]) -> String {
    let mut k = String::with_capacity(34);
    k.push_str("p:");
    k.push_str(&hex::encode(nonce));
    k
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::many_single_char_names, reason = "tests")]

    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::config::ThrottleSettings;

    #[test]
    fn formats_agree_across_crates() {
        assert_eq!(registration::CHALLENGE_LEN, songbird_pow::CHALLENGE_LEN);
        assert_eq!(registration::INVITE_LEN, songbird_accounts::INVITE_CODE_LEN);
    }

    #[test]
    fn ranges_mask_to_the_prefix_and_fold_mapped_addresses() {
        let t = ThrottleSettings::default();
        let a = range_of(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            t.ipv4_prefix,
            t.ipv6_prefix,
        );
        let b = range_of(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)),
            t.ipv4_prefix,
            t.ipv6_prefix,
        );
        let c = range_of(
            IpAddr::V4(Ipv4Addr::new(192, 0, 3, 7)),
            t.ipv4_prefix,
            t.ipv6_prefix,
        );
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(&a[..5], &[4, 192, 0, 2, 0]);
        let mapped = range_of(
            IpAddr::V6(Ipv4Addr::new(192, 0, 2, 9).to_ipv6_mapped()),
            t.ipv4_prefix,
            t.ipv6_prefix,
        );
        assert_eq!(mapped, a);
        let x: Ipv6Addr = "2001:db8:1234:5678::1".parse().unwrap();
        let y: Ipv6Addr = "2001:db8:1234:ffff::2".parse().unwrap();
        let z: Ipv6Addr = "2001:db8:1235::1".parse().unwrap();
        let rx = range_of(IpAddr::V6(x), t.ipv4_prefix, t.ipv6_prefix);
        assert_eq!(rx, range_of(IpAddr::V6(y), t.ipv4_prefix, t.ipv6_prefix));
        assert_ne!(rx, range_of(IpAddr::V6(z), t.ipv4_prefix, t.ipv6_prefix));
        assert_eq!(rx[0], 6);
        assert!(rx[7..].iter().all(|&b| b == 0));
        // An odd prefix keeps only its top bits.
        let odd = ThrottleSettings {
            ipv4_prefix: 20,
            ..t
        };
        assert_eq!(
            &range_of(
                IpAddr::V4(Ipv4Addr::new(10, 1, 0xFF, 1)),
                odd.ipv4_prefix,
                odd.ipv6_prefix
            )[..5],
            &[4, 10, 1, 0xF0, 0]
        );
    }

    #[test]
    fn throttle_records_are_keyed_and_reveal_no_address() {
        let r = Registration::new(
            RegistrationSettings {
                secret: songbird_types::SecretRef::Env("UNUSED".into()),
                invite_only: true,
                allowance: 5,
                invite_ttl_days: 7,
                challenge_ttl_secs: 600,
                max_concurrent_verifications: 1,
                pow: crate::config::PowSettings::default(),
                throttle: ThrottleSettings::default(),
            },
            &[3; 32],
            RegistrationMetrics::default(),
        )
        .unwrap();
        let range = range_of(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24, 48);
        let rec = r.record("r", &range);
        assert_eq!(rec.len(), 36);
        assert!(!rec.contains("c00002"));
        assert_ne!(rec, r.record("c", &range));
    }
}
