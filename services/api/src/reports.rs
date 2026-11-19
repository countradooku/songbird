//! Reporting with message franking (Prompt 4, M5; `docs/PROTOCOL.md` §5.14; D-0063).
//!
//! `POST /v1/reports`, from a listed device, carries one message the device received: the
//! franking stamp it kept, the sender it decrypted, the franking key and the encoded content
//! ([`songbird_proto::report`]). The server:
//!
//! 1. spends the reporter's budget (keyed, in `valkey-hot`), before anything else, so reports
//!    cannot be used to probe stamps;
//! 2. checks its own stamp ([`verify`]): a franking key it holds, a time inside the report window,
//!    and a MAC binding the commitment and time to the sender (or none: a sealed send) and to the
//!    reporter's account (or none: a group's shared body). A stamp for another recipient fails,
//!    so only a recipient can report a message;
//! 3. checks that the commitment opens to the content under the franking key (constant time):
//!    the sender cannot have stamped other words than these;
//! 4. seals a **minimal report** to the moderation key, which the servers never hold: the reason,
//!    the sender and whether the server attests it, direct or group, the stamp's time, the
//!    content. Nothing names the reporter, and nothing else about the conversation is sent;
//! 5. queues it under a keyed hash of the stamp's tag (one report per message), kept for the
//!    retention period.
//!
//! The content is never decoded here (the server does not link `songbird-content`); moderators
//! decode it with `songbird-admin reports open`, which holds the moderation key.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use songbird_accounts::{DeviceRow, Registry, RegistryError};
use songbird_keys::provisioning::Domain;
use songbird_proto::report::Report;
use songbird_send::{Frankers, GateKeys};
use songbird_service::telemetry::sharded::ShardedCounter as Counter;
use songbird_types::AccountId;
use songbird_valkey::ValkeyConn;

use crate::config::ReportSettings;
use crate::devices::Outcome;

/// The HMAC context of franking commitments (`songbird_content::FRANKING_CONTEXT`; the server
/// does not link that crate, and `tests/e2e` checks the two agree).
pub const FRANKING_CONTEXT: &[u8] = b"songbird.v1/franking\0";
/// The domain reports are sealed under (`songbird_keys::provisioning::seal_with`).
pub const SEAL_DOMAIN: Domain = Domain::Report;
/// How far ahead of the server's clock a stamp may be (clock steps between nodes).
pub const MAX_AHEAD_MS: u64 = 5 * 60 * 1000;

/// Counters (aggregate only).
#[derive(Debug, Clone, Default)]
pub struct ReportMetrics {
    /// Reports verified and queued.
    pub queued: Counter,
    /// Reports refused (stamp, commitment, window, malformed).
    pub refused: Counter,
    /// Reports of a message already reported.
    pub duplicates: Counter,
    /// Reports refused by the budget.
    pub throttled: Counter,
}

impl ReportMetrics {
    /// Registers the counters.
    ///
    /// # Errors
    /// A name is refused.
    pub fn register(
        &self,
        m: &mut songbird_service::telemetry::Metrics,
    ) -> Result<(), songbird_service::telemetry::TelemetryError> {
        for (name, help, c) in [
            (
                "api_reports_queued",
                "Reports verified and queued",
                &self.queued,
            ),
            ("api_reports_refused", "Reports refused", &self.refused),
            (
                "api_reports_duplicate",
                "Reports of a message already reported",
                &self.duplicates,
            ),
            (
                "api_reports_throttled",
                "Reports refused by the budget",
                &self.throttled,
            ),
        ] {
            m.register(name, help, c.clone())?;
        }
        Ok(())
    }
}

/// What the server could establish about a reported message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The stamp names the reported sender: the server attests who sent it. False for a sealed
    /// send (the sender is only the reporter's claim).
    pub sender_attested: bool,
    /// A group's shared body (the stamp names no recipient).
    pub group: bool,
}

/// Why a report was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The stamp names a franking key the server does not hold (or no longer accepts).
    Key,
    /// The stamp is older than the report window, or from the future.
    Expired,
    /// The stamp's MAC does not verify for this reporter (and any sender).
    Stamp,
    /// The commitment does not open to the content under the franking key.
    Commitment,
}

impl Refused {
    const fn reason(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Expired => "expired",
            Self::Stamp => "stamp",
            Self::Commitment => "commitment",
        }
    }
}

/// `HMAC-SHA256(franking_key, FRANKING_CONTEXT || content)`.
#[must_use]
pub fn commitment(franking_key: &[u8; 32], content: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, franking_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(FRANKING_CONTEXT);
    ctx.update(content);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// Verifies a report for `reporter` at `now_ms` (pure; known-answer tested).
///
/// # Errors
/// [`Refused`]: the first check that fails, in this order: key, window, stamp, commitment.
pub fn verify(
    frankers: &Frankers,
    r: &Report,
    reporter: &[u8; 16],
    now_ms: u64,
    window_ms: u64,
) -> Result<Verdict, Refused> {
    let f = frankers.by_id(&r.stamp.key_id).ok_or(Refused::Key)?;
    let at = r.stamp.stamped_at_ms;
    if at > now_ms.saturating_add(MAX_AHEAD_MS) || now_ms.saturating_sub(at) > window_ms {
        return Err(Refused::Expired);
    }
    let none = [0u8; 16];
    // The sender the reporter names (attested), else none (a sealed send); this reporter (a
    // direct message), else none (a group's shared body).
    let mut senders = vec![(&none, false)];
    if r.sender != none {
        senders.insert(0, (&r.sender, true));
    }
    let verdict = senders
        .into_iter()
        .flat_map(|s| [(s, reporter, false), (s, &none, true)])
        .find(|((sender, _), recipient, _)| f.verify(&r.stamp, sender, recipient))
        .map(|((_, attested), _, group)| Verdict {
            sender_attested: attested,
            group,
        })
        .ok_or(Refused::Stamp)?;
    verify_slices_are_equal(
        &commitment(&r.franking_key, &r.content),
        &r.stamp.commitment,
    )
    .map_err(|_| Refused::Commitment)?;
    Ok(verdict)
}

/// The report endpoint.
#[derive(Debug)]
pub struct Reports {
    frankers: Frankers,
    keys: GateKeys,
    moderation: [u8; 32],
    settings: ReportSettings,
    metrics: ReportMetrics,
}

impl Reports {
    /// The endpoint, with the franking keys it verifies against, the gate's keys (budgets and
    /// report IDs) and the moderation public key reports are sealed to.
    #[must_use]
    pub fn new(
        frankers: Frankers,
        keys: GateKeys,
        moderation: [u8; 32],
        settings: ReportSettings,
        metrics: ReportMetrics,
    ) -> Self {
        Self {
            frankers,
            keys,
            moderation,
            settings,
            metrics,
        }
    }

    async fn spend(&self, hot: &ValkeyConn, reporter: &[u8; 16]) -> Result<u64, ()> {
        let interval_us = 3_600_000_000 / u64::from(self.settings.per_hour.max(1));
        let tolerance_us = interval_us.saturating_mul(u64::from(self.settings.burst.max(1)));
        hot.query::<i64>(
            redis::cmd("EVAL")
                .arg(crate::messages::GCRA)
                .arg(1)
                .arg(self.keys.record("rp", &[reporter]))
                .arg(interval_us)
                .arg(tolerance_us),
        )
        .await
        .map(|w| u64::try_from(w).unwrap_or(0))
        .map_err(|_| ())
    }

    /// `POST /v1/reports`.
    pub async fn submit(
        &self,
        registry: &Registry,
        hot: &ValkeyConn,
        row: &DeviceRow,
        body: &[u8],
        now_ms: u64,
    ) -> Outcome {
        if row.pending {
            return Outcome::Forbidden("pending");
        }
        let reporter = *row.account.as_bytes();
        match self.spend(hot, &reporter).await {
            Ok(0) => {}
            Ok(wait) => {
                self.metrics.throttled.inc();
                return Outcome::Throttled(wait);
            }
            Err(()) => return Outcome::Unavailable,
        }
        let Ok(report) = Report::decode(body) else {
            self.metrics.refused.inc();
            return Outcome::Malformed("report");
        };
        let window_ms = u64::from(self.settings.window_days) * 86_400_000;
        let verdict = match verify(&self.frankers, &report, &reporter, now_ms, window_ms) {
            Ok(v) => v,
            Err(e) => {
                self.metrics.refused.inc();
                return Outcome::Forbidden(e.reason());
            }
        };
        let minimal = serde_json::json!({
            "version": 1,
            "reason": report.reason.name(),
            "sender": hex::encode(report.sender),
            "sender_attested": verdict.sender_attested,
            "conversation": if verdict.group { "group" } else { "direct" },
            "stamped_at_ms": report.stamp.stamped_at_ms,
            "reported_at_ms": now_ms,
            "content": hex::encode(&report.content),
        });
        let Ok(plain) = serde_json::to_vec(&minimal) else {
            return Outcome::Unavailable;
        };
        let Ok(sealed) =
            songbird_keys::provisioning::seal_with(SEAL_DOMAIN, &self.moderation, &plain)
        else {
            return Outcome::Unavailable;
        };
        let id = self.keys.tag("report", &[&report.stamp.tag]);
        match registry
            .queue_report(&id, &sealed, self.settings.retention_days)
            .await
        {
            Ok(()) => {
                self.metrics.queued.inc();
                // A direct message the server attests: a signal (D-0131). Group messages go to
                // moderators only.
                if verdict.sender_attested && !verdict.group {
                    crate::abuse::on_report(
                        registry,
                        &self.keys,
                        &AccountId::from_bytes(report.sender),
                        songbird_entitlements::today(),
                    )
                    .await;
                }
                Outcome::Done
            }
            Err(RegistryError::Duplicate) => {
                self.metrics.duplicates.inc();
                Outcome::Conflict("duplicate")
            }
            Err(_) => Outcome::Unavailable,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use songbird_proto::report::Reason;
    use songbird_send::Franker;

    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const DAY: u64 = 86_400_000;

    fn keys() -> (Frankers, Franker) {
        let old = Franker::from_secret(&[1; 32]).unwrap();
        let cur = Franker::from_secret(&[2; 32]).unwrap();
        (
            Frankers {
                current: cur.clone(),
                previous: vec![old],
            },
            cur,
        )
    }

    fn report(
        f: &Franker,
        sender: [u8; 16],
        stamped_sender: [u8; 16],
        recipient: [u8; 16],
    ) -> Report {
        let content = b"the reported words".to_vec();
        let fk = [7; 32];
        Report {
            reason: Reason::Harassment,
            stamp: f.stamp(
                &commitment(&fk, &content),
                NOW - DAY,
                &stamped_sender,
                &recipient,
            ),
            sender,
            franking_key: fk,
            content,
        }
    }

    #[test]
    fn commitment_known_answer() {
        // The same value as songbird_content's known answer (Python's hmac).
        assert_eq!(
            hex::encode(commitment(&[0x42; 32], b"hello")),
            "13997e62c03ebcbe38fec3dc88e8b002d8f90378f5e174db2563cbef853680f5"
        );
    }

    #[test]
    fn a_recipients_report_of_an_identified_send_attests_the_sender() {
        let (fs, f) = keys();
        let r = report(&f, [0xA; 16], [0xA; 16], [0xB; 16]);
        assert_eq!(
            verify(&fs, &r, &[0xB; 16], NOW, 30 * DAY),
            Ok(Verdict {
                sender_attested: true,
                group: false
            })
        );
        // Anyone else reporting it (a forwarded opening) is refused.
        assert_eq!(
            verify(&fs, &r, &[0xC; 16], NOW, 30 * DAY),
            Err(Refused::Stamp)
        );
        // Naming another sender is refused.
        let mut other = r.clone();
        other.sender = [0xD; 16];
        assert_eq!(
            verify(&fs, &other, &[0xB; 16], NOW, 30 * DAY),
            Err(Refused::Stamp)
        );
    }

    #[test]
    fn sealed_and_group_messages_verify_with_what_the_stamp_names() {
        let (fs, f) = keys();
        // Sealed: the server never knew the sender; the claim is not attested.
        let r = report(&f, [0xA; 16], [0; 16], [0xB; 16]);
        assert_eq!(
            verify(&fs, &r, &[0xB; 16], NOW, 30 * DAY),
            Ok(Verdict {
                sender_attested: false,
                group: false
            })
        );
        // A group's shared body: no recipient; any member may report it.
        let r = report(&f, [0xA; 16], [0xA; 16], [0; 16]);
        assert_eq!(
            verify(&fs, &r, &[0xE; 16], NOW, 30 * DAY),
            Ok(Verdict {
                sender_attested: true,
                group: true
            })
        );
    }

    #[test]
    fn tampering_keys_and_windows_are_refused() {
        let (fs, f) = keys();
        let good = report(&f, [0xA; 16], [0xA; 16], [0xB; 16]);
        let check = |r: &Report, now| verify(&fs, r, &[0xB; 16], now, 30 * DAY);
        let mut r = good.clone();
        r.content[0] ^= 1;
        assert_eq!(check(&r, NOW), Err(Refused::Commitment), "other words");
        let mut r = good.clone();
        r.franking_key[0] ^= 1;
        assert_eq!(check(&r, NOW), Err(Refused::Commitment), "another key");
        let mut r = good.clone();
        r.stamp.commitment[0] ^= 1;
        assert_eq!(check(&r, NOW), Err(Refused::Stamp), "another commitment");
        let mut r = good.clone();
        r.stamp.stamped_at_ms += 1;
        assert_eq!(check(&r, NOW), Err(Refused::Stamp), "another time");
        let mut r = good.clone();
        r.stamp.tag[0] ^= 1;
        assert_eq!(check(&r, NOW), Err(Refused::Stamp), "a forged tag");
        let mut r = good.clone();
        r.stamp.key_id = [9; 8];
        assert_eq!(check(&r, NOW), Err(Refused::Key), "an unknown key");
        assert_eq!(
            check(&good, NOW + 30 * DAY),
            Err(Refused::Expired),
            "too old"
        );
        assert_eq!(
            check(&good, NOW - DAY - MAX_AHEAD_MS - 1),
            Err(Refused::Expired),
            "future"
        );
        // A previous key still verifies (rotation).
        let old = Franker::from_secret(&[1; 32]).unwrap();
        let r = report(&old, [0xA; 16], [0xA; 16], [0xB; 16]);
        assert!(verify(&fs, &r, &[0xB; 16], NOW, 30 * DAY).is_ok());
    }
}
