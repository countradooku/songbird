//! Metadata-only risk signals and the standing they lead to (Prompt 11, M5; PROTOCOL §14.7;
//! D-0126 §7, D-0131). Nothing here reads content.
//!
//! Two signals, counted under keyed tags (never an ID) and evaluated when they arrive, by the
//! request that knows the account then:
//!
//! - **Reports:** a verified report of a **direct** message the account sent (franking proves the
//!   reporter received it; one report per message). Group messages are reported to moderators
//!   but never move a standing on their own: a group of brigaders could otherwise do it.
//! - **Blocks after requests:** a block by someone the account sent a message request to in the
//!   last week (the gate marks the pair), weighed against how many requests it sent.
//!
//! Over a threshold the account is **limited** for [`LIMIT_DAYS`]: a request budget of a couple
//! an hour and no new group invite links. A new signal while limited extends it; quiet, it lifts
//! by itself. Only a moderator suspends.

use songbird_accounts::Registry;
use songbird_accounts::standing::Signal;
use songbird_send::GateKeys;
use songbird_types::AccountId;
use songbird_valkey::ValkeyConn;

/// Distinct direct messages reported in 30 days that limit an account.
pub const REPORTS_30D: u64 = 5;
/// Blocks after requests in 7 days that may limit an account…
pub const BLOCKS_7D: u64 = 5;
/// …when they are at least this share of its requests in those 7 days (percent).
pub const BLOCK_SHARE_PCT: u64 = 20;
/// Days a limit lasts from its latest signal.
pub const LIMIT_DAYS: u32 = 7;

/// What a signal led to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Under the thresholds.
    Fine,
    /// The account is now limited (until the day given).
    Limited(u32),
}

async fn limit(registry: &Registry, account: &AccountId, reason: &str, today: u32) -> Verdict {
    let until = today + LIMIT_DAYS;
    match registry
        .set_standing(account, "limited", Some(until), reason, "auto")
        .await
    {
        Ok(()) => Verdict::Limited(until),
        Err(e) => {
            tracing::warn!(error = %e, "standing not set");
            Verdict::Fine
        }
    }
}

/// A verified report of a direct message `sender` sent.
pub async fn on_report(
    registry: &Registry,
    keys: &GateKeys,
    sender: &AccountId,
    today: u32,
) -> Verdict {
    let tag = keys.tag("rsig", &[sender.as_bytes()]);
    match registry.count_signal(Signal::Report, &tag, today, 30).await {
        Ok(n) if n >= REPORTS_30D => limit(registry, sender, "reports", today).await,
        Ok(_) => Verdict::Fine,
        Err(e) => {
            tracing::warn!(error = %e, "report signal not counted");
            Verdict::Fine
        }
    }
}

/// A new block of `blocked` by `by`: counted only if `blocked` sent `by` a request in
/// the last week; limited when such blocks are many and a large share of its requests.
pub async fn on_block(
    registry: &Registry,
    hot: &ValkeyConn,
    keys: &GateKeys,
    by: &AccountId,
    blocked: &AccountId,
    today: u32,
) -> Verdict {
    let mark = songbird_send::gate::request_mark(keys, blocked, by);
    let marked = hot
        .query::<Option<String>>(redis::cmd("GET").arg(&mark))
        .await
        .ok()
        .flatten()
        .is_some();
    if !marked {
        return Verdict::Fine;
    }
    let tag = keys.tag("bsig", &[blocked.as_bytes()]);
    let blocks = match registry.count_signal(Signal::Block, &tag, today, 7).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "block signal not counted");
            return Verdict::Fine;
        }
    };
    if blocks < BLOCKS_7D {
        return Verdict::Fine;
    }
    let mut requests = 0u64;
    for d in today.saturating_sub(6)..=today {
        let n = hot
            .query::<Option<u64>>(
                redis::cmd("GET").arg(songbird_send::gate::request_count(keys, blocked, d)),
            )
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
        requests += n;
    }
    if blocks * 100 >= requests.max(1) * BLOCK_SHARE_PCT {
        limit(registry, blocked, "blocks", today).await
    } else {
        Verdict::Fine
    }
}
