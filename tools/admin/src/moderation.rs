//! `songbird-admin moderation` (Prompt 11, M5; D-0126 §7–§8, D-0131): moderators' decisions on
//! franked reports, and lifting a standing after an appeal.
//!
//! - `decide` opens one queued report with the moderation key (offline), shows it, and applies
//!   one decision: `dismiss`; `limit` (the reported sender's new conversations slowed for
//!   `--days`); `suspend` (it cannot send or call, for `--days` or until lifted). The report is
//!   then deleted (short retention: a decision ends it). A report whose sender the server could
//!   not attest (a sealed send) can only be dismissed.
//! - `lift` removes an account's standing (after an appeal through support).
//! - `show` prints an account's standing.
//!
//! Every change needs `--confirm <namespace>/<database>` and writes the audit log with the
//! report, the account, the decision and the reason category, never the reported content.

use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Subcommand, ValueEnum};
use songbird_keys::provisioning::{Domain, open_with};
use songbird_types::AccountId;

use crate::{audit, store};

/// The reasons a decision may give (categories, never free text: the account sees it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Reason {
    /// Unwanted messages to strangers.
    Spam,
    /// Harassment or threats.
    Abuse,
    /// Fraud and scams.
    Fraud,
    /// Pretending to be someone else.
    Impersonation,
    /// Illegal content, on a legal basis.
    Illegal,
}

impl Reason {
    fn name(self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::Abuse => "abuse",
            Self::Fraud => "fraud",
            Self::Impersonation => "impersonation",
            Self::Illegal => "illegal",
        }
    }
}

/// A decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Action {
    /// No action; the report goes.
    Dismiss,
    /// Slow the sender's new conversations.
    Limit,
    /// The sender cannot send or call.
    Suspend,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ModerationCmd {
    /// Decide one report. Audit-logged; the report is deleted.
    Decide {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The moderation private key file (`reports keygen`).
        #[arg(long)]
        key: PathBuf,
        /// The report ID (`reports list`).
        #[arg(long)]
        report: String,
        /// The decision.
        #[arg(long, value_enum)]
        action: Action,
        /// The reason category (for `limit` and `suspend`).
        #[arg(long, value_enum)]
        reason: Option<Reason>,
        /// Days it lasts (for `limit`, and `suspend`; without it a suspension lasts until lifted).
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=3650))]
        days: Option<u32>,
    },
    /// Lift an account's standing (after an appeal). Audit-logged.
    Lift {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The account ID (32 hex characters).
        #[arg(long)]
        account: String,
    },
    /// Print an account's standing.
    Show {
        #[command(flatten)]
        store: store::StoreArgs,
        /// The account ID (32 hex characters).
        #[arg(long)]
        account: String,
    },
}

fn account(s: &str) -> Result<AccountId> {
    hex::decode(s)
        .ok()
        .and_then(|b| AccountId::from_slice(&b).ok())
        .ok_or_else(|| anyhow!("--account must be 32 hex characters"))
}

/// The standing a decision sets: `(kind, until)`, or `None` to set nothing.
pub(crate) fn standing_of(
    action: Action,
    days: Option<u32>,
    today: u32,
) -> Result<Option<(&'static str, Option<u32>)>> {
    Ok(match action {
        Action::Dismiss => None,
        Action::Limit => Some((
            "limited",
            Some(today + days.ok_or_else(|| anyhow!("--days is required to limit"))? - 1),
        )),
        Action::Suspend => Some(("suspended", days.map(|d| today + d - 1))),
    })
}

pub(crate) fn run(cmd: ModerationCmd) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cmd {
            ModerationCmd::Decide {
                store,
                guard,
                key,
                report,
                action,
                reason,
                days,
            } => {
                let mut id = [0u8; 16];
                hex::decode_to_slice(&report, &mut id).context("--report is 32 hex characters")?;
                let k = crate::reports::read_key(&key)?;
                let registry = store.registry().await?;
                let sealed = registry
                    .queued_reports(10_000)
                    .await?
                    .into_iter()
                    .find(|r| r.id == id)
                    .ok_or_else(|| anyhow!("no such report in the queue"))?
                    .sealed;
                let plain = open_with(Domain::Report, &k, &sealed)
                    .map_err(|_| anyhow!("the report does not open with this key"))?;
                let v: serde_json::Value = serde_json::from_slice(&plain).context("report body")?;
                let attested = v.get("sender_attested").and_then(serde_json::Value::as_bool) == Some(true);
                let sender = v
                    .get("sender")
                    .and_then(serde_json::Value::as_str)
                    .map(account)
                    .transpose()?;
                let set = standing_of(action, days, songbird_entitlements::today())?;
                if set.is_some() && !attested {
                    bail!("the server could not attest this report's sender (a sealed send): dismiss it");
                }
                if set.is_some() && reason.is_none() {
                    bail!("--reason is required to limit or suspend");
                }
                let target = sender.map(|a| a.to_hex_unredacted()).unwrap_or_default();
                let entry = guard.begin(
                    "moderation decide",
                    &crate::target(&store),
                    &format!(
                        "report {report} account {target} action {action:?} reason {} days {}",
                        reason.map_or("-", Reason::name),
                        days.map_or_else(|| "-".to_owned(), |d| d.to_string())
                    ),
                )?;
                let r = async {
                    if let (Some((kind, until)), Some(a)) = (set, sender) {
                        registry
                            .set_standing(&a, kind, until, reason.map_or("other", Reason::name), "moderator")
                            .await
                            .map_err(|e| anyhow!("{e}"))?;
                    }
                    registry.delete_report(&id).await.map_err(anyhow::Error::from)
                }
                .await;
                entry.end(&r, "")?;
                r?;
                println!("{action:?}: done, the report is deleted");
            }
            ModerationCmd::Lift {
                store,
                guard,
                account: a,
            } => {
                let id = account(&a)?;
                let entry = guard.begin("moderation lift", &crate::target(&store), &format!("account {a}"))?;
                let r = async { store.registry().await?.lift_standing(&id).await.map_err(anyhow::Error::from) }.await;
                entry.end(&r, "")?;
                r?;
                println!("good standing");
            }
            ModerationCmd::Show { store, account: a } => {
                let id = account(&a)?;
                match store.registry().await?.standing_of(&id).await? {
                    None => println!("good standing"),
                    Some(s) => println!(
                        "{} ({}, by {}), {}",
                        s.kind,
                        s.reason,
                        s.source,
                        s.until.map_or_else(|| "until lifted".to_owned(), |d| format!("through day {d} (UTC)"))
                    ),
                }
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_set_the_right_standing() {
        assert_eq!(standing_of(Action::Dismiss, None, 100).unwrap(), None);
        assert_eq!(
            standing_of(Action::Limit, Some(7), 100).unwrap(),
            Some(("limited", Some(106)))
        );
        assert!(standing_of(Action::Limit, None, 100).is_err());
        assert_eq!(
            standing_of(Action::Suspend, None, 100).unwrap(),
            Some(("suspended", None))
        );
        assert_eq!(
            standing_of(Action::Suspend, Some(30), 100).unwrap(),
            Some(("suspended", Some(129)))
        );
    }
}
