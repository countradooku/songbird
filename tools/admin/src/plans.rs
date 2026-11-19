//! `songbird-admin plans` (Prompt 11, D-0127): operators' grants of a plan level.
//!
//! Paid plans come from anonymous tokens the account redeems itself (D-0126 §2); this is the
//! other source: staff, testers, goodwill. A grant sets the account's level and last day
//! exactly (`grant`), or removes it (`revoke`); `show` prints what the registry holds. Grants and
//! revocations need `--confirm <namespace>/<database>` and are audit-logged with the account,
//! the level and the last day: an operator's change to one account must be attributable.

use anyhow::{Context as _, Result, anyhow, bail};
use clap::Subcommand;
use songbird_accounts::entitlements::Source;
use songbird_entitlements::Level;
use songbird_types::AccountId;

use crate::{audit, store};

/// Longest grant: about two years. A longer one is almost certainly a typo.
const MAX_DAYS: u32 = 800;

#[derive(Debug, Subcommand)]
pub(crate) enum PlansCmd {
    /// Set an account's level through a last day (UTC). Audit-logged.
    Grant {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The account ID (32 hex characters).
        #[arg(long)]
        account: String,
        /// The level (`plus`).
        #[arg(long)]
        level: String,
        /// For this many days from today, today included.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_DAYS)))]
        days: u32,
    },
    /// Put an account back on Free at once. Audit-logged.
    Revoke {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The account ID (32 hex characters).
        #[arg(long)]
        account: String,
    },
    /// Print an account's level, last day and source.
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

/// The last day of a grant of `days` days starting `today` (today counts).
pub(crate) fn last_day(today: u32, days: u32) -> u32 {
    today.saturating_add(days.saturating_sub(1))
}

pub(crate) fn run(cmd: PlansCmd) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cmd {
            PlansCmd::Grant {
                store,
                guard,
                account: a,
                level,
                days,
            } => {
                let id = account(&a)?;
                let level = Level::parse(&level)
                    .filter(|l| *l != Level::Free)
                    .ok_or_else(|| {
                        anyhow!("--level must be a paid level (plus); use revoke for free")
                    })?;
                let last = last_day(songbird_entitlements::today(), days);
                let entry = guard.begin(
                    "plans grant",
                    &crate::target(&store),
                    &format!("account {a} level {} through day {last}", level.name()),
                )?;
                let r = async {
                    let registry = store.registry().await?;
                    registry
                        .set_entitlement(&id, level.as_u8(), last, Source::Grant)
                        .await
                        .map_err(|e| match e {
                            songbird_accounts::RegistryError::NotFound => {
                                anyhow!("no such account")
                            }
                            e => anyhow::Error::from(e),
                        })
                }
                .await;
                entry.end(&r, "")?;
                r?;
                println!("{} through day {last} (UTC)", level.name());
            }
            PlansCmd::Revoke {
                store,
                guard,
                account: a,
            } => {
                let id = account(&a)?;
                let entry = guard.begin(
                    "plans revoke",
                    &crate::target(&store),
                    &format!("account {a}"),
                )?;
                let r = async {
                    store
                        .registry()
                        .await?
                        .revoke_entitlement(&id)
                        .await
                        .map_err(anyhow::Error::from)
                }
                .await;
                entry.end(&r, "")?;
                r?;
                println!("free");
            }
            PlansCmd::Show { store, account: a } => {
                let id = account(&a)?;
                let row = store
                    .registry()
                    .await?
                    .entitlement_of(&id)
                    .await
                    .context("reading the registry")?;
                let today = songbird_entitlements::today();
                match row {
                    None => println!("free"),
                    Some(r) => {
                        let Some(level) = Level::from_u8(r.level) else {
                            bail!("the account holds level {}, unknown to this build", r.level);
                        };
                        let state = if r.last_day >= today {
                            "held"
                        } else {
                            "lapsed"
                        };
                        println!(
                            "{} through day {} (UTC), {state}, from {}",
                            level.name(),
                            r.last_day,
                            r.source.as_str()
                        );
                    }
                }
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_grant_of_n_days_counts_today() {
        assert_eq!(super::last_day(100, 1), 100);
        assert_eq!(super::last_day(100, 30), 129);
        assert_eq!(super::last_day(u32::MAX, 30), u32::MAX);
    }
}
