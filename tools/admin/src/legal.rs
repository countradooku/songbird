//! `songbird-admin legal` and `transparency` (Prompt 11, M6; D-0132; `docs/RUNBOOKS/legal-requests.md`).
//!
//! - `legal export` answers a verified, lawful request about one account with exactly what the
//!   account's own GDPR export holds on the server, never more: no content (end-to-end
//!   encrypted, never held), no payments (billing is another service and holds no account). It
//!   names the case reference, is written to a new file (mode 0600), audit-logged and counted.
//! - `legal record` counts a request that led to no export (rejected, nothing held, a
//!   preservation request, …).
//! - `transparency` prints a half-year's report in Markdown from those counts and the
//!   standings now. The registry keeps counts only (half-year, country, kind, outcome); case
//!   files stay offline with counsel.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Subcommand, ValueEnum};
use songbird_types::AccountId;

use crate::{audit, store};

/// What a request asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Kind {
    /// Data about an account.
    Data,
    /// Keeping data that would otherwise be deleted.
    Preservation,
    /// Removing content or an account.
    Takedown,
    /// Anything else.
    Other,
}

/// How it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Outcome {
    /// Data given (`legal export`).
    Disclosed,
    /// Refused: not lawful, not specific, not verified, or out of jurisdiction.
    Rejected,
    /// Nothing held: no such account, or nothing of what was asked.
    NothingHeld,
    /// Done without giving data (a preservation, a takedown).
    Complied,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Preservation => "preservation",
            Self::Takedown => "takedown",
            Self::Other => "other",
        }
    }
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Self::Disclosed => "disclosed",
            Self::Rejected => "rejected",
            Self::NothingHeld => "nothing-held",
            Self::Complied => "complied",
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum LegalCmd {
    /// Export one account's server-held data for a verified request. Audit-logged; counted.
    Export {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The account ID (32 hex characters).
        #[arg(long)]
        account: String,
        /// The case reference (from counsel's register; letters, digits, `-`, `/`).
        #[arg(long)]
        case: String,
        /// The requesting authority's country (ISO 3166-1 alpha-2).
        #[arg(long)]
        country: String,
        /// The file to write (must not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// Count a request that led to no export. Audit-logged.
    Record {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The case reference.
        #[arg(long)]
        case: String,
        /// The requesting authority's country (ISO 3166-1 alpha-2).
        #[arg(long)]
        country: String,
        /// What it asked for.
        #[arg(long, value_enum)]
        kind: Kind,
        /// How it ended.
        #[arg(long, value_enum)]
        outcome: Outcome,
    },
}

/// `YYYY-H1` or `YYYY-H2` of a UTC day.
pub(crate) fn half_of(day: u32) -> String {
    let date = songbird_s3::sigv4::iso8601(u64::from(day) * 86_400);
    let (y, m) = (&date[..4], date[5..7].parse::<u32>().unwrap_or(1));
    format!("{y}-H{}", if m <= 6 { 1 } else { 2 })
}

fn half_ok(h: &str) -> bool {
    h.len() == 7 && h[..4].bytes().all(|c| c.is_ascii_digit()) && matches!(&h[4..], "-H1" | "-H2")
}

fn country(c: &str) -> Result<String> {
    if c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()) {
        Ok(c.to_ascii_uppercase())
    } else {
        bail!("--country is an ISO 3166-1 alpha-2 code")
    }
}

fn case(c: &str) -> Result<&str> {
    if !c.is_empty()
        && c.len() <= 64
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'/')
    {
        Ok(c)
    } else {
        bail!("--case is 1 to 64 letters, digits, '-' or '/'")
    }
}

/// The export as handed over: the case, the scope, and the account's GDPR export.
pub(crate) fn package(
    case: &str,
    account: &AccountId,
    export: &serde_json::Value,
    now: &str,
) -> serde_json::Value {
    serde_json::json!({
        "case": case,
        "generated_utc": now,
        "account": crate::account_hex(account),
        "scope": [
            "What Songbird's servers hold about this account: the same as the account's own data export.",
            "Messages, calls, attachments and backups are end-to-end encrypted; Songbird holds no key to them and gives none.",
            "Payments are handled by a separate service that holds no account identifier; there is nothing to link.",
        ],
        "data": export,
    })
}

/// The transparency report of a half-year, in Markdown.
pub(crate) fn report(
    half: &str,
    legal: &[(String, String, String, u64)],
    standings: &[(String, String, u64)],
) -> String {
    let mut out = format!("# Songbird transparency report, {half}\n\n## Legal requests\n\n");
    if legal.is_empty() {
        out.push_str("None received.\n");
    } else {
        let total: u64 = legal.iter().map(|r| r.3).sum();
        let disclosed: u64 = legal
            .iter()
            .filter(|r| r.2 == "disclosed")
            .map(|r| r.3)
            .sum();
        let _ = write!(
            out,
            "{total} received; data given in {disclosed}. Data given is only what the account's own export shows: never message content, which Songbird cannot read.\n\n| Country | Kind | Outcome | Requests |\n| --- | --- | --- | --- |\n"
        );
        let mut rows = legal.to_vec();
        rows.sort();
        for (c, k, o, n) in rows {
            let _ = writeln!(out, "| {c} | {k} | {o} | {n} |");
        }
    }
    out.push_str("\n## Accounts limited or suspended (now)\n\n");
    if standings.is_empty() {
        out.push_str("None.\n");
    } else {
        out.push_str("| Standing | Set by | Accounts |\n| --- | --- | --- |\n");
        for (k, s, n) in standings {
            let _ = writeln!(out, "| {k} | {s} | {n} |");
        }
    }
    out
}

fn account(s: &str) -> Result<AccountId> {
    hex::decode(s)
        .ok()
        .and_then(|b| AccountId::from_slice(&b).ok())
        .ok_or_else(|| anyhow!("--account must be 32 hex characters"))
}

pub(crate) fn run(cmd: LegalCmd) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let today = songbird_entitlements::today();
        match cmd {
            LegalCmd::Export {
                store,
                guard,
                account: a,
                case: c,
                country: k,
                out,
            } => {
                let (id, c, k) = (account(&a)?, case(&c)?, country(&k)?);
                let entry = guard.begin(
                    "legal export",
                    &crate::target(&store),
                    &format!("case {c} country {k} account {a}"),
                )?;
                let r = async {
                    let registry = store.registry().await?;
                    let export = registry
                        .export(&id, None)
                        .await
                        .map_err(|_| anyhow!("no such account"))?;
                    let now = songbird_s3::sigv4::iso8601(audit::now_secs());
                    let body = serde_json::to_vec_pretty(&package(c, &id, &export, &now))?;
                    let mut opts = std::fs::OpenOptions::new();
                    opts.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt as _;
                        opts.mode(0o600);
                    }
                    opts.open(&out)
                        .context("creating the export file (it must not exist)")?
                        .write_all(&body)?;
                    registry
                        .count_legal(&half_of(today), &k, "data", "disclosed")
                        .await?;
                    anyhow::Ok(())
                }
                .await;
                entry.end(&r, "")?;
                r?;
                println!("written to {}; counted", out.display());
            }
            LegalCmd::Record {
                store,
                guard,
                case: c,
                country: k,
                kind,
                outcome,
            } => {
                let (c, k) = (case(&c)?, country(&k)?);
                if outcome == Outcome::Disclosed {
                    bail!("a disclosure is counted by `legal export`");
                }
                let entry = guard.begin(
                    "legal record",
                    &crate::target(&store),
                    &format!(
                        "case {c} country {k} kind {} outcome {}",
                        kind.name(),
                        outcome.name()
                    ),
                )?;
                let r = async {
                    store
                        .registry()
                        .await?
                        .count_legal(&half_of(today), &k, kind.name(), outcome.name())
                        .await
                        .map_err(anyhow::Error::from)
                }
                .await;
                entry.end(&r, "")?;
                r?;
                println!("counted");
            }
        }
        Ok(())
    })
}

/// `songbird-admin transparency`.
pub(crate) fn transparency(store: &store::StoreArgs, half: Option<String>) -> Result<()> {
    let half = half.unwrap_or_else(|| half_of(songbird_entitlements::today()));
    if !half_ok(&half) {
        bail!("--half is YYYY-H1 or YYYY-H2");
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let registry = store.registry().await?;
        let legal = registry.legal_counts(&half).await?;
        let standings = registry
            .standing_counts(songbird_entitlements::today())
            .await?;
        print!("{}", report(&half, &legal, &standings));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn halves_and_inputs_are_checked() {
        // 2026-06-30 is day 20634, 2026-07-01 day 20635.
        assert_eq!(half_of(20_634), "2026-H1");
        assert_eq!(half_of(20_635), "2026-H2");
        assert!(half_ok("2026-H2"));
        assert!(!half_ok("2026-H3") && !half_ok("26-H1") && !half_ok("2026H1"));
        assert_eq!(country("de").unwrap(), "DE");
        assert!(country("DEU").is_err() && country("1A").is_err());
        assert!(case("2026/017-a").is_ok());
        assert!(case("").is_err() && case("a b").is_err() && case(&"a".repeat(65)).is_err());
    }

    #[test]
    fn the_report_shows_counts_only() {
        let r = report(
            "2026-H2",
            &[
                ("NL".into(), "data".into(), "disclosed".into(), 1),
                ("DE".into(), "data".into(), "rejected".into(), 3),
            ],
            &[("limited".into(), "auto".into(), 4)],
        );
        assert!(r.starts_with("# Songbird transparency report, 2026-H2"));
        assert!(r.contains("4 received; data given in 1."));
        assert!(r.find("| DE |").unwrap() < r.find("| NL |").unwrap());
        assert!(r.contains("| limited | auto | 4 |"));
        assert!(report("2026-H1", &[], &[]).contains("None received."));
    }

    #[test]
    fn the_package_is_the_export_and_its_scope() {
        let a = AccountId::random().unwrap();
        let p = package(
            "C-1",
            &a,
            &serde_json::json!({ "account": {} }),
            "2026-11-19T00:00:00Z",
        );
        assert_eq!(p["case"], "C-1");
        assert_eq!(p["data"], serde_json::json!({ "account": {} }));
        assert_eq!(p["scope"].as_array().unwrap().len(), 3);
    }
}
