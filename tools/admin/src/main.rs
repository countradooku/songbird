//! `songbird-admin`: operator tool.
//!
//! - `backup`: registry backups (D-0040): `run` (export, encrypt with age, store write-once),
//!   `verify` (restore the newest into a scratch database and check it), `restore`.
//! - `generation`: the store generation clients see in `Hello` (D-0040): shown, or bumped after
//!   a restore or a loss of the mailbox, so clients resend what has no delivery receipt.
//! - `accounts import`: a static directory file as registry accounts (drills, development).
//! - `reports`: the moderation key, and the queue of reports sealed to it (Prompt 4, D-0063).
//! - `plans`: an operator's grant or revocation of a plan level for one account (Prompt 11,
//!   D-0127), audit-logged with the account.
//! - `moderation`: a decision on a franked report (dismiss, limit, suspend) and lifting a
//!   standing (Prompt 11, D-0131), audit-logged.
//! - `invites create`: a batch of invite codes for early testers (D-0038); `invites grant`: more
//!   invites for one account. Codes are printed once and stored only as hashes; the audit log
//!   records how many, never the codes.
//!
//! Commands that change the registry (`backup restore`, `generation bump`, `accounts import`,
//! `invites create`, `invites grant`) need `--confirm <namespace>/<database>` and write an audit
//! log (`audit.rs`).
//! - `ca`: the internal mutual-TLS certificate authority.
//!
//! Every service-to-service connection on the private network uses certificates from this CA (see
//! `docs/RUNBOOKS/mtls-rotation.md`):
//!
//! ```text
//! root CA (10 y, offline, key only ever in SOPS)
//!   └── intermediate CA (1 y, name-constrained to *.songbird.internal and private IP ranges)
//!         └── leaf per host and service (30 d, serverAuth + clientAuth)
//! ```
//!
//! Keys are ECDSA P-256, written with mode 0600. Rotation is `issue` again plus a reload;
//! `check` exits non-zero when a certificate is within its renewal window, so automation can
//! decide without parsing output.
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, reason = "CLI output")]

mod audit;
mod backup;
mod ca;
mod legal;
mod moderation;
mod plans;
mod reports;
mod store;
mod support;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "songbird-admin", version, about = "Songbird operator tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once per process; boxing would not save anything that matters"
)]
enum Cmd {
    /// Internal mutual-TLS certificate authority.
    #[command(subcommand)]
    Ca(CaCmd),
    /// The store generation (D-0040).
    #[command(subcommand)]
    Generation(GenerationCmd),
    /// Registry backups (D-0040).
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Accounts (development and drills).
    #[command(subcommand)]
    Accounts(AccountsCmd),
    /// Invite codes (invite-only registration, D-0038).
    #[command(subcommand)]
    Invites(InvitesCmd),
    /// Reports (Prompt 4, D-0063): the moderation key, and the sealed queue.
    #[command(subcommand)]
    Reports(reports::ReportsCmd),
    /// Plans (Prompt 11, D-0127): operators' grants of a level.
    #[command(subcommand)]
    Plans(plans::PlansCmd),
    /// Moderation (Prompt 11, D-0131): decisions on reports, lifting a standing.
    #[command(subcommand)]
    Moderation(moderation::ModerationCmd),
    /// Support (Prompt 11, D-0132): the support key and tickets.
    #[command(subcommand)]
    Support(support::SupportCmd),
    /// Legal requests (Prompt 11, D-0132): exports and counts.
    #[command(subcommand)]
    Legal(legal::LegalCmd),
    /// The transparency report of a half-year, in Markdown (D-0132).
    Transparency {
        #[command(flatten)]
        store: store::StoreArgs,
        /// `YYYY-H1` or `YYYY-H2` (default: the current one).
        #[arg(long)]
        half: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum InvitesCmd {
    /// Create invite codes and print them (once; only their hashes are stored).
    Create {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// How many codes.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=1000))]
        count: u32,
        /// Registrations each code allows.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100_000))]
        uses: u32,
        /// Days until the codes expire.
        #[arg(long, default_value_t = 14, value_parser = clap::value_parser!(u32).range(1..=90))]
        days: u32,
    },
    /// Give an account more invites.
    Grant {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The account ID (32 hex characters).
        #[arg(long)]
        account: String,
        /// How many to add.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
        add: u32,
    },
}

#[derive(Debug, Subcommand)]
enum AccountsCmd {
    /// Register every device of a static directory file as an account of its own.
    Import {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The directory file (`songbird-loadgen keys` writes `devices.toml`).
        #[arg(long)]
        directory: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum BackupCmd {
    /// Export the registry, encrypt it with age and store it (every 5 minutes, by a timer).
    Run(backup::RunArgs),
    /// Restore the newest backup into a scratch database and check it; non-zero exit when it
    /// is older than allowed or inconsistent (daily, off production).
    Verify(backup::LoadArgs),
    /// Restore a backup into an empty registry database and bump the store generation (restore
    /// runbook). Needs `--confirm <namespace>/<database>`; audit-logged.
    Restore {
        #[command(flatten)]
        load: backup::LoadArgs,
        #[command(flatten)]
        guard: audit::Guard,
        #[command(flatten)]
        journal: backup::JournalArgs,
    },
}

#[derive(Debug, Subcommand)]
enum GenerationCmd {
    /// Print the store generation.
    Show {
        #[command(flatten)]
        store: store::StoreArgs,
    },
    /// Increase it (restore runbook): every client resends what has no delivery receipt.
    /// Needs `--confirm <namespace>/<database>`; audit-logged.
    Bump {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
    },
}

#[derive(Debug, Subcommand)]
enum CaCmd {
    /// Create a root CA (`root.crt`, `root.key`). Encrypt `root.key` with SOPS and delete it.
    InitRoot {
        /// Output directory (created; must not already contain a root).
        #[arg(long)]
        out: PathBuf,
        /// Environment name, written into the subject.
        #[arg(long)]
        env: String,
        /// Validity in days.
        #[arg(long, default_value_t = 3650)]
        days: u32,
    },
    /// Create an intermediate CA signed by the root (`intermediate.crt`, `intermediate.key`).
    InitIntermediate {
        /// Directory holding `root.crt` and `root.key`.
        #[arg(long)]
        root: PathBuf,
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
        /// Environment name, written into the subject.
        #[arg(long)]
        env: String,
        /// Validity in days.
        #[arg(long, default_value_t = 365)]
        days: u32,
    },
    /// Issue a leaf certificate for one service on one host.
    Issue {
        /// Directory holding `intermediate.crt`, `intermediate.key` and `root.crt`.
        #[arg(long)]
        ca: PathBuf,
        /// Common name, e.g. `delivery.core-1.songbird.internal`.
        #[arg(long)]
        name: String,
        /// Subject alternative names (DNS names under songbird.internal, or private IPs).
        #[arg(long = "san", required = true)]
        sans: Vec<String>,
        /// Output directory: `<name>.crt` (leaf + intermediate), `<name>.key`, `ca.crt` (root).
        #[arg(long)]
        out: PathBuf,
        /// Validity in days.
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
    /// Exit 0 if the certificate is valid for more than `--renew-within` days, 1 if it must be
    /// renewed, 2 on error. Prints the days left.
    Check {
        /// PEM certificate (the first certificate in the file is checked).
        #[arg(long)]
        cert: PathBuf,
        /// Renewal window in days.
        #[arg(long, default_value_t = 10)]
        renew_within: i64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Ca(cmd) => match ca_cmd(cmd) {
            Ok(Some(code)) => return code,
            Ok(None) => Ok(()),
            Err(e) => Err(e),
        },
        Cmd::Generation(cmd) => generation_cmd(cmd),
        Cmd::Backup(cmd) => backup_cmd(cmd),
        Cmd::Accounts(AccountsCmd::Import {
            store,
            guard,
            directory,
        }) => accounts_import(&store, &guard, &directory),
        Cmd::Invites(cmd) => invites_cmd(cmd),
        Cmd::Reports(cmd) => reports::run(cmd),
        Cmd::Plans(cmd) => plans::run(cmd),
        Cmd::Moderation(cmd) => moderation::run(cmd),
        Cmd::Support(cmd) => support::run(cmd),
        Cmd::Legal(cmd) => legal::run(cmd),
        Cmd::Transparency { store, half } => legal::transparency(&store, half),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            #[allow(clippy::print_stderr, reason = "CLI error output")]
            {
                eprintln!("songbird-admin: {e:#}");
            }
            ExitCode::from(2)
        }
    }
}

/// Runs a CA command; `Some` carries an exit code of its own (`check`).
fn ca_cmd(cmd: CaCmd) -> anyhow::Result<Option<ExitCode>> {
    match cmd {
        CaCmd::InitRoot { out, env, days } => ca::init_root(&out, &env, days).map(|()| None),
        CaCmd::InitIntermediate {
            root,
            out,
            env,
            days,
        } => ca::init_intermediate(&root, &out, &env, days).map(|()| None),
        CaCmd::Issue {
            ca,
            name,
            sans,
            out,
            days,
        } => ca::issue(&ca, &name, &sans, &out, days).map(|()| None),
        CaCmd::Check { cert, renew_within } => {
            let days = ca::days_left(&cert)?;
            println!("{days}");
            Ok(Some(if days > renew_within {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }))
        }
    }
}

fn generation_cmd(cmd: GenerationCmd) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cmd {
            GenerationCmd::Show { store } => println!("{}", store::show(&store).await?),
            GenerationCmd::Bump { store, guard } => {
                let entry = guard.begin("generation bump", &target(&store), "")?;
                let r = store::bump(&store).await;
                entry.end(
                    &r,
                    &r.as_ref()
                        .map_or(String::new(), |g| format!("generation {g}")),
                )?;
                println!("store generation is now {}", r?);
            }
        }
        Ok(())
    })
}

fn backup_cmd(cmd: BackupCmd) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cmd {
            BackupCmd::Run(a) => {
                let name = backup::run(&a).await?;
                println!("stored {name}");
            }
            BackupCmd::Verify(a) => {
                let r = backup::load(&a).await?;
                print_report(&r);
                if r.orphans > 0 || r.generation == 0 {
                    anyhow::bail!("the restored registry is inconsistent");
                }
                if r.integrity != backup::Integrity::default() {
                    anyhow::bail!(
                        "the bucket shows tampering: {} names written twice, {} misdated backups \
                         (runbook backup-and-restore.md, compromise)",
                        r.integrity.overwritten,
                        r.integrity.misdated
                    );
                }
                println!("verified");
            }
            BackupCmd::Restore {
                load: a,
                guard,
                journal,
            } => {
                let object = a.object.clone().unwrap_or_else(|| "newest".into());
                let detail = if journal.no_journal {
                    format!("{object}; WITHOUT the deletion journal")
                } else {
                    object
                };
                let key = if journal.no_journal {
                    None
                } else {
                    Some(journal.key()?)
                };
                let entry = guard.begin("backup restore", &target(&a.store), &detail)?;
                let r = async {
                    let r = backup::load(&a).await?;
                    print_report(&r);
                    let redeleted = if let Some(key) = &key {
                        let n = backup::reapply_deletions(&a, key).await?;
                        println!("deletion journal: {n} restored accounts with a tombstone are being deleted again");
                        n
                    } else {
                        println!("WARNING: --no-journal: accounts deleted after this backup are back");
                        0
                    };
                    let g = store::bump(&a.store).await?;
                    Ok::<_, anyhow::Error>((r, g, redeleted))
                }
                .await;
                entry.end(
                    &r,
                    &r.as_ref().map_or(String::new(), |(rep, g, redeleted)| {
                        format!(
                            "{}: {} accounts, {} devices; generation {g}; re-deleted {redeleted}; names written twice {}, misdated {}",
                            rep.object,
                            rep.registered,
                            rep.device_rows,
                            rep.integrity.overwritten,
                            rep.integrity.misdated
                        )
                    }),
                )?;
                let (_, g, _) = r?;
                println!(
                    "restored; store generation is now {g}: clients resend what has no receipt"
                );
            }
        }
        Ok(())
    })
}

/// A destructive command's target, as `--confirm` must repeat it.
pub(crate) fn target(s: &store::StoreArgs) -> String {
    format!("{}/{}", s.namespace, s.database)
}

fn accounts_import(
    store: &store::StoreArgs,
    guard: &audit::Guard,
    directory: &std::path::Path,
) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let entry = guard.begin(
            "accounts import",
            &target(store),
            &directory.display().to_string(),
        )?;
        let r = store::import_directory(store, directory).await;
        entry.end(
            &r,
            &r.as_ref().map_or(String::new(), |n| format!("{n} devices")),
        )?;
        println!("registered {} devices", r?);
        Ok(())
    })
}

fn print_report(r: &backup::Report) {
    if r.integrity != backup::Integrity::default() {
        println!(
            "WARNING: the bucket shows tampering: {} names written twice (only their first version \
             is read), {} misdated backups (never read)",
            r.integrity.overwritten, r.integrity.misdated
        );
    }
    println!(
        "backup {} ({} min old): {} accounts, {} devices, {} devices without an account, generation {}",
        r.object,
        r.age_secs / 60,
        r.registered,
        r.device_rows,
        r.orphans,
        r.generation
    );
}

fn invites_cmd(cmd: InvitesCmd) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cmd {
            InvitesCmd::Create {
                store,
                guard,
                count,
                uses,
                days,
            } => {
                let detail = format!("{count} codes, {uses} uses each, {days} days");
                let entry = guard.begin("invites create", &target(&store), &detail)?;
                let r = async {
                    let registry = store.registry().await?;
                    let mut codes = Vec::new();
                    for _ in 0..count {
                        let mut c = [0u8; songbird_accounts::INVITE_CODE_LEN];
                        aws_lc_rs::rand::fill(&mut c)
                            .map_err(|_| anyhow::anyhow!("random source failed"))?;
                        codes.push(c);
                    }
                    let hashes: Vec<[u8; 32]> =
                        codes.iter().map(songbird_accounts::invite_hash).collect();
                    registry
                        .create_invites(
                            &hashes,
                            uses,
                            std::time::Duration::from_secs(u64::from(days) * 86_400),
                        )
                        .await?;
                    Ok::<_, anyhow::Error>(codes)
                }
                .await;
                entry.end(&r, &detail)?;
                for c in r? {
                    println!("{}", songbird_proto::registration::invite::format(&c));
                }
            }
            InvitesCmd::Grant {
                store,
                guard,
                account,
                add,
            } => {
                let id = hex::decode(&account)
                    .ok()
                    .and_then(|b| songbird_types::AccountId::from_slice(&b).ok())
                    .ok_or_else(|| anyhow::anyhow!("--account must be 32 hex characters"))?;
                let entry = guard.begin("invites grant", &target(&store), &format!("+{add}"))?;
                let r = async {
                    let registry = store.registry().await?;
                    let found = registry.add_invite_allowance(&id, add).await?;
                    anyhow::ensure!(found, "no such account");
                    registry
                        .invite_allowance(&id)
                        .await
                        .map_err(anyhow::Error::from)
                }
                .await;
                entry.end(
                    &r,
                    &r.as_ref()
                        .map_or(String::new(), |n| format!("allowance {n}")),
                )?;
                println!("the account may now create {} invites", r?);
            }
        }
        Ok(())
    })
}
