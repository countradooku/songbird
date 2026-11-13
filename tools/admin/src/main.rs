//! `songbird-admin`: operator tool.
//!
//! - `backup`: registry backups (D-0040): `run` (export, encrypt with age, store write-once),
//!   `verify` (restore the newest into a scratch database and check it), `restore`.
//! - `generation`: the store generation clients see in `Hello` (D-0040): shown, or bumped after
//!   a restore or a loss of the mailbox, so clients resend what has no delivery receipt.
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

mod backup;
mod ca;
mod store;

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
    /// Accounts (development and drills until Prompt 3's registration).
    #[command(subcommand)]
    Accounts(AccountsCmd),
}

#[derive(Debug, Subcommand)]
enum AccountsCmd {
    /// Register every device of a static directory file as an account of its own.
    Import {
        #[command(flatten)]
        store: store::StoreArgs,
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
    /// Restore a backup into the registry and bump the store generation (restore runbook).
    Restore(backup::LoadArgs),
}

#[derive(Debug, Subcommand)]
enum GenerationCmd {
    /// Print the store generation.
    Show {
        #[command(flatten)]
        store: store::StoreArgs,
    },
    /// Increase it (restore runbook): every client resends what has no delivery receipt.
    Bump {
        #[command(flatten)]
        store: store::StoreArgs,
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
        Cmd::Accounts(AccountsCmd::Import { store, directory }) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(anyhow::Error::from)
                .and_then(|rt| {
                    rt.block_on(async {
                        let n = store::import_directory(&store, &directory).await?;
                        println!("registered {n} devices");
                        Ok(())
                    })
                })
        }
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
            GenerationCmd::Bump { store } => {
                let g = store::bump(&store).await?;
                println!("store generation is now {g}");
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
                if r.orphan_devices > 0 || r.generation == 0 {
                    anyhow::bail!("the restored registry is inconsistent");
                }
                println!("verified");
            }
            BackupCmd::Restore(a) => {
                let r = backup::load(&a).await?;
                print_report(&r);
                let g = store::bump(&a.store).await?;
                println!(
                    "restored; store generation is now {g}: clients resend what has no receipt"
                );
            }
        }
        Ok(())
    })
}

fn print_report(r: &backup::Report) {
    println!(
        "backup {} ({} min old): {} accounts, {} devices, {} devices without an account, generation {}",
        r.object,
        r.age_secs / 60,
        r.accounts,
        r.devices,
        r.orphan_devices,
        r.generation
    );
}
