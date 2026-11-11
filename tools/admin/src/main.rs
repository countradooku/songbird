//! `songbird-admin`: operator tool.
//!
//! Today it is the internal mutual-TLS certificate authority. Every service-to-service connection
//! on the private network uses certificates from this CA (see `docs/RUNBOOKS/mtls-rotation.md`):
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

mod ca;

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
enum Cmd {
    /// Internal mutual-TLS certificate authority.
    #[command(subcommand)]
    Ca(CaCmd),
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
    let Cmd::Ca(cmd) = cli.cmd;
    let result = match cmd {
        CaCmd::InitRoot { out, env, days } => ca::init_root(&out, &env, days),
        CaCmd::InitIntermediate {
            root,
            out,
            env,
            days,
        } => ca::init_intermediate(&root, &out, &env, days),
        CaCmd::Issue {
            ca,
            name,
            sans,
            out,
            days,
        } => ca::issue(&ca, &name, &sans, &out, days),
        CaCmd::Check { cert, renew_within } => match ca::days_left(&cert) {
            Ok(days) => {
                println!("{days}");
                return if days > renew_within {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                };
            }
            Err(e) => Err(e),
        },
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
