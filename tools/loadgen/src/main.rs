//! Songbird load generator, v0 (milestone 1).
//!
//! ```text
//! songbird-loadgen keys  --devices N --out DIR      device directory for the server + seeds
//! songbird-loadgen run   --addr A --seeds DIR/seeds.txt [--scenario steady|reconnect] ...
//! songbird-loadgen echo  --addr A --connections N --inflight K --size B --secs S
//! ```
//!
//! `run` drives the real `songbird-client` (one client per simulated device), sends 1:1 traffic
//! at a fixed total rate to random peers, acknowledges every delivery, and at the end runs the
//! delivery checker: nothing lost, nothing delivered twice, strictly increasing gap-free `seq`,
//! per-sender FIFO. The process exits non-zero if the checker fails.
//!
//! `echo` measures raw WebSocket round trips against any echo server (the sockudo-ws examples,
//! `songbird-delivery-autobahn`), for library baselines on the same hardware.
#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a CLI: stdout is its report"
)]

mod admin;
mod checker;
mod echo;
mod pusher;
mod run;
mod stats;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

/// Display-only conversion of a count to `f64`.
#[allow(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "rates for display; exact above 2^53 is not needed"
)]
pub(crate) const fn as_f64(x: u64) -> f64 {
    x as f64
}

// Sanitizer builds keep the system allocator: ASan and TSan see only allocations they intercept.
#[cfg(not(songbird_sanitizer))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(
    name = "songbird-loadgen",
    about = "Songbird load generator and delivery checker"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate devices: `devices.toml` for the server's static directory, `seeds.txt` for runs.
    Keys {
        /// Number of devices.
        #[arg(long)]
        devices: usize,
        /// Output directory (created).
        #[arg(long)]
        out: PathBuf,
    },
    /// Run a scenario against a delivery server and check the result.
    Run(run::Args),
    /// Raw WebSocket echo round trips (library baselines).
    Echo(echo::Args),
    /// 1:1 relay through a Pusher-protocol server (the Sockudo server baseline).
    Pusher(pusher::Args),
}

fn keys(devices: usize, out: &std::path::Path) -> anyhow::Result<()> {
    use std::fmt::Write as _;
    std::fs::create_dir_all(out).context("create output directory")?;
    let mut dir = String::from("# Static device directory for songbird-delivery (dev/CI only).\n");
    let mut seeds = String::new();
    for _ in 0..devices {
        let id = songbird_types::DeviceId::random()?;
        let (key, seed) = songbird_client::DeviceKey::generate(id)?;
        let hex_id = id.to_hex_unredacted();
        let _ = write!(
            dir,
            "[[devices]]\nid = \"{hex_id}\"\nauth_key = \"{}\"\n",
            hex::encode(key.public_key())
        );
        let _ = writeln!(seeds, "{hex_id} {}", hex::encode(seed));
    }
    std::fs::write(out.join("devices.toml"), dir).context("write devices.toml")?;
    let seeds_path = out.join("seeds.txt");
    std::fs::write(&seeds_path, seeds).context("write seeds.txt")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&seeds_path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("wrote {devices} devices to {}", out.display());
    Ok(())
}

fn main() -> ExitCode {
    sockudo_ws::init_clock();
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Keys { devices, out } => keys(devices, &out).map(|()| true),
        Cmd::Run(a) => run::main(&a),
        Cmd::Echo(a) => echo::main(&a).map(|()| true),
        Cmd::Pusher(a) => pusher::main(&a),
    };
    match r {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("songbird-loadgen: {e:#}");
            ExitCode::from(2)
        }
    }
}
