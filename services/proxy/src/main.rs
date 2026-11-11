//! `songbird-proxy` binary. See the library docs and `deploy/proxy/README.md`.
//!
//! ```text
//! songbird-proxy [--config <path>]         run (config also from SONGBIRD_PROXY_CONFIG)
//! songbird-proxy --check-config [...]      validate the configuration and exit
//! songbird-proxy --print-link <host[:port]> print the proxy link to share with users
//! ```
//!
//! By design this binary writes nothing at runtime. The only output is a fatal startup error on
//! stderr (it never contains client data, because no client has connected yet).
#![forbid(unsafe_code)]
#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    reason = "CLI output; no logging framework by design"
)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use songbird_proxy::config::{ENV_PREFIX, ProxyConfig};
use songbird_proxy::link::ProxyLink;
use songbird_proxy::relay::{Relay, tls_acceptor};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const DRAIN: Duration = Duration::from_secs(30);
const USAGE: &str =
    "usage: songbird-proxy [--config <path>] [--check-config] | --print-link <host[:port]>";

fn main() -> ExitCode {
    // CLI flags only; argv[0] is skipped and nothing is trusted from it.
    let mut args = std::env::args().skip(1); // nosemgrep: rust.lang.security.args.args
    let mut path = std::env::var_os("SONGBIRD_PROXY_CONFIG").map(PathBuf::from);
    let mut check = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => match args.next() {
                Some(p) => path = Some(p.into()),
                None => return usage(),
            },
            "--check-config" => check = true,
            "--print-link" => {
                let Some(target) = args.next() else {
                    return usage();
                };
                return match ProxyLink::parse(&format!("songbird://proxy#{target}"), &[]) {
                    Ok(l) => {
                        println!("{}", l.to_app_link());
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("songbird-proxy: {e}");
                        ExitCode::from(2)
                    }
                };
            }
            "--version" => {
                println!("songbird-proxy {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => return usage(),
        }
    }

    let config: ProxyConfig = match songbird_types::config::load(path.as_deref(), ENV_PREFIX) {
        Ok(c) => c,
        Err(e) => return fatal(&e),
    };
    let acceptor = match tls_acceptor(&config.tls) {
        Ok(a) => a,
        Err(e) => return fatal(&e),
    };
    if check {
        println!("songbird-proxy: configuration ok");
        return ExitCode::SUCCESS;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fatal(&e),
    };
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(config.listen).await {
            Ok(l) => l,
            Err(e) => return fatal(&e),
        };
        Relay::new(config, acceptor)
            .serve(listener, termination(), DRAIN)
            .await;
        ExitCode::SUCCESS
    })
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn fatal(e: &dyn std::fmt::Display) -> ExitCode {
    eprintln!("songbird-proxy: {e}");
    ExitCode::FAILURE
}

async fn termination() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {},
                _ = tokio::signal::ctrl_c() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
