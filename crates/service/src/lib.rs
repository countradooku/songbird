//! Service bootstrap shared by every Songbird service.
//!
//! [`main`] does, in order: parse `--config <path>` (or `SONGBIRD_CONFIG`), load and validate the
//! configuration (`SONGBIRD__…` environment overrides), install tracing with the redaction layer,
//! build the metric registry, start the admin endpoint, run the service, and on SIGTERM or SIGINT
//! mark the service not ready, signal shutdown and wait up to the configured grace period.
//!
//! The thread-per-core runtime arrives with `crates/runtime` in Prompt 2; until then services run
//! on one current-thread Tokio runtime.
#![forbid(unsafe_code)]

use std::future::Future;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use songbird_telemetry::{Health, Metrics, RedactionMode};
use songbird_types::config::{CommonConfig, Validate, Validator};
use tokio::sync::watch;

pub use songbird_telemetry as telemetry;
pub use songbird_types as types;

/// Boxed error returned by services.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Prefix of configuration environment overrides: `SONGBIRD__COMMON__ADMIN_LISTEN=…`.
pub const ENV_PREFIX: &str = "SONGBIRD";
/// Environment variable naming the configuration file when `--config` is absent.
pub const CONFIG_ENV: &str = "SONGBIRD_CONFIG";

/// Access to the shared section of a service configuration.
pub trait HasCommon {
    /// The `[common]` section.
    fn common(&self) -> &CommonConfig;
}

/// A configuration with only the `[common]` section, for services with no settings of their own.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicConfig {
    /// Shared settings.
    pub common: CommonConfig,
}

impl Validate for BasicConfig {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
    }
}

impl HasCommon for BasicConfig {
    fn common(&self) -> &CommonConfig {
        &self.common
    }
}

/// A Songbird service.
pub trait Service: Sized {
    /// Name used in metrics (`songbird_build_info{service=…}`).
    const NAME: &'static str;
    /// Configuration type.
    type Config: DeserializeOwned + Validate + HasCommon;

    /// Builds the service and registers its metrics. Runs before the admin endpoint starts.
    ///
    /// # Errors
    /// Any startup failure; the process exits with status 1.
    fn new(config: Self::Config, metrics: &mut Metrics) -> Result<Self, BoxError>;

    /// Runs until [`Ctx::shutdown`] resolves, then drains and returns.
    fn run(self, ctx: Ctx) -> impl Future<Output = Result<(), BoxError>>;
}

/// What a running service gets from the bootstrap.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// Readiness flag served at `/readyz`.
    pub health: Arc<Health>,
    shutdown: watch::Receiver<bool>,
}

impl Ctx {
    /// Resolves when the process is asked to stop.
    pub async fn shutdown(&mut self) {
        let _ = self.shutdown.wait_for(|stop| *stop).await;
    }
}

enum Cli {
    Run(Option<PathBuf>),
    CheckConfig(Option<PathBuf>),
    Version,
}

fn parse_cli() -> Result<Cli, String> {
    // CLI flags only; argv[0] is skipped and nothing is trusted from it.
    let mut args = std::env::args_os().skip(1); // nosemgrep: rust.lang.security.args-os.args-os
    let mut path = std::env::var_os(CONFIG_ENV).map(PathBuf::from);
    let mut check = false;
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--config") => path = Some(args.next().ok_or("--config needs a path")?.into()),
            Some("--check-config") => check = true,
            Some("--version") => return Ok(Cli::Version),
            _ => return Err("usage: [--config <path>] [--check-config] [--version]".into()),
        }
    }
    Ok(if check {
        Cli::CheckConfig(path)
    } else {
        Cli::Run(path)
    })
}

/// Process entry point for service `S`. Call it from `fn main`.
#[must_use]
#[allow(
    clippy::print_stderr,
    reason = "before tracing is installed, stderr is the only channel"
)]
pub fn main<S: Service>() -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");
    let (path, check_only) = match parse_cli() {
        Ok(Cli::Version) => {
            eprintln!("{} {version}", S::NAME);
            return ExitCode::SUCCESS;
        }
        Ok(Cli::Run(p)) => (p, false),
        Ok(Cli::CheckConfig(p)) => (p, true),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let config: S::Config = match songbird_types::config::load(path.as_deref(), ENV_PREFIX) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", S::NAME);
            return ExitCode::from(2);
        }
    };
    if check_only {
        eprintln!("{}: configuration ok", S::NAME);
        return ExitCode::SUCCESS;
    }
    let common = config.common().clone();
    let guard = match songbird_telemetry::init_tracing(&common.log, RedactionMode::Refuse) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{}: {e}", S::NAME);
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "cannot build runtime");
            return ExitCode::FAILURE;
        }
    };
    let code = rt.block_on(run_service::<S>(config, &common, &guard, version));
    drop(rt);
    drop(guard); // flushes buffered log lines
    code
}

async fn run_service<S: Service>(
    config: S::Config,
    common: &CommonConfig,
    guard: &songbird_telemetry::TelemetryGuard,
    version: &'static str,
) -> ExitCode {
    let mut metrics = Metrics::new(S::NAME, version);
    metrics.register_self_metrics(Some(guard.dropped_lines()));
    let service = match S::new(config, &mut metrics) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(common.admin_listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "cannot bind admin endpoint");
            return ExitCode::FAILURE;
        }
    };
    let health = Arc::new(Health::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let admin_stop = {
        let mut rx = stop_rx.clone();
        async move {
            let _ = rx.wait_for(|s| *s).await;
        }
    };
    let admin = tokio::spawn(songbird_telemetry::admin::serve(
        listener,
        Arc::new(metrics),
        Arc::clone(&health),
        admin_stop,
    ));
    tracing::info!(service = S::NAME, version, "started");

    let ctx = Ctx {
        health: Arc::clone(&health),
        shutdown: stop_rx,
    };
    let run = service.run(ctx);
    tokio::pin!(run);
    let grace = Duration::from_secs(common.shutdown_grace_secs);
    let result = tokio::select! {
        r = &mut run => r,
        () = termination() => {
            tracing::info!("shutdown requested");
            health.set_ready(false);
            let _ = stop_tx.send(true);
            if let Ok(r) = tokio::time::timeout(grace, &mut run).await {
                r
            } else {
                tracing::error!(grace_secs = common.shutdown_grace_secs, "drain exceeded grace period");
                Err("drain timeout".into())
            }
        }
    };
    let _ = stop_tx.send(true);
    let _ = admin.await;
    match result {
        Ok(()) => {
            tracing::info!("stopped");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "service failed");
            ExitCode::FAILURE
        }
    }
}

async fn termination() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {},
                    _ = tokio::signal::ctrl_c() => {},
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The body of a service that has nothing to do yet: ready at once, idle until shutdown.
pub async fn idle_until_shutdown(mut ctx: Ctx) -> Result<(), BoxError> {
    ctx.health.set_ready(true);
    ctx.shutdown().await;
    Ok(())
}
