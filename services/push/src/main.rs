//! Songbird `push` service. Push: consumes push jobs and talks to APNs, FCM and UnifiedPush; holds the only push credentials (Prompt 8).
//!
//! Empty for now: it loads and validates its configuration, serves `/metrics`, `/healthz` and
//! `/readyz`, and drains on SIGTERM.
#![forbid(unsafe_code)]

use songbird_service::telemetry::Metrics;
use songbird_service::{BasicConfig, BoxError, Ctx, Service};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug)]
struct Push;

impl Service for Push {
    const NAME: &'static str = "push";
    type Config = BasicConfig;

    fn new(_config: BasicConfig, _metrics: &mut Metrics) -> Result<Self, BoxError> {
        Ok(Self)
    }

    async fn run(self, ctx: Ctx) -> Result<(), BoxError> {
        tracing::debug!("no work yet");
        songbird_service::idle_until_shutdown(ctx).await
    }
}

fn main() -> std::process::ExitCode {
    songbird_service::main::<Push>()
}
