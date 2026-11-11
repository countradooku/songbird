//! Songbird `delivery` service binary. See the library crate for the design.
#![forbid(unsafe_code)]

use std::sync::Arc;

use songbird_delivery::{DeliveryConfig, DeliveryMetrics, Directory, Shared, server};
use songbird_mailbox::memory::MemoryMailbox;
use songbird_router::LocalRouter;
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, Service};
use tokio::sync::watch;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

struct Delivery {
    shared: Arc<Shared<MemoryMailbox, LocalRouter>>,
    tls: Option<tokio_rustls::TlsAcceptor>,
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery").finish_non_exhaustive()
    }
}

impl Service for Delivery {
    const NAME: &'static str = "delivery";
    type Config = DeliveryConfig;

    fn new(config: DeliveryConfig, metrics: &mut Metrics) -> Result<Self, BoxError> {
        let d = config.delivery;
        let directory = match &d.directory.file {
            Some(path) => Directory::load(path)?,
            None => Directory::empty(),
        };
        tracing::info!(devices = directory.len(), "device directory loaded");
        let tls = d.tls.as_ref().map(server::tls_acceptor).transpose()?;
        let mailbox = MemoryMailbox::new(d.mailbox.max_per_device, d.mailbox.store_generation);
        let m = DeliveryMetrics::default();
        m.register(metrics)?;
        let shared = Arc::new(Shared::new(d, directory, mailbox, LocalRouter::new(), m));
        Ok(Self { shared, tls })
    }

    async fn run(self, mut ctx: Ctx) -> Result<(), BoxError> {
        let listener = tokio::net::TcpListener::bind(self.shared.config.listen).await?;
        tracing::info!(tls = self.tls.is_some(), "websocket listener bound");
        let (stop_tx, stop_rx) = watch::channel(false);
        let serve = tokio::spawn(server::serve(listener, self.tls, self.shared, stop_rx));
        ctx.health.set_ready(true);
        ctx.shutdown().await;
        let _ = stop_tx.send(true);
        serve.await?;
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    sockudo_ws::init_clock();
    songbird_service::main::<Delivery>()
}
