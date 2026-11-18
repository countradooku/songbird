//! Songbird `push` service binary. See the library crate for the design.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use songbird_jobs::{ConsumeConfig, Queue, QueueConfig, Stream};
use songbird_push::{Handler, Providers, PushConfig, PushMetrics, PushSettings};
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, Service};
use zeroize::Zeroizing;

// Sanitizer builds keep the system allocator: ASan and TSan see only allocations they intercept.
#[cfg(not(songbird_sanitizer))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Everything resolved at startup, before anything connects.
struct Resolved {
    surreal: songbird_surreal::Config,
    jobs: redis::Client,
    jobs_secret: Zeroizing<[u8; 32]>,
    push_key: Zeroizing<[u8; 32]>,
    index_secret: Zeroizing<[u8; 32]>,
    providers: Providers,
    concurrency: usize,
    ring_concurrency: usize,
    debounce: Duration,
}

struct Push {
    resolved: Option<Resolved>,
    metrics: PushMetrics,
}

impl std::fmt::Debug for Push {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Push").finish_non_exhaustive()
    }
}

fn resolve(p: &PushSettings) -> Result<Resolved, BoxError> {
    Ok(Resolved {
        surreal: p.push_tokens.config()?,
        jobs: p.jobs.valkey.client()?,
        jobs_secret: p.jobs.secret.resolve_key32()?,
        push_key: p.push_key.resolve_key32()?,
        index_secret: p.push_index_secret.resolve_key32()?,
        providers: p.providers()?,
        concurrency: p.concurrency,
        ring_concurrency: p.ring_concurrency,
        debounce: Duration::from_millis(p.debounce_ms),
    })
}

impl Service for Push {
    const NAME: &'static str = "push";
    type Config = PushConfig;

    fn new(config: PushConfig, metrics: &mut Metrics) -> Result<Self, BoxError> {
        // The registry's write-conflict retries and busy answers (D-0093).
        for (name, help, read) in songbird_accounts::METRICS
            .into_iter()
            .chain(songbird_jobs::queue::METRICS)
        {
            metrics.register_counter_fn(name, help, read)?;
        }
        let resolved = config.push.as_ref().map(resolve).transpose()?;
        // Fail at startup, not at the first job, if the key is wrong.
        if let Some(r) = &resolved {
            songbird_accounts::push_token::key_pair(&r.push_key)
                .map_err(|_| "push_key is not a valid X25519 private key")?;
        }
        let m = PushMetrics::default();
        m.register(metrics)?;
        Ok(Self {
            resolved,
            metrics: m,
        })
    }

    async fn run(self, mut ctx: Ctx) -> Result<(), BoxError> {
        let Some(r) = self.resolved else {
            tracing::info!("no [push] section: idle (development)");
            return songbird_service::idle_until_shutdown(ctx).await;
        };
        let db = songbird_accounts::Db::connect(r.surreal).await?;
        let store = Arc::new(songbird_accounts::PushStore::connect(db).await?);
        let mut id = [0u8; 8];
        aws_lc_rs::rand::fill(&mut id).map_err(|_| "no system randomness")?;
        let queue = Queue::connect(
            r.jobs,
            &r.jobs_secret,
            QueueConfig::new(format!("push-{}", hex::encode(id))),
        )
        .await?;
        queue.ensure_groups(&[Stream::Push, Stream::Ring]).await?;
        let handler = Handler::new(
            store,
            &r.index_secret,
            &r.push_key,
            r.providers,
            r.debounce,
            self.metrics,
        )?;
        let running = songbird_push::spawn(
            Arc::new(queue),
            Arc::new(handler),
            ConsumeConfig {
                concurrency: r.concurrency,
                ..ConsumeConfig::default()
            },
            ConsumeConfig {
                concurrency: r.ring_concurrency,
                ..ConsumeConfig::default()
            },
        );
        tracing::info!("consuming push and ring jobs");
        ctx.health.set_ready(true);
        ctx.shutdown().await;
        ctx.health.set_ready(false);
        running.stop().await;
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    songbird_service::main::<Push>()
}
