//! Songbird `calls` service (Prompt 7): runs next to LiveKit on each calls host and receives its
//! webhooks on loopback, for cleanup and capacity metrics ([`songbird_calls::webhook`]). Rooms and
//! tokens are issued by `api` through the same library.
//!
//! Without `[calls]` (development) it serves `/metrics`, `/healthz` and `/readyz` and idles.
#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use songbird_calls::webhook::{Answer, MAX_BODY, WebhookMetrics, Webhooks};
use songbird_calls::{CallSettings, Calls};
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, HasCommon, Service};
use songbird_types::config::{CommonConfig, Validate, Validator};

// Sanitizer builds keep the system allocator: ASan and TSan see only allocations they intercept.
#[cfg(not(songbird_sanitizer))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// The configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallsConfig {
    common: CommonConfig,
    /// Absent in development: the service idles.
    #[serde(default)]
    calls: Option<CallsSettings>,
}

/// `[calls]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallsSettings {
    /// Where LiveKit sends webhooks: loopback on the calls host.
    webhook_listen: SocketAddr,
    /// `valkey-hot`, where the call records live.
    valkey_hot: songbird_valkey::ValkeySettings,
    /// LiveKit and the call secret, as `api`'s `[api.calls]`.
    livekit: CallSettings,
}

impl HasCommon for CallsConfig {
    fn common(&self) -> &CommonConfig {
        &self.common
    }
}

impl Validate for CallsConfig {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
        let deployed = self.common.environment.is_deployed();
        let Some(c) = &self.calls else {
            v.check(!deployed, "calls", "is required in staging and production");
            return;
        };
        v.section("calls.valkey_hot", &c.valkey_hot);
        v.section("calls.livekit", &c.livekit);
        v.check(
            c.webhook_listen.ip().is_loopback() || !deployed,
            "calls.webhook_listen",
            "must be a loopback address in staging and production",
        );
        if deployed {
            v.check(
                c.valkey_hot.tls(),
                "calls.valkey_hot.tls_ca",
                "is required in staging and production",
            );
        }
    }
}

#[derive(Debug)]
struct CallsService {
    settings: Option<CallsSettings>,
    metrics: WebhookMetrics,
}

impl Service for CallsService {
    const NAME: &'static str = "calls";
    type Config = CallsConfig;

    fn new(config: CallsConfig, metrics: &mut Metrics) -> Result<Self, BoxError> {
        let m = WebhookMetrics::default();
        m.register(metrics)?;
        Ok(Self {
            settings: config.calls,
            metrics: m,
        })
    }

    async fn run(self, mut ctx: Ctx) -> Result<(), BoxError> {
        let Some(s) = self.settings else {
            tracing::debug!("no [calls]; idling");
            return songbird_service::idle_until_shutdown(ctx).await;
        };
        let calls = Arc::new(Calls::from_settings(&s.livekit)?);
        let hot = songbird_valkey::ValkeyConn::connect(s.valkey_hot.client()?).await?;
        let hooks = Arc::new(Webhooks::new(calls, hot, self.metrics));
        let listener = tokio::net::TcpListener::bind(s.webhook_listen).await?;
        ctx.health.set_ready(true);
        let (stop_tx, stop) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve(listener, hooks, stop));
        ctx.shutdown().await;
        ctx.health.set_ready(false);
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        Ok(())
    }
}

fn status(s: StatusCode) -> Response<Empty<Bytes>> {
    let mut r = Response::new(Empty::new());
    *r.status_mut() = s;
    r
}

async fn webhook(
    hooks: Arc<Webhooks>,
    req: Request<hyper::body::Incoming>,
) -> Response<Empty<Bytes>> {
    if req.method() != Method::POST || req.uri().path() != "/livekit" {
        return status(StatusCode::NOT_FOUND);
    }
    let auth = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v).to_owned());
    let Some(auth) = auth else {
        hooks.metrics.refused.inc();
        return status(StatusCode::UNAUTHORIZED);
    };
    let Ok(body) = Limited::new(req.into_body(), MAX_BODY).collect().await else {
        hooks.metrics.refused.inc();
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    };
    status(match hooks.handle(&auth, &body.to_bytes()).await {
        Answer::Ok => StatusCode::OK,
        Answer::Malformed => StatusCode::BAD_REQUEST,
        Answer::Refused => StatusCode::UNAUTHORIZED,
        Answer::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    })
}

/// Serves webhooks until `stop`.
async fn serve(
    listener: tokio::net::TcpListener,
    hooks: Arc<Webhooks>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .max_buf_size(16 * 1024);
    let builder = Arc::new(builder);
    loop {
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = stop.changed() => return,
        };
        let Ok((tcp, _)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let (hooks, builder) = (Arc::clone(&hooks), Arc::clone(&builder));
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let hooks = Arc::clone(&hooks);
                async move { Ok::<_, Infallible>(webhook(hooks, req).await) }
            });
            let _ = builder.serve_connection(TokioIo::new(tcp), svc).await;
        });
    }
}

fn main() -> std::process::ExitCode {
    songbird_service::main::<CallsService>()
}

#[cfg(test)]
mod credential_scope_tests {
    use super::*;

    /// Push credentials can be configured in the push service only (D-0097): this service's
    /// configuration refuses them, at the top level and in its own section.
    #[test]
    fn push_credentials_are_refused() {
        for (name, value) in [
            (
                "apns",
                r#"{ key = { file = "/run/songbird/secrets/apns_key.p8" } }"#,
            ),
            (
                "fcm",
                r#"{ service_account = { file = "/run/songbird/secrets/fcm.json" } }"#,
            ),
            (
                "webpush",
                r#"{ vapid_key = { file = "/run/songbird/secrets/vapid_key.pem" } }"#,
            ),
            ("push_key", r#"{ file = "/run/songbird/secrets/push_key" }"#),
        ] {
            for text in [
                format!(
                    "{name} = {value}\n[common]\nenvironment = \"dev\"\nadmin_listen = \"127.0.0.1:9100\"\n"
                ),
                format!(
                    "[common]\nenvironment = \"dev\"\nadmin_listen = \"127.0.0.1:9100\"\n[calls]\n{name} = {value}\n"
                ),
            ] {
                let e = songbird_types::config::load_from_parts::<CallsConfig, _>(
                    &text,
                    Vec::<(String, String)>::new(),
                    "SONGBIRD",
                )
                .expect_err(name);
                assert!(e.to_string().contains(name), "{name}: {e}");
            }
        }
    }
}
