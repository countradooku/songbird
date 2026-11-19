//! Songbird `billing` service (Prompt 11, M3; D-0129): see the library's documentation.
//!
//! Without `[billing]` (development) it serves `/metrics`, `/healthz` and `/readyz` and idles.
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use songbird_billing::mollie::Prices;
use songbird_billing::{
    Billing, Env, ProductSetting, Products, RangeBudget, apple, google, http, jose, mollie, store,
};
use songbird_service::telemetry::Metrics;
use songbird_service::{BoxError, Ctx, HasCommon, Service};
use songbird_types::SecretRef;
use songbird_types::config::{CommonConfig, Validate, Validator};

#[cfg(not(songbird_sanitizer))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// SHA-256 of Apple Root CA - G3's DER (`apple.com/certificateauthority`). In production the
/// configured root must be exactly this certificate.
const APPLE_ROOT_G3_SHA256: &str =
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BillingConfig {
    common: CommonConfig,
    #[serde(default)]
    billing: Option<BillingSettings>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsSettings {
    cert_chain: PathBuf,
    key: SecretRef,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenSettings {
    /// The token secret, as `api`'s `[api.tokens] secret`.
    secret: SecretRef,
    /// Key IDs; the highest issues.
    #[serde(default = "default_keys")]
    keys: Vec<u8>,
}

fn default_keys() -> Vec<u8> {
    vec![1]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppleApiSettings {
    #[serde(default = "default_apple_api")]
    base_url: String,
    issuer_id: String,
    key_id: String,
    /// The In-App Purchase key (`.p8`, PEM).
    key: SecretRef,
}

fn default_apple_api() -> String {
    "https://api.storekit.itunes.apple.com".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppleSettings {
    bundle_id: String,
    /// Apple Root CA - G3 (DER).
    root_ca: PathBuf,
    #[serde(default)]
    api: Option<AppleApiSettings>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleSettings {
    package: String,
    /// The Play service account's JSON key.
    service_account: SecretRef,
    #[serde(default = "default_google_api")]
    api_url: String,
    /// The push subscription's OIDC audience.
    push_audience: String,
    /// The push subscription's service account.
    push_email: String,
    #[serde(default = "default_google_certs")]
    certs_url: String,
}

fn default_google_api() -> String {
    "https://androidpublisher.googleapis.com".into()
}
fn default_google_certs() -> String {
    "https://www.googleapis.com/oauth2/v3/certs".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MollieSettings {
    api_key: SecretRef,
    #[serde(default = "default_mollie_api")]
    base_url: String,
    /// This service's public webhook URL (`…/v1/billing/mollie/webhook`).
    webhook_url: String,
    /// Where the browser goes after paying.
    redirect_url: String,
    prices: Prices,
}

fn default_mollie_api() -> String {
    "https://api.mollie.com/v2".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BillingSettings {
    listen: SocketAddr,
    #[serde(default)]
    tls: Option<TlsSettings>,
    environment: Env,
    /// Billing's own database, with a credential for it alone.
    surrealdb: songbird_accounts::SurrealSettings,
    /// 32 bytes (64 hex): keys the subscription rows.
    secret: SecretRef,
    tokens: TokenSettings,
    #[serde(default)]
    products: Vec<ProductSetting>,
    #[serde(default)]
    apple: Option<AppleSettings>,
    #[serde(default)]
    google: Option<GoogleSettings>,
    #[serde(default)]
    mollie: Option<MollieSettings>,
    #[serde(default = "default_per_minute")]
    requests_per_minute: u32,
    #[serde(default = "default_burst")]
    request_burst: u32,
    #[serde(default = "default_connections")]
    max_connections: usize,
}

const fn default_per_minute() -> u32 {
    6
}
const fn default_burst() -> u32 {
    20
}
const fn default_connections() -> usize {
    4_096
}

impl HasCommon for BillingConfig {
    fn common(&self) -> &CommonConfig {
        &self.common
    }
}

fn https_or_loopback(u: &str) -> bool {
    u.starts_with("https://")
        || u.starts_with("http://127.0.0.1")
        || u.starts_with("http://localhost")
}

impl Validate for BillingConfig {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
        let deployed = self.common.environment.is_deployed();
        let Some(b) = &self.billing else {
            v.check(
                !deployed,
                "billing",
                "is required in staging and production",
            );
            return;
        };
        v.section("billing.surrealdb", &b.surrealdb);
        v.check(
            !deployed || b.tls.is_some(),
            "billing.tls",
            "is required in staging and production",
        );
        v.check(
            Products::new(&b.products).is_ok(),
            "billing.products",
            "plans must be plus or family, each ID once",
        );
        v.check(
            (1..=600).contains(&b.requests_per_minute) && (1..=1_000).contains(&b.request_burst),
            "billing.requests_per_minute",
            "must be in 1..=600 (burst 1..=1000)",
        );
        if let Some(m) = &b.mollie {
            v.check(
                m.prices.valid(),
                "billing.mollie.prices",
                "must be <digits>.<2 digits> with an ISO currency",
            );
            for (name, u) in [
                ("billing.mollie.base_url", &m.base_url),
                ("billing.mollie.webhook_url", &m.webhook_url),
                ("billing.mollie.redirect_url", &m.redirect_url),
            ] {
                v.check(https_or_loopback(u), name, "must be https://");
            }
        }
        if let Some(g) = &b.google {
            for (name, u) in [
                ("billing.google.api_url", &g.api_url),
                ("billing.google.certs_url", &g.certs_url),
            ] {
                v.check(https_or_loopback(u), name, "must be https://");
            }
        }
        if let Some(a) = b.apple.as_ref().and_then(|a| a.api.as_ref()) {
            v.check(
                https_or_loopback(&a.base_url),
                "billing.apple.api.base_url",
                "must be https://",
            );
        }
    }
}

fn tls_acceptor(t: &TlsSettings) -> Result<tokio_rustls::TlsAcceptor, BoxError> {
    let file = std::fs::File::open(&t.cert_chain)?;
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(BufReader::new(file)).collect::<Result<_, _>>()?;
    let secret = t.key.resolve()?;
    let key = PrivateKeyDer::from_pem_slice(secret.expose().as_bytes())
        .map_err(|_| "billing.tls.key is not a PEM private key")?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    jose::b64_decode(&b64)
}

async fn build(s: &BillingSettings, deployed: bool) -> Result<Billing, BoxError> {
    let client = http::Client::new(songbird_billing::PROVIDER_TIMEOUT)?;
    let db = songbird_accounts::Db::connect(s.surrealdb.config()?).await?;
    let store = store::Store::connect(db, &*s.secret.resolve_key32()?).await?;
    let keys =
        songbird_tokens::token::Keys::derive(&*s.tokens.secret.resolve_key32()?, &s.tokens.keys)
            .map_err(|_| "billing.tokens.keys")?;
    let products = Products::new(&s.products)?;
    let apple = match &s.apple {
        Some(a) => {
            let root = std::fs::read(&a.root_ca)?;
            if deployed && s.environment == Env::Production {
                let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &root);
                if hex::encode(digest.as_ref()) != APPLE_ROOT_G3_SHA256 {
                    return Err("billing.apple.root_ca is not Apple Root CA - G3".into());
                }
            }
            let api = match &a.api {
                Some(api) => Some(apple::ServerApi {
                    base: api.base_url.clone(),
                    issuer: api.issuer_id.clone(),
                    key_id: api.key_id.clone(),
                    key: jose::Es256::from_pkcs8(
                        &pem_der(api.key.resolve()?.expose())
                            .ok_or("billing.apple.api.key is not PEM")?,
                    )?,
                }),
                None => None,
            };
            Some(apple::Apple::new(
                jose::AppleTrust::apple(root),
                a.bundle_id.clone(),
                s.environment,
                api,
                client.clone(),
            ))
        }
        None => None,
    };
    let google = match &s.google {
        Some(g) => Some(google::Google::new(
            g.package.clone(),
            s.environment,
            google::ServiceAccount::from_json(g.service_account.resolve()?.expose().as_bytes())?,
            g.api_url.clone(),
            google::PushAuth {
                audience: g.push_audience.clone(),
                email: g.push_email.clone(),
                certs_url: g.certs_url.clone(),
            },
            client.clone(),
        )),
        None => None,
    };
    let mollie = match &s.mollie {
        Some(m) => Some(mollie::Mollie::new(
            client.clone(),
            m.api_key.resolve()?.expose().to_owned(),
            m.base_url.clone(),
            m.webhook_url.clone(),
            m.redirect_url.clone(),
            m.prices.clone(),
        )),
        None => None,
    };
    Ok(Billing {
        store,
        keys,
        products,
        apple,
        google,
        mollie,
        budget: RangeBudget::new(s.requests_per_minute, s.request_burst),
    })
}

#[derive(Debug)]
struct BillingService {
    settings: Option<BillingSettings>,
    deployed: bool,
}

impl Service for BillingService {
    const NAME: &'static str = "billing";
    type Config = BillingConfig;

    fn new(config: BillingConfig, _metrics: &mut Metrics) -> Result<Self, BoxError> {
        Ok(Self {
            deployed: config.common.environment.is_deployed(),
            settings: config.billing,
        })
    }

    async fn run(self, mut ctx: Ctx) -> Result<(), BoxError> {
        let Some(s) = self.settings else {
            tracing::debug!("no [billing]; idling");
            return songbird_service::idle_until_shutdown(ctx).await;
        };
        let tls = s.tls.as_ref().map(tls_acceptor).transpose()?;
        let billing = Arc::new(Box::pin(build(&s, self.deployed)).await?);
        let listener = tokio::net::TcpListener::bind(s.listen).await?;
        ctx.health.set_ready(true);
        let (stop_tx, stop) = tokio::sync::watch::channel(false);
        let sweeper = {
            let b = Arc::clone(&billing);
            let mut stop = stop.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(3_600));
                loop {
                    tokio::select! {
                        _ = tick.tick() => {
                            if let Err(e) = b.store.sweep(songbird_billing::today()).await {
                                tracing::warn!(error = %e, "billing sweep failed");
                            }
                        }
                        _ = stop.changed() => return,
                    }
                }
            })
        };
        let server = tokio::spawn(songbird_billing::serve(
            listener,
            tls,
            billing,
            s.max_connections,
            stop,
        ));
        ctx.shutdown().await;
        ctx.health.set_ready(false);
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        sweeper.abort();
        Ok(())
    }
}

fn main() -> std::process::ExitCode {
    songbird_service::main::<BillingService>()
}

#[cfg(test)]
mod credential_scope_tests {
    use super::*;

    /// Push credentials can be configured in the push service only (D-0097).
    #[test]
    fn push_credentials_are_refused() {
        for name in ["apns", "fcm", "webpush", "push_key"] {
            let text = format!(
                "{name} = {{ file = \"/x\" }}\n[common]\nenvironment = \"dev\"\nadmin_listen = \"127.0.0.1:9106\"\n"
            );
            let e = songbird_types::config::load_from_parts::<BillingConfig, _>(
                &text,
                Vec::<(String, String)>::new(),
                "SONGBIRD",
            )
            .expect_err(name);
            assert!(e.to_string().contains(name), "{name}: {e}");
        }
    }
}
