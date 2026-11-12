//! Push configuration (`[push]` section), validated at startup.
//!
//! Every provider credential is a [`SecretRef`] resolved only here, in this service (D-0036):
//! `api` and `worker` hold the push service's public key and nothing else.

use serde::Deserialize;
use songbird_push_providers::apns::{self, Apns, ApnsConfig};
use songbird_push_providers::fcm::{Fcm, FcmConfig, ServiceAccount};
use songbird_push_providers::webpush::{WebPush, WebPushConfig};
use songbird_service::{BoxError, HasCommon};
use songbird_types::SecretRef;
use songbird_types::config::{CommonConfig, Environment, Validate, Validator};

use crate::Providers;

/// The push service's configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushConfig {
    /// Shared settings.
    pub common: CommonConfig,
    /// Push settings; absent (development only): the service idles.
    #[serde(default)]
    pub push: Option<PushSettings>,
}

impl HasCommon for PushConfig {
    fn common(&self) -> &CommonConfig {
        &self.common
    }
}

impl Validate for PushConfig {
    fn validate(&self, v: &mut Validator) {
        v.section("common", &self.common);
        if let Some(p) = &self.push {
            v.section("push", p);
        }
        if self.common.environment.is_deployed() {
            v.check(
                self.push.is_some(),
                "push",
                "is required in staging and production",
            );
            if let Some(p) = &self.push {
                v.check(
                    p.surrealdb.tls_ca.is_some(),
                    "push.surrealdb.tls_ca",
                    "is required in staging and production",
                );
                v.check(
                    p.jobs.valkey.tls(),
                    "push.jobs.valkey.tls_ca",
                    "is required in staging and production",
                );
                v.check(
                    p.apns.is_some() || p.fcm.is_some() || p.webpush.is_some(),
                    "push",
                    "needs at least one provider (apns, fcm, webpush)",
                );
            }
        }
        if self.common.environment == Environment::Production
            && let Some(a) = self.push.as_ref().and_then(|p| p.apns.as_ref())
        {
            v.check(
                !a.sandbox,
                "push.apns.sandbox",
                "must be false in production",
            );
        }
    }
}

/// `[push]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushSettings {
    /// The account registry (sealed push registrations).
    pub surrealdb: songbird_accounts::SurrealSettings,
    /// The job queue.
    pub jobs: JobsSettings,
    /// The push service's X25519 private key, 64 hex characters (registrations are sealed to its
    /// public key).
    pub push_key: SecretRef,
    /// The push-index secret, 64 hex characters (registrations are stored under a keyed hash of
    /// the device ID; shared with `api` and `worker`).
    pub push_index_secret: SecretRef,
    /// Jobs handled at once.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// At most one push per device (and kind) per this many milliseconds; later jobs in the
    /// window are done without a push.
    #[serde(default = "default_debounce_ms")]
    pub debounce_ms: u64,
    /// Apple.
    #[serde(default)]
    pub apns: Option<ApnsSettings>,
    /// Firebase Cloud Messaging.
    #[serde(default)]
    pub fcm: Option<FcmSettings>,
    /// Web Push (`UnifiedPush`).
    #[serde(default)]
    pub webpush: Option<WebPushSettings>,
}

const fn default_concurrency() -> usize {
    64
}

const fn default_debounce_ms() -> u64 {
    1_000
}

impl Validate for PushSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("surrealdb", &self.surrealdb);
        v.section("jobs", &self.jobs);
        v.check(
            (1..=1024).contains(&self.concurrency),
            "concurrency",
            "must be in 1..=1024",
        );
        v.check(
            self.debounce_ms <= 60_000,
            "debounce_ms",
            "must be at most 60000",
        );
        if let Some(a) = &self.apns {
            v.section("apns", a);
        }
        if let Some(w) = &self.webpush {
            v.section("webpush", w);
        }
    }
}

/// `[push.jobs]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobsSettings {
    /// `valkey-jobs`.
    pub valkey: songbird_valkey::ValkeySettings,
    /// 64 hex characters sealing jobs (shared with `delivery` and `worker`).
    pub secret: SecretRef,
}

impl Validate for JobsSettings {
    fn validate(&self, v: &mut Validator) {
        v.section("valkey", &self.valkey);
    }
}

/// `[push.apns]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsSettings {
    /// Apple developer team ID.
    pub team_id: String,
    /// Key ID of the `.p8` signing key.
    pub key_id: String,
    /// The app's bundle ID.
    pub bundle_id: String,
    /// The `.p8` signing key (PKCS#8 PEM).
    pub key: SecretRef,
    /// Apple's development environment (not in production).
    #[serde(default)]
    pub sandbox: bool,
}

impl Validate for ApnsSettings {
    fn validate(&self, v: &mut Validator) {
        let id = |s: &str| {
            s.len() == 10
                && s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        };
        v.check(
            id(&self.team_id),
            "team_id",
            "must be 10 upper-case letters or digits",
        );
        v.check(
            id(&self.key_id),
            "key_id",
            "must be 10 upper-case letters or digits",
        );
        v.check(
            !self.bundle_id.is_empty()
                && self
                    .bundle_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "bundle_id",
            "must be a bundle identifier",
        );
    }
}

/// `[push.fcm]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FcmSettings {
    /// The service-account JSON key file.
    pub service_account: SecretRef,
}

/// `[push.webpush]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebPushSettings {
    /// VAPID contact (`mailto:` or `https:`).
    pub vapid_subject: String,
    /// VAPID signing key (P-256 PKCS#8 PEM).
    pub vapid_key: SecretRef,
}

impl Validate for WebPushSettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            self.vapid_subject.starts_with("mailto:") || self.vapid_subject.starts_with("https://"),
            "vapid_subject",
            "must start with mailto: or https://",
        );
    }
}

impl PushSettings {
    /// Resolves the provider credentials and builds the clients (production endpoints, Mozilla's
    /// roots). Nothing connects yet.
    ///
    /// # Errors
    /// A secret could not be read, or a key or field was refused.
    pub fn providers(&self) -> Result<Providers, BoxError> {
        let apns = self
            .apns
            .as_ref()
            .map(|a| {
                let mut cfg = ApnsConfig::new(&a.team_id, &a.key_id, &a.bundle_id);
                if a.sandbox {
                    apns::SANDBOX.clone_into(&mut cfg.base_url);
                }
                let key = a.key.resolve()?;
                Ok::<_, BoxError>(Apns::new(cfg, key.expose().as_bytes())?)
            })
            .transpose()?;
        let fcm = self
            .fcm
            .as_ref()
            .map(|f| {
                let json = f.service_account.resolve()?;
                let account = ServiceAccount::from_json(json.expose().as_bytes())?;
                Ok::<_, BoxError>(Fcm::new(&FcmConfig::default(), account)?)
            })
            .transpose()?;
        let webpush = self
            .webpush
            .as_ref()
            .map(|w| {
                let key = w.vapid_key.resolve()?;
                Ok::<_, BoxError>(WebPush::new(
                    WebPushConfig::new(&w.vapid_subject),
                    key.expose().as_bytes(),
                )?)
            })
            .transpose()?;
        Ok(Providers { apns, fcm, webpush })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
[common]
environment = "dev"
admin_listen = "127.0.0.1:9103"
shutdown_grace_secs = 5
[common.log]
format = "pretty"
filter = "info"
"#;

    const PUSH: &str = r#"
[push]
push_key = { env = "PUSH_KEY" }
push_index_secret = { env = "PUSH_INDEX" }
[push.surrealdb]
addr = "127.0.0.1:47800"
host = "localhost"
user = "root"
pass = { env = "SURREAL_PASS" }
[push.jobs]
secret = { env = "JOBS_SECRET" }
[push.jobs.valkey]
addr = "127.0.0.1:47380"
pass = { env = "VALKEY_JOBS_PASSWORD" }
[push.apns]
team_id = "TEAM123456"
key_id = "KEYID12345"
bundle_id = "eu.songbird.app"
key = { file = "/run/credentials/apns.p8" }
sandbox = true
"#;

    fn load(text: &str) -> Result<PushConfig, String> {
        songbird_types::config::load_from_parts(text, std::iter::empty::<(String, String)>(), "X_")
            .map_err(|e| format!("{e:?}"))
    }

    #[test]
    fn dev_config_without_push_is_valid() {
        let c = load(BASE).unwrap();
        assert!(c.push.is_none());
    }

    #[test]
    fn full_config_parses_and_validates() {
        let c = load(&format!("{BASE}{PUSH}")).unwrap();
        let p = c.push.as_ref().unwrap();
        assert_eq!(p.concurrency, 64);
        assert_eq!(p.debounce_ms, 1_000);
        assert!(p.apns.as_ref().unwrap().sandbox);
    }

    #[test]
    fn production_rules() {
        let e = load(&format!("{BASE}{PUSH}").replace("\"dev\"", "\"production\"")).unwrap_err();
        assert!(e.contains("push.apns.sandbox"), "{e}");
        assert!(e.contains("push.surrealdb.tls_ca"), "{e}");
        assert!(e.contains("push.jobs.valkey.tls_ca"), "{e}");
        let e = load(&BASE.replace("\"dev\"", "\"production\"")).unwrap_err();
        assert!(e.contains("\"push\""), "{e}");
    }

    #[test]
    fn bad_fields_are_refused() {
        let e = load(&format!("{BASE}{PUSH}").replace("TEAM123456", "team")).unwrap_err();
        assert!(e.contains("push.apns.team_id"), "{e}");
        let e = load(
            &format!("{BASE}{PUSH}")
                .replace("[push.surrealdb]", "concurrency = 0\n[push.surrealdb]"),
        )
        .unwrap_err();
        assert!(e.contains("push.concurrency"), "{e}");
    }
}
