//! Shared Valkey plumbing (D-0034, D-0036).
//!
//! - [`ValkeyConn`]: a command connection that heals itself after Valkey restarts.
//! - [`ValkeySettings`]: the `[*.valkey]` configuration section (address, TLS with the internal
//!   CA, client certificate, ACL user, password by reference), validated, resolved into a
//!   [`redis::Client`] at start-up.
#![forbid(unsafe_code)]

pub mod conn;

use std::path::PathBuf;

use serde::Deserialize;
use songbird_types::config::{Validate, Validator};
use songbird_types::secret::SecretRef;

pub use conn::ValkeyConn;

/// Connection settings for one Valkey instance.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValkeySettings {
    /// `host:port`.
    pub addr: String,
    /// TLS server name (required with `tls_ca`).
    #[serde(default)]
    pub tls_domain: Option<String>,
    /// PEM root of the internal CA; TLS is on when set.
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,
    /// ACL user (default user when absent).
    #[serde(default)]
    pub user: Option<String>,
    /// Password.
    pub pass: SecretRef,
    /// PEM client certificate chain (Valkey requires client certificates in deployments).
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// PEM client key.
    #[serde(default)]
    pub tls_key: Option<SecretRef>,
}

impl Validate for ValkeySettings {
    fn validate(&self, v: &mut Validator) {
        v.check(
            !self.addr.is_empty() && self.addr.contains(':'),
            "addr",
            "must be host:port",
        );
        v.check(
            self.tls_ca.is_none() || self.tls_domain.is_some(),
            "tls_domain",
            "is required with tls_ca",
        );
        v.check(
            self.tls_cert.is_some() == self.tls_key.is_some(),
            "tls_key",
            "and tls_cert go together",
        );
    }
}

/// Why settings could not be turned into a client. Never carries the URL (it holds the
/// password).
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// A secret or file could not be read.
    #[error("valkey settings: cannot read {0}")]
    Read(&'static str),
    /// The client refused the settings.
    #[error("valkey settings: {0}")]
    Client(String),
}

impl ValkeySettings {
    /// Whether TLS is on.
    #[must_use]
    pub fn tls(&self) -> bool {
        self.tls_ca.is_some()
    }

    /// Reads the secrets and files and builds the client (does not connect).
    ///
    /// # Errors
    /// [`SettingsError`].
    pub fn client(&self) -> Result<redis::Client, SettingsError> {
        let pass = self
            .pass
            .resolve()
            .map_err(|_| SettingsError::Read("pass"))?;
        let user = self.user.clone().unwrap_or_default();
        let (scheme, host_port) = match &self.tls_domain {
            // With TLS the URL names the certificate's host (it must resolve to Valkey).
            Some(domain) if self.tls_ca.is_some() => {
                let port = self.addr.rsplit_once(':').map_or("6379", |(_, p)| p);
                ("rediss", format!("{domain}:{port}"))
            }
            _ => ("redis", self.addr.clone()),
        };
        let url = format!("{scheme}://{user}:{}@{host_port}/", pass.expose());
        let r = match &self.tls_ca {
            Some(ca) => {
                let root = std::fs::read(ca).map_err(|_| SettingsError::Read("tls_ca"))?;
                let client_tls = match (&self.tls_cert, &self.tls_key) {
                    (Some(cert), Some(key)) => Some(redis::ClientTlsConfig {
                        client_cert: std::fs::read(cert)
                            .map_err(|_| SettingsError::Read("tls_cert"))?,
                        client_key: key
                            .resolve()
                            .map_err(|_| SettingsError::Read("tls_key"))?
                            .expose()
                            .as_bytes()
                            .to_vec(),
                    }),
                    _ => None,
                };
                redis::Client::build_with_tls(
                    url.as_str(),
                    redis::TlsCertificates {
                        client_tls,
                        root_cert: Some(root),
                    },
                )
            }
            None => redis::Client::open(url.as_str()),
        };
        r.map_err(|e| SettingsError::Client(format!("{:?}", e.kind())))
    }
}
