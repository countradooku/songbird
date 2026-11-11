//! Proxy configuration. Loaded with `songbird_types::config` (TOML file plus
//! `SONGBIRD_PROXY__…` environment overrides), validated before the proxy starts.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use songbird_types::SecretRef;
use songbird_types::config::{Validate, Validator};

use crate::sni::{MAX_RECORD_LEN, validate_host};

/// Environment override prefix.
pub const ENV_PREFIX: &str = "SONGBIRD_PROXY";

/// Top-level proxy configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Address to accept client connections on.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The proxy's own TLS certificate (the outer TLS session, for the proxy's public domain).
    pub tls: TlsConfig,
    /// Allowed destinations, by inner SNI. Anything else is refused: this is not an open relay.
    pub upstream: Vec<Upstream>,
    /// Resource limits.
    #[serde(default)]
    pub limits: Limits,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 443))
}

/// Outer TLS certificate and key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain (leaf first).
    pub cert: PathBuf,
    /// PEM private key: `{ file = "…" }` (must not be world-readable) or `{ env = "…" }`.
    pub key: SecretRef,
}

/// One allowed destination.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Host name the client's inner `ClientHello` must carry (case-insensitive).
    pub sni: String,
    /// Where to forward, `host:port`. Resolved at connect time.
    pub address: String,
}

/// Limits. Defaults suit a small VPS.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Concurrent client connections; extra connections are closed at once.
    pub max_connections: usize,
    /// Seconds allowed for the outer TLS handshake plus the inner `ClientHello`.
    pub handshake_timeout_secs: u64,
    /// Seconds allowed to connect to the upstream.
    pub connect_timeout_secs: u64,
    /// Seconds with no bytes in either direction before the relay closes.
    pub idle_timeout_secs: u64,
    /// Largest inner `ClientHello` accepted, in bytes.
    pub max_client_hello_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 10_000,
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            idle_timeout_secs: 360,
            max_client_hello_bytes: MAX_RECORD_LEN,
        }
    }
}

impl Validate for ProxyConfig {
    fn validate(&self, v: &mut Validator) {
        v.check(
            !self.upstream.is_empty(),
            "upstream",
            "at least one upstream is required",
        );
        v.check(
            self.upstream.len() <= 64,
            "upstream",
            "at most 64 upstreams",
        );
        for (i, u) in self.upstream.iter().enumerate() {
            v.check(
                validate_host(u.sni.as_bytes()).is_ok(),
                &format!("upstream[{i}].sni"),
                "not a DNS host name",
            );
            let addr_ok = u.address.rsplit_once(':').is_some_and(|(h, p)| {
                !h.is_empty() && h.len() <= 253 && p.parse::<u16>().is_ok_and(|p| p != 0)
            });
            v.check(
                addr_ok,
                &format!("upstream[{i}].address"),
                "must be host:port",
            );
        }
        let mut snis: Vec<String> = self
            .upstream
            .iter()
            .map(|u| u.sni.to_ascii_lowercase())
            .collect();
        snis.sort();
        let before = snis.len();
        snis.dedup();
        v.check(before == snis.len(), "upstream", "duplicate sni");
        v.section("limits", &self.limits);
    }
}

impl Validate for Limits {
    fn validate(&self, v: &mut Validator) {
        v.check(
            (1..=1_000_000).contains(&self.max_connections),
            "max_connections",
            "must be 1..=1000000",
        );
        v.check(
            (1..=60).contains(&self.handshake_timeout_secs),
            "handshake_timeout_secs",
            "must be 1..=60",
        );
        v.check(
            (1..=60).contains(&self.connect_timeout_secs),
            "connect_timeout_secs",
            "must be 1..=60",
        );
        v.check(
            (10..=3600).contains(&self.idle_timeout_secs),
            "idle_timeout_secs",
            "must be 10..=3600",
        );
        v.check(
            (512..=4 * MAX_RECORD_LEN).contains(&self.max_client_hello_bytes),
            "max_client_hello_bytes",
            "must be 512..=65536",
        );
    }
}

impl ProxyConfig {
    /// The upstream address for an SNI host, if allowed.
    #[must_use]
    pub fn route(&self, sni: &str) -> Option<&str> {
        self.upstream
            .iter()
            .find(|u| u.sni.eq_ignore_ascii_case(sni))
            .map(|u| u.address.as_str())
    }
}
