//! Configuration loading with validation.
//!
//! Sources, later wins:
//! 1. A TOML file (optional), at most [`MAX_CONFIG_BYTES`], size checked before reading.
//! 2. Environment overrides `<PREFIX>__<SECTION>__<KEY>=<value>`, e.g.
//!    `SONGBIRD__COMMON__ADMIN_LISTEN=10.0.0.5:9100`. The value is parsed as a TOML value; if that
//!    fails it is taken as a string. At most [`MAX_ENV_OVERRIDES`] overrides, each bounded.
//!
//! Then the merged table is deserialized with `deny_unknown_fields` (typos are errors, not silently
//! ignored), and [`Validate`] runs; every violation is reported at once.
//!
//! Secrets are never values in this table: see [`crate::secret::SecretRef`].

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::error::{ConfigError, Violation};

/// Largest configuration file accepted.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Most environment overrides accepted.
pub const MAX_ENV_OVERRIDES: usize = 256;
/// Longest single environment override value.
pub const MAX_ENV_VALUE_BYTES: usize = 4096;
/// Deepest key path in an override (`A__B__C` is depth 3).
pub const MAX_KEY_DEPTH: usize = 8;

/// Validation rules for a configuration type.
pub trait Validate {
    /// Records every violated rule in `v`.
    fn validate(&self, v: &mut Validator);
}

/// Collects violations with dotted field paths.
#[derive(Debug, Default)]
pub struct Validator {
    path: Vec<String>,
    violations: Vec<Violation>,
}

impl Validator {
    /// Records a violation at `field` (relative to the current section) unless `ok`.
    pub fn check(&mut self, ok: bool, field: &str, problem: impl Into<String>) {
        if !ok {
            let mut full = self.path.clone();
            full.push(field.to_owned());
            self.violations.push(Violation {
                field: full.join("."),
                problem: problem.into(),
            });
        }
    }

    /// Validates a nested section under `field`.
    pub fn section(&mut self, field: &str, inner: &impl Validate) {
        self.path.push(field.to_owned());
        inner.validate(self);
        self.path.pop();
    }

    /// Violations so far.
    #[must_use]
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    fn finish(self) -> Result<(), ConfigError> {
        if self.violations.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(self.violations))
        }
    }
}

/// Loads `T` from an optional file plus the process environment.
///
/// # Errors
/// Any [`ConfigError`]: unreadable or oversized file, malformed TOML or override, unknown field,
/// or failed validation.
pub fn load<T>(path: Option<&Path>, env_prefix: &str) -> Result<T, ConfigError>
where
    T: DeserializeOwned + Validate,
{
    let text = match path {
        Some(p) => read_bounded(p)?,
        None => String::new(),
    };
    load_from_parts(
        &text,
        std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
        env_prefix,
    )
}

/// Loads `T` from TOML text and an explicit environment (testable without touching the process).
///
/// # Errors
/// See [`load`].
pub fn load_from_parts<T, I>(text: &str, env: I, env_prefix: &str) -> Result<T, ConfigError>
where
    T: DeserializeOwned + Validate,
    I: IntoIterator<Item = (String, String)>,
{
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            what: "configuration".into(),
            got: u64::try_from(text.len()).unwrap_or(u64::MAX),
            limit: MAX_CONFIG_BYTES,
        });
    }
    let mut table: toml::Table =
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;

    let marker = format!("{env_prefix}__");
    let mut overrides: Vec<(String, String)> = env
        .into_iter()
        .filter(|(k, _)| k.starts_with(&marker))
        .collect();
    if overrides.len() > MAX_ENV_OVERRIDES {
        return Err(ConfigError::TooLarge {
            what: "environment overrides (count)".into(),
            got: u64::try_from(overrides.len()).unwrap_or(u64::MAX),
            limit: u64::try_from(MAX_ENV_OVERRIDES).unwrap_or(u64::MAX),
        });
    }
    // Deterministic order regardless of how the environment was enumerated.
    overrides.sort();
    for (var, raw) in overrides {
        apply_override(&mut table, &marker, &var, &raw)?;
    }

    let value: T = table
        .try_into()
        .map_err(|e| ConfigError::Parse(e.to_string()))?;
    let mut v = Validator::default();
    value.validate(&mut v);
    v.finish()?;
    Ok(value)
}

fn read_bounded(path: &Path) -> Result<String, ConfigError> {
    let io = |source| ConfigError::Io {
        path: path.to_owned(),
        source,
    };
    let meta = std::fs::metadata(path).map_err(io)?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            what: path.display().to_string(),
            got: meta.len(),
            limit: MAX_CONFIG_BYTES,
        });
    }
    std::fs::read_to_string(path).map_err(io)
}

fn apply_override(
    table: &mut toml::Table,
    marker: &str,
    var: &str,
    raw: &str,
) -> Result<(), ConfigError> {
    let env_err = |problem: &str| ConfigError::Env {
        var: var.to_owned(),
        problem: problem.into(),
    };
    if raw.len() > MAX_ENV_VALUE_BYTES {
        return Err(env_err("value too long"));
    }
    if raw.contains(['\n', '\r']) {
        return Err(env_err("value must be a single line"));
    }
    let keys: Vec<String> = var
        .get(marker.len()..)
        .unwrap_or_default()
        .split("__")
        .map(str::to_lowercase)
        .collect();
    if keys.is_empty() || keys.len() > MAX_KEY_DEPTH {
        return Err(env_err("key path empty or too deep"));
    }
    if keys
        .iter()
        .any(|k| k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    {
        return Err(env_err("key segments must be [A-Za-z0-9_]+"));
    }
    let value = parse_env_value(raw);

    let (last, parents) = keys.split_last().ok_or_else(|| env_err("empty key"))?;
    let mut cursor = table;
    for k in parents {
        let entry = cursor
            .entry(k.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cursor = match entry {
            toml::Value::Table(t) => t,
            _ => return Err(env_err("overrides a non-table value with a table")),
        };
    }
    cursor.insert(last.clone(), value);
    Ok(())
}

fn parse_env_value(raw: &str) -> toml::Value {
    // A value that is itself valid TOML (number, bool, array, inline table, quoted string) keeps
    // its type; anything else is a plain string. `raw` is a single line (checked by the caller)
    // and only the `v` key is read back, so it cannot add keys.
    toml::from_str::<toml::Table>(&format!("v = {raw}"))
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(raw.to_owned()))
}

/// Deployment environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// A developer machine.
    Dev,
    /// Continuous integration.
    Ci,
    /// A pre-production environment.
    Staging,
    /// Production.
    Production,
}

impl Environment {
    /// Staging and production get the strict rules.
    #[must_use]
    pub const fn is_deployed(self) -> bool {
        matches!(self, Self::Staging | Self::Production)
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line (deployed environments).
    #[default]
    Json,
    /// Human-readable (development).
    Pretty,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// Output format.
    pub format: LogFormat,
    /// `tracing` filter directive, e.g. `info,songbird_delivery=debug`.
    pub filter: String,
    /// Lines buffered by the non-blocking writer before new lines are dropped (never blocks).
    pub buffered_lines: usize,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            filter: "info".into(),
            buffered_lines: 128 * 1024,
        }
    }
}

impl Validate for LogConfig {
    fn validate(&self, v: &mut Validator) {
        v.check(
            !self.filter.is_empty() && self.filter.len() <= 1024,
            "filter",
            "must be 1..=1024 bytes",
        );
        v.check(
            (1024..=4 * 1024 * 1024).contains(&self.buffered_lines),
            "buffered_lines",
            "must be in 1024..=4194304",
        );
    }
}

/// Settings every Songbird service shares. Services embed it as a `[common]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonConfig {
    /// Where this process runs.
    pub environment: Environment,
    /// Address of the admin endpoint (`/metrics`, `/healthz`, `/readyz`). Private network only.
    #[serde(default = "default_admin_listen")]
    pub admin_listen: SocketAddr,
    /// Logging.
    #[serde(default)]
    pub log: LogConfig,
    /// Seconds to drain after SIGTERM before exiting with an error.
    #[serde(default = "default_shutdown_grace_secs")]
    pub shutdown_grace_secs: u64,
}

const fn default_shutdown_grace_secs() -> u64 {
    30
}

fn default_admin_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9100))
}

/// Loopback or private-range address: never reachable from the internet by itself.
#[must_use]
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_private(),
        IpAddr::V6(a) => a.is_loopback() || a.is_unique_local(),
    }
}

impl Validate for CommonConfig {
    fn validate(&self, v: &mut Validator) {
        if self.environment.is_deployed() {
            v.check(
                is_internal_ip(self.admin_listen.ip()),
                "admin_listen",
                "must be a loopback or private address in staging and production",
            );
            v.check(
                self.log.format == LogFormat::Json,
                "log.format",
                "must be json in staging and production",
            );
        }
        v.check(
            (1..=600).contains(&self.shutdown_grace_secs),
            "shutdown_grace_secs",
            "must be in 1..=600",
        );
        v.section("log", &self.log);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Svc {
        common: CommonConfig,
        #[serde(default)]
        limit: u32,
    }
    impl Validate for Svc {
        fn validate(&self, v: &mut Validator) {
            v.section("common", &self.common);
            v.check(self.limit <= 100, "limit", "must be <= 100");
        }
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn file_then_env_override() {
        let c: Svc = load_from_parts(
            "limit = 3\n[common]\nenvironment = \"dev\"\n",
            env(&[
                ("SB__LIMIT", "7"),
                ("SB__COMMON__ADMIN_LISTEN", "127.0.0.1:9999"),
                ("OTHER", "x"),
            ]),
            "SB",
        )
        .unwrap();
        assert_eq!(c.limit, 7);
        assert_eq!(c.common.admin_listen.port(), 9999);
    }

    #[test]
    fn env_only() {
        let c: Svc = load_from_parts("", env(&[("SB__COMMON__ENVIRONMENT", "ci")]), "SB").unwrap();
        assert_eq!(c.common.environment, Environment::Ci);
    }

    #[test]
    fn unknown_fields_are_errors() {
        let r: Result<Svc, _> = load_from_parts(
            "[common]\nenvironment = \"dev\"\nadmin_lisen = \"x\"\n",
            env(&[]),
            "SB",
        );
        assert!(matches!(r, Err(ConfigError::Parse(_))));
        let r: Result<Svc, _> = load_from_parts(
            "[common]\nenvironment = \"dev\"\n",
            env(&[("SB__TYPO", "1")]),
            "SB",
        );
        assert!(matches!(r, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn all_violations_reported() {
        let r: Result<Svc, _> = load_from_parts(
            "limit = 1000\n[common]\nenvironment = \"production\"\nadmin_listen = \"0.0.0.0:9100\"\n[common.log]\nformat = \"pretty\"\n",
            env(&[]),
            "SB",
        );
        let Err(ConfigError::Invalid(v)) = r else {
            panic!("expected Invalid, got {r:?}")
        };
        let fields: Vec<_> = v.iter().map(|x| x.field.as_str()).collect();
        assert_eq!(
            fields,
            ["common.admin_listen", "common.log.format", "limit"]
        );
    }

    #[test]
    fn production_accepts_private_admin() {
        let c: Svc = load_from_parts(
            "[common]\nenvironment = \"production\"\nadmin_listen = \"10.0.1.5:9100\"\n",
            env(&[]),
            "SB",
        )
        .unwrap();
        assert!(c.common.environment.is_deployed());
    }

    #[test]
    fn bounds_are_enforced() {
        let big = "#".repeat(usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1);
        assert!(matches!(
            load_from_parts::<Svc, _>(&big, env(&[]), "SB"),
            Err(ConfigError::TooLarge { .. })
        ));
        let many: Vec<_> = (0..=MAX_ENV_OVERRIDES)
            .map(|i| (format!("SB__K{i}"), "1".to_owned()))
            .collect();
        assert!(matches!(
            load_from_parts::<Svc, _>("", many, "SB"),
            Err(ConfigError::TooLarge { .. })
        ));
        let long = "x".repeat(MAX_ENV_VALUE_BYTES + 1);
        assert!(matches!(
            load_from_parts::<Svc, _>("", env(&[("SB__LIMIT", &long)]), "SB"),
            Err(ConfigError::Env { .. })
        ));
        let deep = format!("SB__{}", ["A"; MAX_KEY_DEPTH + 1].join("__"));
        assert!(matches!(
            load_from_parts::<Svc, _>("", env(&[(&deep, "1")]), "SB"),
            Err(ConfigError::Env { .. })
        ));
    }

    #[test]
    fn smuggled_lines_do_not_add_keys() {
        let r: Result<Svc, _> = load_from_parts(
            "[common]\nenvironment = \"dev\"\n",
            env(&[("SB__LIMIT", "5\nextra = 1")]),
            "SB",
        );
        assert!(matches!(r, Err(ConfigError::Env { .. })));
    }

    #[test]
    fn errors_do_not_echo_values() {
        let r: Result<Svc, _> = load_from_parts(
            "[common]\nenvironment = \"production\"\nadmin_listen = \"203.0.113.7:9100\"\n",
            env(&[]),
            "SB",
        );
        let msg = r.unwrap_err().to_string();
        assert!(!msg.contains("203.0.113.7"), "{msg}");
    }
}
