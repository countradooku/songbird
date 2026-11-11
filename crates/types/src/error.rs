//! Error types shared across Songbird crates.
//!
//! Error messages never contain secret values, identifiers or addresses (invariant 6): they name
//! the field or source that failed, never its content.

use std::path::PathBuf;

/// Errors produced when creating or parsing identifiers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    /// The operating system's random source failed.
    #[error("random source unavailable")]
    Random,
    /// The input was not exactly 16 bytes (or 32 hex characters).
    #[error("identifier must be 16 bytes, got {got}")]
    Length {
        /// Length of the rejected input, in bytes.
        got: usize,
    },
    /// The input was not valid lowercase or uppercase hex.
    #[error("identifier is not valid hex")]
    Hex,
}

/// One failed validation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Dotted path of the offending field, e.g. `common.admin_listen`.
    pub field: String,
    /// What is wrong, without echoing the value.
    pub problem: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.problem)
    }
}

/// Errors produced while loading configuration or resolving secrets.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File that failed.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// An input exceeded its configured bound before it was read into memory (invariant 7).
    #[error("{what} is {got} bytes, limit is {limit}")]
    TooLarge {
        /// What was too large.
        what: String,
        /// Observed size.
        got: u64,
        /// Allowed maximum.
        limit: u64,
    },
    /// The TOML was malformed or did not match the expected shape.
    #[error("invalid configuration: {0}")]
    Parse(String),
    /// An environment override was malformed.
    #[error("invalid environment override {var}: {problem}")]
    Env {
        /// Variable name (never its value).
        var: String,
        /// What is wrong.
        problem: String,
    },
    /// Validation rules failed. All violations are reported at once.
    #[error("configuration failed validation: {}", join(.0))]
    Invalid(Vec<Violation>),
    /// A secret reference could not be resolved.
    #[error("secret {name} unavailable: {problem}")]
    Secret {
        /// Which secret reference (file path or environment variable name).
        name: String,
        /// What is wrong.
        problem: String,
    },
}

fn join(v: &[Violation]) -> String {
    v.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}
