//! Shared Songbird types.
//!
//! - [`id`]: identifiers as 16-byte random values, typed per kind, redacted in `Debug`.
//! - [`error`]: the error types shared across crates.
//! - [`config`]: configuration loading (TOML file plus environment overrides) with bounded input,
//!   strict unknown-field rejection and explicit validation.
//! - [`dns`]: DNS host-name validation.
//! - [`secret`]: secret values that never appear in configuration files, logs or `Debug` output.
#![forbid(unsafe_code)]

pub mod config;
pub mod dns;
pub mod error;
pub mod id;
pub mod proxy_link;
pub mod secret;

pub use error::{ConfigError, IdError};
pub use id::{AccountId, DeviceId, Id, IdKind, JobId};
pub use secret::{Secret, SecretRef};
