//! Secrets: referenced from configuration, never written in it.
//!
//! A configuration file names *where* a secret lives, never the secret itself:
//!
//! ```toml
//! admin_token = { file = "/run/credentials/songbird-api/admin_token" }  # systemd credential / SOPS tmpfs
//! push_key    = { env = "SONGBIRD_SECRET_PUSH_KEY" }
//! ```
//!
//! A literal string is rejected at parse time, so a secret cannot be committed by accident in a
//! config file. Resolved values are zeroed on drop and redacted in `Debug`.

use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::ConfigError;

/// Largest secret accepted, in bytes. Checked before reading (invariant 7).
pub const MAX_SECRET_BYTES: u64 = 64 * 1024;

/// Where a secret comes from.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum SecretRef {
    /// A file, typically a systemd credential or a SOPS-decrypted file on tmpfs. Must not be
    /// world-readable.
    File(PathBuf),
    /// An environment variable, by name.
    Env(String),
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(p) => f.debug_tuple("File").field(p).finish(),
            Self::Env(n) => f.debug_tuple("Env").field(n).finish(),
        }
    }
}

impl SecretRef {
    /// Reads a 32-byte key written as 64 hex characters (cluster, jobs and index secrets).
    ///
    /// # Errors
    /// As [`SecretRef::resolve`], and [`ConfigError::Secret`] if it is not 64 hex characters.
    pub fn resolve_key32(&self) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
        let s = self.resolve()?;
        let mut out = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(s.expose().trim(), out.as_mut_slice()).map_err(|_| {
            ConfigError::Secret {
                name: match self {
                    Self::File(p) => p.display().to_string(),
                    Self::Env(n) => n.clone(),
                },
                problem: "must be 64 hex characters".into(),
            }
        })?;
        Ok(out)
    }

    /// Reads the secret. A single trailing newline is stripped.
    ///
    /// # Errors
    /// [`ConfigError::Secret`] if it is missing, too large, not UTF-8 or world-readable;
    /// [`ConfigError::TooLarge`] if the file exceeds [`MAX_SECRET_BYTES`].
    pub fn resolve(&self) -> Result<Secret, ConfigError> {
        let mut raw = match self {
            Self::Env(name) => {
                let v = std::env::var(name).map_err(|e| ConfigError::Secret {
                    name: name.clone(),
                    problem: e.to_string(),
                })?;
                if u64::try_from(v.len()).unwrap_or(u64::MAX) > MAX_SECRET_BYTES {
                    return Err(ConfigError::TooLarge {
                        what: format!("secret {name}"),
                        got: u64::try_from(v.len()).unwrap_or(u64::MAX),
                        limit: MAX_SECRET_BYTES,
                    });
                }
                Zeroizing::new(v)
            }
            Self::File(path) => {
                let name = path.display().to_string();
                let meta = std::fs::metadata(path).map_err(|e| ConfigError::Secret {
                    name: name.clone(),
                    problem: e.to_string(),
                })?;
                if meta.len() > MAX_SECRET_BYTES {
                    return Err(ConfigError::TooLarge {
                        what: format!("secret {name}"),
                        got: meta.len(),
                        limit: MAX_SECRET_BYTES,
                    });
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o004 != 0 {
                        return Err(ConfigError::Secret {
                            name,
                            problem: "file is world-readable; chmod o-r".into(),
                        });
                    }
                }
                let bytes =
                    Zeroizing::new(std::fs::read(path).map_err(|e| ConfigError::Secret {
                        name: name.clone(),
                        problem: e.to_string(),
                    })?);
                let s = std::str::from_utf8(&bytes).map_err(|_| ConfigError::Secret {
                    name,
                    problem: "not UTF-8".into(),
                })?;
                Zeroizing::new(s.to_owned())
            }
        };
        if raw.ends_with('\n') {
            raw.pop();
        }
        Ok(Secret(raw))
    }
}

/// A resolved secret. Zeroed on drop; `Debug` never shows the value.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a value produced at runtime (for example a generated key).
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The secret value. Never log or format it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct C {
        token: SecretRef,
    }

    #[test]
    fn literal_secrets_are_rejected() {
        assert!(toml::from_str::<C>(r#"token = "hunter2""#).is_err());
        let ok: C = toml::from_str(r#"token = { env = "X" }"#).unwrap();
        assert_eq!(ok.token, SecretRef::Env("X".into()));
    }

    #[test]
    #[cfg_attr(miri, ignore = "chmod/set_len are not supported by Miri")]
    fn file_secret_resolves_and_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");
        std::fs::write(&p, "value\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let s = SecretRef::File(p).resolve().unwrap();
        assert_eq!(s.expose(), "value");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "chmod/set_len are not supported by Miri")]
    fn world_readable_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");
        std::fs::write(&p, "value").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SecretRef::File(p).resolve().is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "chmod/set_len are not supported by Miri")]
    fn oversized_file_is_rejected_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(MAX_SECRET_BYTES + 1).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            SecretRef::File(p).resolve(),
            Err(ConfigError::TooLarge { .. })
        ));
    }
}
