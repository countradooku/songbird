//! Destructive commands: an explicit confirmation naming the target, and an append-only audit
//! log (master prompt §7: "Admin tooling requires explicit confirmation for destructive actions
//! and writes an audit log").
//!
//! The log is JSON lines, one when an action starts and one when it ends, so an action that
//! crashed half-way still shows. Writing it fails closed: no log line, no action. It records who
//! (the login and, under sudo, the invoking user), what, where (namespace/database) and the
//! outcome; never a password or a key.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::Args;

/// Settings every destructive command takes.
#[derive(Debug, Clone, Args)]
pub(crate) struct Guard {
    /// Repeat the target as `<namespace>/<database>` to confirm (a wrong target is refused).
    #[arg(long)]
    pub(crate) confirm: Option<String>,
    /// Append-only audit log (JSON lines).
    #[arg(long, default_value = "/var/log/songbird/admin-audit.jsonl")]
    pub(crate) audit_log: PathBuf,
}

impl Guard {
    /// Checks the confirmation against the target, then logs the start. Returns the handle that
    /// logs the end.
    pub(crate) fn begin(&self, action: &str, target: &str, detail: &str) -> Result<Entry> {
        match &self.confirm {
            Some(c) if c == target => {}
            Some(c) => bail!("--confirm {c} does not match the target {target}"),
            None => bail!("{action} changes {target}: repeat it as --confirm {target}"),
        }
        let entry = Entry {
            log: self.audit_log.clone(),
            action: action.to_owned(),
            target: target.to_owned(),
        };
        entry.write("started", detail)?;
        Ok(entry)
    }
}

/// An action in progress.
pub(crate) struct Entry {
    log: PathBuf,
    action: String,
    target: String,
}

impl Entry {
    /// Logs the outcome (an error's message, which carries no secrets: they never reach errors).
    pub(crate) fn end<T>(&self, r: &Result<T>, detail: &str) -> Result<()> {
        match r {
            Ok(_) => self.write("succeeded", detail),
            Err(e) => self.write("failed", &format!("{e:#}")),
        }
    }

    fn write(&self, outcome: &str, detail: &str) -> Result<()> {
        let line = serde_json::json!({
            "at": songbird_s3::sigv4::iso8601(now_secs()),
            "user": std::env::var("USER").unwrap_or_default(),
            "sudo_user": std::env::var("SUDO_USER").unwrap_or_default(),
            "host": hostname(),
            "action": self.action,
            "target": self.target,
            "outcome": outcome,
            "detail": detail,
        });
        append(&self.log, &format!("{line}\n"))
            .with_context(|| format!("writing the audit log {}", self.log.display()))
    }
}

fn append(path: &Path, line: &str) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_owned())
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_wrong_confirmation_is_refused_and_logs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let g = |confirm: Option<&str>| Guard {
            confirm: confirm.map(str::to_owned),
            audit_log: log.clone(),
        };
        assert!(g(None).begin("restore", "songbird/songbird", "").is_err());
        assert!(
            g(Some("songbird/other"))
                .begin("restore", "songbird/songbird", "")
                .is_err()
        );
        assert!(!log.exists());
        let e = g(Some("songbird/songbird"))
            .begin("restore", "songbird/songbird", "obj")
            .unwrap();
        e.end(&Ok::<(), anyhow::Error>(()), "generation 7").unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["outcome"], "started");
        assert_eq!(lines[1]["outcome"], "succeeded");
        assert_eq!(lines[1]["detail"], "generation 7");
    }

    #[test]
    fn an_unwritable_log_stops_the_action() {
        let g = Guard {
            confirm: Some("a/b".into()),
            audit_log: PathBuf::from("/proc/no/such/dir/audit.jsonl"),
        };
        assert!(g.begin("bump", "a/b", "").is_err());
    }
}
