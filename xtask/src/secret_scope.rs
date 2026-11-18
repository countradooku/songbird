//! Push credentials stay in the push service (Prompt 8, D-0097).
//!
//! The provider credentials (the APNs `.p8`, the FCM service account, the VAPID key) and the
//! push service's X25519 key are named in SOPS and reach a host only through
//! `roles/songbird/tasks/push.yml`, into a directory mounted into the push container alone. This
//! check fails if any other file under `deploy/` or `config/` names one of them, or mounts that
//! directory outside the push container's own line.

use std::path::{Path, PathBuf};

use crate::Result;

/// The SOPS names of what only the push service may hold.
const CREDENTIALS: &[&str] = &[
    "push_apns_key_p8",
    "push_fcm_service_account_json",
    "push_vapid_key_pem",
    "push_x25519_key",
    "push_db_password_push",
];
/// Files allowed to name them: the one task that writes them, and the generator of the SOPS file.
const CREDENTIAL_FILES: &[&str] = &[
    "deploy/ansible/roles/songbird/tasks/push.yml",
    "deploy/bin/secrets-init",
];
/// The host directory holding them.
const SECRETS_DIR: &str = "/etc/songbird/secrets/push";
/// Files allowed to name that directory: the task that fills it, the post-rollout check, and the
/// container task (on the push container's own line only, checked below).
const DIR_FILES: &[&str] = &[
    "deploy/ansible/roles/songbird/tasks/push.yml",
    "deploy/ansible/roles/songbird/tasks/verify-push-credentials.yml",
    "deploy/ansible/roles/songbird/tasks/main.yml",
];

pub(crate) fn check(root: &Path) -> Result {
    let mut files = Vec::new();
    for dir in ["deploy", "config"] {
        walk(&root.join(dir), &mut files)?;
    }
    let mut problems = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(text) = std::fs::read_to_string(f) else {
            continue; // binary files cannot name a key
        };
        problems.extend(check_file(&rel, &text));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "push credentials outside the push service (D-0097):\n  {}",
            problems.join("\n  ")
        ))
    }
}

pub(crate) fn check_file(rel: &str, text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for c in CREDENTIALS {
            // The data host defines the push service's database user, so it must know its
            // password; it never holds a provider key.
            let defines_user =
                *c == "push_db_password_push" && rel == "deploy/ansible/roles/data/tasks/main.yml";
            if line.contains(c) && !CREDENTIAL_FILES.contains(&rel) && !defines_user {
                problems.push(format!("{rel}:{}: names `{c}`", n + 1));
            }
        }
        if line.contains(SECRETS_DIR) {
            if !DIR_FILES.contains(&rel) {
                problems.push(format!("{rel}:{}: names {SECRETS_DIR}", n + 1));
            } else if rel.ends_with("tasks/main.yml") && !line.contains("if item == 'push'") {
                problems.push(format!(
                    "{rel}:{}: mounts {SECRETS_DIR} outside the push container",
                    n + 1
                ));
            }
        }
    }
    problems
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for e in rd {
        let e = e.map_err(|e| format!("{}: {e}", dir.display()))?;
        let p = e.path();
        let name = e.file_name();
        if name == ".terraform" || name == "target" {
            continue;
        }
        if p.is_dir() {
            walk(&p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_repository_keeps_push_credentials_in_push() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        check(&root).unwrap();
    }

    #[test]
    fn a_credential_named_elsewhere_fails() {
        let p = check_file(
            "deploy/ansible/roles/songbird/templates/service.toml.j2",
            "key = \"{{ secrets.push_apns_key_p8 }}\"",
        );
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(
            check_file(
                "deploy/ansible/roles/songbird/tasks/push.yml",
                "push_apns_key_p8"
            )
            .is_empty()
        );
    }

    #[test]
    fn the_secrets_directory_mounted_into_another_container_fails() {
        let bad = check_file(
            "deploy/ansible/roles/songbird/tasks/main.yml",
            "  - /etc/songbird/secrets/push:/run/songbird/secrets:ro",
        );
        assert_eq!(bad.len(), 1, "{bad:?}");
        let ok = check_file(
            "deploy/ansible/roles/songbird/tasks/main.yml",
            "+ (['/etc/songbird/secrets/push:/run/songbird/secrets:ro'] if item == 'push' else [])",
        );
        assert!(ok.is_empty(), "{ok:?}");
        assert_eq!(
            check_file(
                "deploy/ansible/roles/calls/tasks/main.yml",
                "/etc/songbird/secrets/push"
            )
            .len(),
            1
        );
    }
}
