//! The server never opens a backup (D-0119): no service depends on the backup format, which
//! holds every key derived from the recovery key. Checked from the manifests, so a new
//! dependency fails here before review.
#![allow(clippy::unwrap_used, reason = "tests")]

#[test]
fn no_service_depends_on_the_backup_format() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../services");
    let mut checked = 0;
    for e in std::fs::read_dir(root).unwrap() {
        let path = e.unwrap().path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        assert!(
            !text.contains("songbird-backup-format") && !text.contains("songbird-backup-storage"),
            "{} depends on a backup crate",
            path.display()
        );
        checked += 1;
    }
    assert!(checked >= 5, "found the manifests ({checked})");
}
