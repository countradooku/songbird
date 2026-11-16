//! The server never decodes content (constitution, privacy model): no service, and no crate a
//! service links, may depend on `songbird-content`. Checked from the manifests, so a new
//! dependency fails here before review.
#![allow(clippy::unwrap_used, reason = "tests")]

#[test]
fn no_service_or_server_crate_depends_on_content() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut checked = 0;
    for dir in ["services", "crates"] {
        for e in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = e.unwrap().path().join("Cargo.toml");
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if text.contains("name = \"songbird-content\"") {
                continue;
            }
            assert!(
                !text.contains("songbird-content"),
                "{} depends on songbird-content",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(checked >= 20, "found the manifests ({checked})");
}
