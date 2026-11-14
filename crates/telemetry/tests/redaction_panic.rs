//! Panic mode fails loudly on a sensitive field (invariant 6).
//!
//! Kept apart from `redaction.rs` on purpose: each integration-test file is its own binary, so this
//! panic-mode layer never shares tracing's process-wide callsite registry with a refuse-mode test,
//! whichever runner (`cargo test`, nextest) executes them.

use songbird_telemetry::{RedactionLayer, RedactionMode};
use tracing_subscriber::layer::SubscriberExt;

#[test]
#[should_panic(expected = "invariant 6")]
fn panic_mode_fails_loudly() {
    let subscriber = tracing_subscriber::registry().with(RedactionLayer::new(RedactionMode::Panic));
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!(password = "x", "nope");
    });
}
