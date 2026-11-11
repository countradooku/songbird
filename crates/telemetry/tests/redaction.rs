//! End-to-end: sensitive callsites never reach the writer (invariant 6).
//! nextest runs each test in its own process, so callsite interest caching cannot leak between them.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::as_conversions,
    reason = "integration test: failures should panic"
)]

use std::io::Write;
use std::sync::{Arc, Mutex};

use songbird_telemetry::{RedactionLayer, RedactionMode};
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn subscriber(buf: &Buf, mode: RedactionMode) -> impl tracing::Subscriber + Send + Sync {
    let b = buf.clone();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(move || b.clone()),
        )
        .with(RedactionLayer::new(mode))
}

#[test]
fn sensitive_events_and_spans_are_dropped() {
    let buf = Buf::default();
    tracing::subscriber::with_default(subscriber(&buf, RedactionMode::Refuse), || {
        tracing::info!(frames = 3, "allowed");
        tracing::info!(device_id = "0011aabb", "refused event");
        tracing::info!(client_ip = "203.0.113.9", "refused event");
        let span = tracing::info_span!("conn", remote_addr = "203.0.113.9:4000");
        span.in_scope(|| tracing::info!(seq = 1, "inside refused span"));
    });
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(out.contains("allowed"), "{out}");
    assert!(out.contains("inside refused span"), "{out}");
    assert!(!out.contains("0011aabb"), "{out}");
    assert!(!out.contains("203.0.113.9"), "{out}");
    assert!(!out.contains("refused event"), "{out}");
    assert!(songbird_telemetry::redaction::refused_callsites() >= 3);
}

#[test]
#[should_panic(expected = "invariant 6")]
fn panic_mode_fails_loudly() {
    let buf = Buf::default();
    tracing::subscriber::with_default(subscriber(&buf, RedactionMode::Panic), || {
        tracing::warn!(password = "x", "nope");
    });
}
