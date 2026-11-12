//! Push metrics: aggregate counters only, labelled by provider kind and result, never by device
//! (invariant 6).

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use songbird_service::telemetry::{Metrics, TelemetryError};

/// A provider kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Apple.
    Apns,
    /// Firebase Cloud Messaging.
    Fcm,
    /// Web Push (`UnifiedPush`).
    WebPush,
}

impl Kind {
    /// The label value.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
            Self::WebPush => "webpush",
        }
    }
}

type Labels = Vec<(&'static str, &'static str)>;

/// Every push metric.
#[derive(Debug, Clone, Default)]
pub struct PushMetrics {
    /// Per provider and result: `sent`, `unregistered`, `retried`, `failed`, `debounced`,
    /// `unconfigured`.
    pub results: Family<Labels, Counter>,
    /// Jobs for devices without a registration (done; the device fetches at next connection).
    pub no_registration: Counter,
    /// Registrations that did not open (dead-lettered; wrong key or tampering).
    pub unopenable: Counter,
    /// Call jobs for Apple devices without a `PushKit` token.
    pub calls_without_voip: Counter,
    /// Registry failures (job retried).
    pub registry_errors: Counter,
}

impl PushMetrics {
    /// The counter for `kind` and `result`.
    #[must_use]
    pub fn result(&self, kind: Kind, result: &'static str) -> Counter {
        self.results
            .get_or_create(&vec![("provider", kind.label()), ("result", result)])
            .clone()
    }

    /// The count for `kind` and `result` (tests).
    #[must_use]
    pub fn count(&self, kind: Kind, result: &'static str) -> u64 {
        self.result(kind, result).get()
    }

    /// Registers every metric.
    ///
    /// # Errors
    /// [`TelemetryError`] if a name is refused by the redaction rules.
    pub fn register(&self, m: &mut Metrics) -> Result<(), TelemetryError> {
        m.register(
            "push_results",
            "Push jobs by provider and result",
            self.results.clone(),
        )?;
        m.register(
            "push_jobs_without_registration",
            "Push jobs for devices without a registration",
            self.no_registration.clone(),
        )?;
        m.register(
            "push_registrations_unopenable",
            "Push registrations that did not open",
            self.unopenable.clone(),
        )?;
        m.register(
            "push_calls_without_voip",
            "Call push jobs for Apple devices without a VoIP registration",
            self.calls_without_voip.clone(),
        )?;
        m.register(
            "push_registry_errors",
            "Registry failures while handling push jobs",
            self.registry_errors.clone(),
        )?;
        Ok(())
    }
}
