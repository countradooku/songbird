//! Reconnect backoff: exponential with full jitter, never shorter than the server's retry hint.

use std::time::Duration;

/// Backoff settings.
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    /// Ceiling of the first wait.
    pub initial: Duration,
    /// Largest ceiling.
    pub max: Duration,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(250),
            max: Duration::from_secs(30),
        }
    }
}

/// Backoff state across reconnect attempts.
#[derive(Debug, Clone)]
pub struct Backoff {
    cfg: BackoffConfig,
    attempt: u32,
}

impl Backoff {
    /// Fresh state.
    #[must_use]
    pub const fn new(cfg: BackoffConfig) -> Self {
        Self { cfg, attempt: 0 }
    }

    /// Call after a successful connection.
    pub const fn reset(&mut self) {
        self.attempt = 0;
    }

    /// The next wait: uniform in `[0, min(max, initial · 2^attempt)]` ("full jitter", so a fleet
    /// of clients disconnected together spreads out), then at least `hint` plus up to 10 % of it.
    pub fn next(&mut self, hint: Option<Duration>) -> Duration {
        let ceiling = self
            .cfg
            .initial
            .saturating_mul(1u32.checked_shl(self.attempt.min(20)).unwrap_or(u32::MAX))
            .min(self.cfg.max);
        self.attempt = self.attempt.saturating_add(1);
        let jittered = scale(ceiling, unit());
        match hint {
            Some(h) => jittered.max(h.saturating_add(scale(h, unit() / 10.0))),
            None => jittered,
        }
    }

    /// Wait for a "reconnect now" close: a small jitter so a drained node's clients do not all
    /// arrive in the same millisecond.
    #[must_use]
    pub fn now_jitter() -> Duration {
        scale(Duration::from_millis(500), unit())
    }
}

fn scale(d: Duration, f: f64) -> Duration {
    Duration::try_from_secs_f64(d.as_secs_f64() * f).unwrap_or(d)
}

/// Uniform in `[0, 1)` from the OS random source (jitter only; not security sensitive, but the
/// OS source avoids a dependency and is fast enough at reconnect rates).
fn unit() -> f64 {
    let r = getrandom::u32().unwrap_or(0);
    f64::from(r) / (f64::from(u32::MAX) + 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_and_caps() {
        let cfg = BackoffConfig {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(1),
        };
        let mut b = Backoff::new(cfg);
        for _ in 0..50 {
            assert!(b.next(None) <= Duration::from_secs(1));
        }
        b.reset();
        assert!(b.next(None) <= Duration::from_millis(100));
    }

    #[test]
    fn honours_retry_hint() {
        let mut b = Backoff::new(BackoffConfig::default());
        for _ in 0..20 {
            let w = b.next(Some(Duration::from_secs(5)));
            assert!(w >= Duration::from_secs(5) && w <= Duration::from_secs(31));
        }
    }
}
