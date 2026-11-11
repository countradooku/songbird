//! Token bucket for rate limits (per connection, per listener). Owned by one task: no atomics.

use std::time::{Duration, Instant};

/// A token bucket refilled continuously at `rate` per second up to `burst`.
#[derive(Debug, Clone)]
pub struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl Bucket {
    /// A full bucket.
    #[must_use]
    pub fn new(rate: u32, burst: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            rate: f64::from(rate),
            burst: f64::from(burst),
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
    }

    /// Takes one token, or returns how long until one is available.
    pub fn take(&mut self, now: Instant) -> Result<(), Duration> {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let wait = if self.rate > 0.0 {
                (1.0 - self.tokens) / self.rate
            } else {
                1.0
            };
            Err(Duration::try_from_secs_f64(wait).unwrap_or(Duration::from_secs(1)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_rate() {
        let t0 = Instant::now();
        let mut b = Bucket::new(10, 3, t0);
        assert!(b.take(t0).is_ok());
        assert!(b.take(t0).is_ok());
        assert!(b.take(t0).is_ok());
        let wait = b.take(t0).unwrap_err();
        assert!(wait <= Duration::from_millis(101) && wait >= Duration::from_millis(99));
        assert!(b.take(t0 + Duration::from_millis(100)).is_ok());
        // Never exceeds the burst after a long pause.
        let later = t0 + Duration::from_secs(60);
        for _ in 0..3 {
            assert!(b.take(later).is_ok());
        }
        assert!(b.take(later).is_err());
    }
}
