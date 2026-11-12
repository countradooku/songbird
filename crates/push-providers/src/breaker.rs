//! A circuit breaker per provider.
//!
//! Closed: requests flow; `failures` consecutive transient failures within `window` open it.
//! Open: requests are refused at once with the time left until `cooldown` ends. After the
//! cooldown one request is let through as a probe (half-open): success closes the breaker, failure
//! opens it again. A probe that never reports (its future was dropped) frees the half-open slot
//! after another cooldown.
//!
//! Only transient outcomes (rate limiting, 5xx, network, timeouts) count as failures: they say
//! the provider is in trouble. A rejected token is a healthy answer. Time is Tokio's, so tests
//! run on paused time.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

/// Breaker tuning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreakerConfig {
    /// Consecutive transient failures that open the breaker.
    pub failures: u32,
    /// The failures must fall within this window (a slow trickle of errors does not open it).
    pub window: Duration,
    /// How long the breaker stays open before a probe.
    pub cooldown: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failures: 10,
            window: Duration::from_secs(30),
            cooldown: Duration::from_secs(10),
        }
    }
}

/// The breaker's state, for metrics and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    /// Requests flow.
    Closed,
    /// Requests are refused.
    Open,
    /// One probe is (or may be) in flight.
    HalfOpen,
}

#[derive(Debug)]
enum State {
    Closed { failures: u32, since: Instant },
    Open { until: Instant },
    HalfOpen { since: Instant },
}

/// Whether a request may go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Go ahead.
    Go,
    /// Go ahead as the half-open probe.
    Probe,
    /// Refused; try again after this long.
    Reject(Duration),
}

/// A circuit breaker.
#[derive(Debug)]
pub struct CircuitBreaker {
    cfg: BreakerConfig,
    state: Mutex<State>,
}

impl CircuitBreaker {
    /// A closed breaker.
    #[must_use]
    pub fn new(cfg: BreakerConfig) -> Self {
        Self {
            cfg: BreakerConfig {
                failures: cfg.failures.max(1),
                ..cfg
            },
            state: Mutex::new(State::Closed {
                failures: 0,
                since: Instant::now(),
            }),
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> BreakerState {
        match *self.lock() {
            State::Closed { .. } => BreakerState::Closed,
            State::Open { until } if Instant::now() < until => BreakerState::Open,
            State::Open { .. } | State::HalfOpen { .. } => BreakerState::HalfOpen,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn admit(&self) -> Admit {
        let now = Instant::now();
        let mut s = self.lock();
        match *s {
            State::Closed { .. } => Admit::Go,
            State::Open { until } if now < until => Admit::Reject(until - now),
            State::HalfOpen { since } if now < since + self.cfg.cooldown => {
                Admit::Reject(since + self.cfg.cooldown - now)
            }
            State::Open { .. } | State::HalfOpen { .. } => {
                *s = State::HalfOpen { since: now };
                Admit::Probe
            }
        }
    }

    /// Records the result of an admitted request (`failed`: a transient failure).
    pub(crate) fn record(&self, admit: Admit, failed: bool) {
        let now = Instant::now();
        let mut s = self.lock();
        match (&mut *s, admit) {
            (State::HalfOpen { .. }, Admit::Probe) => {
                *s = if failed {
                    State::Open {
                        until: now + self.cfg.cooldown,
                    }
                } else {
                    State::Closed {
                        failures: 0,
                        since: now,
                    }
                };
            }
            (State::Closed { failures, since }, _) => {
                if !failed {
                    *failures = 0;
                    return;
                }
                if *failures == 0 || now.duration_since(*since) > self.cfg.window {
                    *failures = 1;
                    *since = now;
                } else {
                    *failures += 1;
                }
                if *failures >= self.cfg.failures {
                    *s = State::Open {
                        until: now + self.cfg.cooldown,
                    };
                }
            }
            // A late answer from before the breaker opened, or from a request admitted before
            // another became the probe: the probe decides.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BreakerConfig {
        BreakerConfig {
            failures: 3,
            window: Duration::from_secs(10),
            cooldown: Duration::from_secs(5),
        }
    }

    fn fail(b: &CircuitBreaker) {
        let a = b.admit();
        b.record(a, true);
    }

    #[tokio::test(start_paused = true)]
    async fn opens_after_consecutive_failures_then_probes() {
        let b = CircuitBreaker::new(cfg());
        fail(&b);
        fail(&b);
        assert_eq!(b.state(), BreakerState::Closed);
        fail(&b);
        assert_eq!(b.state(), BreakerState::Open);
        assert_eq!(b.admit(), Admit::Reject(Duration::from_secs(5)));

        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(b.admit(), Admit::Reject(Duration::from_secs(3)));

        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(b.admit(), Admit::Probe);
        // Only one probe at a time.
        assert!(matches!(b.admit(), Admit::Reject(_)));
        b.record(Admit::Probe, false);
        assert_eq!(b.state(), BreakerState::Closed);
        assert_eq!(b.admit(), Admit::Go);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_probe_reopens() {
        let b = CircuitBreaker::new(cfg());
        for _ in 0..3 {
            fail(&b);
        }
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(b.admit(), Admit::Probe);
        b.record(Admit::Probe, true);
        assert_eq!(b.state(), BreakerState::Open);
        assert_eq!(b.admit(), Admit::Reject(Duration::from_secs(5)));
    }

    #[tokio::test(start_paused = true)]
    async fn success_resets_the_count_and_the_window_expires_old_failures() {
        let b = CircuitBreaker::new(cfg());
        fail(&b);
        fail(&b);
        let a = b.admit();
        b.record(a, false);
        fail(&b);
        fail(&b);
        assert_eq!(b.state(), BreakerState::Closed);
        tokio::time::advance(Duration::from_secs(11)).await;
        fail(&b);
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_probe_frees_the_slot_after_a_cooldown() {
        let b = CircuitBreaker::new(cfg());
        for _ in 0..3 {
            fail(&b);
        }
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(b.admit(), Admit::Probe);
        // The probe never reports.
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(b.admit(), Admit::Probe);
    }

    #[tokio::test(start_paused = true)]
    async fn late_answers_do_not_close_an_open_breaker() {
        let b = CircuitBreaker::new(cfg());
        let early = b.admit();
        for _ in 0..3 {
            fail(&b);
        }
        b.record(early, false);
        assert_eq!(b.state(), BreakerState::Open);
    }
}
