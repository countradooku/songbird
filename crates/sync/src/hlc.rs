//! A hybrid logical clock (Kulkarni et al., 2014), stamped into every record.
//!
//! A stamp is `(wall ms, counter, node)`, ordered in that order, so two stamps from different
//! devices never tie. A device's clock never goes backwards, and moves past every stamp it has
//! seen, but never more than [`MAX_SKEW_MS`] ahead of its own physical time: one device with a
//! bad clock cannot drag every other device's clock into the future.
//!
//! A write to a key always gets a stamp above the key's current one ([`Clock::stamp_after`]),
//! however far ahead that stamp is, so a key a bad clock wrote is never pinned: the next write
//! anywhere wins.

/// How far ahead of physical time a clock follows a remote stamp: one day.
pub const MAX_SKEW_MS: u64 = 24 * 3_600_000;

/// A stamp. Ordered by wall time, then counter, then node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Hlc {
    /// Milliseconds since the Unix epoch (hybrid: at least the physical time it was made at).
    pub wall_ms: u64,
    /// Breaks ties within one millisecond.
    pub counter: u32,
    /// The writing device's node ID (random, 16 bytes; breaks ties between devices).
    pub node: [u8; 16],
}

impl Hlc {
    /// The smallest stamp above `self` from `node`.
    #[must_use]
    pub fn successor(self, node: [u8; 16]) -> Self {
        match self.counter.checked_add(1) {
            Some(counter) => Self {
                wall_ms: self.wall_ms,
                counter,
                node,
            },
            None => Self {
                wall_ms: self.wall_ms.saturating_add(1),
                counter: 0,
                node,
            },
        }
    }
}

/// One device's clock.
#[derive(Debug, Clone)]
pub struct Clock {
    node: [u8; 16],
    last: Hlc,
}

impl Clock {
    /// A clock for `node`.
    #[must_use]
    pub fn new(node: [u8; 16]) -> Self {
        Self {
            node,
            last: Hlc {
                wall_ms: 0,
                counter: 0,
                node,
            },
        }
    }

    /// The node ID.
    #[must_use]
    pub fn node(&self) -> [u8; 16] {
        self.node
    }

    /// The last stamp issued or observed.
    #[must_use]
    pub fn last(&self) -> Hlc {
        self.last
    }

    /// A new stamp at physical time `phys_ms`.
    pub fn now(&mut self, phys_ms: u64) -> Hlc {
        let next = if phys_ms > self.last.wall_ms {
            Hlc {
                wall_ms: phys_ms,
                counter: 0,
                node: self.node,
            }
        } else {
            self.last.successor(self.node)
        };
        self.last = next;
        next
    }

    /// A new stamp above both the clock and `current` (the key's current stamp), so the write
    /// it marks wins over `current`.
    pub fn stamp_after(&mut self, current: Option<Hlc>, phys_ms: u64) -> Hlc {
        let t = self.now(phys_ms);
        match current {
            Some(c) if c >= t => {
                let s = c.successor(self.node);
                // Followed only within the skew bound; the stamp itself still wins.
                self.observe(s, phys_ms);
                s
            }
            _ => t,
        }
    }

    /// Moves the clock past a remote stamp, but never beyond `phys_ms + MAX_SKEW_MS`.
    pub fn observe(&mut self, remote: Hlc, phys_ms: u64) {
        let bound = phys_ms.saturating_add(MAX_SKEW_MS);
        if remote > self.last && remote.wall_ms <= bound {
            self.last = Hlc {
                node: self.node,
                ..remote
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn stamps_only_grow_and_ties_break_by_node() {
        let mut c = Clock::new([1; 16]);
        let a = c.now(100);
        let b = c.now(100);
        let d = c.now(50);
        assert!(a < b && b < d);
        let other = Hlc { node: [2; 16], ..a };
        assert!(a < other);
    }

    #[test]
    fn a_far_future_stamp_does_not_drag_the_clock_but_never_pins_a_key() {
        let mut c = Clock::new([1; 16]);
        let future = Hlc {
            wall_ms: 10 * MAX_SKEW_MS,
            counter: 0,
            node: [9; 16],
        };
        c.observe(future, 1_000);
        assert!(c.last().wall_ms < future.wall_ms);
        let s = c.stamp_after(Some(future), 1_000);
        assert!(s > future);
        // The clock itself stays near physical time.
        assert!(c.now(2_000).wall_ms <= 2_000 + MAX_SKEW_MS);
    }

    proptest! {
        #[test]
        fn stamp_after_always_wins(
            phys in 0u64..1_000_000,
            wall in 0u64..2_000_000,
            counter in any::<u32>(),
        ) {
            let mut c = Clock::new([3; 16]);
            let cur = Hlc { wall_ms: wall, counter, node: [7; 16] };
            let s = c.stamp_after(Some(cur), phys);
            prop_assert!(s > cur);
            // The clock never goes backwards.
            let before = c.last();
            prop_assert!(c.now(phys) > before);
        }
    }
}
