//! The delivery checker (master prompt §8): for every device, nothing lost, nothing delivered
//! twice to the app, strictly increasing gap-free `seq`, and per-sender FIFO.
//!
//! Every load, chaos and failover run must pass it. A fast run with one lost message fails.

use std::collections::HashMap;

/// A message identity inside the payload: (sender index, sender's counter).
pub(crate) type MsgId = (u32, u64);

/// What one device's app received, in order.
#[derive(Debug, Default, Clone)]
pub(crate) struct Received {
    /// `(seq, message)` in arrival order; `None` for a message from an earlier run (left in
    /// the mailbox by it), which counts for `seq` order only.
    pub(crate) items: Vec<(u64, Option<MsgId>)>,
}

/// Checker verdict.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    /// Messages accepted by the server for a device and never delivered to it.
    pub(crate) lost: u64,
    /// Messages delivered more than once to the same device's app.
    pub(crate) duplicates: u64,
    /// Deliveries whose `seq` was not exactly the previous one plus one.
    pub(crate) seq_violations: u64,
    /// Deliveries out of send order for the same sender.
    pub(crate) fifo_violations: u64,
    /// Deliveries of messages never accepted for that device.
    pub(crate) unexpected: u64,
    /// Messages accepted.
    pub(crate) expected: u64,
    /// Distinct messages delivered.
    pub(crate) delivered: u64,
    /// Messages from earlier runs (not part of this check).
    pub(crate) stale: u64,
}

impl Report {
    /// Whether every property holds.
    #[must_use]
    pub(crate) const fn passed(&self) -> bool {
        self.lost == 0
            && self.duplicates == 0
            && self.seq_violations == 0
            && self.fifo_violations == 0
            && self.unexpected == 0
    }
}

/// Checks `received[d]` against `expected[d]` (messages accepted for device `d`, any order).
#[must_use]
pub(crate) fn check(expected: &[Vec<MsgId>], received: &[Received]) -> Report {
    let mut r = Report::default();
    for (d, exp) in expected.iter().enumerate() {
        r.expected += u64::try_from(exp.len()).unwrap_or(u64::MAX);
        let mut want: HashMap<MsgId, bool> = exp.iter().map(|m| (*m, false)).collect();
        let empty = Received::default();
        let got = received.get(d).unwrap_or(&empty);
        let mut prev_seq: Option<u64> = None;
        let mut last_per_sender: HashMap<u32, u64> = HashMap::new();
        for (seq, id) in &got.items {
            if let Some(p) = prev_seq
                && Some(*seq) != p.checked_add(1)
            {
                r.seq_violations += 1;
            }
            prev_seq = Some(*seq);
            let Some(id) = id else {
                r.stale += 1;
                continue;
            };
            match want.get_mut(id) {
                None => r.unexpected += 1,
                Some(seen) if *seen => r.duplicates += 1,
                Some(seen) => {
                    *seen = true;
                    r.delivered += 1;
                }
            }
            let last = last_per_sender.entry(id.0).or_insert(0);
            if id.1 < *last {
                r.fifo_violations += 1;
            }
            *last = (*last).max(id.1);
        }
        r.lost += u64::try_from(want.values().filter(|s| !**s).count()).unwrap_or(u64::MAX);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recv(items: &[(u64, MsgId)]) -> Received {
        Received {
            items: items.iter().map(|(s, m)| (*s, Some(*m))).collect(),
        }
    }

    #[test]
    fn stale_messages_count_for_order_only() {
        let exp = vec![vec![(1, 0)]];
        let got = vec![Received {
            items: vec![(4, None), (5, Some((1, 0)))],
        }];
        let r = check(&exp, &got);
        assert!(r.passed(), "{r:?}");
        assert_eq!(r.stale, 1);
    }

    #[test]
    fn clean_run_passes() {
        let exp = vec![vec![(1, 0), (2, 0), (1, 1)]];
        let got = vec![recv(&[(1, (1, 0)), (2, (2, 0)), (3, (1, 1))])];
        let r = check(&exp, &got);
        assert!(r.passed(), "{r:?}");
        assert_eq!((r.expected, r.delivered), (3, 3));
    }

    #[test]
    fn detects_every_failure_kind() {
        let exp = vec![vec![(1, 0), (1, 1), (1, 2)]];
        // Loss of (1,2), duplicate of (1,0), seq gap 1→3, FIFO break, unexpected (9,9).
        let got = vec![recv(&[(1, (1, 1)), (3, (1, 0)), (4, (1, 0)), (5, (9, 9))])];
        let r = check(&exp, &got);
        assert_eq!(r.lost, 1);
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.seq_violations, 1);
        assert_eq!(r.fifo_violations, 2);
        assert_eq!(r.unexpected, 1);
        assert!(!r.passed());
    }
}
