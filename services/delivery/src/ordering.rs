//! The per-device ordering rule of a session (invariant 2), as a pure state machine.
//!
//! A session sends envelopes from two sources: mailbox drains (`fetch_after`, ascending) and
//! live notifications from the router (any order, possibly duplicated, possibly dropped). The
//! cursor is the highest `seq` written to the socket on this connection:
//!
//! - a live `seq` equal to `cursor + 1` is sent inline;
//! - a live `seq` at or below the cursor is a duplicate and dropped;
//! - a live `seq` above `cursor + 1` reveals a gap: drain the mailbox from the cursor instead
//!   (the live envelope is in the mailbox too, so it is fetched in order);
//! - drained entries are sent if above the cursor.
//!
//! The session always attaches to the router before its first drain, so every envelope stored
//! after attach is either fetched by a drain or announced live (the property test below runs
//! random interleavings against a model mailbox).

/// What to do with a live notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveAction {
    /// Send it now; the cursor advanced.
    Send,
    /// Already sent on this connection; drop.
    Duplicate,
    /// Something before it is missing: drain the mailbox.
    Gap,
}

/// Highest `seq` written to the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    last_sent: u64,
}

impl Cursor {
    /// Starts after what the device already acknowledged.
    #[must_use]
    pub const fn new(resume_after: u64) -> Self {
        Self {
            last_sent: resume_after,
        }
    }

    /// The highest `seq` sent.
    #[must_use]
    pub const fn last_sent(&self) -> u64 {
        self.last_sent
    }

    /// Classifies a live notification; advances on [`LiveAction::Send`].
    pub fn on_live(&mut self, seq: u64) -> LiveAction {
        if seq <= self.last_sent {
            LiveAction::Duplicate
        } else if Some(seq) == self.last_sent.checked_add(1) {
            self.last_sent = seq;
            LiveAction::Send
        } else {
            LiveAction::Gap
        }
    }

    /// Whether a drained entry should be sent; advances if so. Drains return ascending `seq`s,
    /// possibly with holes where envelopes expired, so any `seq` above the cursor is next.
    pub fn on_drained(&mut self, seq: u64) -> bool {
        if seq > self.last_sent {
            self.last_sent = seq;
            true
        } else {
            false
        }
    }

    /// Whether a device may acknowledge `up_to`: never beyond what this connection sent.
    #[must_use]
    pub const fn ack_allowed(&self, up_to: u64) -> bool {
        up_to <= self.last_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rules() {
        let mut c = Cursor::new(5);
        assert_eq!(c.on_live(5), LiveAction::Duplicate);
        assert_eq!(c.on_live(7), LiveAction::Gap);
        assert_eq!(c.last_sent(), 5);
        assert_eq!(c.on_live(6), LiveAction::Send);
        assert!(c.on_drained(9));
        assert!(!c.on_drained(8));
        assert!(c.ack_allowed(9) && !c.ack_allowed(10));
        let mut top = Cursor::new(u64::MAX);
        assert_eq!(top.on_live(u64::MAX), LiveAction::Duplicate);
    }

    /// Events in a model run: a store (which the router may announce, drop, or announce late
    /// and twice), or a delivery step of the session.
    #[derive(Debug, Clone)]
    enum Ev {
        Store { announce: bool, twice: bool },
        Step,
        SafetySweep,
    }

    fn ev() -> impl Strategy<Value = Ev> {
        prop_oneof![
            3 => (any::<bool>(), any::<bool>()).prop_map(|(a, t)| Ev::Store { announce: a, twice: t }),
            3 => Just(Ev::Step),
            1 => Just(Ev::SafetySweep),
        ]
    }

    /// Runs the session algorithm against a model mailbox and returns what reached the socket.
    fn simulate(events: &[Ev], page: usize, inbox_cap: usize) -> (Vec<u64>, u64) {
        let mut stored: u64 = 0; // seqs 1..=stored are in the mailbox
        let mut inbox: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
        let mut lagged = false;
        let mut cursor = Cursor::new(0);
        let mut sent = Vec::new();
        let drain = |cursor: &mut Cursor, sent: &mut Vec<u64>, stored: u64| loop {
            let from = cursor.last_sent();
            let batch: Vec<u64> = (from + 1..=stored).take(page).collect();
            for s in &batch {
                if cursor.on_drained(*s) {
                    sent.push(*s);
                }
            }
            if batch.len() < page {
                break;
            }
        };
        // Attach, then the initial drain.
        drain(&mut cursor, &mut sent, stored);
        let mut late: Vec<u64> = Vec::new();
        for e in events {
            match e {
                Ev::Store { announce, twice } => {
                    stored += 1;
                    let mut push = |s: u64, inbox: &mut std::collections::VecDeque<u64>| {
                        if inbox.len() < inbox_cap {
                            inbox.push_back(s);
                        } else {
                            lagged = true;
                        }
                    };
                    if *announce {
                        push(stored, &mut inbox);
                    }
                    if *twice {
                        late.push(stored);
                    }
                    if stored.is_multiple_of(3) {
                        for s in late.drain(..) {
                            push(s, &mut inbox);
                        }
                    }
                }
                Ev::Step => {
                    if let Some(s) = inbox.pop_front() {
                        match cursor.on_live(s) {
                            LiveAction::Send => sent.push(s),
                            LiveAction::Duplicate => {}
                            LiveAction::Gap => drain(&mut cursor, &mut sent, stored),
                        }
                    }
                    if inbox.is_empty() && std::mem::take(&mut lagged) {
                        drain(&mut cursor, &mut sent, stored);
                    }
                }
                Ev::SafetySweep => drain(&mut cursor, &mut sent, stored),
            }
        }
        // End of run: the safety sweep eventually fires.
        while let Some(s) = inbox.pop_front() {
            if cursor.on_live(s) == LiveAction::Send {
                sent.push(s);
            }
        }
        drain(&mut cursor, &mut sent, stored);
        (sent, stored)
    }

    proptest! {
        /// Whatever the router does (drops, duplicates, reorders, overflows), the socket sees
        /// every stored seq exactly once, strictly increasing.
        #[test]
        fn every_seq_once_in_order(
            events in proptest::collection::vec(ev(), 0..300),
            page in 1usize..8,
            cap in 1usize..6,
        ) {
            let (sent, stored) = simulate(&events, page, cap);
            let want: Vec<u64> = (1..=stored).collect();
            prop_assert_eq!(sent, want);
        }
    }
}
