//! Last write per author wins, by the author's counter: reactions and RSVPs.
//!
//! One slot per (target, author). A write replaces the slot's value when its `(counter, value)`
//! is greater, so the slot ends at the greatest write whatever order the writes came in (a
//! join-semilattice: `max` is associative, commutative and idempotent).

use std::collections::{BTreeMap, HashMap};

use super::{Account, MsgKey};
use crate::schema::{Reaction, Rsvp};

/// Slots keyed by (target, author), each holding the greatest `(counter, value)` written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lww<V: Ord + Clone> {
    slots: HashMap<(MsgKey, Account), (u64, V)>,
}

impl<V: Ord + Clone> Lww<V> {
    /// Records a write; keeps it if it is greater than the slot's.
    pub fn write(&mut self, target: MsgKey, author: Account, counter: u64, value: V) {
        let new = (counter, value);
        self.slots
            .entry((target, author))
            .and_modify(|cur| {
                if new > *cur {
                    cur.clone_from(&new);
                }
            })
            .or_insert(new);
    }

    /// The current value of every author's slot for `target`, by author.
    #[must_use]
    pub fn of(&self, target: &MsgKey) -> BTreeMap<Account, &V> {
        self.slots
            .iter()
            .filter(|((t, _), _)| t == target)
            .map(|((_, a), (_, v))| (*a, v))
            .collect()
    }
}

/// A reactor's reaction: an emoji, or `None` once removed.
pub type ReactionValue = Option<String>;

/// Reactions on messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reactions(Lww<ReactionValue>);

impl Reactions {
    /// Applies a (validated) reaction from `reactor`.
    pub fn apply(&mut self, reactor: Account, r: &Reaction) {
        let Some(target) = r.target.as_ref().and_then(MsgKey::from_ref) else {
            return;
        };
        let value = (!r.remove).then(|| r.emoji.clone());
        self.0.write(target, reactor, r.counter, value);
    }

    /// Emoji → the accounts that reacted with it, for `target`.
    #[must_use]
    pub fn summary(&self, target: &MsgKey) -> BTreeMap<String, Vec<Account>> {
        let mut out: BTreeMap<String, Vec<Account>> = BTreeMap::new();
        for (who, v) in self.0.of(target) {
            if let Some(e) = v {
                out.entry(e.clone()).or_default().push(who);
            }
        }
        out
    }
}

/// RSVPs to events: the responder's answer (`rsvp::Answer` as `i32`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rsvps(Lww<i32>);

impl Rsvps {
    /// Applies a (validated) RSVP from `responder`.
    pub fn apply(&mut self, responder: Account, r: &Rsvp) {
        if let Some(event) = r.event.as_ref().and_then(MsgKey::from_ref) {
            self.0.write(event, responder, r.counter, r.answer);
        }
    }

    /// Answer → the accounts that gave it, for `event`.
    #[must_use]
    pub fn summary(&self, event: &MsgKey) -> BTreeMap<i32, Vec<Account>> {
        let mut out: BTreeMap<i32, Vec<Account>> = BTreeMap::new();
        for (who, a) in self.0.of(event) {
            out.entry(*a).or_default().push(who);
        }
        out
    }
}
