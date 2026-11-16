//! Poll tallying (PROTOCOL §5.5).
//!
//! - **Open poll:** each voter's vote with the highest counter counts (a tie on the counter
//!   breaks on the larger option list). A vote naming an option the poll does not have, or
//!   several options in a single-choice poll, counts as no vote. No options retracts.
//! - **Closing** (only by the poll's author) lists each voter's counter as the author saw it. From
//!   then on exactly that vote of each listed voter counts, and nobody else's, so the result no
//!   longer depends on which late votes a device received. Of two closes the greater [`Stamp`]
//!   wins.
//!
//! Votes may arrive before the poll itself; they are kept and judged once it is known. Each
//! voter keeps at most [`VOTES_PER_VOTER`] votes (the highest counters): a function of the set
//! of votes, so still order-independent, and it bounds what one voter can make a device store.

use std::collections::{BTreeMap, BTreeSet};

use super::{Account, MsgKey, Stamp};
use crate::schema::{PollClose, PollCreate, PollVote};

/// Most votes kept per voter (the highest counters).
pub const VOTES_PER_VOTER: usize = 64;

/// One poll's state. Operations for another poll (their reference names another message) and
/// closes by anyone but the poll's author are dropped on arrival.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poll {
    /// The message holding the poll.
    key: MsgKey,
    /// (option count, multiple choice), once the poll is known.
    created: Option<(usize, bool)>,
    /// Per voter: (counter, sorted options).
    votes: BTreeMap<Account, BTreeSet<(u64, Vec<u32>)>>,
    /// The winning close by the author: its stamp and voter → counter.
    close: Option<(Stamp, BTreeMap<Account, u64>)>,
}

/// A poll's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tally {
    /// Votes per option.
    pub counts: Vec<u32>,
    /// Who voted for each option (sorted).
    pub voters: Vec<Vec<Account>>,
    /// Whether the author closed it.
    pub closed: bool,
}

impl Poll {
    /// The state of the poll in message `key`.
    #[must_use]
    pub const fn new(key: MsgKey) -> Self {
        Self {
            key,
            created: None,
            votes: BTreeMap::new(),
            close: None,
        }
    }

    fn mine(&self, r: Option<&crate::schema::MessageRef>) -> bool {
        r.and_then(MsgKey::from_ref) == Some(self.key)
    }

    /// The poll itself, from the `Message` `key` names, sent by `author`.
    pub fn create(&mut self, author: Account, p: &PollCreate) {
        if author != self.key.author {
            return;
        }
        // One message holds one poll; a repeat with other options is a bug: the greater wins so
        // every device agrees.
        let new = (p.options.len(), p.multiple_choice);
        if self.created.is_none_or(|c| new > c) {
            self.created = Some(new);
        }
    }

    /// A vote from `voter`.
    pub fn vote(&mut self, voter: Account, v: &PollVote) {
        if !self.mine(v.poll.as_ref()) {
            return;
        }
        let mut options = v.options.clone();
        options.sort_unstable();
        let set = self.votes.entry(voter).or_default();
        set.insert((v.counter, options));
        while set.len() > VOTES_PER_VOTER {
            set.pop_first();
        }
    }

    /// A close from `closer`: dropped unless it is this poll's and `closer` is its author.
    pub fn close(&mut self, closer: Account, stamp: Stamp, c: &PollClose) {
        if closer != self.key.author || !self.mine(c.poll.as_ref()) {
            return;
        }
        let heads: BTreeMap<Account, u64> = c
            .heads
            .iter()
            .filter_map(|h| Some((h.voter.as_slice().try_into().ok()?, h.counter)))
            .collect();
        let new = (stamp, heads);
        if self.close.as_ref().is_none_or(|cur| new > *cur) {
            self.close = Some(new);
        }
    }

    /// The result, once the poll is known.
    #[must_use]
    pub fn tally(&self) -> Option<Tally> {
        let (n, multiple) = self.created?;
        let valid = |o: &[u32]| {
            (multiple || o.len() <= 1) && o.iter().all(|i| usize::try_from(*i).is_ok_and(|i| i < n))
        };
        let close = self.close.as_ref();
        let mut voters = vec![Vec::new(); n];
        for (voter, votes) in &self.votes {
            let chosen = match close {
                None => votes.last(),
                Some((_, heads)) => heads
                    .get(voter)
                    .and_then(|c| votes.iter().rev().find(|(k, _)| k == c)),
            };
            if let Some((_, options)) = chosen.filter(|(_, o)| valid(o)) {
                for i in options {
                    if let Some(v) = usize::try_from(*i).ok().and_then(|i| voters.get_mut(i)) {
                        v.push(*voter);
                    }
                }
            }
        }
        Some(Tally {
            counts: voters
                .iter()
                .map(|v| u32::try_from(v.len()).unwrap_or(u32::MAX))
                .collect(),
            voters,
            closed: close.is_some(),
        })
    }
}
