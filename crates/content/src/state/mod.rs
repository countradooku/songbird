//! Reference semantics of chat state (PROTOCOL §5.5, §5.6; decision D-0060): what every app must
//! compute from the messages it has, so every device of every participant shows the same thing.
//!
//! **Arrival order never matters.** Every state here is a function of the *set* of operations
//! received: applying them in any order, with any duplicates, gives the same result (the property
//! tests in `tests/convergence.rs` check every state over random orderings). Two tools make
//! that so:
//!
//! - **last write per author wins, by the author's own counter** (reactions, votes, RSVPs, edits):
//!   only one author writes each slot, and the author's counter orders its own writes, so no
//!   clock is trusted. Ties (a buggy or malicious author reusing a counter) break on the value's
//!   bytes, so they too converge;
//! - **a total order on (time, author, message ID)** ([`Stamp`]) for state many people write
//!   (pins, the disappearing timer, the restricted-chat policy). The time is the server's franking
//!   stamp where there is one (§5.13), else the sender's clock: skewed clocks change who wins,
//!   never whether devices agree.
//!
//! Nothing here allocates in proportion to anything an attacker controls beyond the bounds
//! [`crate::validate`] already enforces, plus the per-voter cap in [`poll`].

pub mod chat;
pub mod edits;
pub mod lww;
pub mod poll;
pub mod receipts;
pub mod status;

use crate::schema::MessageRef;

/// An account ID.
pub type Account = [u8; 16];
/// A message ID (16 random bytes, PROTOCOL §5.1).
pub type MessageId = [u8; 16];

/// A message: its author and its ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MsgKey {
    /// The author's account.
    pub author: Account,
    /// The message ID.
    pub id: MessageId,
}

impl MsgKey {
    /// From a validated [`MessageRef`].
    #[must_use]
    pub fn from_ref(r: &MessageRef) -> Option<Self> {
        Some(Self {
            author: r.author.as_slice().try_into().ok()?,
            id: r.message_id.as_slice().try_into().ok()?,
        })
    }
}

/// The total order of operations many people write: time first, then author, then message ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stamp {
    /// The server's stamp time when the message carried one, else the sender's `sent_at_ms`.
    pub at_ms: u64,
    /// The operation's author.
    pub author: Account,
    /// The operation's message ID.
    pub id: MessageId,
}

/// The 24-hour edit window and delete-for-everyone limit (D-0058).
pub const EDIT_WINDOW_MS: u64 = 24 * 3600 * 1000;
