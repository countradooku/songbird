//! Message status (PROTOCOL §5.6): sending, sent, delivered, read, played, failed.
//!
//! | Status | Produced by |
//! | --- | --- |
//! | Sending, Failed | the sender's app, locally |
//! | Sent | the server's `Accepted` answer (stored durably) |
//! | Delivered, Read, Played | the recipients' end-to-end encrypted receipts |
//!
//! Receipts only ever raise a status: each recipient's level is the greatest receipt it sent
//! (delivered < read < played), and the status is computed from those levels, so it moves forward
//! whatever order receipts arrive in. A receipt also proves the message was stored, so it lifts a
//! message the app had marked failed.
//!
//! **Groups** ("Message info"): the audience is the members when the message was sent. Members
//! who left since are no longer waited for, and members who joined later never received it.
//! Two ticks when every remaining audience member has a device that received it; read when every
//! one of them read it.
//!
//! **The read-receipt setting** is reciprocal and applies to groups too (D-0058): with it off,
//! an app sends no read or played receipts and shows nobody's.

use std::collections::{BTreeMap, BTreeSet};

use super::Account;

/// What the sender's app shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    /// Not yet stored on the server.
    Sending,
    /// Could not be sent after retries.
    Failed,
    /// Stored durably on the server (one tick).
    Sent,
    /// At least one device of the recipient (every member, in a group) decrypted and saved it.
    Delivered,
    /// The recipient (every member) opened the chat.
    Read,
    /// The recipient (every member) played the voice or video note.
    Played,
}

/// A receipt's level (the `ReceiptMessage` kinds, in order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Delivered.
    Delivered,
    /// Read.
    Read,
    /// Played.
    Played,
}

impl Level {
    /// From a `receipt_message::Kind` value; unknown kinds are ignored.
    #[must_use]
    pub const fn from_kind(kind: i32) -> Option<Self> {
        match kind {
            1 => Some(Self::Delivered),
            2 => Some(Self::Read),
            3 => Some(Self::Played),
            _ => None,
        }
    }

    const fn status(self) -> Status {
        match self {
            Self::Delivered => Status::Delivered,
            Self::Read => Status::Read,
            Self::Played => Status::Played,
        }
    }
}

/// The sender's own progress before any receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Local {
    /// Waiting for the server.
    Sending,
    /// Given up after retries.
    Failed,
    /// The server answered `Accepted`.
    Sent,
}

/// An outgoing message's status, 1:1 or group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    local: Local,
    /// The members when sent (a 1:1 chat: the one recipient).
    audience: BTreeSet<Account>,
    /// Each recipient account's greatest receipt.
    levels: BTreeMap<Account, Level>,
}

impl Outgoing {
    /// A new message to `audience` (one account for a 1:1 chat).
    #[must_use]
    pub fn new(audience: impl IntoIterator<Item = Account>) -> Self {
        Self {
            local: Local::Sending,
            audience: audience.into_iter().collect(),
            levels: BTreeMap::new(),
        }
    }

    /// The server accepted it.
    pub fn accepted(&mut self) {
        self.local = Local::Sent;
    }

    /// The app gave up (only while still sending).
    pub fn failed(&mut self) {
        if self.local == Local::Sending {
            self.local = Local::Failed;
        }
    }

    /// A receipt from one of `from`'s devices (receipts from outside the audience are ignored).
    pub fn receipt(&mut self, from: Account, level: Level) {
        if !self.audience.contains(&from) {
            return;
        }
        let cur = self.levels.entry(from).or_insert(level);
        if level > *cur {
            *cur = level;
        }
    }

    /// The status to show, given the chat's current members (for a 1:1 chat, pass the
    /// recipient) and this user's read-receipt setting.
    #[must_use]
    pub fn status(&self, members_now: &BTreeSet<Account>, read_receipts: bool) -> Status {
        let waiting: Vec<&Account> = self.audience.intersection(members_now).collect();
        let received = waiting
            .iter()
            .map(|a| self.levels.get(*a).copied())
            .min()
            .flatten();
        // Any receipt proves the server stored it.
        let base = match self.local {
            _ if !self.levels.is_empty() => Status::Sent,
            Local::Sending => Status::Sending,
            Local::Failed => Status::Failed,
            Local::Sent => Status::Sent,
        };
        // Everyone left: nothing to wait for beyond the server.
        let Some(level) = received.filter(|_| !waiting.is_empty()) else {
            return base;
        };
        let shown = level.status();
        if !read_receipts && shown > Status::Delivered {
            return Status::Delivered;
        }
        shown
    }

    /// "Message info": each audience member still in the chat and their greatest receipt.
    #[must_use]
    pub fn info(&self, members_now: &BTreeSet<Account>) -> BTreeMap<Account, Option<Level>> {
        self.audience
            .intersection(members_now)
            .map(|a| (*a, self.levels.get(a).copied()))
            .collect()
    }
}
