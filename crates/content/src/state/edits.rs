//! Edits and delete for everyone (PROTOCOL §5.4): the author's own messages, within 24 hours
//! (D-0058), judged from the times the messages carry, never from when they arrived.
//!
//! An edit or delete may arrive before the message it targets; both are kept and judged once the
//! original's author and time are known. The shown text is the valid edit with the highest
//! revision (a tie breaks on the text's bytes); every valid revision is the message's history.

use std::collections::{BTreeMap, BTreeSet};

use prost::Message as _;

use super::{Account, EDIT_WINDOW_MS, MessageId, MsgKey};
use crate::schema::{Delete, Edit, Text};

/// Most revisions kept per message (the highest).
pub const REVISIONS_PER_MESSAGE: usize = 64;

/// Whether an operation at `at_ms` falls in the window of a message sent at `original_ms`.
#[must_use]
pub const fn in_window(original_ms: u64, at_ms: u64) -> bool {
    at_ms >= original_ms && at_ms - original_ms <= EDIT_WINDOW_MS
}

/// One recorded edit: (revision, encoded text, editor, time).
type Revision = (u32, Vec<u8>, Account, u64);

/// Edits of every message, by target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Edits {
    by_target: BTreeMap<MessageId, BTreeSet<Revision>>,
}

impl Edits {
    /// Records a (validated) edit by `editor` at `at_ms`.
    pub fn apply(&mut self, editor: Account, at_ms: u64, e: &Edit) {
        let (Ok(target), Some(text)) = (
            <MessageId>::try_from(e.target_message_id.as_slice()),
            e.text.as_ref(),
        ) else {
            return;
        };
        let set = self.by_target.entry(target).or_default();
        set.insert((e.revision, text.encode_to_vec(), editor, at_ms));
        while set.len() > REVISIONS_PER_MESSAGE {
            set.pop_first();
        }
    }

    /// The valid revisions of `message` (sent at `original_ms`), oldest first.
    #[must_use]
    pub fn history(&self, message: &MsgKey, original_ms: u64) -> Vec<(u32, Text)> {
        let Some(set) = self.by_target.get(&message.id) else {
            return Vec::new();
        };
        let mut out: Vec<(u32, Text)> = Vec::new();
        for (rev, bytes, editor, at) in set {
            if *editor != message.author || !in_window(original_ms, *at) {
                continue;
            }
            if let Ok(t) = Text::decode(bytes.as_slice()) {
                // One entry per revision: the set is ordered, so the last one kept is the
                // greatest text for that revision.
                if out.last().is_some_and(|(r, _)| r == rev) {
                    out.pop();
                }
                out.push((*rev, t));
            }
        }
        out
    }

    /// The text to show for `message`: its newest valid revision, if any.
    #[must_use]
    pub fn current(&self, message: &MsgKey, original_ms: u64) -> Option<Text> {
        self.history(message, original_ms).pop().map(|(_, t)| t)
    }
}

/// Deletes for everyone, by target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deletes {
    by_target: BTreeMap<MsgKey, BTreeSet<(Account, u64)>>,
}

impl Deletes {
    /// Records a (validated) delete by `deleter` at `at_ms`.
    pub fn apply(&mut self, deleter: Account, at_ms: u64, d: &Delete) {
        if let Some(target) = d.target.as_ref().and_then(MsgKey::from_ref) {
            let set = self.by_target.entry(target).or_default();
            // Bounded: the first few deleters are enough to decide.
            if set.len() < 16 {
                set.insert((deleter, at_ms));
            }
        }
    }

    /// Whether `message` (sent at `original_ms`) is deleted for everyone: by its author, or by
    /// someone `is_admin` accepts (group admins, Prompt 5), within the window.
    #[must_use]
    pub fn is_deleted(
        &self,
        message: &MsgKey,
        original_ms: u64,
        is_admin: &dyn Fn(&Account) -> bool,
    ) -> bool {
        self.by_target.get(message).is_some_and(|set| {
            set.iter().any(|(who, at)| {
                (*who == message.author || is_admin(who)) && in_window(original_ms, *at)
            })
        })
    }
}
