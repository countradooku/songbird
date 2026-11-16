//! Receipt batching on the recipient's side (PROTOCOL §5.6).
//!
//! Receipts go to each message's **author only** (every device of the author, through the
//! mailbox), never to the whole group. The coalescer gathers them per (chat, author, kind) for a
//! short window, then emits one [`ReceiptMessage`] per group:
//!
//! - delivered and played receipts list message IDs (at most 512 per receipt, split beyond);
//! - a read receipt says "up to here": opening a chat with 200 unread messages from one author
//!   sends one receipt naming the newest;
//! - the window is 1 s, and 10 s in groups above 32 members ([`window_for`]);
//! - the reader's own other devices get one `ReadSync` with what was read (at most 512 marks per
//!   message).
//!
//! With the read-receipt setting off (D-0058: groups too), no read or played receipt is sent; the
//! own-device sync still is.

use std::collections::{BTreeMap, BTreeSet};

use super::{Account, MessageId, MsgKey};
use crate::schema::{MessageRef, ReadMark, ReadSync, ReceiptMessage, receipt_message};
use crate::validate::MAX_BATCH;

/// A chat as the coalescer keys it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChatKey {
    /// A 1:1 chat with this account.
    Direct(Account),
    /// A group or channel.
    Group([u8; 16]),
}

impl ChatKey {
    fn group_id(self) -> Vec<u8> {
        match self {
            Self::Direct(_) => Vec::new(),
            Self::Group(g) => g.to_vec(),
        }
    }
}

/// One receipt to send: to `author`'s devices.
#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing {
    /// The author it goes to.
    pub author: Account,
    /// The receipt.
    pub receipt: ReceiptMessage,
}

#[derive(Debug, Default)]
struct Pending {
    since_ms: u64,
    ids: BTreeSet<MessageId>,
    /// "Read up to": (the app's order of the message, its ID); the greatest wins.
    up_to: Option<(u64, MessageId)>,
}

/// The coalescer.
#[derive(Debug)]
pub struct Coalescer {
    window_ms: u64,
    read_receipts: bool,
    pending: BTreeMap<(ChatKey, Account, i32), Pending>,
    marks: Vec<ReadMark>,
}

/// The batching window of 1:1 chats and groups up to [`LARGE_GROUP`] members.
pub const WINDOW_MS: u64 = 1_000;
/// The batching window of larger groups (the M2 load test: in a 1,024-member group it takes
/// receipts from 66 % to 47 % of all envelopes when members chat in bursts).
pub const LARGE_GROUP_WINDOW_MS: u64 = 10_000;
/// Groups above this many members batch over [`LARGE_GROUP_WINDOW_MS`].
pub const LARGE_GROUP: usize = 32;

/// The batching window for a chat of `members` members (2 for a 1:1 chat).
#[must_use]
pub const fn window_for(members: usize) -> u64 {
    if members > LARGE_GROUP {
        LARGE_GROUP_WINDOW_MS
    } else {
        WINDOW_MS
    }
}

impl Coalescer {
    /// A coalescer with a batching window and the user's read-receipt setting.
    #[must_use]
    pub const fn new(window_ms: u64, read_receipts: bool) -> Self {
        Self {
            window_ms,
            read_receipts,
            pending: BTreeMap::new(),
            marks: Vec::new(),
        }
    }

    /// The read-receipt setting changed.
    pub const fn set_read_receipts(&mut self, on: bool) {
        self.read_receipts = on;
    }

    fn slot(&mut self, chat: ChatKey, author: Account, kind: i32, now_ms: u64) -> &mut Pending {
        self.pending
            .entry((chat, author, kind))
            .or_insert_with(|| Pending {
                since_ms: now_ms,
                ..Pending::default()
            })
    }

    /// A message was decrypted and saved.
    pub fn delivered(&mut self, chat: ChatKey, m: MsgKey, now_ms: u64) {
        let kind = receipt_message::Kind::Delivered.into();
        self.slot(chat, m.author, kind, now_ms).ids.insert(m.id);
    }

    /// The user read `read` (the messages that became read, any authors), up to the newest per
    /// author: `order` is the app's position of each message in the chat.
    pub fn read(&mut self, chat: ChatKey, read: &[(MsgKey, u64)], now_ms: u64) {
        for (m, order) in read {
            self.marks.push(ReadMark {
                message: Some(MessageRef {
                    author: m.author.to_vec(),
                    message_id: m.id.to_vec(),
                }),
                at_ms: now_ms,
            });
            if !self.read_receipts {
                continue;
            }
            let kind = receipt_message::Kind::Read.into();
            let p = self.slot(chat, m.author, kind, now_ms);
            if p.up_to.is_none_or(|u| (*order, m.id) > u) {
                p.up_to = Some((*order, m.id));
            }
        }
    }

    /// A voice or video note was played.
    pub fn played(&mut self, chat: ChatKey, m: MsgKey, now_ms: u64) {
        if self.read_receipts {
            let kind = receipt_message::Kind::Played.into();
            self.slot(chat, m.author, kind, now_ms).ids.insert(m.id);
        }
    }

    /// The receipts whose window has passed, and the own-device read sync (if anything was read).
    pub fn due(&mut self, now_ms: u64) -> (Vec<Outgoing>, Vec<ReadSync>) {
        let window = self.window_ms;
        let marks_due = self
            .marks
            .first()
            .is_some_and(|m| now_ms.saturating_sub(m.at_ms) >= window);
        self.take(|p| now_ms.saturating_sub(p.since_ms) >= window, marks_due)
    }

    /// Everything pending (the app is going to the background).
    pub fn flush(&mut self) -> (Vec<Outgoing>, Vec<ReadSync>) {
        self.take(|_| true, true)
    }

    fn take(
        &mut self,
        ready: impl Fn(&Pending) -> bool,
        marks_due: bool,
    ) -> (Vec<Outgoing>, Vec<ReadSync>) {
        let keys: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| ready(p))
            .map(|(k, _)| *k)
            .collect();
        let mut out = Vec::new();
        for key in keys {
            let Some(p) = self.pending.remove(&key) else {
                continue;
            };
            let (chat, author, kind) = key;
            let ids: Vec<Vec<u8>> = p.ids.iter().map(|i| i.to_vec()).collect();
            let up_to = p.up_to.map(|(_, id)| id.to_vec()).unwrap_or_default();
            let mut chunks: Vec<Vec<Vec<u8>>> = ids.chunks(MAX_BATCH).map(<[_]>::to_vec).collect();
            if chunks.is_empty() {
                chunks.push(Vec::new());
            }
            let last = chunks.len() - 1;
            for (i, message_ids) in chunks.into_iter().enumerate() {
                out.push(Outgoing {
                    author,
                    receipt: ReceiptMessage {
                        kind,
                        group_id: chat.group_id(),
                        message_ids,
                        up_to: if i == last { up_to.clone() } else { Vec::new() },
                    },
                });
            }
        }
        let syncs = if marks_due {
            std::mem::take(&mut self.marks)
                .chunks(MAX_BATCH)
                .map(|c| ReadSync { marks: c.to_vec() })
                .collect()
        } else {
            Vec::new()
        };
        (out, syncs)
    }
}
