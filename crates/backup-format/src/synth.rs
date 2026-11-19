//! A deterministic synthetic history, for tests, vectors and the cost measurements (M1, M4).
//! Never real data: names, texts and media are pseudo-random from a seed.

use crate::Error;
use crate::schema::{
    Account, Chat, ChatKind, Contact, Media, Message, MessageStatus, Profile, Setting, record::Body,
};
use crate::writer::{ChunkSink, Writer};

/// The shape of a history.
#[derive(Debug, Clone, Copy)]
pub struct Shape {
    /// The generator's seed.
    pub seed: u64,
    /// Chats.
    pub chats: u32,
    /// Messages in each chat.
    pub messages_per_chat: u32,
    /// One message in this many carries a media file (0: none).
    pub media_every: u32,
    /// Media sizes cycle through these.
    pub media_sizes: &'static [usize],
    /// Contacts.
    pub contacts: u32,
}

/// A small xorshift generator (not cryptographic).
#[derive(Debug, Clone)]
pub struct Gen(u64);

impl Gen {
    /// Seeded.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    /// The next value.
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n + 8);
        while v.len() < n {
            v.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        v.truncate(n);
        v
    }
    /// A 16-byte ID.
    pub fn id(&mut self) -> Vec<u8> {
        self.bytes(16)
    }
    /// Words of text, `words` long.
    pub fn text(&mut self, words: usize) -> String {
        const W: &[&str] = &[
            "the", "song", "bird", "flies", "over", "a", "quiet", "river", "at", "dawn", "and",
            "sings", "to", "every", "friend", "it", "meets", "on", "the", "way", "home",
        ];
        let mut s = String::new();
        for i in 0..words {
            if i > 0 {
                s.push(' ');
            }
            let k =
                usize::try_from(self.next_u64() % u64::try_from(W.len()).unwrap_or(1)).unwrap_or(0);
            s.push_str(W.get(k).copied().unwrap_or("x"));
        }
        s
    }
}

/// The account record of the history with this seed.
#[must_use]
pub fn account(seed: u64) -> Account {
    let mut g = Gen::new(seed ^ 0xacc0);
    Account {
        account_id: g.id(),
        identity_seed: g.bytes(32),
        profile_key: g.bytes(32),
        storage_key: g.bytes(32),
        access_key: g.bytes(16),
        username: "songbird.42".into(),
        username_key: g.bytes(32),
        device_list_version: 3,
        server_name: "chat.example".into(),
    }
}

/// The media file of message `n` in chat `c`, if it has one.
#[must_use]
pub fn media_of(shape: &Shape, c: u32, n: u32) -> Option<Vec<u8>> {
    if shape.media_every == 0
        || !n.is_multiple_of(shape.media_every)
        || shape.media_sizes.is_empty()
    {
        return None;
    }
    let k =
        usize::try_from((c + n) % u32::try_from(shape.media_sizes.len()).unwrap_or(1)).unwrap_or(0);
    let size = shape.media_sizes.get(k).copied().unwrap_or(0);
    // Every 5th media file repeats an earlier one (a forward): stored once.
    let key = if n.is_multiple_of(shape.media_every * 5) {
        7
    } else {
        u64::from(c) << 32 | u64::from(n)
    };
    Some(Gen::new(shape.seed ^ key).bytes(size))
}

/// Writes the history in canonical order; `extra` more messages at the end of each chat (a
/// later backup of the same account). Returns the records written, in order.
///
/// # Errors
/// The writer's.
pub fn write<S: ChunkSink>(
    w: &mut Writer<'_, S>,
    shape: &Shape,
    extra: u32,
) -> Result<Vec<Body>, Error> {
    write_edited(w, shape, extra, 0)
}

/// As [`write()`], with the oldest `drop_oldest` messages of every chat deleted, as a later backup
/// after the user cleared old messages.
///
/// # Errors
/// The writer's.
#[allow(
    clippy::too_many_lines,
    reason = "one generator, in the canonical order"
)]
pub fn write_edited<S: ChunkSink>(
    w: &mut Writer<'_, S>,
    shape: &Shape,
    extra: u32,
    drop_oldest: u32,
) -> Result<Vec<Body>, Error> {
    let mut out = vec![];
    let mut put = |w: &mut Writer<'_, S>, b: Body| -> Result<(), Error> {
        out.push(b.clone());
        w.record(b)
    };
    put(w, Body::Account(account(shape.seed)))?;
    let mut g = Gen::new(shape.seed);
    put(
        w,
        Body::Profile(Profile {
            name: "Ada".into(),
            about: g.text(6),
            status_text: "at the river".into(),
            status_emoji: "\u{1f426}".into(),
            status_expires_ms: 1_800_000_000_000,
            avatar: vec![],
            profile_version: 4,
        }),
    )?;
    for (k, v) in [
        ("s/theme", &b"dark"[..]),
        ("s/read_receipts", b"\x01"),
        ("d/enter_sends", b"\x00"),
    ] {
        put(
            w,
            Body::Setting(Setting {
                key: k.into(),
                value: v.to_vec(),
            }),
        )?;
    }
    for _ in 0..shape.contacts {
        put(
            w,
            Body::Contact(Contact {
                contact_id: g.id(),
                account_id: g.id(),
                name: g.text(2),
                notes: g.text(5),
                buddy_groups: vec!["Friends".into()],
                identity_key: g.bytes(32),
                verified: g.next_u64().is_multiple_of(2),
            }),
        )?;
    }
    // Canonical order (PROTOCOL §11.5): every chat, then every message by time, so a day of new
    // messages lands at the end of the stream and old ones deleted at its start.
    let mut chats = vec![];
    for c in 0..shape.chats {
        let mut cg = Gen::new(shape.seed ^ (u64::from(c) << 20) ^ 0xc4a7);
        let chat_id = cg.id();
        put(
            w,
            Body::Chat(Chat {
                chat_id: chat_id.clone(),
                kind: ChatKind::Direct.into(),
                title: cg.text(2),
                created_ms: 1_700_000_000_000 + u64::from(c),
                ..Chat::default()
            }),
        )?;
        chats.push((cg, chat_id));
    }
    for n in 0..shape.messages_per_chat + extra {
        for (c, (cg, chat_id)) in (0u32..).zip(chats.iter_mut()) {
            if n < drop_oldest {
                // Deleted: the generator advances exactly as for a written message, so later
                // messages are unchanged.
                let words = usize::try_from(4 + cg.next_u64() % 30).unwrap_or(4);
                let _ = cg.id();
                let _ = cg.text(words);
                continue;
            }
            let mut media = vec![];
            if let Some(bytes) = media_of(shape, c, n) {
                let r = w.media(
                    Media {
                        mime: "image/jpeg".into(),
                        width: 640,
                        height: 480,
                        ..Media::default()
                    },
                    &mut bytes.as_slice(),
                )?;
                media.push(r.to_vec());
            }
            let words = usize::try_from(4 + cg.next_u64() % 30).unwrap_or(4);
            put(
                w,
                Body::Message(Message {
                    chat_id: chat_id.clone(),
                    message_id: cg.id(),
                    sender: if n % 2 == 0 { vec![] } else { chat_id.clone() },
                    sent_ms: 1_700_000_000_000 + u64::from(n) * 60_000,
                    received_ms: 1_700_000_000_000 + u64::from(n) * 60_000 + 150,
                    content: cg.text(words).into_bytes(),
                    media,
                    status: MessageStatus::Read.into(),
                    starred: n % 97 == 0,
                }),
            )?;
        }
    }
    Ok(out)
}
