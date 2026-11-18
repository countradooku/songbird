//! The chat list's data, as plain Rust: which chats a list shows and in
//! what order, what each row says, message requests and local search.
//! No NSH here, so it is unit-tested directly.

use std::collections::HashMap;

use crate::{
    store::{
        Body, Chat, ChatId, ChatKind, Contact, ContactId, Message, MsgId, Presence, when_label,
    },
    ui::{Availability, Tick},
};

/// Which chats the list shows: All, or one of the user's lists in the
/// Lists capsule. Favourites, Groups and Channels stay as views the list
/// menu offers (the capsule shows the one chosen beside All); WhatsApp is a
/// segment of its own while the user keeps those chats apart (A15). Unread
/// is not a view but a toggle over any of them (`ChatFilter::unread`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Filter {
    #[default]
    All,
    Favourites,
    Groups,
    Channels,
    /// Chats bridged to WhatsApp (A15), when the user keeps them apart.
    WhatsApp,
    /// A custom list ("Family", "Work").
    List(String),
}

impl Filter {
    pub fn label(&self) -> String {
        match self {
            Filter::All => "All".into(),
            Filter::Favourites => "Favourites".into(),
            Filter::Groups => "Groups".into(),
            Filter::Channels => "Channels".into(),
            Filter::WhatsApp => "WhatsApp".into(),
            Filter::List(name) => name.clone(),
        }
    }

    /// One of the views the list menu offers (not a list of the user's,
    /// not All): the capsule shows it as a segment only while it is chosen.
    pub fn from_menu(&self) -> bool {
        matches!(self, Filter::Favourites | Filter::Groups | Filter::Channels)
    }

    fn matches(&self, c: &Chat) -> bool {
        match self {
            Filter::All => true,
            Filter::Favourites => c.favourite,
            Filter::Groups => c.kind == ChatKind::Group,
            Filter::Channels => matches!(c.kind, ChatKind::Channel { .. }),
            Filter::WhatsApp => matches!(c.kind, ChatKind::WhatsApp(_)),
            Filter::List(name) => c.lists.iter().any(|l| l == name),
        }
    }

    /// The empty state's title and sentence for this view, with the Unread
    /// toggle `unread` on or off.
    pub fn empty_copy(&self, unread: bool) -> (String, String) {
        if unread {
            return match self {
                Filter::All => (
                    "You're all caught up".into(),
                    "Chats with new messages show here.".into(),
                ),
                other => (
                    format!("Nothing unread in {}", other.label()),
                    "Turn off Unread to see every chat here.".into(),
                ),
            };
        }
        match self {
            Filter::All => (
                "No chats yet".into(),
                "Start a chat with someone in your contacts, or invite a friend to Songbird."
                    .into(),
            ),
            Filter::Favourites => (
                "No favourites yet".into(),
                "Add a chat to favourites from its menu to find it here quickly.".into(),
            ),
            Filter::Groups => ("No groups yet".into(), "Groups you're in show here.".into()),
            Filter::Channels => (
                "No channels yet".into(),
                "Channels you follow show here.".into(),
            ),
            Filter::WhatsApp => (
                "No WhatsApp chats".into(),
                "Chats with your WhatsApp contacts show here.".into(),
            ),
            Filter::List(name) => (
                format!("No chats in {name}"),
                "Add chats to this list from a chat's menu.".into(),
            ),
        }
    }
}

/// Which chats a list shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListScope {
    /// The Chats tab: not archived, not requests, not locked.
    Inbox,
    Archived,
    /// The Locked chats page.
    Locked,
}

impl ListScope {
    fn includes(self, c: &Chat) -> bool {
        if c.request || c.kind == ChatKind::Community {
            return false;
        }
        match self {
            ListScope::Inbox => !c.archived && !c.locked,
            ListScope::Archived => c.archived && !c.locked,
            ListScope::Locked => c.locked,
        }
    }
}

/// What the second line of a row says.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Preview {
    #[default]
    None,
    /// Someone is typing ("typing…").
    Typing(String),
    /// The user's unsent draft.
    Draft(String),
    /// The last message, with the sender's first name in groups and the
    /// status when it is the user's. A row draws only a failed status
    /// (the conversation shows the rest once, under the latest message).
    Message {
        sender: Option<String>,
        text: String,
        tick: Option<Tick>,
    },
}

impl Preview {
    /// The preview as prefix and text.
    pub fn text(&self) -> (String, String) {
        match self {
            Preview::None => (String::new(), String::new()),
            Preview::Typing(t) => (String::new(), t.clone()),
            Preview::Draft(d) => ("Draft: ".into(), d.clone()),
            Preview::Message {
                sender: Some(s),
                text,
                ..
            } => (format!("{s}: "), text.clone()),
            Preview::Message {
                sender: None, text, ..
            } => (String::new(), text.clone()),
        }
    }
}

/// `name` cut around the first match of `query` (folded: case and
/// accents), for highlighting: before, the match, after. `None` when it
/// does not match.
pub fn cut_match(name: &str, query: &str) -> Option<(String, String, String)> {
    let q = fold(query.trim());
    let at = find(&fold(name), &q)?;
    let chars: Vec<char> = name.chars().collect();
    let part = |a: usize, b: usize| chars[a..b].iter().collect::<String>();
    Some((
        part(0, at),
        part(at, at + q.len()),
        part(at + q.len(), chars.len()),
    ))
}

/// One chat row: everything the row shows, as plain data.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ChatRow {
    pub id: ChatId,
    pub title: String,
    pub seed: u64,
    /// The other person of a direct chat.
    pub peer: Option<ContactId>,
    pub group: bool,
    pub channel: bool,
    pub verified: bool,
    pub whatsapp: bool,
    pub preview: Preview,
    /// The last message's preview whatever the row shows (the open chat's
    /// row shows it in place of the draft being typed there).
    pub latest: Preview,
    /// The last message is a voice note (a mic leads its preview).
    pub voice: bool,
    /// The last message is someone else's (not the user's, not a system
    /// line): the chat may be waiting for the user.
    pub theirs: bool,
    pub when: String,
    pub at: Option<i64>,
    pub unread: u32,
    pub marked_unread: bool,
    pub muted: bool,
    pub mention: bool,
    pub pinned: bool,
    pub disappearing: bool,
    pub locked: bool,
    pub favourite: bool,
    pub archived: bool,
    pub lists: Vec<String>,
    /// The other person's presence, for a direct chat whose person shares
    /// it (online, away, busy; never a group).
    pub availability: Option<Availability>,
}

impl ChatRow {
    /// Unread at all (a count, or marked unread).
    pub fn is_unread(&self) -> bool {
        self.unread > 0 || self.marked_unread
    }

    /// Waiting for the user (desktop's "Needs a reply"): someone else
    /// wrote last and it is unread in a chat that is not muted, or the user
    /// was mentioned and has not read it.
    pub fn needs_reply(&self) -> bool {
        (self.theirs && self.unread > 0 && !self.muted) || self.mention
    }

    /// The last message the user sent did not go out.
    pub fn failed(&self) -> bool {
        matches!(
            self.preview,
            Preview::Message {
                tick: Some(Tick::Failed),
                ..
            }
        )
    }

    /// The preview as one plain string (prefix and text).
    pub fn preview_text(&self) -> (String, String) {
        self.preview.text()
    }

    /// What the row previews: its draft is left out while its chat is
    /// `open` (the draft is in the composer right there).
    pub fn shown(&self, open: bool) -> &Preview {
        if open && matches!(self.preview, Preview::Draft(_)) {
            &self.latest
        } else {
            &self.preview
        }
    }

    /// What a screen reader says for the row, in reading order.
    pub fn spoken(&self) -> String {
        let mut parts = vec![self.title.clone()];
        if self.verified {
            parts.push("verified".into());
        }
        if self.whatsapp {
            parts.push("WhatsApp chat".into());
        }
        if self.pinned {
            parts.push("pinned".into());
        }
        if self.muted {
            parts.push("muted".into());
        }
        if self.unread > 0 {
            parts.push(if self.unread == 1 {
                "1 unread message".into()
            } else {
                format!("{} unread messages", self.unread)
            });
        } else if self.marked_unread {
            parts.push("marked as unread".into());
        }
        if self.mention {
            parts.push("you were mentioned".into());
        }
        if let Some(a) = self.availability {
            parts.push(a.label().into());
        }
        let (prefix, text) = self.preview_text();
        if !text.is_empty() {
            parts.push(format!("{prefix}{text}"));
        }
        // Only a failed send is said (and drawn): delivery states live in
        // the conversation, once, under the latest message.
        if self.failed() {
            parts.push(Tick::Failed.label().to_lowercase());
        }
        if !self.when.is_empty() {
            parts.push(self.when.clone());
        }
        if self.disappearing {
            parts.push("disappearing messages on".into());
        }
        parts.join(", ")
    }
}

/// The first word of a name ("Elena Rădulescu" → "Elena").
pub fn first_name(name: &str) -> String {
    name.split_whitespace().next().unwrap_or(name).to_string()
}

/// A name with the words that start with no letter or digit left out
/// ("Familia 🏡" → "Familia"), so initials never take an emoji.
pub fn letters(name: &str) -> String {
    let kept: Vec<&str> = name
        .split_whitespace()
        .filter(|w| w.chars().next().is_some_and(char::is_alphanumeric))
        .collect();
    if kept.is_empty() {
        name.to_string()
    } else {
        kept.join(" ")
    }
}

fn contact<'a>(contacts: &'a [Contact], id: ContactId) -> Option<&'a Contact> {
    contacts.iter().find(|c| c.id == id)
}

/// The row for `c`.
pub fn row(c: &Chat, messages: &HashMap<ChatId, Vec<Message>>, contacts: &[Contact]) -> ChatRow {
    let last = messages.get(&c.id).and_then(|v| v.last());
    let peer = match c.kind {
        ChatKind::Direct(p) | ChatKind::WhatsApp(p) => contact(contacts, p),
        _ => None,
    };
    let group = matches!(
        c.kind,
        ChatKind::Group | ChatKind::Community | ChatKind::Channel { .. }
    );
    let latest = match last {
        Some(m) => {
            let system = matches!(m.body, Body::System(_));
            let sender = match (m.from, &c.kind) {
                (Some(from), ChatKind::Group | ChatKind::Community) if !system => {
                    contact(contacts, from).map(|p| first_name(&p.name))
                }
                _ => None,
            };
            let tick =
                (m.mine() && !system && !matches!(m.body, Body::Deleted)).then_some(m.status);
            Preview::Message {
                sender,
                text: m.body.preview(),
                tick,
            }
        }
        None => Preview::None,
    };
    let preview = if let Some(t) = &c.typing {
        Preview::Typing(t.clone())
    } else if !c.draft.is_empty() {
        Preview::Draft(c.draft.clone())
    } else {
        latest.clone()
    };
    ChatRow {
        id: c.id,
        title: c.title.clone(),
        seed: c.seed,
        peer: peer.map(|p| p.id),
        group,
        channel: matches!(c.kind, ChatKind::Channel { .. }),
        verified: peer.is_some_and(|p| p.verified),
        whatsapp: matches!(c.kind, ChatKind::WhatsApp(_)),
        preview,
        latest,
        voice: last.is_some_and(|m| matches!(m.body, Body::Voice { .. })),
        theirs: last.is_some_and(|m| !m.mine() && !matches!(m.body, Body::System(_))),
        when: last.map(|m| when_label(m.at)).unwrap_or_default(),
        at: last.map(|m| m.at),
        unread: c.unread,
        marked_unread: c.marked_unread,
        muted: c.muted,
        mention: c.mentions > 0,
        pinned: c.pinned,
        disappearing: c.disappearing.is_some(),
        locked: c.locked,
        favourite: c.favourite,
        archived: c.archived,
        lists: c.lists.clone(),
        availability: if group {
            None
        } else {
            peer.and_then(|p| availability(&p.presence))
        },
    }
}

/// The mark a person's presence shows (last seen and invisible show none).
pub fn availability(p: &Presence) -> Option<Availability> {
    match p {
        Presence::Online => Some(Availability::Online),
        Presence::Away => Some(Availability::Away),
        Presence::Busy => Some(Availability::Busy),
        Presence::Invisible | Presence::LastSeen(_) => None,
    }
}

/// The rows a list shows: in `scope`, through `filter`, pinned first (in
/// the inbox), then newest first.
pub fn rows(
    chats: &[Chat],
    messages: &HashMap<ChatId, Vec<Message>>,
    contacts: &[Contact],
    scope: ListScope,
    filter: &Filter,
) -> Vec<ChatRow> {
    let mut out: Vec<ChatRow> = chats
        .iter()
        .filter(|c| scope.includes(c) && filter.matches(c))
        .map(|c| row(c, messages, contacts))
        .collect();
    let pins = scope == ListScope::Inbox;
    out.sort_by(|a, b| {
        let pin = if pins {
            b.pinned.cmp(&a.pinned)
        } else {
            std::cmp::Ordering::Equal
        };
        pin.then(b.at.unwrap_or(i64::MIN).cmp(&a.at.unwrap_or(i64::MIN)))
    });
    out
}

/// How many chats are in `scope`, and how many of them are unread.
pub fn count(chats: &[Chat], scope: ListScope) -> (usize, usize) {
    let inside = chats.iter().filter(|c| scope.includes(c));
    inside.fold((0, 0), |(n, u), c| {
        (n + 1, u + usize::from(c.unread > 0 || c.marked_unread))
    })
}

/// The most pinned people above the list (two rows of four); more pinned
/// chats stay in the list, first.
pub const MAX_PINNED: usize = 8;
/// "Needs a reply" shows this many until "Show all".
pub const MAX_NEEDS: usize = 5;

/// The Chats tab's list, split into its parts.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Inbox {
    /// Pinned people, in the order of the user's chats (stable: they do
    /// not reshuffle when a message arrives).
    pub pinned: Vec<ChatRow>,
    /// "Needs a reply" (desktop), newest first, cut at [`MAX_NEEDS`]
    /// unless shown all.
    pub needs: Vec<ChatRow>,
    /// How many more need a reply than `needs` holds.
    pub more_needs: usize,
    /// Everything else, newest first ("Recent" on desktop; the whole list
    /// on phones).
    pub recent: Vec<ChatRow>,
}

impl Inbox {
    pub fn is_empty(&self) -> bool {
        self.pinned.is_empty() && self.needs.is_empty() && self.recent.is_empty()
    }
}

/// Splits `rows` (as [`rows`] orders them) into the inbox's parts.
/// `order` is the user's chats in the store's order (the pinned people's
/// order); `unread` keeps only unread chats; `triage` makes "Needs a reply"
/// (desktop); `show_all` lifts its cut.
pub fn inbox(
    rows: Vec<ChatRow>,
    order: &[ChatId],
    unread: bool,
    triage: bool,
    show_all: bool,
) -> Inbox {
    let rows: Vec<ChatRow> = rows
        .into_iter()
        .filter(|r| !unread || r.is_unread())
        .collect();
    let place = |id: ChatId| order.iter().position(|&o| o == id).unwrap_or(usize::MAX);
    let mut pinned: Vec<ChatRow> = rows.iter().filter(|r| r.pinned).cloned().collect();
    pinned.sort_by_key(|r| place(r.id));
    pinned.truncate(MAX_PINNED);
    let mut out = Inbox::default();
    let mut needs = Vec::new();
    for r in rows {
        if pinned.iter().any(|p| p.id == r.id) {
            continue;
        }
        if triage && r.needs_reply() {
            needs.push(r);
        } else {
            out.recent.push(r);
        }
    }
    if !show_all && needs.len() > MAX_NEEDS {
        out.more_needs = needs.len() - MAX_NEEDS;
        needs.truncate(MAX_NEEDS);
    }
    out.pinned = pinned;
    out.needs = needs;
    out
}

/// The custom list names: the user's own order first, then any a chat
/// names that the order lacks.
pub fn list_names(order: &[String], chats: &[Chat]) -> Vec<String> {
    let mut out: Vec<String> = order.to_vec();
    for c in chats {
        for l in &c.lists {
            if !out.contains(l) {
                out.push(l.clone());
            }
        }
    }
    out
}

// ---------------------------------------------------------------- requests

/// A message request: someone not in the user's contacts wrote first.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestRow {
    pub chat: ChatId,
    pub name: String,
    pub username: String,
    pub seed: u64,
    pub first: String,
    pub more: usize,
    pub when: String,
}

pub fn requests(
    chats: &[Chat],
    messages: &HashMap<ChatId, Vec<Message>>,
    contacts: &[Contact],
) -> Vec<RequestRow> {
    chats
        .iter()
        .filter(|c| c.request)
        .map(|c| {
            let thread = messages.get(&c.id).map(Vec::as_slice).unwrap_or_default();
            let first = thread
                .iter()
                .find(|m| !m.mine() && !matches!(m.body, Body::System(_)));
            let peer = match c.kind {
                ChatKind::Direct(p) | ChatKind::WhatsApp(p) => contact(contacts, p),
                _ => None,
            };
            RequestRow {
                chat: c.id,
                name: peer
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| c.title.clone()),
                username: peer.map(|p| p.username.clone()).unwrap_or_default(),
                seed: c.seed,
                first: first.map(|m| m.body.preview()).unwrap_or_default(),
                more: thread.len().saturating_sub(1),
                when: first.map(|m| when_label(m.at)).unwrap_or_default(),
            }
        })
        .collect()
}

/// Contacts the user can start a chat with, A–Z: not blocked, and not
/// someone who only wrote a message request.
pub fn contacts_az(chats: &[Chat], contacts: &[Contact], query: &str) -> Vec<Contact> {
    let strangers: Vec<ContactId> = chats
        .iter()
        .filter(|c| c.request)
        .filter_map(|c| match c.kind {
            ChatKind::Direct(p) | ChatKind::WhatsApp(p) => Some(p),
            _ => None,
        })
        .collect();
    let q = fold(query.trim());
    let mut out: Vec<Contact> = contacts
        .iter()
        .filter(|c| !c.blocked && !strangers.contains(&c.id))
        .filter(|c| {
            q.is_empty()
                || find(&fold(&c.name), &q).is_some()
                || find(&fold(&c.username), &q).is_some()
        })
        .cloned()
        .collect();
    out.sort_by_key(|c| fold(&c.name).into_iter().collect::<String>());
    out
}

// ---------------------------------------------------------------- search

/// A character as search compares it: lower case, Latin accents and
/// Romanian comma-below letters folded ("Ș" finds "s").
fn fold_char(c: char) -> char {
    let lower = c.to_lowercase().next().unwrap_or(c);
    match lower {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ă' | 'ā' | 'ą' => 'a',
        'ç' | 'ć' | 'č' => 'c',
        'è' | 'é' | 'ê' | 'ë' | 'ę' | 'ě' | 'ē' => 'e',
        'ì' | 'í' | 'î' | 'ï' | 'ī' => 'i',
        'ñ' | 'ń' | 'ň' => 'n',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => 'o',
        'ș' | 'ş' | 'ś' | 'š' => 's',
        'ț' | 'ţ' | 'ť' => 't',
        'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' => 'u',
        'ý' | 'ÿ' => 'y',
        'ź' | 'ż' | 'ž' => 'z',
        'ł' => 'l',
        'ß' => 's',
        other => other,
    }
}

/// `s` folded, one char per char of `s` (so positions map back).
pub fn fold(s: &str) -> Vec<char> {
    s.chars().map(fold_char).collect()
}

/// Where `needle` first occurs in `hay`, in chars.
pub fn find(hay: &[char], needle: &[char]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A message that matches, with the match cut out for highlighting.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageHit {
    pub chat: ChatId,
    pub msg: MsgId,
    pub title: String,
    pub seed: u64,
    pub when: String,
    /// Up to the match, shortened from the start with "…".
    pub before: String,
    pub matched: String,
    pub after: String,
}

/// Search results in three sections.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Results {
    pub chats: Vec<ChatRow>,
    pub messages: Vec<MessageHit>,
    pub contacts: Vec<Contact>,
}

impl Results {
    pub fn is_empty(&self) -> bool {
        self.chats.is_empty() && self.messages.is_empty() && self.contacts.is_empty()
    }
}

/// The most message hits search shows (newest first).
pub const MAX_MESSAGE_HITS: usize = 50;
/// Chars of context kept before a match.
const CONTEXT: usize = 24;

/// Splits `text` around the match at `at..at + len` (chars), keeping a
/// short lead-in.
pub fn cut(text: &str, at: usize, len: usize) -> (String, String, String) {
    let chars: Vec<char> = text.chars().collect();
    let start = at.saturating_sub(CONTEXT);
    let mut before: String = chars[start..at].iter().collect();
    if start > 0 {
        before = format!("…{}", before.trim_start());
    }
    let matched: String = chars[at..at + len].iter().collect();
    let after: String = chars[at + len..].iter().collect();
    (before, matched, after)
}

/// Searches chat titles, message text and contacts on the device.
/// Locked chats and message requests stay out of results.
// mock: app-core's encrypted full-text index (SQLCipher FTS5) answers
// this in the real app; the UI gets the same three sections.
pub fn search(
    query: &str,
    chats: &[Chat],
    messages: &HashMap<ChatId, Vec<Message>>,
    contacts: &[Contact],
) -> Results {
    let q = fold(query.trim());
    if q.is_empty() {
        return Results::default();
    }
    let open: Vec<&Chat> = chats
        .iter()
        .filter(|c| !c.locked && !c.request && c.kind != ChatKind::Community)
        .collect();
    let mut chat_rows: Vec<ChatRow> = open
        .iter()
        .filter(|c| find(&fold(&c.title), &q).is_some())
        .map(|c| row(c, messages, contacts))
        .collect();
    chat_rows.sort_by(|a, b| b.at.unwrap_or(i64::MIN).cmp(&a.at.unwrap_or(i64::MIN)));

    let mut hits: Vec<(i64, MessageHit)> = Vec::new();
    for c in &open {
        let Some(thread) = messages.get(&c.id) else {
            continue;
        };
        for m in thread.iter().rev() {
            let text = match &m.body {
                Body::Text(t) => t.as_str(),
                Body::Link { text, .. } => text.as_str(),
                Body::Image { caption, .. } | Body::Video { caption, .. } => caption.as_str(),
                Body::File { name, .. } => name.as_str(),
                Body::Poll { question, .. } => question.as_str(),
                Body::Event { title, .. } => title.as_str(),
                _ => continue,
            };
            let Some(at) = find(&fold(text), &q) else {
                continue;
            };
            let (before, matched, after) = cut(text, at, q.len());
            hits.push((
                m.at,
                MessageHit {
                    chat: c.id,
                    msg: m.id,
                    title: c.title.clone(),
                    seed: c.seed,
                    when: when_label(m.at),
                    before,
                    matched,
                    after,
                },
            ));
            if hits.len() >= MAX_MESSAGE_HITS * 4 {
                break;
            }
        }
    }
    hits.sort_by(|a, b| b.0.cmp(&a.0));
    hits.truncate(MAX_MESSAGE_HITS);

    // People whose chat is not already above.
    let people = contacts_az(chats, contacts, query)
        .into_iter()
        .filter(|p| !chat_rows.iter().any(|r| r.peer == Some(p.id)))
        .collect();

    Results {
        chats: chat_rows,
        messages: hits.into_iter().map(|(_, h)| h).collect(),
        contacts: people,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> (Vec<Chat>, HashMap<ChatId, Vec<Message>>, Vec<Contact>) {
        crate::store::Store::seed_parts()
    }

    #[test]
    fn inbox_pins_first_then_newest_and_hides_archived_requests_locked() {
        let (mut chats, m, ct) = data();
        chats.iter_mut().find(|c| c.id == 18).unwrap().locked = true;
        let r = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::All);
        assert!(r[0].pinned && r[1].pinned);
        assert!(r.iter().all(|x| !x.archived && !x.locked));
        assert!(!r.iter().any(|x| x.id == 15), "requests stay out");
        assert!(!r.iter().any(|x| x.id == 7), "community homes stay out");
        assert!(!r.iter().any(|x| x.id == 18), "locked chats stay out");
        let unpinned: Vec<i64> = r
            .iter()
            .filter(|x| !x.pinned)
            .filter_map(|x| x.at)
            .collect();
        assert!(unpinned.windows(2).all(|w| w[0] >= w[1]));
        let locked = rows(&chats, &m, &ct, ListScope::Locked, &Filter::All);
        assert_eq!(locked.len(), 1);
    }

    #[test]
    fn filters_pick_their_chats() {
        let (chats, m, ct) = data();
        let groups = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::Groups);
        assert!(groups.iter().all(|r| r.group && !r.channel));
        let channels = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::Channels);
        assert_eq!(channels.len(), 1);
        let family = rows(
            &chats,
            &m,
            &ct,
            ListScope::Inbox,
            &Filter::List("Family".into()),
        );
        assert!(
            family
                .iter()
                .all(|r| r.lists.contains(&"Family".to_string()))
                && family.len() == 2
        );
        let favs = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::Favourites);
        assert!(favs.iter().all(|r| r.favourite));
    }

    #[test]
    fn the_open_chat_hides_its_draft_and_voice_notes_are_marked() {
        let (chats, m, ct) = data();
        let r = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::All);
        let andrei = r.iter().find(|x| x.id == 13).unwrap();
        assert!(matches!(andrei.shown(false), Preview::Draft(_)));
        assert!(matches!(andrei.shown(true), Preview::Message { .. }));
        let mama = r.iter().find(|x| x.id == 11).unwrap();
        assert!(mama.voice && mama.disappearing);
        assert_eq!(
            cut_match("Ioana Ștefănescu", "stef"),
            Some(("Ioana ".into(), "Ștef".into(), "ănescu".into()))
        );
        assert_eq!(cut_match("Mama", "x"), None);
    }

    #[test]
    fn previews_say_who_typing_and_drafts() {
        let (mut chats, m, ct) = data();
        let fam = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::All)
            .into_iter()
            .find(|r| r.id == 2)
            .unwrap();
        assert_eq!(
            fam.preview_text(),
            ("Elena: ".into(), "Mihai says hi 👋".into())
        );
        assert!(fam.mention);
        let andrei = row(chats.iter().find(|c| c.id == 13).unwrap(), &m, &ct);
        assert!(matches!(andrei.preview, Preview::Draft(_)));
        let mihai = row(chats.iter().find(|c| c.id == 3).unwrap(), &m, &ct);
        assert!(matches!(
            mihai.preview,
            Preview::Message {
                tick: Some(Tick::Failed),
                sender: None,
                ..
            }
        ));
        assert!(mihai.failed() && mihai.spoken().contains("not sent"));
        chats.iter_mut().find(|c| c.id == 3).unwrap().typing = Some("typing…".into());
        let typing = row(chats.iter().find(|c| c.id == 3).unwrap(), &m, &ct);
        assert_eq!(typing.preview, Preview::Typing("typing…".into()));
        let ana = row(chats.iter().find(|c| c.id == 1).unwrap(), &m, &ct);
        assert!(ana.verified);
        let wa = row(chats.iter().find(|c| c.id == 14).unwrap(), &m, &ct);
        assert!(wa.whatsapp);
        assert!(
            ana.spoken()
                .starts_with("Ana Popescu, verified, pinned, 2 unread messages")
        );
    }

    #[test]
    fn archived_and_request_counts() {
        let (chats, m, ct) = data();
        assert_eq!(count(&chats, ListScope::Archived).0, 2);
        let req = requests(&chats, &m, &ct);
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].username, "deal.hunter.88");
        assert!(req[0].first.starts_with("Hi! You won"));
    }

    #[test]
    fn search_folds_case_and_diacritics_and_finds_messages() {
        let (chats, m, ct) = data();
        let r = search("stefanescu", &chats, &m, &ct);
        assert!(
            r.chats.iter().any(|c| c.title == "Ioana Ștefănescu"),
            "archived chats are found"
        );
        let r = search("BUDGET", &chats, &m, &ct);
        let hit = r
            .messages
            .iter()
            .find(|h| h.chat == 1)
            .expect("Ana's budget message");
        assert_eq!(hit.matched, "budget");
        assert!(r.messages.len() <= MAX_MESSAGE_HITS);
        let r = search("free phone", &chats, &m, &ct);
        assert!(r.messages.is_empty(), "message requests stay out of search");
        assert!(search("   ", &chats, &m, &ct).is_empty());
        assert!(search("zzzz-nothing", &chats, &m, &ct).is_empty());
        let r = search("priya", &chats, &m, &ct);
        assert!(
            r.contacts.is_empty(),
            "a contact with a chat shows as the chat"
        );
        let r = search("amélie", &chats, &m, &ct);
        assert_eq!(
            r.contacts.len(),
            1,
            "a contact without a chat shows under Contacts"
        );
    }

    #[test]
    fn locked_chats_stay_out_of_search() {
        let (mut chats, m, ct) = data();
        chats.iter_mut().find(|c| c.id == 1).unwrap().locked = true;
        let r = search("budget", &chats, &m, &ct);
        assert!(!r.messages.iter().any(|h| h.chat == 1));
        assert!(!r.chats.iter().any(|c| c.id == 1));
    }

    #[test]
    fn letters_skip_emoji_words() {
        assert_eq!(letters("Familia 🏡"), "Familia");
        assert_eq!(letters("Dr. Marin – Clinic"), "Dr. Marin Clinic");
        assert_eq!(letters("🏡"), "🏡");
    }

    #[test]
    fn cut_keeps_a_short_lead_in() {
        let (b, m, a) = cut(
            "The quick brown fox jumps over the lazy dog every day",
            40,
            3,
        );
        assert_eq!(m, "dog");
        assert!(b.starts_with('…'));
        assert_eq!(a, " every day");
        let (b, _, _) = cut("Hello world", 6, 5);
        assert_eq!(b, "Hello ");
    }

    #[test]
    fn contacts_are_a_to_z_without_strangers_or_blocked() {
        let (chats, _, mut ct) = data();
        ct.iter_mut().find(|c| c.id == 2).unwrap().blocked = true;
        let az = contacts_az(&chats, &ct, "");
        assert!(!az.iter().any(|c| c.id == 16 || c.id == 2));
        let names: Vec<String> = az
            .iter()
            .map(|c| fold(&c.name).into_iter().collect())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert_eq!(contacts_az(&chats, &ct, "lukas").len(), 1);
    }

    #[test]
    fn list_names_keep_the_users_order() {
        let (chats, _, _) = data();
        let names = list_names(
            &[
                "Family".into(),
                "Work".into(),
                "Friends".into(),
                "Gym".into(),
            ],
            &chats,
        );
        assert_eq!(names, vec!["Family", "Work", "Friends", "Gym"]);
        assert_eq!(list_names(&[], &chats), vec!["Work", "Family", "Friends"]);
    }

    #[test]
    fn pinned_people_leave_the_list_in_the_users_order() {
        let (chats, m, ct) = data();
        let order: Vec<ChatId> = chats.iter().map(|c| c.id).collect();
        let all = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::All);
        let n = all.len();
        let inbox = inbox(all, &order, false, false, false);
        assert_eq!(
            inbox.pinned.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(inbox.needs.is_empty(), "phones have no triage");
        assert!(inbox.recent.iter().all(|r| !r.pinned));
        assert_eq!(inbox.pinned.len() + inbox.recent.len(), n);
    }

    #[test]
    fn more_than_eight_pins_stay_in_the_list() {
        let (mut chats, m, ct) = data();
        for c in chats.iter_mut().filter(|c| !c.request && !c.archived) {
            c.pinned = true;
        }
        let order: Vec<ChatId> = chats.iter().map(|c| c.id).collect();
        let all = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::All);
        let inbox = inbox(all, &order, false, false, false);
        assert_eq!(inbox.pinned.len(), MAX_PINNED);
        assert!(inbox.recent.iter().any(|r| r.pinned));
    }

    #[test]
    fn needs_a_reply_is_theirs_unread_and_loud_or_a_mention() {
        let (chats, m, ct) = data();
        let order: Vec<ChatId> = chats.iter().map(|c| c.id).collect();
        let all = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::All);
        let inbox = inbox(all, &order, false, true, false);
        assert!(inbox.needs.iter().all(ChatRow::needs_reply));
        assert!(inbox.recent.iter().all(|r| !r.needs_reply()));
        assert!(
            !inbox.needs.iter().any(|r| r.id == 4),
            "a muted chat never needs a reply"
        );
        assert!(inbox.needs.len() <= MAX_NEEDS);
        let at: Vec<i64> = inbox.needs.iter().filter_map(|r| r.at).collect();
        assert!(at.windows(2).all(|w| w[0] >= w[1]));
    }

    #[test]
    fn needs_a_reply_cuts_at_five_until_show_all() {
        let (mut chats, mut m, ct) = data();
        // Every chat unread, with someone else's message last.
        for c in chats.iter_mut() {
            c.unread = 1;
            c.muted = false;
            c.pinned = false;
        }
        for thread in m.values_mut() {
            if let Some(last) = thread.last_mut() {
                last.from = Some(1);
                last.body = Body::Text("hi".into());
            }
        }
        let order: Vec<ChatId> = chats.iter().map(|c| c.id).collect();
        let all = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::All);
        let cut = inbox(all.clone(), &order, false, true, false);
        assert_eq!(cut.needs.len(), MAX_NEEDS);
        assert!(cut.more_needs > 0);
        let full = inbox(all, &order, false, true, true);
        assert_eq!(full.needs.len(), MAX_NEEDS + cut.more_needs);
        assert_eq!(full.more_needs, 0);
    }

    #[test]
    fn unread_keeps_only_unread_chats_pinned_included() {
        let (chats, m, ct) = data();
        let order: Vec<ChatId> = chats.iter().map(|c| c.id).collect();
        let all = rows(&chats, &m, &ct, ListScope::Inbox, &Filter::All);
        let inbox = inbox(all, &order, true, false, false);
        assert!(!inbox.is_empty());
        assert!(
            inbox
                .pinned
                .iter()
                .chain(&inbox.recent)
                .all(ChatRow::is_unread)
        );
        let (title, _) = Filter::List("Work".into()).empty_copy(true);
        assert_eq!(title, "Nothing unread in Work");
    }
}
