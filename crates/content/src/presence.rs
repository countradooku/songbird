//! Presence, last seen and nudges (PROTOCOL §10.5; Prompt 9, M3, D-0104).
//!
//! The server never says who is online. Each app tells its allowed contacts itself:
//!
//! - **Presence** (`Content.presence`) goes **sealed** in one batch to every allowed contact's
//!   devices (`PUT /v1/ephemeral/sealed`), never stored, delivered to online devices only.
//! - **Last seen** rides in the same message when the app goes to the background ("offline at
//!   this minute"). A contact who was offline all along keeps the last value it saw (or shows
//!   "last seen recently"): no server state (D-0101 question 4).
//! - **Invisible** sends nothing at all: not "online", not "offline", not a reply.
//! - **Nudges** (`Content.attention`) go identified, one device at a time, in the server's
//!   attention class (frame `0x04`), held to budgets per pair of accounts. A nudge to an offline
//!   contact is lost, as Yahoo's buzz was.
//!
//! [`Presencer`] holds the sender's rules (who may see what, debouncing, reply once), as a pure
//! state machine every app reproduces; the tests prove that invisible sends nothing and that the
//! last change is always sent.

use std::collections::{BTreeMap, BTreeSet};

/// The smallest gap between two presence batches from one device.
pub const DEBOUNCE_MS: u64 = 5_000;
/// A device answers one contact's "online" at most this often.
pub const REPLY_EVERY_MS: u64 = 60_000;
/// Last seen is told to the minute, never finer.
pub const LAST_SEEN_GRAIN_MS: u64 = 60_000;

/// A presence state on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum State {
    /// Not set (invalid on the wire).
    Unspecified = 0,
    /// The app is in the foreground.
    Online = 1,
    /// The user set "away".
    Away = 2,
    /// The user set "busy".
    Busy = 3,
    /// The app went to the background; `last_seen_ms` is set.
    Offline = 4,
}

/// `Content.presence` (tag 17).
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Presence {
    /// The state.
    #[prost(enumeration = "State", tag = "1")]
    pub state: i32,
    /// When last seen, to the minute (with [`State::Offline`]; 0 when not shared).
    #[prost(uint64, tag = "2")]
    pub last_seen_ms: u64,
    /// The sender just came online and asks online contacts for their state, once.
    #[prost(bool, tag = "3")]
    pub wants_reply: bool,
}

/// What an attention event is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AttentionKind {
    /// Not set (invalid).
    Unspecified = 0,
    /// A nudge (Yahoo's buzz): shake the chat window or vibrate.
    Nudge = 1,
}

/// `Content.attention` (tag 18): sent in the attention class.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Attention {
    /// The kind.
    #[prost(enumeration = "AttentionKind", tag = "1")]
    pub kind: i32,
}

/// What the user chose for themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Online when the app is in the foreground.
    Online,
    /// Away.
    Away,
    /// Busy.
    Busy,
    /// Invisible: nothing is ever sent.
    Invisible,
}

/// Who may see something (the privacy settings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// Every contact (and nobody else: only contacts hold the access keys).
    Contacts,
    /// Nobody.
    Nobody,
}

/// What [`Presencer`] decided to send now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// The message.
    pub presence: Presence,
    /// To whom (accounts; the app addresses all their devices in one sealed batch).
    pub to: BTreeSet<[u8; 16]>,
}

/// The sender's presence rules.
#[derive(Clone, Debug)]
pub struct Presencer {
    choice: Choice,
    online_audience: Audience,
    last_seen_audience: Audience,
    contacts: BTreeSet<[u8; 16]>,
    foreground: bool,
    last_sent_ms: Option<u64>,
    /// The state to send once the debounce allows (the latest wins).
    due: Option<Presence>,
    last_sent: Option<Presence>,
    replied: BTreeMap<[u8; 16], u64>,
}

impl Presencer {
    /// The rules with the user's choices and contacts.
    #[must_use]
    pub fn new(
        choice: Choice,
        online_audience: Audience,
        last_seen_audience: Audience,
        contacts: BTreeSet<[u8; 16]>,
    ) -> Self {
        Self {
            choice,
            online_audience,
            last_seen_audience,
            contacts,
            foreground: false,
            last_sent_ms: None,
            due: None,
            last_sent: None,
            replied: BTreeMap::new(),
        }
    }

    /// Whether anything at all may be sent.
    fn silent(&self) -> bool {
        self.choice == Choice::Invisible
            || (self.online_audience == Audience::Nobody
                && self.last_seen_audience == Audience::Nobody)
    }

    fn current(&self, now_ms: u64, wants_reply: bool) -> Option<Presence> {
        if self.silent() {
            return None;
        }
        let (state, last_seen_ms) = if self.foreground {
            if self.online_audience == Audience::Nobody {
                return None;
            }
            let s = match self.choice {
                Choice::Away => State::Away,
                Choice::Busy => State::Busy,
                Choice::Online | Choice::Invisible => State::Online,
            };
            (s, 0)
        } else {
            let seen = if self.last_seen_audience == Audience::Contacts {
                now_ms - now_ms % LAST_SEEN_GRAIN_MS
            } else {
                0
            };
            (State::Offline, seen)
        };
        Some(Presence {
            state: i32::from(state),
            last_seen_ms,
            wants_reply,
        })
    }

    fn queue(&mut self, p: Option<Presence>) {
        if let Some(p) = p {
            self.due = Some(p);
        }
    }

    /// The app came to the foreground.
    pub fn foreground(&mut self, now_ms: u64) {
        self.foreground = true;
        let p = self.current(now_ms, true);
        self.queue(p);
    }

    /// The app went to the background.
    pub fn background(&mut self, now_ms: u64) {
        self.foreground = false;
        let p = self.current(now_ms, false);
        self.queue(p);
    }

    /// The user changed their choice. Turning invisible drops anything not yet sent.
    pub fn set_choice(&mut self, choice: Choice, now_ms: u64) {
        self.choice = choice;
        if self.silent() {
            self.due = None;
            return;
        }
        let p = self.current(now_ms, false);
        self.queue(p);
    }

    /// The user changed who may see their presence and last seen.
    pub fn set_audiences(&mut self, online: Audience, last_seen: Audience, now_ms: u64) {
        self.online_audience = online;
        self.last_seen_audience = last_seen;
        if self.silent() {
            self.due = None;
            return;
        }
        let p = self.current(now_ms, false);
        self.queue(p);
    }

    /// The contact list changed (saved contacts, accepted requests).
    pub fn set_contacts(&mut self, contacts: BTreeSet<[u8; 16]>) {
        self.contacts = contacts;
    }

    /// A contact's presence arrived: answer once (a fresh contact asks), at most every
    /// [`REPLY_EVERY_MS`] per contact, only while this device is visible and in the foreground.
    pub fn received(&mut self, from: [u8; 16], p: &Presence, now_ms: u64) -> Option<Outgoing> {
        if !p.wants_reply || !self.contacts.contains(&from) || !self.foreground {
            return None;
        }
        if self
            .replied
            .get(&from)
            .is_some_and(|t| now_ms.saturating_sub(*t) < REPLY_EVERY_MS)
        {
            return None;
        }
        let presence = self.current(now_ms, false)?;
        self.replied.insert(from, now_ms);
        Some(Outgoing {
            presence,
            to: BTreeSet::from([from]),
        })
    }

    /// What to send now, if anything: the latest due state, at most once per [`DEBOUNCE_MS`],
    /// and never the same state twice in a row.
    pub fn poll(&mut self, now_ms: u64) -> Option<Outgoing> {
        let due = self.due.clone()?;
        if self.silent() {
            self.due = None;
            return None;
        }
        if self
            .last_sent_ms
            .is_some_and(|t| now_ms.saturating_sub(t) < DEBOUNCE_MS)
        {
            return None;
        }
        self.due = None;
        if self.last_sent.as_ref().is_some_and(|l| {
            l.state == due.state && l.last_seen_ms == due.last_seen_ms && !due.wants_reply
        }) {
            return None;
        }
        if self.contacts.is_empty() {
            return None;
        }
        self.last_sent_ms = Some(now_ms);
        self.last_sent = Some(due.clone());
        Some(Outgoing {
            presence: due,
            to: self.contacts.clone(),
        })
    }

    /// When [`Presencer::poll`] should be called next (a due state waiting out the debounce).
    #[must_use]
    pub fn next_poll(&self) -> Option<u64> {
        self.due.as_ref()?;
        Some(self.last_sent_ms.map_or(0, |t| t + DEBOUNCE_MS))
    }
}

/// WhatsApp's reciprocity: a user who shares their last seen with nobody sees nobody's.
#[must_use]
pub fn may_show_last_seen(own: Audience) -> bool {
    own == Audience::Contacts
}

/// What a contact's presence shows at `now_ms`, from what the app last received.
#[must_use]
pub fn shown(p: &Presence) -> Option<State> {
    State::try_from(p.state)
        .ok()
        .filter(|s| *s != State::Unspecified)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use super::*;
    use proptest::prelude::*;

    fn contacts() -> BTreeSet<[u8; 16]> {
        BTreeSet::from([[1; 16], [2; 16]])
    }

    #[test]
    fn going_online_then_away_sends_both_debounced() {
        let mut p = Presencer::new(
            Choice::Online,
            Audience::Contacts,
            Audience::Contacts,
            contacts(),
        );
        p.foreground(1_000);
        let first = p.poll(1_000).unwrap();
        assert_eq!(first.presence.state, i32::from(State::Online));
        assert!(first.presence.wants_reply);
        assert_eq!(first.to, contacts());
        p.set_choice(Choice::Away, 2_000);
        assert_eq!(p.poll(2_000), None, "debounced");
        assert_eq!(p.next_poll(), Some(6_000));
        assert_eq!(
            p.poll(6_000).unwrap().presence.state,
            i32::from(State::Away)
        );
        p.background(70_123);
        let off = p.poll(70_123).unwrap();
        assert_eq!(off.presence.state, i32::from(State::Offline));
        assert_eq!(off.presence.last_seen_ms, 60_000, "to the minute");
    }

    #[test]
    fn last_seen_shared_with_nobody_is_left_out() {
        let mut p = Presencer::new(
            Choice::Online,
            Audience::Contacts,
            Audience::Nobody,
            contacts(),
        );
        p.background(100_000);
        assert_eq!(p.poll(100_000).unwrap().presence.last_seen_ms, 0);
        assert!(!may_show_last_seen(Audience::Nobody));
    }

    #[test]
    fn replies_go_once_per_contact_and_only_when_visible() {
        let mut p = Presencer::new(
            Choice::Busy,
            Audience::Contacts,
            Audience::Contacts,
            contacts(),
        );
        p.foreground(0);
        let _ = p.poll(0);
        let ask = Presence {
            state: i32::from(State::Online),
            last_seen_ms: 0,
            wants_reply: true,
        };
        let r = p.received([1; 16], &ask, 10).unwrap();
        assert_eq!(r.to, BTreeSet::from([[1; 16]]));
        assert_eq!(r.presence.state, i32::from(State::Busy));
        assert!(!r.presence.wants_reply);
        assert_eq!(p.received([1; 16], &ask, 20), None);
        assert_eq!(p.received([9; 16], &ask, 20), None, "not a contact");
        p.set_choice(Choice::Invisible, 30);
        assert_eq!(p.received([2; 16], &ask, 30), None);
    }

    #[derive(Debug, Clone)]
    enum Ev {
        Fg,
        Bg,
        Choose(u8),
        Audiences(bool, bool),
        Ask(u8),
        Tick(u64),
    }

    fn ev() -> impl Strategy<Value = Ev> {
        prop_oneof![
            Just(Ev::Fg),
            Just(Ev::Bg),
            (0u8..4).prop_map(Ev::Choose),
            (any::<bool>(), any::<bool>()).prop_map(|(a, b)| Ev::Audiences(a, b)),
            (0u8..3).prop_map(Ev::Ask),
            (0u64..20_000).prop_map(Ev::Tick),
        ]
    }

    fn choice(c: u8) -> Choice {
        match c {
            0 => Choice::Online,
            1 => Choice::Away,
            2 => Choice::Busy,
            _ => Choice::Invisible,
        }
    }

    proptest! {
        #[test]
        fn invisible_never_sends_anything(evs in proptest::collection::vec(ev(), 0..60)) {
            let mut p = Presencer::new(Choice::Invisible, Audience::Contacts, Audience::Contacts, contacts());
            let mut now = 0u64;
            for e in evs {
                match e {
                    Ev::Fg => p.foreground(now),
                    Ev::Bg => p.background(now),
                    Ev::Choose(_) => p.set_choice(Choice::Invisible, now),
                    Ev::Audiences(a, b) => p.set_audiences(
                        if a { Audience::Contacts } else { Audience::Nobody },
                        if b { Audience::Contacts } else { Audience::Nobody },
                        now,
                    ),
                    Ev::Ask(c) => {
                        let ask = Presence { state: 1, last_seen_ms: 0, wants_reply: true };
                        prop_assert_eq!(p.received([c; 16], &ask, now), None);
                    }
                    Ev::Tick(t) => now += t,
                }
                prop_assert_eq!(p.poll(now), None);
            }
        }

        #[test]
        fn sends_are_debounced_and_the_last_state_is_always_sent(
            evs in proptest::collection::vec(ev(), 1..60),
        ) {
            let mut p = Presencer::new(Choice::Online, Audience::Contacts, Audience::Contacts, contacts());
            let mut now = 0u64;
            let mut sent: Vec<(u64, Presence)> = Vec::new();
            for e in evs {
                match e {
                    Ev::Fg => p.foreground(now),
                    Ev::Bg => p.background(now),
                    Ev::Choose(c) => p.set_choice(choice(c), now),
                    Ev::Audiences(a, b) => p.set_audiences(
                        if a { Audience::Contacts } else { Audience::Nobody },
                        if b { Audience::Contacts } else { Audience::Nobody },
                        now,
                    ),
                    Ev::Ask(_) | Ev::Tick(_) => {}
                }
                if let Ev::Tick(t) = e { now += t; }
                if let Some(o) = p.poll(now) { sent.push((now, o.presence)); }
            }
            for w in sent.windows(2) {
                prop_assert!(w[1].0 - w[0].0 >= DEBOUNCE_MS);
            }
            // After the debounce, whatever is due goes out (or nothing is due).
            if let Some(at) = p.next_poll() {
                let o = p.poll(at.max(now));
                let silent = p.silent();
                prop_assert!(o.is_some() || silent || p.last_sent.is_some());
            }
            prop_assert_eq!(p.next_poll(), None);
        }
    }
}
