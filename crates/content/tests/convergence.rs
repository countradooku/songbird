//! The Prompt 4 gate's convergence item: polls, reactions, RSVPs, edits, deletes, pins, timers and
//! policies reach the same state on every device, whatever order the operations arrive in and
//! however often they repeat; message status only moves forward, whatever order receipts arrive
//! in. Each property applies one random set of operations in two random orders, the second with
//! random duplicates, and compares both the internal state and what the app shows.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::needless_for_each,
    clippy::as_conversions,
    reason = "tests"
)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use songbird_content::schema::{
    ChatPolicy, Delete, Edit, MessageRef, Pin, PollClose, PollCreate, PollVote, Reaction, Rsvp,
    Text, TimerChange, VoteHead,
};
use songbird_content::state::chat::Chat;
use songbird_content::state::edits::{Deletes, Edits};
use songbird_content::state::lww::{Reactions, Rsvps};
use songbird_content::state::poll::Poll;
use songbird_content::state::status::{Level, Outgoing, Status};
use songbird_content::state::{Account, MsgKey, Stamp};

const AUTHOR: Account = [0xA0; 16];

fn acct(i: u8) -> Account {
    [i; 16]
}

fn msg(a: u8, m: u8) -> MessageRef {
    MessageRef {
        author: vec![a; 16],
        message_id: vec![m; 16],
    }
}

fn key(a: u8, m: u8) -> MsgKey {
    MsgKey::from_ref(&msg(a, m)).unwrap()
}

/// Two orders of the same operations: a shuffle, and another shuffle with random repeats.
fn two_orders<T: Clone + std::fmt::Debug>(
    ops: impl Strategy<Value = Vec<T>>,
) -> impl Strategy<Value = (Vec<T>, Vec<T>)> {
    ops.prop_flat_map(|v| {
        let n = v.len();
        (
            Just(v.clone()).prop_shuffle(),
            (Just(v), proptest::collection::vec(0..n.max(1), 0..=n)).prop_flat_map(
                |(mut v, dups)| {
                    let extra: Vec<T> = dups.iter().filter_map(|i| v.get(*i).cloned()).collect();
                    v.extend(extra);
                    Just(v).prop_shuffle()
                },
            ),
        )
    })
}

#[derive(Debug, Clone)]
enum PollOp {
    Create(bool),
    Vote(u8, u64, Vec<u32>),
    Close(Account, u64, Vec<(u8, u64)>),
}

fn poll_ops() -> impl Strategy<Value = Vec<PollOp>> {
    let vote = (1u8..6, 1u64..6, proptest::collection::vec(0u32..6, 0..4))
        .prop_map(|(v, c, o)| PollOp::Vote(v, c, o));
    let close = (
        prop_oneof![Just(AUTHOR), Just(acct(1))],
        0u64..1000,
        proptest::collection::vec((1u8..6, 1u64..6), 0..5),
    )
        .prop_map(|(who, at, heads)| PollOp::Close(who, at, heads));
    (
        any::<bool>(),
        proptest::collection::vec(prop_oneof![4 => vote, 1 => close], 0..24),
    )
        .prop_map(|(multiple, mut ops)| {
            ops.push(PollOp::Create(multiple));
            ops
        })
}

fn apply_poll(p: &mut Poll, op: &PollOp) {
    match op {
        PollOp::Create(multiple) => p.create(
            AUTHOR,
            &PollCreate {
                question: "q".into(),
                options: vec!["a".into(), "b".into(), "c".into(), "d".into()],
                multiple_choice: *multiple,
            },
        ),
        PollOp::Vote(v, counter, options) => {
            let mut o = options.clone();
            o.sort_unstable();
            o.dedup();
            p.vote(
                acct(*v),
                &PollVote {
                    poll: Some(msg(0xA0, 1)),
                    options: o,
                    counter: *counter,
                },
            );
        }
        PollOp::Close(who, at, heads) => {
            let mut seen = BTreeSet::new();
            p.close(
                *who,
                Stamp {
                    at_ms: *at,
                    author: *who,
                    id: [2; 16],
                },
                &PollClose {
                    // Some closes name another poll.
                    poll: Some(msg(0xA0, if *at % 5 == 0 { 9 } else { 1 })),
                    heads: heads
                        .iter()
                        .filter(|(v, _)| seen.insert(*v))
                        .map(|(v, c)| VoteHead {
                            voter: vec![*v; 16],
                            counter: *c,
                        })
                        .collect(),
                },
            );
        }
    }
}

#[derive(Debug, Clone)]
struct LwwOp(u8, u8, u64, u8);

fn lww_ops() -> impl Strategy<Value = Vec<LwwOp>> {
    proptest::collection::vec(
        (1u8..5, 1u8..3, 1u64..6, 0u8..4).prop_map(|(a, t, c, v)| LwwOp(a, t, c, v)),
        0..30,
    )
}

#[derive(Debug, Clone)]
enum EditOp {
    Edit(bool, u32, u64, u8),
    Delete(bool, u64),
}

fn edit_ops() -> impl Strategy<Value = Vec<EditOp>> {
    let day = 24 * 3600 * 1000u64;
    proptest::collection::vec(
        prop_oneof![
            (any::<bool>(), 1u32..5, 0u64..2 * day, 0u8..3)
                .prop_map(|(own, r, at, t)| EditOp::Edit(own, r, at, t)),
            (any::<bool>(), 0u64..2 * day).prop_map(|(own, at)| EditOp::Delete(own, at)),
        ],
        0..20,
    )
}

#[derive(Debug, Clone)]
enum ChatOp {
    Pin(u8, u64, u8, bool, u8),
    Timer(u8, u64, u32),
    Policy(u8, u64, bool, bool),
}

fn chat_ops() -> impl Strategy<Value = Vec<ChatOp>> {
    proptest::collection::vec(
        prop_oneof![
            (1u8..4, 0u64..1000, 1u8..6, any::<bool>(), 0u8..3)
                .prop_map(|(a, t, m, u, d)| ChatOp::Pin(a, t, m, u, d)),
            (
                1u8..4,
                0u64..1000,
                prop_oneof![Just(0u32), Just(60), Just(86_400)]
            )
                .prop_map(|(a, t, s)| ChatOp::Timer(a, t, s)),
            (1u8..4, 0u64..1000, any::<bool>(), any::<bool>())
                .prop_map(|(a, t, e, s)| ChatOp::Policy(a, t, e, s)),
        ],
        0..30,
    )
}

fn stamp(a: u8, at: u64, salt: u8) -> Stamp {
    Stamp {
        at_ms: at,
        author: acct(a),
        id: [salt; 16],
    }
}

fn apply_chat(c: &mut Chat, op: &ChatOp) {
    match op {
        ChatOp::Pin(a, t, m, unpin, d) => c.pin(
            stamp(*a, *t, *m),
            &Pin {
                target: Some(msg(9, *m)),
                unpin: *unpin,
                duration_s: if *unpin {
                    0
                } else {
                    [86_400, 604_800, 2_592_000][usize::from(*d)]
                },
            },
        ),
        ChatOp::Timer(a, t, s) => {
            c.timer_change(stamp(*a, *t, 0x71), &TimerChange { expire_timer_s: *s });
        }
        ChatOp::Policy(a, t, e, s) => c.policy_change(
            stamp(*a, *t, 0x72),
            &ChatPolicy {
                restrict_export: *e,
                restrict_auto_save: *s,
            },
        ),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn polls_converge_in_any_order((a, b) in two_orders(poll_ops())) {
        let k = MsgKey { author: AUTHOR, id: [1; 16] };
        let (mut x, mut y) = (Poll::new(k), Poll::new(k));
        a.iter().for_each(|op| apply_poll(&mut x, op));
        b.iter().for_each(|op| apply_poll(&mut y, op));
        prop_assert_eq!(&x, &y);
        prop_assert_eq!(x.tally(), y.tally());
        let t = x.tally().unwrap();
        // Single choice never counts more votes than voters.
        let voters: BTreeSet<_> = t.voters.iter().flatten().collect();
        prop_assert!(t.counts.iter().sum::<u32>() as usize >= voters.len());
    }

    #[test]
    fn reactions_and_rsvps_converge_in_any_order((a, b) in two_orders(lww_ops())) {
        let emoji = ["", "👍", "❤️", "😂"];
        let run = |ops: &[LwwOp]| {
            let (mut r, mut v) = (Reactions::default(), Rsvps::default());
            for LwwOp(who, t, c, val) in ops {
                r.apply(acct(*who), &Reaction {
                    target: Some(msg(7, *t)),
                    emoji: emoji[usize::from(*val)].into(),
                    remove: *val == 0,
                    counter: *c,
                });
                v.apply(acct(*who), &Rsvp {
                    event: Some(msg(7, *t)),
                    answer: i32::from(*val % 3 + 1),
                    counter: *c,
                });
            }
            (r, v)
        };
        let (x, y) = (run(&a), run(&b));
        prop_assert_eq!(&x, &y);
        for t in 1..3 {
            prop_assert_eq!(x.0.summary(&key(7, t)), y.0.summary(&key(7, t)));
            prop_assert_eq!(x.1.summary(&key(7, t)), y.1.summary(&key(7, t)));
        }
    }

    #[test]
    fn edits_and_deletes_converge_in_any_order((a, b) in two_orders(edit_ops())) {
        let original = key(0x31, 0x32);
        let sent = 1_000;
        let run = |ops: &[EditOp]| {
            let (mut e, mut d) = (Edits::default(), Deletes::default());
            for op in ops {
                match op {
                    EditOp::Edit(own, rev, at, t) => e.apply(
                        if *own { original.author } else { acct(1) },
                        sent + at,
                        &Edit {
                            target_message_id: original.id.to_vec(),
                            text: Some(Text { body: format!("v{t}"), spans: vec![] }),
                            revision: *rev,
                        },
                    ),
                    EditOp::Delete(own, at) => d.apply(
                        if *own { original.author } else { acct(1) },
                        sent + at,
                        &Delete { target: Some(msg(0x31, 0x32)) },
                    ),
                }
            }
            (e, d)
        };
        let (x, y) = (run(&a), run(&b));
        prop_assert_eq!(&x, &y);
        prop_assert_eq!(x.0.history(&original, sent), y.0.history(&original, sent));
        let none = |_: &Account| false;
        prop_assert_eq!(
            x.1.is_deleted(&original, sent, &none),
            y.1.is_deleted(&original, sent, &none)
        );
        // Only the author's edits within 24 hours are ever shown.
        for (rev, _) in x.0.history(&original, sent) {
            prop_assert!(a.iter().any(|op| matches!(op,
                EditOp::Edit(true, r, at, _) if *r == rev && *at <= 24 * 3600 * 1000)));
        }
    }

    #[test]
    fn pins_timers_and_policies_converge_in_any_order((a, b) in two_orders(chat_ops())) {
        let (mut x, mut y) = (Chat::default(), Chat::default());
        a.iter().for_each(|op| apply_chat(&mut x, op));
        b.iter().for_each(|op| apply_chat(&mut y, op));
        prop_assert_eq!(&x, &y);
        for now in [0, 500, 86_400_000, 700_000_000, 3_000_000_000] {
            let p = x.pinned(now);
            prop_assert!(p.len() <= 3);
            prop_assert_eq!(p, y.pinned(now));
        }
        prop_assert_eq!(x.timer(), y.timer());
        prop_assert_eq!(x.policy(), y.policy());
    }

    #[test]
    fn statuses_only_move_forward_in_any_receipt_order(
        (a, b) in two_orders(proptest::collection::vec((1u8..6, 0u8..3), 0..20)),
        accepted_at in 0usize..20,
        read_receipts in any::<bool>(),
    ) {
        let audience: BTreeSet<Account> = (1..5).map(acct).collect();
        let run = |ops: &[(u8, u8)]| {
            let mut o = Outgoing::new(audience.iter().copied());
            let mut seen = vec![o.status(&audience, read_receipts)];
            for (i, (who, lvl)) in ops.iter().enumerate() {
                if i == accepted_at {
                    o.accepted();
                }
                let level = [Level::Delivered, Level::Read, Level::Played][usize::from(*lvl)];
                // Account 5 is outside the audience: ignored.
                o.receipt(acct(*who), level);
                seen.push(o.status(&audience, read_receipts));
            }
            o.accepted();
            seen.push(o.status(&audience, read_receipts));
            (o, seen)
        };
        let ((x, sx), (y, sy)) = (run(&a), run(&b));
        prop_assert_eq!(&x, &y);
        prop_assert_eq!(sx.last(), sy.last());
        for s in [&sx, &sy] {
            for w in s.windows(2) {
                // Forward only (Sending moves to Sent or beyond, never back).
                prop_assert!(w[1] >= w[0], "{:?}", s);
            }
            if !read_receipts {
                prop_assert!(*s.last().unwrap() <= Status::Delivered);
            }
        }
    }
}
