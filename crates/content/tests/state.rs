//! Known cases of the state semantics: poll closing, group "Message info" with members joining
//! and leaving, receipt batching and coalescing, the reciprocal read-receipt setting.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::collections::BTreeSet;

use songbird_content::schema::{MessageRef, PollClose, PollCreate, PollVote, VoteHead};
use songbird_content::state::poll::Poll;
use songbird_content::state::receipts::{ChatKey, Coalescer};
use songbird_content::state::status::{Level, Outgoing, Status};
use songbird_content::state::{Account, MsgKey, Stamp};

fn acct(i: u8) -> Account {
    [i; 16]
}

fn set(ids: &[u8]) -> BTreeSet<Account> {
    ids.iter().map(|i| acct(*i)).collect()
}

fn vote(p: &mut Poll, voter: u8, counter: u64, options: &[u32]) {
    p.vote(
        acct(voter),
        &PollVote {
            poll: Some(MessageRef {
                author: vec![1; 16],
                message_id: vec![2; 16],
            }),
            options: options.to_vec(),
            counter,
        },
    );
}

#[test]
fn a_closed_poll_counts_exactly_the_votes_its_author_saw() {
    let mut p = Poll::new(MsgKey {
        author: acct(1),
        id: [2; 16],
    });
    // Votes before the poll is known are kept.
    vote(&mut p, 3, 1, &[0]);
    assert!(p.tally().is_none());
    p.create(
        acct(1),
        &PollCreate {
            question: "Lunch?".into(),
            options: vec!["Pizza".into(), "Sushi".into()],
            multiple_choice: false,
        },
    );
    vote(&mut p, 4, 1, &[1]);
    vote(&mut p, 4, 2, &[0]);
    // Two options in a single-choice poll count as no vote.
    vote(&mut p, 5, 1, &[0, 1]);
    let t = p.tally().unwrap();
    assert_eq!(t.counts, vec![2, 0]);
    assert!(!t.closed);

    let close = |who: u8, heads: &[(u8, u64)]| PollClose {
        poll: Some(MessageRef {
            author: vec![who; 16],
            message_id: vec![2; 16],
        }),
        heads: heads
            .iter()
            .map(|(v, c)| VoteHead {
                voter: vec![*v; 16],
                counter: *c,
            })
            .collect(),
    };
    let at = |ms| Stamp {
        at_ms: ms,
        author: acct(1),
        id: [9; 16],
    };
    // A stranger cannot close it, whatever it claims, nor can a close of another poll.
    p.close(acct(7), at(10), &close(7, &[]));
    p.close(acct(7), at(11), &close(1, &[]));
    p.close(
        acct(7),
        at(12),
        &PollClose {
            poll: None,
            heads: Vec::new(),
        },
    );
    assert!(!p.tally().unwrap().closed);
    // The author saw voter 4 at counter 1 and voter 3: those votes count, nobody else's.
    p.close(acct(1), at(10), &close(1, &[(4, 1), (3, 1)]));
    // A later vote changes nothing.
    vote(&mut p, 3, 5, &[1]);
    let t = p.tally().unwrap();
    assert!(t.closed);
    assert_eq!(t.counts, vec![1, 1]);
    assert_eq!(t.voters[0], vec![acct(3)]);
    assert_eq!(t.voters[1], vec![acct(4)]);
}

#[test]
fn group_ticks_wait_for_every_member_who_is_still_there() {
    let mut o = Outgoing::new(set(&[1, 2, 3]));
    let now = set(&[1, 2, 3]);
    assert_eq!(o.status(&now, true), Status::Sending);
    o.accepted();
    assert_eq!(o.status(&now, true), Status::Sent);
    o.receipt(acct(1), Level::Read);
    o.receipt(acct(2), Level::Delivered);
    assert_eq!(o.status(&now, true), Status::Sent, "3 has nothing yet");
    o.receipt(acct(3), Level::Delivered);
    assert_eq!(o.status(&now, true), Status::Delivered);

    // 2 leaves before reading: no longer waited for. 4 joins after the send: never counted.
    let now = set(&[1, 3, 4]);
    o.receipt(acct(4), Level::Delivered);
    o.receipt(acct(3), Level::Read);
    assert_eq!(o.status(&now, true), Status::Read);
    assert_eq!(o.info(&now).len(), 2);
    assert_eq!(o.info(&now)[&acct(1)], Some(Level::Read));

    // Reciprocal setting: off shows at most two ticks.
    assert_eq!(o.status(&now, false), Status::Delivered);

    // Everyone left: one tick, the server stored it.
    assert_eq!(o.status(&set(&[9]), true), Status::Sent);
}

#[test]
fn a_receipt_lifts_a_message_marked_failed() {
    let mut o = Outgoing::new(set(&[1]));
    o.failed();
    assert_eq!(o.status(&set(&[1]), true), Status::Failed);
    o.receipt(acct(1), Level::Delivered);
    assert_eq!(o.status(&set(&[1]), true), Status::Delivered);
}

fn m(author: u8, id: u16) -> MsgKey {
    let mut i = [0; 16];
    i[..2].copy_from_slice(&id.to_be_bytes());
    MsgKey {
        author: acct(author),
        id: i,
    }
}

#[test]
fn opening_a_chat_with_200_unread_messages_sends_one_read_receipt() {
    let mut c = Coalescer::new(1_000, true);
    let chat = ChatKey::Direct(acct(2));
    let read: Vec<(MsgKey, u64)> = (0..200).map(|i| (m(2, i), u64::from(i))).collect();
    c.read(chat, &read, 0);
    assert_eq!(c.due(999).0.len(), 0, "still inside the window");
    let (receipts, syncs) = c.due(1_000);
    assert_eq!(receipts.len(), 1);
    let r = &receipts[0];
    assert_eq!(r.author, acct(2));
    assert_eq!(r.receipt.kind, 2);
    assert_eq!(r.receipt.message_ids.len(), 0);
    assert_eq!(r.receipt.up_to, m(2, 199).id.to_vec());
    // The reader's own devices learn every message read, in one sync message.
    assert_eq!(syncs.len(), 1);
    assert_eq!(syncs[0].marks.len(), 200);
}

#[test]
fn group_receipts_go_to_each_author_only_and_batch_per_window() {
    let mut c = Coalescer::new(1_000, true);
    let g = ChatKey::Group([7; 16]);
    for i in 0..600u16 {
        // Three authors; 600 messages delivered within one window.
        c.delivered(g, m(u8::try_from(i % 3).unwrap() + 1, i), u64::from(i));
    }
    let (receipts, syncs) = c.due(2_000);
    assert_eq!(syncs.len(), 0);
    // 200 per author fit one receipt each.
    assert_eq!(receipts.len(), 3);
    for r in &receipts {
        assert_eq!(r.receipt.message_ids.len(), 200);
        assert_eq!(r.receipt.group_id, vec![7; 16]);
    }

    // More than 512 for one author: split.
    for i in 0..1_100u16 {
        c.delivered(g, m(1, i), 0);
    }
    let (receipts, _) = c.flush();
    assert_eq!(receipts.len(), 3);
    assert_eq!(
        receipts
            .iter()
            .map(|r| r.receipt.message_ids.len())
            .sum::<usize>(),
        1_100
    );
}

#[test]
fn with_read_receipts_off_only_the_own_devices_learn_what_was_read() {
    let mut c = Coalescer::new(0, false);
    let chat = ChatKey::Group([7; 16]);
    c.read(chat, &[(m(2, 1), 1)], 0);
    c.played(chat, m(2, 2), 0);
    c.delivered(chat, m(2, 3), 0);
    let (receipts, syncs) = c.flush();
    assert_eq!(receipts.len(), 1, "delivered only");
    assert_eq!(receipts[0].receipt.kind, 1);
    assert_eq!(syncs[0].marks.len(), 1);
}
