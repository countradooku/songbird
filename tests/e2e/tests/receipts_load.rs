//! Receipt traffic as a share of all envelopes in a 1,024-member group (Prompt 4's load test,
//! M2, D-0060).
//!
//! The real receipt coalescer (`songbird_content::state::receipts`) on every device drives the
//! real send path (`songbird_send::SendPath` over the in-process mailbox). Group messages are one
//! shared body to every other device (MLS, Prompt 5). Receipts are per-device envelopes to the
//! author's devices, and read syncs go to the reader's other device. Every envelope is sealed
//! content (`songbird_content::seal`, padded), so sizes are real too.
//!
//! The model, for one simulated hour:
//! - 1,024 members with 2 devices each;
//! - 60 messages: one a minute from random members ("steady"), or 6 bursts of 10 within 20 s,
//!   each burst two members chatting back and forth ("bursty");
//! - 80 % of devices online from the start; the rest come online at a random time and catch up;
//! - each member's primary opens the chat 3 times, reading everything received so far;
//! - every device sends delivered receipts (§5.6), and read receipts are on.
//!
//! `ci fast` runs one scenario; `--ignored` runs the whole matrix printed in the M2 report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::too_many_lines,
    reason = "a load test: it prints its measurements"
)]

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::Instant;

use bytes::Bytes;
use songbird_content::schema::{
    Content, DataMessage, Message, SyncMessage, Text, content::Body, data_message::Kind,
    sync_message,
};
use songbird_content::state::MsgKey;
use songbird_content::state::receipts::{ChatKey, Coalescer};
use songbird_mailbox::memory::MemoryMailbox;
use songbird_proto::frame::{Recipient, SendFrame, SendPayload};
use songbird_router::LocalRouter;
use songbird_send::{Directory, LiveDirectory, Pusher, SendMetrics, SendPath};
use songbird_types::{AccountId, DeviceId};

const MEMBERS: usize = 1_024;
const DEVICES: usize = 2;
const MESSAGES: usize = 60;
const HOUR_MS: u64 = 3_600_000;
const GROUP: [u8; 16] = [0x99; 16];

/// `SplitMix64`: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn account(m: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..8].copy_from_slice(&(m as u64).to_be_bytes());
    a[15] = 0xAC;
    a
}

fn device(m: usize, d: usize) -> DeviceId {
    let mut b = account(m);
    b[14] = u8::try_from(d).unwrap();
    b[15] = 0xDE;
    DeviceId::from_bytes(b)
}

fn content(id: u64, body: Body) -> Content {
    let mut message_id = [0u8; 16];
    message_id[..8].copy_from_slice(&id.to_be_bytes());
    Content {
        version: 1,
        message_id: message_id.to_vec(),
        sent_at_ms: 1_800_000_000_000,
        body: Some(body),
        ..Content::default()
    }
}

fn sealed(c: &Content) -> Bytes {
    Bytes::from(songbird_content::seal(c, None).unwrap().0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    /// A device receives message `msg`.
    Receive { dev: (usize, usize), msg: usize },
    /// A device's coalescer may have receipts due.
    Due { dev: (usize, usize) },
    /// A member's primary opens the chat.
    Open { member: usize },
}

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    messages: u64,
    receipts: u64,
    syncs: u64,
    message_bytes: u64,
    receipt_bytes: u64,
    sync_bytes: u64,
    receipt_sends: u64,
    read_receipt_sends: u64,
    messages_read: u64,
}

struct Scenario {
    bursty: bool,
    window_ms: u64,
    delivered_by_every_device: bool,
}

async fn run(s: &Scenario) -> Counts {
    let mut rng = Rng(0x5EED);
    let directory: LiveDirectory = Directory::from_accounts((0..MEMBERS).flat_map(|m| {
        (0..DEVICES).map(move |d| (device(m, d), [0; 32], AccountId::from_bytes(account(m))))
    }))
    .into();
    let mailbox = MemoryMailbox::new(1_000_000, 1);
    let router = LocalRouter::new();
    let push = Pusher::disabled();
    let metrics = SendMetrics::default();
    let policy = songbird_send::Policy::default();
    let path = SendPath {
        directory: &directory,
        mailbox: &mailbox,
        router: &router,
        push: &push,
        metrics: &metrics,
        policy: &policy,
    };
    let mut scratch = Vec::new();
    let mut counts = Counts::default();
    let mut idem = 0u64;
    let mut send = async |sender: DeviceId, payload: SendPayload| {
        idem += 1;
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&idem.to_be_bytes());
        let mut frame = SendFrame {
            hints: songbird_proto::frame::SendHints::default(),
            req_id: 1,
            idempotency_key: key,
            mls: None,
            payload,
        };
        path.store(&sender, &mut frame, Instant::now(), &mut scratch)
            .await
            .expect("stored");
    };

    // When each device comes online, and each message's time and author.
    let mut online_from: HashMap<(usize, usize), u64> = HashMap::new();
    for m in 0..MEMBERS {
        for d in 0..DEVICES {
            let t = if rng.below(10) < 8 {
                0
            } else {
                rng.below(HOUR_MS)
            };
            online_from.insert((m, d), t);
        }
    }
    let mut events: BinaryHeap<Reverse<(u64, Event)>> = BinaryHeap::new();
    let mut authors: Vec<(usize, u64)> = Vec::new();
    for i in 0..MESSAGES {
        let t = if s.bursty {
            (i as u64 / 10) * 600_000 + (i as u64 % 10) * 2_000
        } else {
            i as u64 * 60_000
        };
        // Bursts are two members chatting back and forth; steady traffic has random authors.
        let author = if s.bursty && i % 10 >= 2 {
            authors[i - 2].0
        } else {
            usize::try_from(rng.below(MEMBERS as u64)).unwrap()
        };
        authors.push((author, t));
    }
    // The messages: one shared body from the author's primary to every other device.
    for (i, (author, t)) in authors.iter().enumerate() {
        let body = sealed(&content(
            i as u64,
            Body::Data(DataMessage {
                group_id: GROUP.to_vec(),
                expire_timer_s: 0,
                kind: Some(Kind::Message(Message {
                    text: Some(Text {
                        body: format!("message {i} to the group"),
                        spans: vec![],
                    }),
                    ..Message::default()
                })),
            }),
        ));
        let devices: Vec<DeviceId> = (0..MEMBERS)
            .flat_map(|m| (0..DEVICES).map(move |d| (m, d)))
            .filter(|(m, d)| !(*m == *author && *d == 0))
            .map(|(m, d)| device(m, d))
            .collect();
        counts.messages += devices.len() as u64;
        counts.message_bytes += (devices.len() * body.len()) as u64;
        send(device(*author, 0), SendPayload::Shared { devices, body }).await;
        for m in 0..MEMBERS {
            for d in 0..DEVICES {
                if m == *author && d == 0 {
                    continue;
                }
                let at = (*t).max(online_from[&(m, d)]) + 200;
                events.push(Reverse((
                    at,
                    Event::Receive {
                        dev: (m, d),
                        msg: i,
                    },
                )));
            }
        }
    }
    for m in 0..MEMBERS {
        for _ in 0..3 {
            events.push(Reverse((rng.below(HOUR_MS), Event::Open { member: m })));
        }
    }

    let mut coalescers: HashMap<(usize, usize), Coalescer> = HashMap::new();
    let mut received: HashMap<(usize, usize), Vec<usize>> = HashMap::new();
    let mut read_upto: HashMap<usize, usize> = HashMap::new();
    let msg_key = |i: usize| {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        MsgKey {
            author: account(authors[i].0),
            id,
        }
    };
    let chat = ChatKey::Group(GROUP);
    let mut next_id = 1_000_000u64;
    while let Some(Reverse((now, ev))) = events.pop() {
        match ev {
            Event::Receive { dev, msg } => {
                received.entry(dev).or_default().push(msg);
                if s.delivered_by_every_device || dev.1 == 0 {
                    let c = coalescers
                        .entry(dev)
                        .or_insert_with(|| Coalescer::new(s.window_ms, true));
                    c.delivered(chat, msg_key(msg), now);
                    events.push(Reverse((now + s.window_ms, Event::Due { dev })));
                }
            }
            Event::Open { member } => {
                let dev = (member, 0);
                if now < online_from[&dev] {
                    continue;
                }
                let from = read_upto.get(&member).copied().unwrap_or(0);
                let mut got = received.get(&dev).cloned().unwrap_or_default();
                got.sort_unstable();
                let unread: Vec<(MsgKey, u64)> = got
                    .iter()
                    .filter(|i| **i >= from && authors[**i].0 != member)
                    .map(|i| (msg_key(*i), *i as u64))
                    .collect();
                if let Some(last) = got.last() {
                    read_upto.insert(member, last + 1);
                }
                if !unread.is_empty() {
                    counts.messages_read += unread.len() as u64;
                    coalescers
                        .entry(dev)
                        .or_insert_with(|| Coalescer::new(s.window_ms, true))
                        .read(chat, &unread, now);
                    events.push(Reverse((now + s.window_ms, Event::Due { dev })));
                }
            }
            Event::Due { dev } => {
                let Some(c) = coalescers.get_mut(&dev) else {
                    continue;
                };
                let (receipts, syncs) = c.due(now);
                for r in receipts {
                    if r.receipt.kind == 2 {
                        counts.read_receipt_sends += 1;
                    }
                    next_id += 1;
                    let env = sealed(&content(next_id, Body::Receipt(r.receipt)));
                    let author =
                        usize::try_from(u64::from_be_bytes(r.author[..8].try_into().unwrap()))
                            .unwrap();
                    // To every device of the author (the sender's own device excluded).
                    let to: Vec<Recipient> = (0..DEVICES)
                        .map(|d| device(author, d))
                        .filter(|d| *d != device(dev.0, dev.1))
                        .map(|device| Recipient {
                            device,
                            envelope: env.clone(),
                        })
                        .collect();
                    counts.receipts += to.len() as u64;
                    counts.receipt_bytes += (to.len() * env.len()) as u64;
                    counts.receipt_sends += 1;
                    send(device(dev.0, dev.1), SendPayload::PerDevice(to)).await;
                }
                for sync in syncs {
                    next_id += 1;
                    let env = sealed(&content(
                        next_id,
                        Body::Sync(SyncMessage {
                            kind: Some(sync_message::Kind::Read(sync)),
                        }),
                    ));
                    let to: Vec<Recipient> = (0..DEVICES)
                        .filter(|d| *d != dev.1)
                        .map(|d| Recipient {
                            device: device(dev.0, d),
                            envelope: env.clone(),
                        })
                        .collect();
                    counts.syncs += to.len() as u64;
                    counts.sync_bytes += (to.len() * env.len()) as u64;
                    send(device(dev.0, dev.1), SendPayload::PerDevice(to)).await;
                }
            }
        }
    }
    // Nothing was refused: every envelope counted here was stored.
    assert_eq!(metrics.sends_rejected.get(), 0);
    assert_eq!(
        metrics.envelopes_stored.get(),
        counts.messages + counts.receipts + counts.syncs
    );
    counts
}

fn report(name: &str, c: &Counts) -> f64 {
    let all = c.messages + c.receipts + c.syncs;
    let bytes = c.message_bytes + c.receipt_bytes + c.sync_bytes;
    let share = c.receipts as f64 / all as f64;
    println!(
        "{name}: envelopes {all} (messages {}, receipts {}, read syncs {}); receipt sends {}; \
         receipts {:.1} % of envelopes, {:.1} % of bytes",
        c.messages,
        c.receipts,
        c.syncs,
        c.receipt_sends,
        share * 100.0,
        c.receipt_bytes as f64 / bytes as f64 * 100.0,
    );
    share
}

#[tokio::test(flavor = "current_thread")]
async fn receipt_share_in_a_1024_member_group() {
    let c = run(&Scenario {
        bursty: true,
        window_ms: songbird_content::state::receipts::window_for(MEMBERS),
        delivered_by_every_device: true,
    })
    .await;
    let share = report("bursty, the protocol's window (10 s), every device", &c);
    // "Read up to here": at most one read receipt per author per opening; in a big group most
    // messages read in one opening have different authors, so this is close to one per message.
    println!(
        "read receipts sent {} for {} messages read",
        c.read_receipt_sends, c.messages_read
    );
    assert!(c.read_receipt_sends <= c.messages_read);
    // Every receiving device sends at most one delivered receipt per message.
    assert!(c.receipt_sends - c.read_receipt_sends <= (MESSAGES * (MEMBERS * DEVICES - 1)) as u64);
    // Measured 47.2 % (report P04-M2); a regression in batching shows here.
    assert!(share > 0.3 && share < 0.55, "{share}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "the full matrix for the M2 report: cargo test --release -p songbird-e2e --test receipts_load -- --ignored --nocapture"]
async fn receipt_share_matrix() {
    for bursty in [false, true] {
        for window_ms in [1_000, 10_000] {
            for every in [true, false] {
                let c = run(&Scenario {
                    bursty,
                    window_ms,
                    delivered_by_every_device: every,
                })
                .await;
                report(
                    &format!(
                        "{}, {} s window, delivered from {}",
                        if bursty { "bursty" } else { "steady" },
                        window_ms / 1000,
                        if every { "every device" } else { "primaries" }
                    ),
                    &c,
                );
            }
        }
    }
}
