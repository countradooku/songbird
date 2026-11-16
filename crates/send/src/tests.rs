#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::time::Instant;

use bytes::Bytes;
use songbird_mailbox::Mailbox as _;
use songbird_mailbox::memory::MemoryMailbox;
use songbird_proto::frame::{Recipient, RejectReason, SendFrame, SendPayload, SendStatus};
use songbird_proto::system::{self, DeviceListChanged, Kind, SystemFrame};
use songbird_router::{InboxSizes, LocalRouter};
use songbird_types::{AccountId, DeviceId};

use super::*;
use crate::system::SystemSigner;

fn dev(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

struct Fixture {
    directory: LiveDirectory,
    mailbox: MemoryMailbox,
    router: LocalRouter,
    push: Pusher,
    metrics: SendMetrics,
    policy: Policy,
}

impl Fixture {
    fn new() -> Self {
        let alice = AccountId::from_bytes([0xA; 16]);
        let bob = AccountId::from_bytes([0xB; 16]);
        Self {
            directory: Directory::from_accounts([
                (dev(1), [0; 32], alice),
                (dev(2), [0; 32], bob),
                (dev(3), [0; 32], bob),
            ])
            .into(),
            mailbox: MemoryMailbox::new(1000, 1),
            router: LocalRouter::new(),
            push: Pusher::disabled(),
            metrics: SendMetrics::default(),
            policy: Policy {
                franking: Some(Franker::from_secret(&[0x46; 32]).unwrap()),
                ..Policy::default()
            },
        }
    }

    fn path(&self) -> SendPath<'_, MemoryMailbox, LocalRouter> {
        SendPath {
            directory: &self.directory,
            mailbox: &self.mailbox,
            router: &self.router,
            push: &self.push,
            metrics: &self.metrics,
            policy: &self.policy,
        }
    }
}

fn to(devices: &[DeviceId], envelope: impl Into<Bytes>) -> SendFrame {
    let envelope = envelope.into();
    SendFrame::per_device(
        7,
        [3; 16],
        devices
            .iter()
            .map(|d| Recipient {
                device: *d,
                envelope: envelope.clone(),
            })
            .collect(),
    )
}

fn check(ids: &[u8]) -> bool {
    let devices: Vec<DeviceId> = ids.iter().map(|b| dev(*b)).collect();
    has_duplicate_device(&devices)
}

#[test]
fn duplicate_detection_small_and_large() {
    assert!(!check(&[1, 2, 3]));
    assert!(check(&[1, 2, 1]));
    let many: Vec<u8> = (0..100).collect();
    assert!(!check(&many));
    let mut dup = many.clone();
    dup.push(57);
    assert!(check(&dup));
}

#[tokio::test]
async fn the_send_path_checks_stores_once_and_routes() {
    let f = Fixture::new();
    let mut scratch = Vec::new();
    // Bob's device 3 left out: device mismatch, nothing stored.
    let st = f
        .path()
        .send(
            &dev(1),
            to(&[dev(2)], &b"x"[..]),
            Instant::now(),
            &mut scratch,
        )
        .await;
    assert!(matches!(st, SendStatus::DeviceMismatch(ref m) if m.missing.len() == 1));
    assert_eq!(f.mailbox.count_pending(&dev(2)).await.unwrap(), 0);
    // Complete: stored for both, routed to the one with a session.
    let mut inbox = f
        .router
        .attach(
            dev(2),
            InboxSizes {
                live: 8,
                ephemeral: 8,
            },
        )
        .await;
    let st = f
        .path()
        .send(
            &dev(1),
            to(&[dev(2), dev(3)], &b"hi"[..]),
            Instant::now(),
            &mut scratch,
        )
        .await;
    assert_eq!(st, SendStatus::Accepted);
    assert_eq!(inbox.live.recv().await.unwrap().seq, 1);
    assert_eq!(f.metrics.routes_offline.get(), 1);
    // The same idempotency key again: a replay, nothing stored twice.
    let st = f
        .path()
        .send(
            &dev(1),
            to(&[dev(2), dev(3)], &b"hi"[..]),
            Instant::now(),
            &mut scratch,
        )
        .await;
    assert_eq!(st, SendStatus::Accepted);
    assert_eq!(f.mailbox.count_pending(&dev(2)).await.unwrap(), 1);
    assert_eq!(f.metrics.sends_replayed.get(), 1);
    assert_eq!(f.metrics.sends_accepted.get(), 1);
    assert_eq!(f.metrics.sends_rejected.get(), 1);
}

#[tokio::test]
async fn user_envelopes_in_the_system_frame_format_are_refused() {
    let f = Fixture::new();
    let mut forged = system::MAGIC.to_vec();
    forged.extend_from_slice(&[0; 100]);
    let forged = Bytes::from(forged);
    let st = f
        .path()
        .send(
            &dev(1),
            to(&[dev(2), dev(3)], forged.clone()),
            Instant::now(),
            &mut Vec::new(),
        )
        .await;
    assert_eq!(
        st,
        SendStatus::Rejected {
            reason: RejectReason::ReservedEnvelope,
            retry_after_ms: 0
        }
    );
    assert_eq!(f.mailbox.count_pending(&dev(2)).await.unwrap(), 0);
    // Shared bodies too.
    let shared = SendFrame {
        hints: songbird_proto::frame::SendHints::default(),
        req_id: 1,
        idempotency_key: [4; 16],
        mls: None,
        payload: SendPayload::Shared {
            devices: vec![dev(2), dev(3)],
            body: forged,
        },
    };
    let st = f
        .path()
        .send(&dev(1), shared, Instant::now(), &mut Vec::new())
        .await;
    assert!(matches!(
        st,
        SendStatus::Rejected {
            reason: RejectReason::ReservedEnvelope,
            ..
        }
    ));
}

#[tokio::test]
async fn system_notices_are_signed_per_device_stored_once_and_verify() {
    let f = Fixture::new();
    let signer = SystemSigner::from_seed(&[5; 32]).unwrap();
    let body = DeviceListChanged {
        account: AccountId::from_bytes([0xB; 16]),
    }
    .encode();
    let mut inbox = f
        .router
        .attach(
            dev(2),
            InboxSizes {
                live: 8,
                ephemeral: 8,
            },
        )
        .await;
    let id = [8; 16];
    f.path()
        .send_system(
            &signer,
            &[dev(2), dev(3)],
            Kind::DeviceListChanged,
            &body,
            id,
        )
        .await
        .unwrap();
    // A retry with the same notice ID stores nothing new.
    f.path()
        .send_system(
            &signer,
            &[dev(2), dev(3)],
            Kind::DeviceListChanged,
            &body,
            id,
        )
        .await
        .unwrap();
    assert_eq!(f.mailbox.count_pending(&dev(3)).await.unwrap(), 1);
    let live = inbox.live.recv().await.unwrap();
    let u = SystemFrame::decode(&live.envelope).unwrap();
    assert_eq!(u.frame.device, dev(2));
    assert_eq!(u.frame.kind, Kind::DeviceListChanged);
    assert_eq!(u.frame.key_id, crate::system::key_id(&signer.public_key()));
    // It verifies under the server's public key, and only over its own bytes.
    let pk = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ED25519,
        signer.public_key(),
    );
    pk.verify(&u.message(), &u.signature).unwrap();
    let mut other = u.message();
    if let Some(b) = other.last_mut() {
        *b ^= 1;
    }
    assert!(pk.verify(&other, &u.signature).is_err());
    // Device 3's copy names device 3: a notice cannot be replayed to another device.
    let stored = f.mailbox.fetch_after(&dev(3), 0, 10).await.unwrap();
    let u3 = SystemFrame::decode(&stored[0].envelope).unwrap();
    assert_eq!(u3.frame.device, dev(3));
    // Unknown devices: nothing stored for anyone.
    assert!(
        f.path()
            .send_system(
                &signer,
                &[dev(2), dev(9)],
                Kind::DeviceListChanged,
                &body,
                [9; 16]
            )
            .await
            .is_err()
    );
}

/// Alice has two devices (1 and 4), Bob two (2 and 3).
fn two_device_fixture() -> Fixture {
    let alice = AccountId::from_bytes([0xA; 16]);
    let bob = AccountId::from_bytes([0xB; 16]);
    Fixture {
        directory: Directory::from_accounts([
            (dev(1), [0; 32], alice),
            (dev(4), [0; 32], alice),
            (dev(2), [0; 32], bob),
            (dev(3), [0; 32], bob),
        ])
        .into(),
        ..Fixture::new()
    }
}

fn franked(devices: &[DeviceId], commitment: [u8; 32]) -> SendFrame {
    let mut s = to(devices, "ciphertext");
    s.hints.commitment = Some(commitment);
    s
}

#[tokio::test]
async fn franked_envelopes_for_other_accounts_are_stamped_and_own_devices_are_not() {
    use songbird_proto::envelope::Stamp;
    let f = two_device_fixture();
    let st = f
        .path()
        .send(
            &dev(1),
            franked(&[dev(2), dev(3), dev(4)], [7; 32]),
            Instant::now(),
            &mut Vec::new(),
        )
        .await;
    assert_eq!(st, SendStatus::Accepted);
    let franker = f.policy.franking.as_ref().unwrap();
    for d in [dev(2), dev(3)] {
        let got = f.mailbox.fetch_after(&d, 0, 10).await.unwrap();
        let (stamp, env) = Stamp::split(&got[0].envelope).unwrap();
        assert_eq!(env, b"ciphertext");
        assert_eq!(stamp.commitment, [7; 32]);
        // Bound to Alice as sender and Bob as recipient, nobody else.
        assert!(franker.verify(&stamp, &[0xA; 16], &[0xB; 16]));
        assert!(!franker.verify(&stamp, &[0xA; 16], &[0xA; 16]));
        assert!(!franker.verify(&stamp, &[0; 16], &[0xB; 16]));
    }
    // Alice's own other device gets the envelope as sent (a sync transcript is not franked).
    let own = f.mailbox.fetch_after(&dev(4), 0, 10).await.unwrap();
    assert_eq!(&own[0].envelope[..], b"ciphertext");

    // A shared body is stamped once, for no recipient in particular.
    let mut shared = franked(&[dev(2)], [8; 32]);
    shared.idempotency_key = [9; 16];
    shared.payload = SendPayload::Shared {
        devices: vec![dev(2), dev(3), dev(4)],
        body: Bytes::from_static(b"group"),
    };
    assert_eq!(
        f.path()
            .send(&dev(1), shared, Instant::now(), &mut Vec::new())
            .await,
        SendStatus::Accepted
    );
    let got = f.mailbox.fetch_after(&dev(4), 1, 10).await.unwrap();
    let (stamp, env) = Stamp::split(&got[0].envelope).unwrap();
    assert_eq!(env, b"group");
    assert!(franker.verify(&stamp, &[0xA; 16], &[0; 16]));
}

#[tokio::test]
async fn a_sealed_franked_send_is_stamped_without_a_sender() {
    use songbird_proto::envelope::Stamp;
    let f = two_device_fixture();
    // The sealed endpoint's sentinel: no device of the sender is known.
    let st = f
        .path()
        .send(
            &SEALED_SENDER,
            franked(&[dev(2), dev(3)], [7; 32]),
            Instant::now(),
            &mut Vec::new(),
        )
        .await;
    assert_eq!(st, SendStatus::Accepted);
    let got = f.mailbox.fetch_after(&dev(2), 0, 10).await.unwrap();
    let (stamp, _) = Stamp::split(&got[0].envelope).unwrap();
    assert!(
        f.policy
            .franking
            .as_ref()
            .unwrap()
            .verify(&stamp, &[0; 16], &[0xB; 16])
    );
}

#[tokio::test]
async fn franking_without_a_key_is_refused_and_forged_stamps_are_reserved() {
    let mut f = two_device_fixture();
    f.policy.franking = None;
    let st = f
        .path()
        .send(
            &dev(1),
            franked(&[dev(2), dev(3)], [7; 32]),
            Instant::now(),
            &mut Vec::new(),
        )
        .await;
    assert!(matches!(
        st,
        SendStatus::Rejected {
            reason: RejectReason::Unavailable,
            ..
        }
    ));
    // A user envelope that looks like a stamp (or anything else the server writes) is refused.
    let mut forged = songbird_proto::envelope::FRANKED_MAGIC.to_vec();
    forged.extend_from_slice(&[0; 100]);
    for env in [forged, b"\xF5SBanything".to_vec()] {
        let st = f
            .path()
            .send(
                &dev(1),
                to(&[dev(2), dev(3)], Bytes::from(env)),
                Instant::now(),
                &mut Vec::new(),
            )
            .await;
        assert_eq!(
            st,
            SendStatus::Rejected {
                reason: RejectReason::ReservedEnvelope,
                retry_after_ms: 0
            }
        );
    }
    assert_eq!(f.mailbox.count_pending(&dev(2)).await.unwrap(), 0);
}

#[tokio::test]
async fn the_disappearing_hint_reaches_the_mailbox() {
    let f = two_device_fixture();
    let mut s = to(&[dev(2), dev(3)], "soon gone");
    s.hints.expire_after_s = Some(1);
    assert_eq!(
        f.path()
            .send(&dev(1), s, Instant::now(), &mut Vec::new())
            .await,
        SendStatus::Accepted
    );
    assert_eq!(
        f.mailbox.fetch_after(&dev(2), 0, 10).await.unwrap().len(),
        1
    );
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    assert_eq!(
        f.mailbox.fetch_after(&dev(2), 0, 10).await.unwrap().len(),
        0
    );
}

// ---- Prompt 4, M4: the contact gate ----------------------------------------------------------

const ALICE: [u8; 16] = [0xA; 16];
const BOB: [u8; 16] = [0xB; 16];
const CAROL: [u8; 16] = [0xC; 16];
const DAVE: [u8; 16] = [0xD; 16];

/// Alice (devices 1, 4), Bob (2, 3), Carol (5), Dave (6), Erin (7, no profile), Olga (8, open).
/// Every account is closed (as from the registry) unless said otherwise.
fn gated(limits: RequestLimits) -> (Fixture, Arc<MemoryGate>) {
    use crate::directory::Access;
    let acct = AccountId::from_bytes;
    let erin = acct([0xE; 16]);
    let olga = acct([0x0F; 16]);
    let key = |b: u8| Access {
        key: Some([b; 16]),
        open: false,
        requests_off: false,
    };
    let gate = Arc::new(MemoryGate::new(limits));
    let mut f = Fixture::new();
    f.directory = Directory::from_accounts([
        (dev(1), [0; 32], acct(ALICE)),
        (dev(4), [0; 32], acct(ALICE)),
        (dev(2), [0; 32], acct(BOB)),
        (dev(3), [0; 32], acct(BOB)),
        (dev(5), [0; 32], acct(CAROL)),
        (dev(6), [0; 32], acct(DAVE)),
        (dev(7), [0; 32], erin),
        (dev(8), [0; 32], olga),
    ])
    .with_access([
        (acct(ALICE), key(0x1A)),
        (acct(BOB), key(0x1B)),
        (
            acct(CAROL),
            Access {
                requests_off: true,
                ..key(0x1C)
            },
        ),
        (acct(DAVE), key(0x1D)),
        (olga, Access::OPEN),
    ])
    .into();
    f.policy.gate = Some(gate.clone());
    f.policy.max_broadcast_accounts = limits.max_broadcast_accounts;
    (f, gate)
}

/// Envelopes `d` can still fetch (a dropped part is stored already expired: never fetchable).
async fn visible(f: &Fixture, d: u8) -> usize {
    f.mailbox.fetch_after(&dev(d), 0, 100).await.unwrap().len()
}

fn status_of(st: &SendStatus) -> Option<RejectReason> {
    match st {
        SendStatus::Rejected { reason, .. } => Some(*reason),
        _ => None,
    }
}

async fn go(f: &Fixture, sender: u8, s: SendFrame) -> SendStatus {
    f.path()
        .send(&dev(sender), s, Instant::now(), &mut Vec::new())
        .await
}

fn hinted(devices: &[u8], key: u8, f: impl FnOnce(&mut SendFrame)) -> SendFrame {
    let ds: Vec<DeviceId> = devices.iter().map(|b| dev(*b)).collect();
    let mut s = to(&ds, "m");
    s.idempotency_key = [key; 16];
    f(&mut s);
    s
}

#[tokio::test]
async fn a_send_to_another_account_needs_its_access_key_or_a_request() {
    let (f, _) = gated(RequestLimits::default());
    let access_required = Some(RejectReason::AccessRequired);
    // No key, no request.
    let st = go(&f, 1, hinted(&[2, 3], 1, |_| {})).await;
    assert_eq!(status_of(&st), access_required);
    // A wrong key.
    let st = go(
        &f,
        1,
        hinted(&[2, 3], 2, |s| s.hints.access = Some([0x1C; 16])),
    )
    .await;
    assert_eq!(status_of(&st), access_required);
    // Bob's key: a contact.
    let st = go(
        &f,
        1,
        hinted(&[2, 3, 4], 3, |s| s.hints.access = Some([0x1B; 16])),
    )
    .await;
    assert_eq!(st, SendStatus::Accepted);
    // A request must be franked.
    let st = go(&f, 1, hinted(&[2, 3], 4, |s| s.hints.request = true)).await;
    assert_eq!(status_of(&st), Some(RejectReason::InvalidRequest));
    let st = go(
        &f,
        1,
        hinted(&[2, 3], 5, |s| {
            s.hints.request = true;
            s.hints.commitment = Some([7; 32]);
        }),
    )
    .await;
    assert_eq!(st, SendStatus::Accepted);
    assert_eq!(f.metrics.requests.get(), 1);
    // Erin has no profile: no key can work, only a request.
    let st = go(&f, 1, hinted(&[7], 6, |s| s.hints.access = Some([0; 16]))).await;
    assert_eq!(status_of(&st), access_required);
    // Olga is open: no key needed.
    assert_eq!(
        go(&f, 1, hinted(&[8], 7, |_| {})).await,
        SendStatus::Accepted
    );
    // Alice's own other device (a sync message): no key needed.
    assert_eq!(
        go(&f, 1, hinted(&[4], 8, |_| {})).await,
        SendStatus::Accepted
    );
    // Nothing refused was stored.
    assert_eq!(visible(&f, 2).await, 2);
}

#[tokio::test]
async fn a_request_addresses_one_account_only() {
    let (f, _) = gated(RequestLimits::default());
    let st = go(
        &f,
        1,
        hinted(&[2, 3, 6], 1, |s| {
            s.hints.request = true;
            s.hints.commitment = Some([7; 32]);
        }),
    )
    .await;
    assert_eq!(status_of(&st), Some(RejectReason::InvalidRequest));
}

#[tokio::test]
async fn requests_from_a_blocked_sender_or_to_an_account_refusing_them_are_dropped_silently() {
    let (f, gate) = gated(RequestLimits::default());
    gate.block(AccountId::from_bytes(BOB), AccountId::from_bytes(ALICE));
    let request = |key: u8, devices: &[u8]| {
        hinted(devices, key, |s| {
            s.hints.request = true;
            s.hints.commitment = Some([7; 32]);
        })
    };
    // Accepted, as if delivered; Bob's devices get nothing; Alice's own device its transcript.
    assert_eq!(
        go(&f, 1, request(1, &[2, 3, 4])).await,
        SendStatus::Accepted
    );
    assert_eq!(visible(&f, 2).await, 0);
    assert_eq!(visible(&f, 3).await, 0);
    assert_eq!(visible(&f, 4).await, 1);
    // Carol refuses requests: the same answer, nothing stored.
    assert_eq!(go(&f, 1, request(2, &[5])).await, SendStatus::Accepted);
    assert_eq!(visible(&f, 5).await, 0);
    assert_eq!(f.metrics.requests_dropped.get(), 2);
    // Reusing the request's idempotency key for other devices gets the answer an undropped
    // request's key gets (reason 7): the block does not show through idempotency.
    let mut reuse = to(&[dev(6)], "other");
    reuse.idempotency_key = [1; 16];
    reuse.hints.access = Some([0x1D; 16]);
    assert_eq!(
        status_of(&go(&f, 1, reuse).await),
        Some(RejectReason::IdempotencyConflict)
    );
    // So does reusing it for a subset of the same devices (Bob's only).
    assert_eq!(
        status_of(&go(&f, 1, request(1, &[2, 3])).await),
        Some(RejectReason::IdempotencyConflict)
    );
    // A retry of the dropped request itself is answered as a retry is.
    assert_eq!(
        go(&f, 1, request(1, &[2, 3, 4])).await,
        SendStatus::Accepted
    );
    assert_eq!(visible(&f, 2).await, 0);
    assert_eq!(visible(&f, 4).await, 1, "the sync transcript once");
    assert_eq!(f.metrics.requests.get(), 0);
    // Dave has not blocked Alice.
    assert_eq!(go(&f, 1, request(3, &[6])).await, SendStatus::Accepted);
    assert_eq!(visible(&f, 6).await, 1);
}

#[tokio::test]
async fn request_floods_are_held_to_their_budgets_and_a_block_does_not_show() {
    let limits = RequestLimits {
        per_sender_burst: 3,
        per_pair_burst: 2,
        per_recipient_burst: 4,
        ..RequestLimits::default()
    };
    let request = |key: u8, devices: &[u8]| {
        hinted(devices, key, |s| {
            s.hints.request = true;
            s.hints.commitment = Some([7; 32]);
        })
    };
    let limited = Some(RejectReason::RateLimited);
    // One sender to many recipients: the sender's budget (3).
    let (f, _) = gated(limits);
    for (i, d) in [6u8, 7, 6].into_iter().enumerate() {
        let st = go(&f, 1, request(u8::try_from(i).unwrap(), &[d])).await;
        assert_eq!(st, SendStatus::Accepted, "{i}");
    }
    assert_eq!(status_of(&go(&f, 1, request(9, &[7])).await), limited);
    // One pair: its own budget (2), whoever else the sender writes to.
    let (f, _) = gated(limits);
    assert_eq!(go(&f, 1, request(1, &[6])).await, SendStatus::Accepted);
    assert_eq!(go(&f, 1, request(2, &[6])).await, SendStatus::Accepted);
    assert_eq!(status_of(&go(&f, 1, request(3, &[6])).await), limited);
    // Many senders to one recipient: the recipient's budget (4).
    let (f, _) = gated(limits);
    let mut accepted = 0;
    for (i, sender) in [1u8, 2, 5, 7, 8].into_iter().enumerate() {
        let st = go(&f, sender, request(u8::try_from(i).unwrap(), &[6])).await;
        if st == SendStatus::Accepted {
            accepted += 1;
        } else {
            assert_eq!(status_of(&st), limited);
        }
    }
    assert_eq!(accepted, 4);
    // A blocked sender meets exactly the same budgets: blocking cannot be probed by flooding.
    let (f, gate) = gated(limits);
    gate.block(AccountId::from_bytes(DAVE), AccountId::from_bytes(ALICE));
    assert_eq!(go(&f, 1, request(1, &[6])).await, SendStatus::Accepted);
    assert_eq!(go(&f, 1, request(2, &[6])).await, SendStatus::Accepted);
    assert_eq!(status_of(&go(&f, 1, request(3, &[6])).await), limited);
    assert_eq!(visible(&f, 6).await, 0);
}

#[tokio::test]
async fn broadcasts_need_every_contacts_key_and_respect_their_budget() {
    let limits = RequestLimits {
        max_broadcast_accounts: 3,
        broadcast_burst: 5,
        ..RequestLimits::default()
    };
    let (f, _) = gated(limits);
    let xor = |keys: &[u8]| {
        let mut k = [0u8; 16];
        for b in keys {
            for x in &mut k {
                *x ^= b;
            }
        }
        k
    };
    // Bob and Dave (closed) and Olga (open): the XOR of Bob's and Dave's keys.
    let to3 = |key: u8, access: Option<[u8; 16]>| {
        hinted(&[2, 3, 6, 8], key, move |s| s.hints.access = access)
    };
    assert_eq!(
        status_of(&go(&f, 1, to3(1, Some(xor(&[0x1B])))).await),
        Some(RejectReason::AccessRequired)
    );
    assert_eq!(
        status_of(&go(&f, 1, to3(2, None)).await),
        Some(RejectReason::AccessRequired)
    );
    assert_eq!(
        go(&f, 1, to3(3, Some(xor(&[0x1B, 0x1D])))).await,
        SendStatus::Accepted
    );
    assert_eq!(f.metrics.broadcasts.get(), 1);
    // Erin has no profile: never part of a broadcast.
    let st = go(
        &f,
        1,
        hinted(&[2, 3, 7], 4, |s| s.hints.access = Some(xor(&[0x1B]))),
    )
    .await;
    assert_eq!(status_of(&st), Some(RejectReason::AccessRequired));
    // More accounts than allowed.
    let st = go(
        &f,
        1,
        hinted(&[2, 3, 5, 6, 8], 5, |s| {
            s.hints.access = Some(xor(&[0x1B, 0x1C, 0x1D]));
        }),
    )
    .await;
    assert_eq!(status_of(&st), Some(RejectReason::TooManyRecipients));
    // The budget: 5 accounts, 3 spent; 3 more is over it.
    let st = go(&f, 1, to3(6, Some(xor(&[0x1B, 0x1D])))).await;
    assert_eq!(status_of(&st), Some(RejectReason::RateLimited));
}

#[tokio::test]
async fn groups_and_sealed_sends_are_not_classified_as_strangers() {
    let (f, _) = gated(RequestLimits::default());
    // A shared body (an MLS group) to closed accounts: until Prompt 5, every closed member's
    // access key, combined, or it is refused, so a shared body is no way around requests and
    // blocks.
    let mut shared = SendFrame {
        hints: songbird_proto::frame::SendHints::default(),
        req_id: 1,
        idempotency_key: [1; 16],
        mls: None,
        payload: SendPayload::Shared {
            devices: vec![dev(2), dev(3), dev(5)],
            body: Bytes::from_static(b"group"),
        },
    };
    assert_eq!(
        status_of(&go(&f, 1, shared.clone()).await),
        Some(RejectReason::AccessRequired)
    );
    shared.hints.access = Some([0x1B; 16]);
    assert_eq!(
        status_of(&go(&f, 1, shared.clone()).await),
        Some(RejectReason::AccessRequired),
        "Carol's key is missing"
    );
    let mut k = [0x1B; 16];
    for x in &mut k {
        *x ^= 0x1C;
    }
    shared.hints.access = Some(k);
    assert_eq!(f.path().lane(&dev(1), &shared), Ok(Lane::Group));
    assert_eq!(go(&f, 1, shared).await, SendStatus::Accepted);
    // A sender not in the snapshot (yet) is never treated as sealed.
    let s = hinted(&[8], 3, |_| {});
    assert_eq!(
        f.path().lane(&dev(0xEE), &s).map_err(|e| status_of(&e)),
        Err(Some(RejectReason::Unavailable))
    );
    // A sealed send: the sealed endpoint checked the access keys.
    let s = hinted(&[2, 3], 2, |_| {});
    assert_eq!(f.path().lane(&SEALED_SENDER, &s), Ok(Lane::Sealed));
    assert_eq!(
        f.path()
            .send(&SEALED_SENDER, s, Instant::now(), &mut Vec::new())
            .await,
        SendStatus::Accepted
    );
}

#[tokio::test]
async fn an_open_account_takes_anyone_but_its_blocks_still_apply() {
    let (f, gate) = gated(RequestLimits::default());
    // Olga (8) is open: no key, no request.
    assert_eq!(
        go(&f, 1, hinted(&[8], 1, |_| {})).await,
        SendStatus::Accepted
    );
    assert_eq!(visible(&f, 8).await, 1);
    // Once she blocks Alice, Alice's sends are accepted and never reach her.
    gate.block(
        AccountId::from_bytes([0x0F; 16]),
        AccountId::from_bytes(ALICE),
    );
    assert_eq!(
        go(&f, 1, hinted(&[8], 2, |_| {})).await,
        SendStatus::Accepted
    );
    assert_eq!(visible(&f, 8).await, 1);
    // Carol is not blocked.
    assert_eq!(
        go(&f, 5, hinted(&[8], 3, |_| {})).await,
        SendStatus::Accepted
    );
    assert_eq!(visible(&f, 8).await, 2);
}

#[tokio::test]
async fn without_a_gate_requests_and_broadcasts_are_unavailable() {
    let (mut f, _) = gated(RequestLimits::default());
    f.policy.gate = None;
    let st = go(
        &f,
        1,
        hinted(&[2, 3], 1, |s| {
            s.hints.request = true;
            s.hints.commitment = Some([7; 32]);
        }),
    )
    .await;
    assert_eq!(status_of(&st), Some(RejectReason::Unavailable));
    // A contact's send never needs the gate.
    let st = go(
        &f,
        1,
        hinted(&[2, 3], 2, |s| s.hints.access = Some([0x1B; 16])),
    )
    .await;
    assert_eq!(st, SendStatus::Accepted);
}

/// A group application message (`PrivateMessage`) of group `g` at `epoch`.
fn group_message(g: [u8; 16], epoch: u64, content_type: u8) -> Bytes {
    let mut m = vec![0, 1, 0, 2, 16];
    m.extend_from_slice(&g);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.push(content_type);
    m.extend_from_slice(&[0, 1, 0xAA, 3, 1, 2, 3]);
    Bytes::from(m)
}

fn group_send(g: [u8; 16], body: Bytes) -> SendFrame {
    SendFrame {
        req_id: 9,
        idempotency_key: [0x77; 16],
        mls: None,
        hints: songbird_proto::frame::SendHints {
            group: Some(g),
            ..Default::default()
        },
        payload: SendPayload::Shared {
            devices: Vec::new(),
            body,
        },
    }
}

fn with_rosters(f: &mut Fixture, g: [u8; 16], epoch: u64, devices: &[DeviceId]) {
    let r = MemoryRosters::default();
    r.set(g, epoch, devices.to_vec());
    f.policy.rosters = Some(Arc::new(r));
}

#[tokio::test]
async fn group_messages_go_to_the_roster_and_only_from_members() {
    const G: [u8; 16] = [0x5B; 16];
    let mut f = Fixture::new();
    // Device 3 (Bob's second device) is not in the group: it never receives, and members
    // need no access keys (membership replaces D-0064's interim rule).
    with_rosters(&mut f, G, 4, &[dev(1), dev(2)]);
    let mut scratch = Vec::new();
    let st = f
        .path()
        .send(
            &dev(1),
            group_send(G, group_message(G, 4, 1)),
            Instant::now(),
            &mut scratch,
        )
        .await;
    assert_eq!(st, SendStatus::Accepted, "{st:?}");
    assert_eq!(f.mailbox.count_pending(&dev(2)).await.unwrap(), 1);
    assert_eq!(f.mailbox.count_pending(&dev(3)).await.unwrap(), 0);
    assert_eq!(
        f.mailbox.count_pending(&dev(1)).await.unwrap(),
        0,
        "not to the sender"
    );

    // The previous epoch is still accepted (sent just before a commit landed).
    let mut prev = group_send(G, group_message(G, 3, 1));
    prev.idempotency_key = [0x78; 16];
    let st = f
        .path()
        .send(&dev(2), prev, Instant::now(), &mut scratch)
        .await;
    assert_eq!(st, SendStatus::Accepted, "{st:?}");

    let refused = |reason| SendStatus::Rejected {
        reason,
        retry_after_ms: 0,
    };
    let cases = [
        // A device outside the roster.
        (
            dev(3),
            group_send(G, group_message(G, 4, 1)),
            refused(RejectReason::NotMember),
        ),
        // An unknown group: the same answer.
        (
            dev(1),
            group_send([9; 16], group_message([9; 16], 4, 1)),
            refused(RejectReason::NotMember),
        ),
        // Too old, or ahead of the roster.
        (
            dev(1),
            group_send(G, group_message(G, 2, 1)),
            refused(RejectReason::StaleEpoch),
        ),
        (
            dev(1),
            group_send(G, group_message(G, 5, 1)),
            refused(RejectReason::StaleEpoch),
        ),
        // Another group's message under this group's flag; a handshake; not MLS at all.
        (
            dev(1),
            group_send(G, group_message([9; 16], 4, 1)),
            refused(RejectReason::InvalidGroupMessage),
        ),
        (
            dev(1),
            group_send(G, group_message(G, 4, 3)),
            refused(RejectReason::InvalidGroupMessage),
        ),
        (
            dev(1),
            group_send(G, Bytes::from_static(b"hello")),
            refused(RejectReason::InvalidGroupMessage),
        ),
    ];
    for (i, (sender, frame, want)) in cases.into_iter().enumerate() {
        let mut frame = frame;
        frame.idempotency_key = [u8::try_from(i).unwrap(); 16];
        let st = f
            .path()
            .send(&sender, frame, Instant::now(), &mut scratch)
            .await;
        assert_eq!(st, want, "case {i}");
    }
    assert_eq!(
        f.mailbox.count_pending(&dev(2)).await.unwrap(),
        1,
        "nothing refused was stored"
    );
}

#[tokio::test]
async fn group_messages_without_rosters_are_unavailable() {
    let f = Fixture::new();
    let g = [0x5B; 16];
    let st = f
        .path()
        .send(
            &dev(1),
            group_send(g, group_message(g, 1, 1)),
            Instant::now(),
            &mut Vec::new(),
        )
        .await;
    assert!(matches!(
        st,
        SendStatus::Rejected {
            reason: RejectReason::Unavailable,
            ..
        }
    ));
}
