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
    // No device of the sender is known (the sealed endpoint's sentinel).
    let st = f
        .path()
        .send(
            &dev(0xEE),
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
