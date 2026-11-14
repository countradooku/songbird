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
        }
    }

    fn path(&self) -> SendPath<'_, MemoryMailbox, LocalRouter> {
        SendPath {
            directory: &self.directory,
            mailbox: &self.mailbox,
            router: &self.router,
            push: &self.push,
            metrics: &self.metrics,
        }
    }
}

fn to(devices: &[DeviceId], envelope: &'static [u8]) -> SendFrame {
    SendFrame::per_device(
        7,
        [3; 16],
        devices
            .iter()
            .map(|d| Recipient {
                device: *d,
                envelope: Bytes::from_static(envelope),
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
        .send(&dev(1), to(&[dev(2)], b"x"), Instant::now(), &mut scratch)
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
            to(&[dev(2), dev(3)], b"hi"),
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
            to(&[dev(2), dev(3)], b"hi"),
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
    let forged: &'static [u8] = forged.leak();
    let st = f
        .path()
        .send(
            &dev(1),
            to(&[dev(2), dev(3)], forged),
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
        req_id: 1,
        idempotency_key: [4; 16],
        mls: None,
        payload: SendPayload::Shared {
            devices: vec![dev(2), dev(3)],
            body: Bytes::from_static(forged),
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
