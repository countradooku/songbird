//! Store generation and client resend (D-0040, PROTOCOL.md §3.6): after a restore, users lose no
//! message. Runs on the mailbox the invariant tests use (Iggy in CI's compose job).
//!
//! - `a_lost_mailbox_is_refilled_by_senders`: the mailbox is lost entirely and replaced by an
//!   empty one (as after a restore: the mailbox is never backed up); the generation grows; the
//!   sender resends every message without a delivery receipt, and the recipient gets exactly
//!   those, in order.
//! - `a_surviving_mailbox_stores_nothing_twice`: the generation grows but the mailbox survived
//!   (only the registry was restored); the resend reuses each message's idempotency key, so the
//!   recipient sees each message once.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use songbird_client::Event;
use songbird_e2e::{key, next_delivery, start, start_with, to};
use songbird_mailbox::memory::MemoryMailbox;
use songbird_mailbox::{Mailbox, MailboxError, StoreOutcome, StoreRequest, Stored};
use songbird_proto::frame::SendStatus;
use songbird_types::DeviceId;

/// A mailbox that can be lost: the test swaps in an empty one, as a disaster would leave it.
struct Losable(RwLock<Arc<MemoryMailbox>>);

impl Losable {
    fn new() -> Self {
        Self(RwLock::new(Arc::new(MemoryMailbox::new(10_000, 1))))
    }
    fn current(&self) -> Arc<MemoryMailbox> {
        Arc::clone(&self.0.read().unwrap())
    }
    fn lose(&self) {
        *self.0.write().unwrap() = Arc::new(MemoryMailbox::new(10_000, 1));
    }
}

impl Mailbox for Losable {
    async fn store(&self, req: StoreRequest) -> Result<StoreOutcome, MailboxError> {
        self.current().store(req).await
    }
    async fn fetch_after(
        &self,
        d: &DeviceId,
        after: u64,
        n: usize,
    ) -> Result<Vec<Stored>, MailboxError> {
        self.current().fetch_after(d, after, n).await
    }
    async fn ack_up_to(&self, d: &DeviceId, up: u64) -> Result<(), MailboxError> {
        self.current().ack_up_to(d, up).await
    }
    async fn expire_older_than(&self, age: Duration) -> Result<u64, MailboxError> {
        self.current().expire_older_than(age).await
    }
    async fn store_generation(&self) -> Result<u64, MailboxError> {
        self.current().store_generation().await
    }
    async fn count_pending(&self, d: &DeviceId) -> Result<u64, MailboxError> {
        self.current().count_pending(d).await
    }
    async fn forget(&self, ds: &[DeviceId]) -> Result<(), MailboxError> {
        self.current().forget(ds).await
    }
    async fn knows(&self, d: &DeviceId) -> Result<bool, MailboxError> {
        self.current().knows(d).await
    }
}

/// Waits for the generation change on a client's event stream (deliveries are not expected).
async fn wait_restored(ev: &mut tokio::sync::mpsc::Receiver<Event>) -> (u64, u64) {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ev.recv())
            .await
            .expect("no generation change")
            .expect("client stopped")
        {
            Event::StoreGenerationChanged { previous, current } => return (previous, current),
            Event::Connected { .. } | Event::Disconnected { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_lost_mailbox_is_refilled_by_senders() {
    let s = start_with(Losable::new(), 2, |_| {}).await;
    let (alice, mut aev) = s.connect(0).await;
    let bob = s.device(1);
    // Five messages to Bob while he is offline; Bob's app later confirms the first two through
    // end-to-end delivery receipts (simulated here), so only three are left without one.
    let keys: Vec<[u8; 16]> = (0..5).map(|_| key()).collect();
    for (i, k) in keys.iter().enumerate() {
        let r = alice
            .send(*k, vec![to(bob, format!("m{i}"))])
            .await
            .unwrap();
        assert_eq!(r, SendStatus::Accepted);
    }
    for k in &keys[..2] {
        alice.confirm_delivered(*k).await.unwrap();
    }
    assert_eq!(s.pending(1).await, 5);

    // Disaster: the mailbox is gone (messages, counters, idempotency records), and the restore
    // runbook bumps the generation.
    s.shared.mailbox.lose();
    assert_eq!(s.pending(1).await, 0);
    s.shared.generation.store(2, Ordering::Release);

    // Alice reconnects, sees the new generation and resends the three unconfirmed messages.
    alice.abort_connection().await.unwrap();
    assert_eq!(wait_restored(&mut aev).await, (1, 2));
    for _ in 0..200 {
        if s.pending(1).await == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        s.pending(1).await,
        3,
        "exactly the unconfirmed ones were stored again"
    );

    // Bob connects and gets them in order, numbered from 1 again (the counters were lost).
    let (_bob_c, mut bev) = s.connect(1).await;
    for (i, want) in ["m2", "m3", "m4"].iter().enumerate() {
        let (seq, env) = next_delivery(&mut bev).await;
        assert_eq!(seq, u64::try_from(i).unwrap() + 1);
        assert_eq!(&env[..], want.as_bytes());
    }
    s.stop().await;
}

#[tokio::test]
async fn a_surviving_mailbox_stores_nothing_twice() {
    let s = start(2, |_| {}).await;
    let (alice, mut aev) = s.connect(0).await;
    let bob = s.device(1);
    for i in 0..3 {
        let r = alice
            .send(key(), vec![to(bob, format!("m{i}"))])
            .await
            .unwrap();
        assert_eq!(r, SendStatus::Accepted);
    }
    assert_eq!(s.pending(1).await, 3);
    // Only the registry was restored: the generation grows, the mailbox is intact.
    s.shared.generation.store(2, Ordering::Release);
    alice.abort_connection().await.unwrap();
    assert_eq!(wait_restored(&mut aev).await, (1, 2));
    // The resends replay their idempotency records: nothing is stored twice.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(s.pending(1).await, 3);
    let (_bob_c, mut bev) = s.connect(1).await;
    for i in 0..3u64 {
        let (seq, env) = next_delivery(&mut bev).await;
        assert_eq!((seq, &env[..]), (i + 1, format!("m{i}").as_bytes()));
    }
    // And nothing more arrives.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), next_delivery(&mut bev))
            .await
            .is_err()
    );
    s.stop().await;
}
