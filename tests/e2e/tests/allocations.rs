//! Heap allocations per message on the server in steady state (master prompt §4: "steady-state
//! delivery must not allocate per message"; M3 gate).
//!
//! The server runs on its own thread (a current-thread runtime, as one delivery core), and a
//! counting global allocator counts only that thread's allocations. A sender and a receiver
//! (clients, on the test's own threads) exchange messages; after a warm-up, the allocations on
//! the server thread are divided by the messages that went through it: decoded, checked, stored
//! (in-memory mailbox), routed, written to the receiver and acknowledged.
//!
//! The test asserts the budget below and prints the measurement, so a regression fails CI.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::too_many_lines,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use songbird_client::{Client, ClientConfig, DeviceKey, Event, ResumeState};
use songbird_delivery::{DeliveryMetrics, Directory, Shared, server};
use songbird_e2e::{SERVER_NAME, key, next_event, settings, to};
use songbird_mailbox::AnyMailbox;
use songbird_mailbox::memory::MemoryMailbox;
use songbird_proto::frame::SendStatus;
use songbird_router::LocalRouter;
use songbird_types::DeviceId;
use tokio::sync::watch;

#[global_allocator]
static GLOBAL: songbird_alloc_count::Counting = songbird_alloc_count::Counting;

/// Allocations per message on the server, measured (M3, report P02-M3; DHAT attributes each):
/// the send path makes five, one each: the decoded recipient list (`frame.rs`), the store
/// request handed to the mailbox, the in-memory mailbox's idempotency record and recipient list,
/// and the `seq` list it returns. The delivery path (route, socket write, ACK) makes none. The
/// fraction above five is amortised buffer growth. A new allocation anywhere on the path fails
/// this budget.
const BUDGET_PER_MESSAGE: f64 = 5.5;

fn client_config(addr: std::net::SocketAddr) -> ClientConfig {
    let mut c = ClientConfig::new(addr.to_string(), SERVER_NAME);
    c.backoff.initial = Duration::from_millis(20);
    c.ack_delay = Duration::from_millis(1);
    c
}

#[test]
fn server_allocations_per_message_stay_within_budget() {
    let mut cfg = settings();
    // Far above this test's rate: nothing here is rate limited.
    cfg.session.sends_per_sec = 1_000_000;
    cfg.session.send_burst = 1_000_000;
    cfg.session.frames_per_sec = 1_000_000;
    cfg.session.frame_burst = 1_000_000;
    let mut keys = Vec::new();
    let mut seeds = Vec::new();
    for _ in 0..2 {
        let account = songbird_types::AccountId::random().unwrap();
        let device = DeviceId::random().unwrap();
        let (k, seed) = DeviceKey::generate(device).unwrap();
        keys.push((device, k.public_key(), account));
        seeds.push((device, seed));
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stop_rx) = watch::channel(false);
    let shared = Arc::new(Shared::new(
        cfg,
        Directory::from_accounts(keys),
        AnyMailbox::Memory(MemoryMailbox::new(100_000, 1)),
        LocalRouter::new(),
        DeliveryMetrics::default(),
    ));
    let server_shared = Arc::clone(&shared);
    let server = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let shared = server_shared;
            songbird_alloc_count::count_this_thread(true);
            let l = tokio::net::TcpListener::from_std(listener).unwrap();
            server::serve(l, None, shared, stop_rx).await;
            songbird_alloc_count::count_this_thread(false);
        });
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (per_msg, bytes_per_msg) = rt.block_on(async move {
        let key_of = |i: usize| DeviceKey::from_seed(seeds[i].0, &seeds[i].1).unwrap();
        let (mut a, mut a_ev) = Client::start(client_config(addr), key_of(0), ResumeState::default());
        let (mut b, mut b_ev) = Client::start(client_config(addr), key_of(1), ResumeState::default());
        for (c, ev) in [(&mut a, &mut a_ev), (&mut b, &mut b_ev)] {
            c.wait_for(songbird_client::State::Connected).await;
            assert!(matches!(next_event(ev).await, Event::Connected { .. }));
        }
        let bob = seeds[1].0;
        let body = bytes::Bytes::from(vec![0x5A; 256]);
        // One message at a time, each delivered and acknowledged before the next: every
        // per-message allocation on the server is counted, none hidden by batching.
        let mut round = async |n: u64| {
            for _ in 0..n {
                let sent = a.send(key(), vec![to(bob, body.clone())]).await.unwrap();
                assert_eq!(sent, SendStatus::Accepted);
                loop {
                    let ev = tokio::time::timeout(Duration::from_secs(5), b_ev.recv()).await;
                    let Ok(Some(ev)) = ev else {
                        let m = &shared.metrics;
                        panic!(
                            "no delivery: stored={} live={} drained={} offline={} rejected={} auth_ok={}",
                            m.envelopes_stored.get(),
                            m.delivered_live.get(),
                            m.delivered_drained.get(),
                            m.routes_offline.get(),
                            m.sends_rejected.get(),
                            m.auth_ok.get()
                        );
                    };
                    match ev {
                        Event::Deliver { seq, .. } => {
                            b.ack(seq).await.unwrap();
                            break;
                        }
                        Event::Connected { .. } | Event::Disconnected { .. } => {}
                        other => panic!("unexpected {other:?}"),
                    }
                }
            }
            // Let the last ACK reach the server.
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        round(500).await;
        let (a0, b0) = songbird_alloc_count::snapshot();
        let n = 2_000;
        round(n).await;
        let (a1, b1) = songbird_alloc_count::snapshot();
        (
            (a1 - a0) as f64 / n as f64,
            (b1 - b0) as f64 / n as f64,
        )
    });
    let _ = stop.send(true);
    server.join().unwrap();
    println!("server allocations per message: {per_msg:.2} ({bytes_per_msg:.0} bytes)");
    assert!(
        per_msg <= BUDGET_PER_MESSAGE,
        "{per_msg:.2} allocations per message, budget {BUDGET_PER_MESSAGE}"
    );
}
