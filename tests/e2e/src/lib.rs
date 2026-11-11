//! Test harness: an in-process delivery server on a loopback port with generated devices, and
//! helpers to connect real clients to it.
#![forbid(unsafe_code)]
#![allow(
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test harness: failing loudly is the point"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use songbird_client::{Client, ClientConfig, DeviceKey, Event, ResumeState};
use songbird_delivery::config::DeliveryConfig;
use songbird_delivery::{DeliveryMetrics, DeliverySettings, Directory, Shared, server};
use songbird_mailbox::Mailbox;
use songbird_mailbox::memory::MemoryMailbox;
use songbird_proto::frame::Recipient;
use songbird_router::LocalRouter;
use songbird_types::DeviceId;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Server name used by every test server.
pub const SERVER_NAME: &str = "delivery.test";

/// Default settings for tests (development environment, loopback, ephemeral port).
#[must_use]
pub fn settings() -> DeliverySettings {
    let text = format!(
        "[common]\nenvironment = \"dev\"\n[delivery]\nlisten = \"127.0.0.1:0\"\nserver_name = \"{SERVER_NAME}\"\n"
    );
    let c: DeliveryConfig =
        songbird_types::config::load_from_parts(&text, Vec::<(String, String)>::new(), "SONGBIRD")
            .unwrap();
    c.delivery
}

/// A running server.
#[allow(missing_debug_implementations, reason = "test harness")]
pub struct TestServer<M: Mailbox> {
    /// Where it listens.
    pub addr: SocketAddr,
    /// Its shared state (mailbox, router, metrics) for assertions.
    pub shared: Arc<Shared<M, LocalRouter>>,
    seeds: Vec<(DeviceId, [u8; 32])>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// Starts a server with `n` known devices and the in-memory mailbox.
pub async fn start(
    n: usize,
    tweak: impl FnOnce(&mut DeliverySettings),
) -> TestServer<MemoryMailbox> {
    start_with(MemoryMailbox::new(10_000, 1), n, tweak).await
}

/// Starts a server with `n` known devices and the given mailbox.
pub async fn start_with<M: Mailbox>(
    mailbox: M,
    n: usize,
    tweak: impl FnOnce(&mut DeliverySettings),
) -> TestServer<M> {
    let mut cfg = settings();
    tweak(&mut cfg);
    let mut seeds = Vec::with_capacity(n);
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        let device = DeviceId::random().unwrap();
        let (key, seed) = DeviceKey::generate(device).unwrap();
        keys.push((device, key.public_key()));
        seeds.push((device, seed));
    }
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tls = cfg.tls.as_ref().map(|t| server::tls_acceptor(t).unwrap());
    let shared = Arc::new(Shared::new(
        cfg,
        Directory::from_keys(keys),
        mailbox,
        LocalRouter::new(),
        DeliveryMetrics::default(),
    ));
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(server::serve(listener, tls, Arc::clone(&shared), stop_rx));
    TestServer {
        addr,
        shared,
        seeds,
        stop,
        task,
    }
}

impl<M: Mailbox> TestServer<M> {
    /// Device `i`.
    #[must_use]
    pub fn device(&self, i: usize) -> DeviceId {
        self.seeds[i].0
    }

    /// Device `i`'s key.
    #[must_use]
    pub fn key(&self, i: usize) -> DeviceKey {
        let (d, seed) = &self.seeds[i];
        DeviceKey::from_seed(*d, seed).unwrap()
    }

    /// A client configuration for this server.
    #[must_use]
    pub fn client_config(&self) -> ClientConfig {
        let mut c = ClientConfig::new(self.addr.to_string(), SERVER_NAME);
        c.backoff.initial = Duration::from_millis(20);
        c.backoff.max = Duration::from_millis(200);
        c.ack_delay = Duration::from_millis(2);
        c
    }

    /// Starts a client for device `i` and waits until it is connected.
    pub async fn connect(&self, i: usize) -> (Client, mpsc::Receiver<Event>) {
        self.connect_with(i, self.client_config(), ResumeState::default())
            .await
    }

    /// Starts a client with explicit settings and waits until it is connected.
    pub async fn connect_with(
        &self,
        i: usize,
        cfg: ClientConfig,
        resume: ResumeState,
    ) -> (Client, mpsc::Receiver<Event>) {
        let (mut c, mut ev) = Client::start(cfg, self.key(i), resume);
        let state = tokio::time::timeout(
            Duration::from_secs(5),
            c.wait_for(songbird_client::State::Connected),
        )
        .await
        .expect("connect timeout");
        assert_eq!(state, songbird_client::State::Connected);
        match next_event(&mut ev).await {
            Event::Connected { .. } => {}
            other => panic!("expected Connected, got {other:?}"),
        }
        (c, ev)
    }

    /// Stops the server (graceful drain) and waits for it.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}

/// Next event within 5 s.
pub async fn next_event(ev: &mut mpsc::Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(5), ev.recv())
        .await
        .expect("event timeout")
        .expect("client stopped")
}

/// Next event that is not `Connected`/`Disconnected` bookkeeping, within 5 s.
pub async fn next_delivery(ev: &mut mpsc::Receiver<Event>) -> (u64, Bytes) {
    loop {
        match next_event(ev).await {
            Event::Deliver { seq, envelope } => return (seq, envelope),
            Event::Connected { .. } | Event::Disconnected { .. } => {}
            other => panic!("expected Deliver, got {other:?}"),
        }
    }
}

/// One recipient entry.
#[must_use]
pub fn to(device: DeviceId, envelope: impl Into<Bytes>) -> Recipient {
    Recipient {
        device,
        envelope: envelope.into(),
    }
}

/// A fresh idempotency key.
#[must_use]
pub fn key() -> [u8; 16] {
    *DeviceId::random().unwrap().as_bytes()
}
