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
use songbird_mailbox::iggy::{IggyConfig, IggyConnection, IggyMailbox};
use songbird_mailbox::memory::MemoryMailbox;
use songbird_mailbox::surreal::{SurrealConfig, SurrealMailbox};
use songbird_mailbox::{AnyMailbox, Mailbox};
use songbird_proto::frame::Recipient;
use songbird_router::LocalRouter;
use songbird_types::DeviceId;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Server name used by every test server.
pub const SERVER_NAME: &str = "delivery.test";

/// Factor for wall-clock budgets in tests: `cargo xtask sanitize` builds (`songbird_sanitizer`)
/// run 5-15 times slower under the sanitizers. A test keeps its meaning (well within a timeout),
/// only the scale changes.
pub const SLOW: u32 = if cfg!(songbird_sanitizer) { 10 } else { 1 };

/// Default settings for tests (development environment, loopback, ephemeral port).
#[must_use]
pub fn settings() -> DeliverySettings {
    let text = format!(
        "[common]\nenvironment = \"dev\"\n[delivery]\nlisten = \"127.0.0.1:0\"\nserver_name = \"{SERVER_NAME}\"\n"
    );
    let c: DeliveryConfig =
        songbird_types::config::load_from_parts(&text, Vec::<(String, String)>::new(), "SONGBIRD")
            .unwrap();
    let mut d = c.delivery;
    // Sanitizer builds are 5-15 times slower; a handshake that times out there tests nothing.
    d.session.handshake_timeout_ms *= u64::from(SLOW);
    d.session.auth_timeout_ms *= u64::from(SLOW);
    d
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

/// SurrealDB for the tests, if `SONGBIRD_TEST_SURREALDB` (`host:port`) and
/// `SONGBIRD_TEST_SURREALDB_PASS` are set; each call gets a fresh database. With
/// `SONGBIRD_REQUIRE_SURREALDB=1` (the compose CI job) a missing database fails the test instead of
/// falling back to the in-memory store.
#[must_use]
pub fn surreal_config() -> Option<SurrealConfig> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_SURREALDB") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_SURREALDB").is_err(),
            "SONGBIRD_REQUIRE_SURREALDB is set but SONGBIRD_TEST_SURREALDB is not"
        );
        return None;
    };
    let db = DeviceId::random().unwrap().to_hex_unredacted();
    Some(SurrealConfig {
        rpc: songbird_surreal::Config {
            host: addr.split(':').next().unwrap_or("localhost").to_owned(),
            addr,
            tls: None,
            user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
            pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS")
                .expect("SONGBIRD_TEST_SURREALDB_PASS"),
            namespace: "songbird_e2e".into(),
            database: format!("e2e_{}", &db[..16]),
            timeout: Duration::from_secs(10),
            max_message_bytes: 64 << 20,
        },
        max_batch: 256,
        max_wait: Duration::ZERO,
        ack_interval: Duration::from_millis(10),
        max_per_device: 10_000,
        idempotency_secret: [9; 32],
    })
}

/// A new private directory for a test's key stores: an unpredictable name, created exclusively
/// with mode 0700 under the build's own directory (never a predictable path in a shared temp dir).
fn private_key_dir(parent: &std::path::Path) -> std::path::PathBuf {
    std::fs::create_dir_all(parent).unwrap();
    let dir = parent.join(DeviceId::random().unwrap().to_hex_unredacted());
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir).unwrap();
    dir
}

/// Apache Iggy for the tests, if `SONGBIRD_TEST_IGGY` (`host:port`) and `SONGBIRD_TEST_IGGY_PASS`
/// are set (`SONGBIRD_TEST_IGGY_USER` defaults to `iggy`); each call gets a fresh stream. With
/// `SONGBIRD_REQUIRE_IGGY=1` (the compose CI job) a missing server fails the test.
#[must_use]
pub fn iggy_config() -> Option<IggyConfig> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_IGGY") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_IGGY").is_err(),
            "SONGBIRD_REQUIRE_IGGY is set but SONGBIRD_TEST_IGGY is not"
        );
        return None;
    };
    let connection = IggyConnection {
        addr,
        tls_domain: None,
        tls_ca_file: None,
        user: std::env::var("SONGBIRD_TEST_IGGY_USER").unwrap_or_else(|_| "iggy".into()),
        pass: std::env::var("SONGBIRD_TEST_IGGY_PASS").expect("SONGBIRD_TEST_IGGY_PASS"),
    };
    let id = DeviceId::random().unwrap().to_hex_unredacted();
    let stream = format!("e2e_{}", &id[..16]);
    let key_dir = private_key_dir(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-keys"),
    );
    let mut master = [0u8; 32];
    master.copy_from_slice(&DeviceId::random().unwrap().as_bytes().repeat(2));
    let mut cfg = IggyConfig::new(connection, [9; 32], key_dir, master);
    cfg.stream = stream;
    cfg.ack_interval = Duration::from_millis(10);
    cfg.timeout = Duration::from_secs(10);
    Some(cfg)
}

/// The mailbox the invariant tests run on: Iggy when configured (the deployed store), else
/// SurrealDB when configured, else in memory.
pub async fn test_mailbox() -> AnyMailbox {
    if let Some(cfg) = iggy_config() {
        return AnyMailbox::Iggy(IggyMailbox::connect(cfg).await.unwrap());
    }
    match surreal_config() {
        Some(cfg) => AnyMailbox::Surreal(SurrealMailbox::connect(cfg).await.unwrap()),
        None => AnyMailbox::Memory(MemoryMailbox::new(10_000, 1)),
    }
}

/// Starts a server with `n` known devices on [`test_mailbox`].
pub async fn start(n: usize, tweak: impl FnOnce(&mut DeliverySettings)) -> TestServer<AnyMailbox> {
    start_with(test_mailbox().await, n, tweak).await
}

/// Starts a server with `n` known devices and the given mailbox.
pub async fn start_with<M: Mailbox>(
    mailbox: M,
    n: usize,
    tweak: impl FnOnce(&mut DeliverySettings),
) -> TestServer<M> {
    start_accounts(mailbox, &vec![1; n], tweak).await
}

/// Starts a server whose devices form accounts: `layout[a]` devices for account `a`, numbered
/// consecutively (device indices `0..sum(layout)`).
pub async fn start_accounts<M: Mailbox>(
    mailbox: M,
    layout: &[usize],
    tweak: impl FnOnce(&mut DeliverySettings),
) -> TestServer<M> {
    let mut cfg = settings();
    tweak(&mut cfg);
    let n: usize = layout.iter().sum();
    let mut seeds = Vec::with_capacity(n);
    let mut keys = Vec::with_capacity(n);
    for &count in layout {
        let account = songbird_types::AccountId::random().unwrap();
        for _ in 0..count {
            let device = DeviceId::random().unwrap();
            let (key, seed) = DeviceKey::generate(device).unwrap();
            keys.push((device, key.public_key(), account));
            seeds.push((device, seed));
        }
    }
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tls = cfg.tls.as_ref().map(|t| server::tls_acceptor(t).unwrap());
    let shared = Arc::new(Shared::new(
        cfg,
        Directory::from_accounts(keys),
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
    /// Unacknowledged envelopes of device `i` (a mailbox range count).
    pub async fn pending(&self, i: usize) -> u64 {
        self.shared
            .mailbox
            .count_pending(&self.device(i))
            .await
            .unwrap()
    }

    /// Waits up to 5 s until device `i` has `want` unacknowledged envelopes (ACK deletes are
    /// batched).
    pub async fn wait_pending(&self, i: usize, want: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.pending(i).await != want {
            assert!(
                std::time::Instant::now() < deadline,
                "pending of device {i} never reached {want}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

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
