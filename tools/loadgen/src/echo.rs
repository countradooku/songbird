//! `echo`: closed-loop WebSocket round trips against any echo server, for library baselines
//! (sockudo-ws examples versus `songbird-delivery-autobahn`) on the same hardware.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::{BufMut as _, BytesMut};
use futures_core::Stream as _;
use futures_sink::Sink as _;
use sockudo_ws::client::WebSocketClient;
use sockudo_ws::{Http1, Message, WebSocketStream};
use tokio::net::TcpStream;

use crate::stats;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Echo server `host:port`.
    #[arg(long)]
    addr: String,
    /// Request path.
    #[arg(long, default_value = "/")]
    path: String,
    /// Connections.
    #[arg(long, default_value_t = 100)]
    connections: usize,
    /// Messages in flight per connection.
    #[arg(long, default_value_t = 1)]
    inflight: usize,
    /// Message size in bytes (at least 8).
    #[arg(long, default_value_t = 256)]
    size: usize,
    /// Seconds to run.
    #[arg(long, default_value_t = 10)]
    secs: u64,
    /// Load generator worker threads.
    #[arg(long, default_value_t = 4)]
    threads: usize,
}

pub(crate) fn main(a: &Args) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(a.threads.max(1))
        .enable_all()
        .build()?;
    rt.block_on(run(a))
}

type Ws = WebSocketStream<TcpStream>;

async fn send(ws: &mut Ws, m: Message) -> sockudo_ws::Result<()> {
    poll_fn(|cx| Pin::new(&mut *ws).poll_ready(cx)).await?;
    Pin::new(&mut *ws).start_send(m)?;
    poll_fn(|cx| Pin::new(&mut *ws).poll_flush(cx)).await
}

async fn run(a: &Args) -> anyhow::Result<()> {
    let size = a.size.max(8);
    let epoch = Instant::now();
    let until = epoch + Duration::from_secs(a.secs);
    let total = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::with_capacity(a.connections);
    for _ in 0..a.connections {
        let tcp = TcpStream::connect(&a.addr).await.context("connect")?;
        tcp.set_nodelay(true)?;
        let host = a.addr.split(':').next().unwrap_or("localhost").to_owned();
        let (mut ws, _) = WebSocketClient::<Http1>::new(sockudo_ws::Config::default())
            .connect_raw(tcp, &host, &a.path, None)
            .await
            .context("upgrade")?;
        let total = Arc::clone(&total);
        let inflight = a.inflight.max(1);
        tasks.push(tokio::spawn(async move {
            let mut lat: Vec<u32> = Vec::new();
            let msg = |buf: &mut BytesMut| {
                buf.put_u64(u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(0));
                buf.resize(size, 0x5A);
                Message::Binary(buf.split().freeze())
            };
            let mut buf = BytesMut::with_capacity(size * 4);
            for _ in 0..inflight {
                if send(&mut ws, msg(&mut buf)).await.is_err() {
                    return lat;
                }
            }
            while let Some(Ok(m)) = poll_fn(|cx| Pin::new(&mut ws).poll_next(cx)).await {
                if let Message::Binary(b) = m {
                    if let Some(t) = b.get(..8).and_then(|s| s.try_into().ok()) {
                        let sent = u64::from_be_bytes(t);
                        let now = u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(0);
                        lat.push(
                            u32::try_from(now.saturating_sub(sent) / 1000).unwrap_or(u32::MAX),
                        );
                    }
                    total.fetch_add(1, Ordering::Relaxed);
                    if Instant::now() >= until {
                        break;
                    }
                    if send(&mut ws, msg(&mut buf)).await.is_err() {
                        break;
                    }
                }
            }
            let _ = ws.close(1000, "").await;
            lat
        }));
    }
    let mut lat = Vec::new();
    for t in tasks {
        lat.extend(t.await?);
    }
    let secs = epoch.elapsed().as_secs_f64();
    let rate = crate::as_f64(total.load(Ordering::Relaxed)) / secs;
    let s = stats::summarize(&mut lat);
    println!(
        "echo addr={} connections={} inflight={} size={} secs={}",
        a.addr, a.connections, a.inflight, size, a.secs
    );
    println!("throughput: {rate:.0} msg/s");
    println!("round trip: {s}");
    Ok(())
}
