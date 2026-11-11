//! `pusher`: 1:1 relay through a Pusher-protocol server (the Sockudo server), for the baseline the
//! master prompt asks for (§8, "Baselines on the same hardware: Sockudo").
//!
//! Devices form pairs; each pair shares a private channel and exchanges client events on it
//! (Pusher delivers a client event to every other subscriber, never the sender). Each device sends
//! at an equal share of the total rate, open loop. Sockudo stores nothing and nobody
//! acknowledges, so this is a *lighter* workload than `run` against Songbird (store, ACK,
//! delete): the comparison bounds what a relay without durability costs on the same core.
//! Checked: every sent event received once, per-sender order kept.

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use aws_lc_rs::hmac;
use bytes::Bytes;
use futures_core::Stream as _;
use futures_sink::Sink as _;
use sockudo_ws::client::WebSocketClient;
use sockudo_ws::{Http1, Message, WebSocketStream};
use tokio::net::TcpStream;

use crate::stats;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Server `host:port`.
    #[arg(long, default_value = "127.0.0.1:6001")]
    addr: String,
    /// App key.
    #[arg(long, default_value = "app-key")]
    key: String,
    /// App secret (signs private-channel subscriptions).
    #[arg(long, default_value = "app-secret")]
    secret: String,
    /// Devices (even; pairs share a channel).
    #[arg(long, default_value_t = 1000)]
    devices: usize,
    /// Total events per second across all devices.
    #[arg(long, default_value_t = 10_000)]
    rate: u64,
    /// Approximate event size in bytes on the wire.
    #[arg(long, default_value_t = 256)]
    size: usize,
    /// Seconds of sending.
    #[arg(long, default_value_t = 10)]
    secs: u64,
    /// Load generator worker threads.
    #[arg(long, default_value_t = 8)]
    threads: usize,
}

pub(crate) fn main(a: &Args) -> anyhow::Result<bool> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(a.threads.max(1))
        .enable_all()
        .build()?;
    rt.block_on(run(a))
}

type Ws = WebSocketStream<TcpStream>;

async fn send_text(ws: &mut Ws, text: String) -> anyhow::Result<()> {
    poll_fn(|cx| Pin::new(&mut *ws).poll_ready(cx)).await?;
    Pin::new(&mut *ws).start_send(Message::Text(Bytes::from(text)))?;
    poll_fn(|cx| Pin::new(&mut *ws).poll_flush(cx)).await?;
    Ok(())
}

async fn next_text(ws: &mut Ws) -> anyhow::Result<Bytes> {
    loop {
        match poll_fn(|cx| Pin::new(&mut *ws).poll_next(cx)).await {
            Some(Ok(Message::Text(t))) => return Ok(t),
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_))) => {}
            other => bail!("connection ended: {other:?}"),
        }
    }
}

/// The digits after `"<field>":` (numbers) or inside `\"<field>\":\"…\"` (the escaped socket ID).
fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let at = text.find(name)? + name.len();
    let rest = text.get(at..)?;
    let start = rest.find(|c: char| c.is_ascii_digit())?;
    let rest = rest.get(start..)?;
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    rest.get(..end)
}

async fn connect(a: &Args, channel: &str) -> anyhow::Result<Ws> {
    let tcp = TcpStream::connect(&a.addr).await.context("connect")?;
    tcp.set_nodelay(true)?;
    let path = format!(
        "/app/{}?protocol=7&client=songbird-loadgen&version=0.1",
        a.key
    );
    let host = a.addr.split(':').next().unwrap_or("localhost");
    let (mut ws, _) = WebSocketClient::<Http1>::new(sockudo_ws::Config::default())
        .connect_raw(tcp, host, &path, None)
        .await
        .context("upgrade")?;
    let hello = next_text(&mut ws).await?;
    let hello = std::str::from_utf8(&hello)?;
    let socket_id = field(hello, "socket_id")
        .context("no socket_id")?
        .to_owned();
    let key = hmac::Key::new(hmac::HMAC_SHA256, a.secret.as_bytes());
    let sig = hex::encode(hmac::sign(
        &key,
        format!("{socket_id}:{channel}").as_bytes(),
    ));
    send_text(
        &mut ws,
        format!(
            r#"{{"event":"pusher:subscribe","data":{{"channel":"{channel}","auth":"{}:{sig}"}}}}"#,
            a.key
        ),
    )
    .await?;
    loop {
        let m = next_text(&mut ws).await?;
        let m = std::str::from_utf8(&m)?;
        if m.contains("subscription_succeeded") {
            return Ok(ws);
        }
        if m.contains("pusher:error") || m.contains("subscription_error") {
            bail!("subscribe refused");
        }
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "one scenario, read top to bottom"
)]
async fn run(a: &Args) -> anyhow::Result<bool> {
    let n = a.devices & !1;
    anyhow::ensure!(n >= 2, "need at least 2 devices");
    let mut conns = Vec::with_capacity(n);
    for i in 0..n {
        conns.push(connect(a, &format!("private-pair-{}", i / 2)).await?);
    }
    let epoch = Instant::now();
    let until = epoch + Duration::from_secs(a.secs);
    let period = Duration::from_secs_f64(
        f64::from(u32::try_from(n).unwrap_or(u32::MAX)) / crate::as_f64(a.rate.max(1)),
    );
    let pad = "x".repeat(a.size.saturating_sub(110));
    let received_total = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::with_capacity(n);
    for (i, mut ws) in conns.into_iter().enumerate() {
        let channel = format!("private-pair-{}", i / 2);
        let pad = pad.clone();
        let total = Arc::clone(&received_total);
        tasks.push(tokio::spawn(async move {
            let mut sent = 0u64;
            let mut got = 0u64;
            let mut last_n: Option<u64> = None;
            let (mut dup_or_reorder, mut lat) = (0u64, Vec::<u32>::new());
            let first = Duration::from_nanos(
                u64::try_from(period.as_nanos()).unwrap_or(1) * (u64::try_from(i).unwrap_or(0) % 97) / 97,
            );
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + first, period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let grace = until + Duration::from_secs(3);
            loop {
                let now = Instant::now();
                if now >= grace {
                    break;
                }
                tokio::select! {
                    _ = tick.tick(), if now < until => {
                        let t = u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(0);
                        let msg = format!(
                            r#"{{"event":"client-m","channel":"{channel}","data":{{"n":{sent},"t":{t},"p":"{pad}"}}}}"#
                        );
                        if send_text(&mut ws, msg).await.is_err() {
                            break;
                        }
                        sent += 1;
                    }
                    m = poll_fn(|cx| Pin::new(&mut ws).poll_next(cx)) => match m {
                        Some(Ok(Message::Text(b))) => {
                            let Ok(text) = std::str::from_utf8(&b) else { continue };
                            if !text.contains("client-m") {
                                continue;
                            }
                            let num = |f| field(text, f).and_then(|v| v.parse::<u64>().ok());
                            if let (Some(seq), Some(t)) = (num("\"n\":"), num("\"t\":")) {
                                if last_n.is_some_and(|l| seq <= l) {
                                    dup_or_reorder += 1;
                                }
                                last_n = Some(seq);
                                got += 1;
                                total.fetch_add(1, Ordering::Relaxed);
                                let now = u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(0);
                                lat.push(u32::try_from(now.saturating_sub(t) / 1000).unwrap_or(u32::MAX));
                            }
                        }
                        Some(Ok(_)) => {}
                        _ => break,
                    },
                    () = tokio::time::sleep_until(grace.into()) => break,
                }
            }
            (i, sent, got, dup_or_reorder, lat)
        }));
    }
    let mut sent = vec![0u64; n];
    let mut got = vec![0u64; n];
    let (mut bad, mut lat) = (0u64, Vec::new());
    for t in tasks {
        let (i, s, g, d, l) = t.await?;
        if let (Some(sv), Some(gv)) = (sent.get_mut(i), got.get_mut(i)) {
            *sv = s;
            *gv = g;
        }
        bad += d;
        lat.extend(l);
    }
    // Device i's events are received by its partner i ^ 1.
    let mut lost = 0u64;
    for i in 0..n {
        let s = sent.get(i).copied().unwrap_or(0);
        let g = got.get(i ^ 1).copied().unwrap_or(0);
        lost += s.saturating_sub(g);
    }
    let total_sent: u64 = sent.iter().sum();
    let secs = crate::as_f64(a.secs);
    let s = stats::summarize(&mut lat);
    println!(
        "pusher addr={} devices={n} pairs={} secs={} target_rate={} size~{}",
        a.addr,
        n / 2,
        a.secs,
        a.rate,
        a.size
    );
    println!(
        "events: sent={total_sent} received={} achieved_rate={:.0}/s lost={lost} dup_or_reorder={bad}",
        received_total.load(Ordering::Relaxed),
        crate::as_f64(total_sent) / secs
    );
    println!("latency send->receive (client-observed): {s}");
    Ok(lost == 0 && bad == 0)
}
