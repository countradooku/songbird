//! D-0028: the same WebSocket echo server (sockudo-ws) on two thread-per-core runtimes, with
//! `WORKERS` pinned workers each owning an `SO_REUSEPORT` listener on `ADDR`:
//!
//! - `MODE=tokio`: a current-thread Tokio runtime per core (epoll), as `delivery` runs.
//! - `MODE=compio`: a compio runtime per core (io_uring, completion based), sockudo-ws's native
//!   compio API.
//!
//! Driven by `songbird-loadgen echo` (round trips per second and latency).
#![allow(clippy::all)]

use futures_util::{SinkExt as _, StreamExt as _};
use sockudo_ws::{Config, Message};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let mode = std::env::var("MODE").unwrap_or_else(|_| "tokio".into());
    let workers: usize = std::env::var("WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "127.0.0.1:9391".into());
    let listeners = songbird_runtime::reuseport_listeners(addr.parse().unwrap(), workers, 4096)
        .expect("bind");
    let listeners = std::sync::Arc::new(std::sync::Mutex::new(
        listeners.into_iter().map(Some).collect::<Vec<_>>(),
    ));
    let compio = mode == "compio";
    println!("echo mode={mode} workers={workers} addr={addr}");
    let w = songbird_runtime::start(
        songbird_runtime::Config {
            workers,
            pin: true,
        },
        move |core| {
            let l = listeners.lock().unwrap()[core.index].take().unwrap();
            async move {
                if compio {
                    // A compio runtime on this (pinned) thread; the Tokio runtime around it idles.
                    let rt = compio::runtime::Runtime::new().expect("compio runtime");
                    rt.block_on(compio_serve(l));
                } else {
                    tokio_serve(l).await;
                }
            }
        },
    )
    .expect("start");
    w.join();
}

async fn tokio_serve(l: std::net::TcpListener) {
    let l = tokio::net::TcpListener::from_std(l).unwrap();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    continue;
                };
                let _ = s.set_nodelay(true);
                tokio::task::spawn_local(async move {
                    let Ok(h) = sockudo_ws::handshake::server_handshake(&mut s).await else {
                        return;
                    };
                    let mut ws = sockudo_ws::WebSocketStream::from_raw_with_leftover(
                        s,
                        sockudo_ws::Role::Server,
                        Config::default(),
                        h.leftover,
                    );
                    while let Some(Ok(m)) = ws.next().await {
                        match m {
                            Message::Binary(_) | Message::Text(_) => {
                                if ws.send(m).await.is_err() {
                                    break;
                                }
                            }
                            Message::Close(_) => break,
                            _ => {}
                        }
                    }
                });
            }
        })
        .await;
}

async fn compio_serve(l: std::net::TcpListener) {
    let l = compio::net::TcpListener::from_std(l).unwrap();
    loop {
        let Ok((s, _)) = l.accept().await else {
            continue;
        };
        let _ = s.set_nodelay(true);
        compio::runtime::spawn(async move {
            let Ok((mut ws, _)) = sockudo_ws::compio::accept_async(s, Config::default()).await
            else {
                return;
            };
            while let Some(Ok(m)) = ws.next().await {
                match m {
                    Message::Binary(_) | Message::Text(_) => {
                        if ws.send(m).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        })
        .detach();
    }
}
