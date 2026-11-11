//! Echo server for the Autobahn WebSocket conformance suite (`cargo xtask autobahn`).
//!
//! It uses the delivery service's own upgrade code and WebSocket configuration
//! (`songbird_delivery::ws`), with the default limits, so the suite tests what production runs.
//! The only differences: any path, no subprotocol, and text messages are echoed (the Songbird
//! protocol itself is binary-only). Not deployed.
//!
//! Usage: `songbird-delivery-autobahn [addr] [max_message_bytes]`. The second argument raises
//! the message limit to check that the WebSocket layer itself handles the suite's 16 MiB cases;
//! the default is the production limit.
#![forbid(unsafe_code)]
#![allow(clippy::print_stderr, reason = "a test tool; stderr is its interface")]

use std::net::SocketAddr;
use std::process::ExitCode;

use sockudo_ws::Message;
use songbird_delivery::config::SessionConfig;
use songbird_delivery::ws;
use songbird_proto::Limits;

fn main() -> ExitCode {
    sockudo_ws::init_clock();
    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9001".into())
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 9001)));
    let max = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| Limits::DEFAULT.max_message_bytes());
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    rt.block_on(async move {
        let Ok(listener) = tokio::net::TcpListener::bind(addr).await else {
            eprintln!("cannot bind {addr}");
            return ExitCode::FAILURE;
        };
        eprintln!("autobahn echo on {addr}, max message {max} bytes");
        let session = SessionConfig::default();
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let _ = tcp.set_nodelay(true);
            let cfg = ws::ws_config(&session, max);
            let timeout = session.handshake_timeout();
            tokio::spawn(async move {
                let policy = ws::Policy {
                    path: None,
                    protocol: None,
                };
                let Ok(mut w) = ws::upgrade(tcp, policy, cfg, timeout).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws::next(&mut w).await {
                    let echo = match msg {
                        Message::Text(_) | Message::Binary(_) => msg,
                        Message::Close(_) => break,
                        Message::Ping(_) | Message::Pong(_) => continue,
                    };
                    if ws::feed(&mut w, echo).await.is_err() || ws::flush(&mut w).await.is_err() {
                        break;
                    }
                }
                // Drive the closing handshake to completion.
                while ws::next(&mut w).await.is_some() {}
            });
        }
    })
}
