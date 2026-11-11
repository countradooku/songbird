//! Round-trip latency of small SurrealDB RPC requests (diagnostics for the commit path).
//! `SURREAL_ADDR=… SURREAL_PASS=… cargo run --release -p songbird-surreal --example rtt`
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "a diagnostic tool"
)]

use std::time::{Duration, Instant};

use songbird_surreal::{Client, Config, Value};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let addr = std::env::var("SURREAL_ADDR").expect("SURREAL_ADDR");
    let c = Client::connect(&Config {
        host: "localhost".into(),
        addr,
        tls: None,
        user: "root".into(),
        pass: std::env::var("SURREAL_PASS").expect("SURREAL_PASS"),
        namespace: "rtt".into(),
        database: "rtt".into(),
        timeout: Duration::from_secs(10),
        max_message_bytes: 1 << 20,
    })
    .await
    .unwrap();
    for (name, sql) in [
        ("ping", ""),
        ("RETURN 1", "RETURN 1;"),
        (
            "BEGIN; RETURN 1; COMMIT",
            "BEGIN TRANSACTION; RETURN 1; COMMIT TRANSACTION;",
        ),
        ("CREATE one row", "CREATE t SET x = 1 RETURN NONE;"),
        (
            "BEGIN; CREATE; COMMIT",
            "BEGIN TRANSACTION; CREATE t SET x = 1 RETURN NONE; COMMIT TRANSACTION;",
        ),
    ] {
        let mut v = Vec::new();
        for _ in 0..200 {
            let t = Instant::now();
            if sql.is_empty() {
                c.call("ping", Value::Array(vec![])).await.unwrap();
            } else {
                c.query(sql, vec![]).await.unwrap();
            }
            v.push(t.elapsed().as_micros());
        }
        v.sort_unstable();
        println!("{name:28} p50={}us p99={}us", v[100], v[198]);
    }
}
