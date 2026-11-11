//! Against a real SurrealDB 4: run with `SONGBIRD_TEST_SURREALDB=host:port` and
//! `SONGBIRD_TEST_SURREALDB_PASS` (root user). Skipped when unset, unless
//! `SONGBIRD_REQUIRE_SURREALDB=1` (the compose CI job sets it), which turns a missing database
//! into a failure.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::time::Duration;

use bytes::Bytes;
use songbird_surreal::{Client, Config, Value};

fn config() -> Option<Config> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_SURREALDB") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_SURREALDB").is_err(),
            "SONGBIRD_REQUIRE_SURREALDB is set but SONGBIRD_TEST_SURREALDB is not"
        );
        return None;
    };
    Some(Config {
        host: addr.split(':').next().unwrap_or("localhost").to_owned(),
        addr,
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").expect("SONGBIRD_TEST_SURREALDB_PASS"),
        namespace: "songbird_test".into(),
        database: format!("rpc_{}", std::process::id()),
        timeout: Duration::from_secs(10),
        max_message_bytes: 16 << 20,
    })
}

#[tokio::test]
async fn query_round_trips_bytes_ints_and_record_ids() {
    let Some(cfg) = config() else { return };
    let c = Client::connect(&cfg).await.unwrap();
    let env = Bytes::from_static(&[0, 1, 2, 255]);
    let r = c
        .query(
            "CREATE t:[$d, 7] SET env = $e RETURN NONE; SELECT meta::id(id) AS k, env FROM t:[$d, 0]..=[$d, 99];",
            vec![
                ("d".into(), Value::Bytes(Bytes::from_static(b"dev"))),
                ("e".into(), Value::Bytes(env.clone())),
            ],
        )
        .await
        .unwrap();
    assert_eq!(r.len(), 2);
    let rows = r[1].clone().unwrap().into_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("env").unwrap().as_bytes().unwrap(), &env);
    let k = rows[0].get("k").unwrap().as_array().unwrap();
    assert_eq!(k[1].as_i64(), Some(7));
    // A failing statement is reported per statement, with its kind.
    let r = c
        .query(
            "CREATE t:[$d, 7];",
            vec![("d".into(), Value::Bytes(Bytes::from_static(b"dev")))],
        )
        .await
        .unwrap();
    let e = r[0].clone().unwrap_err();
    assert_ne!(e.kind, "");
}

#[tokio::test]
async fn pipelines_many_requests() {
    let Some(cfg) = config() else { return };
    let c = Client::connect(&cfg).await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..200i64 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            let r = c
                .query("RETURN $x * 2;", vec![("x".into(), Value::Int(i))])
                .await
                .unwrap();
            assert_eq!(r[0].clone().unwrap().as_i64(), Some(i * 2));
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}
