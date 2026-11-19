//! The cost of tokens (D-0128): a client's request and finish, the issuer's batched evaluation,
//! and the redeemer's check, for batches of 1, 2 and 7 (Plus and Family's monthly caps).
//!
//! `cargo test --release -p songbird-tokens --test bench -- --ignored --nocapture`
#![allow(
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::similar_names,
    reason = "a benchmark"
)]

use std::time::Instant;

use songbird_tokens::token::{self, Info, Keys, Kind};

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

#[test]
#[ignore = "a benchmark: run in release"]
fn token_costs() {
    let keys = Keys::derive(&[9; 32], &[1]).unwrap();
    let pinned = keys.public()[0].1;
    let info = Info {
        kind: Kind::Plan,
        level: 1,
        period: 683,
    };
    for n in [1usize, 2, 7] {
        let (mut req_t, mut iss_t, mut fin_t, mut red_t) = (vec![], vec![], vec![], vec![]);
        for _ in 0..200 {
            let t = Instant::now();
            let (pending, req) = token::request(1, info, n).unwrap();
            req_t.push(t.elapsed().as_secs_f64() * 1e6);
            let t = Instant::now();
            let resp = keys.issue(&req).unwrap();
            iss_t.push(t.elapsed().as_secs_f64() * 1e6);
            let t = Instant::now();
            let tokens = pending.finish(&pinned, &resp).unwrap();
            fin_t.push(t.elapsed().as_secs_f64() * 1e6);
            let t = Instant::now();
            keys.redeem(&tokens[0]).unwrap();
            red_t.push(t.elapsed().as_secs_f64() * 1e6);
        }
        eprintln!(
            "batch {n}: client request {:.0} µs, issuer {:.0} µs, client finish {:.0} µs, redeem one {:.0} µs (medians of 200)",
            median(req_t),
            median(iss_t),
            median(fin_t),
            median(red_t)
        );
    }
}
