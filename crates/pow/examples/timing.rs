//! Argon2id evaluation time for candidate parameters, and full solves at the chosen defaults
//! (D-0048). `cargo run --release -p songbird-pow --example timing`.
#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    clippy::indexing_slicing,
    reason = "benchmark tool"
)]

use std::time::Instant;

use songbird_pow::{ChallengeKey, Params, evaluate, solve};

fn main() {
    let key = ChallengeKey::derive(&[1; 32]).unwrap();
    println!("memory_kib iterations  per_eval_ms (median of 41)");
    for (m, t) in [
        (4096, 1),
        (8192, 1),
        (16384, 1),
        (32768, 1),
        (8192, 2),
        (16384, 2),
    ] {
        let c = key
            .issue(
                Params {
                    memory_kib: m,
                    iterations: t,
                    bits: 0,
                    solutions: 1,
                },
                0,
            )
            .unwrap();
        let mut times: Vec<f64> = (0..41u32)
            .map(|i| {
                let s = Instant::now();
                evaluate(&c, i).unwrap();
                s.elapsed().as_secs_f64() * 1e3
            })
            .collect();
        times.sort_by(f64::total_cmp);
        println!("{m:>10} {t:>10} {:>12.2}", times[20]);
    }
    let p = Params {
        memory_kib: std::env::var("POW_M")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(16384),
        iterations: 1,
        bits: std::env::var("POW_BITS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4),
        solutions: std::env::var("POW_K")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8),
    };
    let mut solves: Vec<f64> = (0..30)
        .map(|_| {
            let c = key.issue(p, 0).unwrap();
            let s = Instant::now();
            solve(&c).unwrap().unwrap();
            s.elapsed().as_secs_f64()
        })
        .collect();
    solves.sort_by(f64::total_cmp);
    println!(
        "solve {p:?}: expected {} evaluations; 30 runs p10 {:.2} s, median {:.2} s, p90 {:.2} s, max {:.2} s",
        p.expected_evaluations(),
        solves[3],
        solves[15],
        solves[27],
        solves[29]
    );
    let c = key.issue(p, 0).unwrap();
    let sol = solve(&c).unwrap().unwrap();
    let s = Instant::now();
    songbird_pow::verify(&c, &sol).unwrap();
    println!(
        "verify (all {} solutions): {:.1} ms",
        p.solutions,
        s.elapsed().as_secs_f64() * 1e3
    );
}
