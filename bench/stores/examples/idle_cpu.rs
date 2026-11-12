//! Idle CPU of (a) bare Iggy SDK clients and (b) the mailbox, on a current-thread runtime.
//! IGGY_ADDR, IGGY_PASS, CLIENTS (default 1), MODE=sdk|mailbox.
use std::time::Duration;

fn cpu_ticks() -> u64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap();
    let f: Vec<&str> = s.rsplit(')').next().unwrap().split_whitespace().collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

fn main() {
    let rt = if std::env::var("MT").is_ok() { tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap() } else { tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap() };
    rt.block_on(async {
        let conn = songbird_mailbox::iggy::IggyConnection {
            addr: std::env::var("IGGY_ADDR").unwrap(),
            tls_domain: None,
            tls_ca_file: None,
            user: "iggy".into(),
            pass: std::env::var("IGGY_PASS").unwrap(),
        };
        let mode = std::env::var("MODE").unwrap_or_else(|_| "sdk".into());
        let n: usize = std::env::var("CLIENTS").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
        let mut keep = Vec::new();
        let mut mb = None;
        if mode == "sdk" {
            for _ in 0..n {
                keep.push(conn.client().await.unwrap());
            }
        } else {
            let mut cfg = songbird_mailbox::iggy::IggyConfig::new(conn, random_secret(), private_key_dir(), random_secret());
            cfg.stream = format!("idle{}", std::process::id());
            mb = Some(songbird_mailbox::iggy::IggyMailbox::connect(cfg).await.unwrap());
        }
        let t0 = cpu_ticks();
        tokio::time::sleep(Duration::from_secs(5)).await;
        let t1 = cpu_ticks();
        println!("mode={mode} clients={n} idle cpu ticks over 5 s: {}", t1 - t0);
        drop(mb);
    });
}

/// A new private directory for this run's mailbox key stores: an unpredictable name, created
/// exclusively with mode 0700 under `target/` (never a predictable path in a shared temp dir).
fn private_key_dir() -> std::path::PathBuf {
    let parent = std::path::Path::new("target").join("bench-keys");
    std::fs::create_dir_all(&parent).expect("create target/bench-keys");
    let name: String = random_secret()[..16].iter().map(|b| format!("{b:02x}")).collect();
    let dir = parent.join(name);
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir).expect("create a private key directory");
    dir
}

/// A fresh random idempotency secret for each benchmark run (never a fixed key).
fn random_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    aws_lc_rs::rand::fill(&mut k).expect("system randomness");
    k
}
