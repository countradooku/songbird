//! Prompt 10's gate: the incremental cost of backups on a large simulated history, in memory
//! (the vault's run is `gate_p10::incremental_cost_on_the_vault`).
//!
//! `cargo test --release -p songbird-backup-storage --test cost -- --ignored --nocapture`
#![allow(
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    reason = "a measurement"
)]

use std::sync::Arc;

use songbird_backup_format::RecoveryKey;
use songbird_backup_format::synth::Shape;
use songbird_backup_storage::conformance::{self, Step};
use songbird_backup_storage::memory::MemoryStore;

/// About a million messages in 2,000 chats, and 22,000 media messages (about 18,000 distinct
/// files: every fifth is a forward), 20 to 200 kB each.
pub const LARGE: Shape = Shape {
    seed: 1_000_000,
    chats: 2_000,
    messages_per_chat: 501,
    media_every: 50,
    media_sizes: &[20_000, 60_000, 200_000],
    contacts: 500,
};

fn print(where_: &str, steps: &[Step]) {
    eprintln!(
        "{where_}: step | new chunks | new MB | reused chunks | deleted | plaintext MB | seconds"
    );
    for s in steps {
        eprintln!(
            "{} | {} | {:.1} | {} | {} | {:.0} | {:.1}",
            s.what,
            s.new_chunks,
            s.new_bytes as f64 / 1e6,
            s.reused_chunks,
            s.deleted,
            s.plaintext as f64 / 1e6,
            s.seconds
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a measurement: run in release by hand"]
async fn incremental_cost_in_memory() {
    let keys = Arc::new(RecoveryKey::from_secret([0x77; 32]).derive().unwrap());
    let steps = conformance::incremental_cost(Arc::new(MemoryStore::default()), keys, LARGE, 1, 25)
        .await
        .unwrap();
    print("memory", &steps);
}
