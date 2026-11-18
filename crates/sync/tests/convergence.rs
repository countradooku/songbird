//! The record store converges (Prompt 9's gate): devices editing offline, syncing in any order,
//! with skewed clocks, against the reference server; and a malicious server is caught.
#![allow(clippy::indexing_slicing, clippy::panic, reason = "tests")]

use proptest::prelude::*;
use songbird_sync::memory::{MemoryServer, block_on};
use songbird_sync::{HORIZON_MS, Replica, StorageKey, SyncError, rotate, sync};

const KEYS: [&str; 4] = ["s/theme", "s/read_receipts", "c/ab/mute", "k/01"];

fn key() -> StorageKey {
    StorageKey::from_bytes([7; 32])
}

fn device(i: u8) -> Replica {
    Replica::new(key(), [i; 16])
}

#[derive(Debug, Clone)]
enum Op {
    Set { dev: usize, key: usize, value: u8 },
    Delete { dev: usize, key: usize },
    Sync { dev: usize },
    Tick { ms: u64 },
}

fn op(devices: usize) -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..devices, 0..KEYS.len(), any::<u8>())
            .prop_map(|(dev, key, value)| Op::Set { dev, key, value }),
        1 => (0..devices, 0..KEYS.len()).prop_map(|(dev, key)| Op::Delete { dev, key }),
        3 => (0..devices).prop_map(|dev| Op::Sync { dev }),
        1 => (0u64..5_000).prop_map(|ms| Op::Tick { ms }),
    ]
}

/// The newest edit of each key over every device, by its stamp: what every device must end with.
type Oracle = std::collections::BTreeMap<&'static str, (songbird_sync::Hlc, Option<u8>)>;

fn run(ops: &[Op], skews: &[i64]) -> Result<(), TestCaseError> {
    let server = MemoryServer::new();
    let mut devs: Vec<Replica> = (0..skews.len())
        .map(|i| device(u8::try_from(i).unwrap_or(0) + 1))
        .collect();
    let mut now: u64 = 1_000_000;
    let phys = |now: u64, i: usize| now.saturating_add_signed(skews.get(i).copied().unwrap_or(0));
    let mut oracle = Oracle::new();
    let note = |o: &mut Oracle, k: &'static str, h: songbird_sync::Hlc, v: Option<u8>| {
        if o.get(k).is_none_or(|(old, _)| h > *old) {
            o.insert(k, (h, v));
        }
    };
    for op in ops {
        match *op {
            Op::Set { dev, key, value } => {
                let k = KEYS[key];
                let h = devs[dev]
                    .set(k, vec![value], phys(now, dev))
                    .map_err(|e| TestCaseError::fail(format!("set: {e}")))?;
                note(&mut oracle, k, h, Some(value));
            }
            Op::Delete { dev, key } => {
                let k = KEYS[key];
                let h = devs[dev]
                    .delete(k, phys(now, dev))
                    .map_err(|e| TestCaseError::fail(format!("delete: {e}")))?;
                note(&mut oracle, k, h, None);
            }
            Op::Sync { dev } => {
                block_on(sync(&mut devs[dev], &server, phys(now, dev)))
                    .map_err(|e| TestCaseError::fail(format!("sync: {e}")))?;
            }
            Op::Tick { ms } => now += ms,
        }
    }
    // Everyone syncs until nothing is pending: two rounds suffice (the last writer's edits
    // reach the others in the second).
    for _ in 0..3 {
        for (i, d) in devs.iter_mut().enumerate() {
            block_on(sync(d, &server, phys(now, i)))
                .map_err(|e| TestCaseError::fail(format!("final sync: {e}")))?;
        }
    }
    let first = devs[0].entries();
    for d in &devs {
        prop_assert!(!d.has_pending());
        prop_assert_eq!(&d.entries(), &first);
    }
    for (k, (_, v)) in &oracle {
        prop_assert_eq!(
            devs[0].get(k).map(<[u8]>::to_vec),
            v.map(|x| vec![x]),
            "key {}",
            k
        );
    }
    // No key is stored twice, and only the live keys and recent tombstones are stored.
    let snap = server.snapshot();
    prop_assert!(snap.records.len() <= KEYS.len());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn devices_converge_on_the_newest_edit_of_each_key(
        skews in proptest::collection::vec(-3_600_000i64..3_600_000, 2..5),
        ops in proptest::collection::vec(op(4), 0..80),
    ) {
        let n = skews.len();
        let ops: Vec<Op> = ops
            .into_iter()
            .map(|o| match o {
                Op::Set { dev, key, value } => Op::Set { dev: dev % n, key, value },
                Op::Delete { dev, key } => Op::Delete { dev: dev % n, key },
                Op::Sync { dev } => Op::Sync { dev: dev % n },
                t @ Op::Tick { .. } => t,
            })
            .collect();
        run(&ops, &skews)?;
    }

    #[test]
    fn a_device_with_a_clock_days_ahead_never_pins_a_key(
        ahead in (2 * 24 * 3_600_000i64)..(400 * 24 * 3_600_000i64),
        v in any::<u8>(),
    ) {
        let server = MemoryServer::new();
        let mut fast = device(1);
        let mut slow = device(2);
        let t: u64 = 10_000_000_000;
        fast.set("s/theme", vec![0], t.saturating_add_signed(ahead)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        block_on(sync(&mut fast, &server, t.saturating_add_signed(ahead))).map_err(|e| TestCaseError::fail(e.to_string()))?;
        block_on(sync(&mut slow, &server, t)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        slow.set("s/theme", vec![v], t).map_err(|e| TestCaseError::fail(e.to_string()))?;
        block_on(sync(&mut slow, &server, t)).map_err(|e| TestCaseError::fail(e.to_string()))?;
        block_on(sync(&mut fast, &server, t.saturating_add_signed(ahead))).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(fast.get("s/theme"), Some(&[v][..]));
    }
}

#[test]
fn a_delete_and_an_offline_edit_converge_by_their_stamps() -> Result<(), SyncError> {
    let server = MemoryServer::new();
    let mut a = device(1);
    let mut b = device(2);
    a.set("k/01", b"Ana".to_vec(), 1_000)?;
    block_on(sync(&mut a, &server, 1_000))?;
    block_on(sync(&mut b, &server, 1_000))?;
    // b goes offline and edits; a deletes later.
    b.set("k/01", b"Ana M.".to_vec(), 2_000)?;
    a.delete("k/01", 3_000)?;
    block_on(sync(&mut a, &server, 3_000))?;
    block_on(sync(&mut b, &server, 4_000))?;
    block_on(sync(&mut a, &server, 4_000))?;
    assert_eq!(a.get("k/01"), None);
    assert_eq!(b.get("k/01"), None);
    Ok(())
}

#[test]
fn tombstones_are_collected_after_the_horizon_and_old_edits_do_not_come_back()
-> Result<(), SyncError> {
    let server = MemoryServer::new();
    let mut a = device(1);
    let mut b = device(2);
    a.set("k/01", b"x".to_vec(), 1_000)?;
    block_on(sync(&mut a, &server, 1_000))?;
    block_on(sync(&mut b, &server, 1_000))?;
    // b edits, then stays away past the horizon.
    b.set("k/01", b"y".to_vec(), 2_000)?;
    a.delete("k/01", 3_000)?;
    block_on(sync(&mut a, &server, 3_000))?;
    let later = 3_000 + HORIZON_MS + 1;
    block_on(sync(&mut a, &server, later))?;
    assert_eq!(
        server.snapshot().records.len(),
        0,
        "the tombstone is collected"
    );
    block_on(sync(&mut b, &server, later))?;
    assert_eq!(
        b.get("k/01"),
        None,
        "the stale edit was dropped, not resurrected"
    );
    assert_eq!(server.snapshot().records.len(), 0);
    Ok(())
}

fn two_devices_with_data() -> Result<(MemoryServer, Replica, Replica), SyncError> {
    let server = MemoryServer::new();
    let mut a = device(1);
    let mut b = device(2);
    a.set("s/theme", b"dark".to_vec(), 1_000)?;
    a.set("s/read_receipts", vec![1], 1_000)?;
    block_on(sync(&mut a, &server, 1_000))?;
    block_on(sync(&mut b, &server, 1_000))?;
    Ok((server, a, b))
}

#[test]
fn a_withheld_record_is_caught() -> Result<(), SyncError> {
    let (server, mut a, _) = two_devices_with_data()?;
    let victim = *server
        .snapshot()
        .records
        .keys()
        .next()
        .ok_or(SyncError::Malformed)?;
    // Left out of the ID list and the reads: the manifest's digest no longer matches.
    server.faults.borrow_mut().withhold = Some(victim);
    let mut fresh = device(3);
    assert_eq!(
        block_on(sync(&mut fresh, &server, 2_000)),
        Err(SyncError::Tampered)
    );
    // Listed but never served: the device never accepts a partial store.
    server.faults.borrow_mut().withhold = None;
    server.faults.borrow_mut().unreadable = Some(victim);
    let mut fresh = device(4);
    assert_eq!(
        block_on(sync(&mut fresh, &server, 2_000)),
        Err(SyncError::Busy)
    );
    assert_eq!(fresh.entries().len(), 0);
    server.faults.borrow_mut().unreadable = None;
    server.faults.borrow_mut().withhold = Some(victim);
    // A device that already holds the store checks the manifest against its own IDs, which
    // still match: it keeps every record.
    block_on(sync(&mut a, &server, 2_000))?;
    assert_eq!(a.entries().len(), 2);
    Ok(())
}

#[test]
fn a_rollback_to_an_older_version_is_caught() -> Result<(), SyncError> {
    let (server, mut a, mut b) = two_devices_with_data()?;
    let old = server.snapshot();
    a.set("s/theme", b"light".to_vec(), 2_000)?;
    block_on(sync(&mut a, &server, 2_000))?;
    block_on(sync(&mut b, &server, 2_000))?;
    server.faults.borrow_mut().serve = Some(old);
    assert_eq!(
        block_on(sync(&mut b, &server, 3_000)),
        Err(SyncError::Rollback)
    );
    Ok(())
}

#[test]
fn a_record_swapped_or_changed_is_caught() -> Result<(), SyncError> {
    let (server, _, _) = two_devices_with_data()?;
    let mut s = server.snapshot();
    let ids: Vec<[u8; 16]> = s.records.keys().copied().collect();
    let (Some(x), Some(y)) = (ids.first(), ids.get(1)) else {
        return Err(SyncError::Malformed);
    };
    let bx = s.records.get(x).cloned().unwrap_or_default();
    let by = s.records.get(y).cloned().unwrap_or_default();
    s.records.insert(*x, by);
    s.records.insert(*y, bx);
    server.faults.borrow_mut().serve = Some(s);
    let mut fresh = device(5);
    assert_eq!(
        block_on(sync(&mut fresh, &server, 2_000)),
        Err(SyncError::Tampered)
    );
    Ok(())
}

#[test]
fn a_key_rotation_rewrites_everything_and_old_keys_cannot_read_it() -> Result<(), SyncError> {
    let (server, mut a, mut b) = two_devices_with_data()?;
    let before: Vec<[u8; 16]> = server.snapshot().records.keys().copied().collect();
    let new = StorageKey::from_bytes([9; 32]);
    block_on(rotate(&mut a, &server, new.clone(), 2_000))?;
    let after = server.snapshot();
    assert_eq!(after.records.len(), before.len());
    assert!(
        before.iter().all(|i| !after.records.contains_key(i)),
        "fresh IDs"
    );
    assert_eq!(
        block_on(sync(&mut b, &server, 2_000)),
        Err(SyncError::KeyChanged)
    );
    b.set_key(new);
    block_on(sync(&mut b, &server, 2_000))?;
    assert_eq!(b.get("s/theme"), Some(&b"dark"[..]));
    assert_eq!(b.entries(), a.entries());
    Ok(())
}

#[test]
fn records_are_padded_so_sizes_say_little() -> Result<(), SyncError> {
    let server = MemoryServer::new();
    let mut a = device(1);
    a.set("s/a", vec![1], 1_000)?;
    a.set("k/02", vec![0; 30], 1_000)?;
    block_on(sync(&mut a, &server, 1_000))?;
    let sizes: std::collections::BTreeSet<usize> =
        server.snapshot().records.values().map(Vec::len).collect();
    assert_eq!(sizes.len(), 1, "both fit the smallest bucket: {sizes:?}");
    Ok(())
}

#[test]
fn a_saved_replica_comes_back_whole_and_keeps_syncing() -> Result<(), SyncError> {
    let (server, mut a, _) = two_devices_with_data()?;
    a.set("s/theme", b"light".to_vec(), 5_000)?;
    let back = Replica::load(&a.save())?;
    assert_eq!(back.entries(), a.entries());
    assert!(back.has_pending());
    let mut back = back;
    block_on(sync(&mut back, &server, 6_000))?;
    // Its clock came back too: a later edit still wins.
    let h = back.set("s/theme", b"dark".to_vec(), 1)?;
    assert!(h.wall_ms >= 5_000);
    assert!(Replica::load(b"junk").is_err());
    Ok(())
}
