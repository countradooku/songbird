//! Stored groups survive OpenMLS upgrades (D-0066): a group record written by OpenMLS 0.9.2
//! (`fixtures/openmls-0.9.2`, made by `tests/groups/tests/make_fixtures.rs`) must load, show
//! the same epoch, roster and ratchet tree, and re-encode to exactly the stored bytes.
//!
//! When an OpenMLS upgrade changes the storage format, this test fails in CI instead of groups
//! failing to load in production. Then: keep this fixture, add a migration, and add a fixture for
//! the new version.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use songbird_groups::{Group, Record};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/openmls-0.9.2")
            .join(name),
    )
    .unwrap()
}

#[test]
fn a_group_stored_by_openmls_0_9_2_loads_and_reencodes_byte_for_byte() {
    let stored = fixture("record.bin");
    let meta = String::from_utf8(fixture("meta.txt")).unwrap();
    let mut lines = meta.lines().map(str::trim);
    let epoch: u64 = lines
        .next()
        .unwrap()
        .strip_prefix("epoch ")
        .unwrap()
        .parse()
        .unwrap();
    let roster: Vec<&str> = lines
        .next()
        .unwrap()
        .strip_prefix("roster ")
        .unwrap()
        .split(' ')
        .collect();

    let g = Group::load(Record::decode(&stored).unwrap()).unwrap();
    assert_eq!(g.epoch(), epoch);
    let devices: Vec<String> = g
        .roster()
        .devices()
        .map(|d| d.to_hex_unredacted())
        .collect();
    assert_eq!(devices, roster);
    assert_eq!(
        g.ratchet_tree().unwrap(),
        fixture("tree.bin"),
        "the RFC 9420 tree is unchanged"
    );
    assert_eq!(
        g.record().encode().unwrap(),
        stored,
        "the stored form is unchanged"
    );
}

#[test]
fn a_damaged_record_is_refused_not_misread() {
    let mut stored = fixture("record.bin");
    // The storage version tag, then a truncated record.
    let r = Record::decode(&stored).unwrap();
    let mut other = r.clone();
    other.state.version = other.state.version.wrapping_add(1);
    assert!(Group::load(other).is_err());
    stored.truncate(stored.len() / 2);
    assert!(Record::decode(&stored).is_err());
}
