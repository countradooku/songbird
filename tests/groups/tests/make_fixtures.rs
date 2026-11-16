//! Writes the stored-group fixtures `crates/groups/tests/record_fixtures.rs` reloads (D-0066):
//! a group made and changed by OpenMLS clients, as the server stores it. Run by hand when a new
//! OpenMLS version's storage format is adopted, never in CI:
//!
//! ```text
//! cargo test -p songbird-groups-harness --test make_fixtures -- --ignored
//! ```
//!
//! The fixtures hold public group state only (keys, credentials, hashes): nothing secret.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use songbird_groups::Limits;
use songbird_groups_harness::{Device, Dir, id_from, server_create, welcome_of};
use songbird_types::AccountId;

#[test]
#[ignore = "writes fixtures; run by hand"]
fn write_fixtures() {
    let mut dir = Dir::default();
    let mut d: Vec<Device> = (1..=4)
        .map(|n| Device::new(n, AccountId::from_bytes(id_from(n, 0xA0)), &mut dir))
        .collect();
    let mut g = server_create(&mut d[0], &dir);
    let apply = |g: songbird_groups::Group, who: usize, b: &[u8], d: &mut Vec<Device>| {
        let (g, _) = g
            .apply_commit(&d[who].id, b, &dir, &Limits::default())
            .unwrap();
        d[who].merge();
        g
    };
    // Epoch 1: three added. Epoch 2: an update. Epoch 3: one removed.
    let kps: Vec<_> = d[1..].iter().map(Device::key_package).collect();
    let b = d[0].add(&kps);
    g = apply(g, 0, &b, &mut d);
    let tree = g.ratchet_tree().unwrap();
    for x in &mut d[1..] {
        x.join(&welcome_of(&b), &tree);
    }
    let b = d[1].update();
    g = apply(g, 1, &b, &mut d);
    for i in [0, 2, 3] {
        d[i].receive(&b);
    }
    let leaf = d[3].leaf();
    let b = d[2].remove(&[leaf]);
    g = apply(g, 2, &b, &mut d);

    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/groups/tests/fixtures/openmls-0.9.2");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("record.bin"), g.record().encode().unwrap()).unwrap();
    std::fs::write(out.join("tree.bin"), g.ratchet_tree().unwrap()).unwrap();
    let roster: Vec<String> = g
        .roster()
        .devices()
        .map(|x| x.to_hex_unredacted())
        .collect();
    std::fs::write(
        out.join("meta.txt"),
        format!("epoch {}\nroster {}\n", g.epoch(), roster.join(" ")),
    )
    .unwrap();
}
