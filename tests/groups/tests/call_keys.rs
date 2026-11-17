//! A group call's media keys from the MLS exporter (Prompt 7, PROTOCOL §8.3, D-0086): every
//! member derives the same sender keys at an epoch, a commit gives new ones at the next key
//! index, and a removed device cannot derive the new epoch's keys.

#![allow(clippy::unwrap_used, reason = "tests: failing loudly is the point")]

use songbird_content::call::{EpochSecret, GROUP_EXPORTER_LABEL, GROUP_EXPORTER_LEN};
use songbird_groups::Limits;
use songbird_groups_harness::{Device, Dir, id_from, server_create, welcome_of};
use songbird_types::AccountId;

const CALL: [u8; 16] = [0xCA; 16];

fn account(n: u16) -> AccountId {
    AccountId::from_bytes(id_from(n, 0xA0))
}

fn secret(d: &Device, call: &[u8; 16]) -> EpochSecret {
    let x = d.export(GROUP_EXPORTER_LABEL, call, GROUP_EXPORTER_LEN);
    EpochSecret::group(x.try_into().unwrap(), d.epoch())
}

fn key(d: &Device, call: &[u8; 16], identity: &str) -> [u8; 32] {
    *secret(d, call).sender_key(identity.as_bytes()).unwrap()
}

#[test]
fn members_agree_and_a_removal_rotates_the_keys() {
    let mut dir = Dir::default();
    let mut alice = Device::new(1, account(1), &mut dir);
    let mut bob = Device::new(2, account(2), &mut dir);
    let mut carol = Device::new(3, account(3), &mut dir);
    let server = server_create(&mut alice, &dir);
    let b = alice.add(&[bob.key_package(), carol.key_package()]);
    let (server, _) = server
        .apply_commit(&alice.id, &b, &dir, &Limits::default())
        .unwrap();
    alice.merge();
    let tree = server.ratchet_tree().unwrap();
    bob.join(&welcome_of(&b), &tree);
    carol.join(&welcome_of(&b), &tree);

    // Epoch 1: everyone derives the same key for each sender; senders' keys differ, and so do
    // two calls' keys.
    let before = key(&alice, &CALL, "p-alice");
    assert_eq!(before, key(&bob, &CALL, "p-alice"));
    assert_eq!(before, key(&carol, &CALL, "p-alice"));
    assert_ne!(before, key(&alice, &CALL, "p-bob"));
    assert_ne!(before, key(&alice, &[0xCB; 16], "p-alice"));
    assert_eq!(secret(&alice, &CALL).key_index(), 1);

    // Alice removes Carol: a new epoch, a new key at the next index, which Bob derives and
    // Carol (still holding epoch 1) cannot.
    let b = alice.remove(&[carol.leaf()]);
    server
        .apply_commit(&alice.id, &b, &dir, &Limits::default())
        .unwrap();
    alice.merge();
    bob.receive(&b);
    let after = key(&alice, &CALL, "p-alice");
    assert_eq!(after, key(&bob, &CALL, "p-alice"));
    assert_ne!(after, before);
    assert_eq!(secret(&alice, &CALL).key_index(), 2);
    assert_eq!(
        key(&carol, &CALL, "p-alice"),
        before,
        "Carol stays at the old epoch"
    );
}
