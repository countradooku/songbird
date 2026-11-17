//! The delivery-service core against OpenMLS clients: a group's life, and every refusal.

#![allow(
    clippy::unwrap_used,
    clippy::many_single_char_names,
    clippy::needless_pass_by_value,
    clippy::type_complexity,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests: failing loudly is the point"
)]
use songbird_groups::wire::{self, Bundle, LogEntry};
use songbird_groups::{Group, GroupError, Limits, Record};
use songbird_groups_harness::{
    Device, Dir, GID, LinkSecret, id_from, server_create, welcome_of, with_log,
};
use songbird_types::{AccountId, DeviceId};

fn account(n: u16) -> AccountId {
    AccountId::from_bytes(id_from(n, 0xA0))
}

fn apply(g: Group, sender: &Device, bundle: &[u8], dir: &Dir) -> Result<Group, GroupError> {
    g.apply_commit(&sender.id, bundle, dir, &Limits::default())
        .map(|(g, _)| g)
}

/// Reloads the server's group from its stored bytes, as a node with a cold cache would.
fn reload(g: &Group) -> Group {
    let bytes = g.record().encode().unwrap();
    Group::load(Record::decode(&bytes).unwrap()).unwrap()
}

#[test]
fn a_group_lives_through_adds_updates_removals_and_reloads() {
    let mut dir = Dir::default();
    let mut alice = Device::new(1, account(1), &mut dir);
    let mut bob = Device::new(2, account(2), &mut dir);
    let mut carol = Device::new(3, account(3), &mut dir);
    let mut server = server_create(&mut alice, &dir);
    assert_eq!(server.epoch(), 0);

    // Alice adds Bob and Carol in one commit; the server learns who gets the Welcome.
    let b = alice.add(&[bob.key_package(), carol.key_package()]);
    let (s, applied) = server
        .apply_commit(&alice.id, &b, &dir, &Limits::default())
        .unwrap();
    server = reload(&s);
    alice.merge();
    let mut added = applied.added.clone();
    added.sort_unstable();
    assert_eq!(added, vec![bob.id, carol.id]);
    assert_eq!(applied.removed, Vec::new());
    let tree = server.ratchet_tree().unwrap();
    bob.join(&welcome_of(&b), &tree);
    carol.join(&welcome_of(&b), &tree);
    assert_eq!(server.epoch(), 1);

    // Bob updates his keys; the others follow.
    let b = bob.update();
    server = apply(server, &bob, &b, &dir).unwrap();
    bob.merge();
    alice.receive(&b);
    carol.receive(&b);

    // Bob, a member, may not remove Carol (D-0070); Alice, the owner, does. Carol is told (she
    // gets the commit) and is out of the roster.
    let refused = bob.remove(&[carol.leaf()]);
    let e = Group::load(server.record())
        .unwrap()
        .apply_commit(&bob.id, &refused, &dir, &Limits::default())
        .unwrap_err();
    assert!(matches!(e, GroupError::Forbidden(_)), "{e:?}");
    bob.discard();
    let b = alice.remove(&[carol.leaf()]);
    let (s, applied) = server
        .apply_commit(&alice.id, &b, &dir, &Limits::default())
        .unwrap();
    server = reload(&s);
    alice.merge();
    bob.receive(&b);
    assert_eq!(applied.removed, vec![carol.id]);
    assert_eq!(applied.from_epoch, 2);

    let mut expected = vec![alice.id, bob.id];
    expected.sort_unstable();
    assert_eq!(server.roster().devices().collect::<Vec<_>>(), expected);
    assert_eq!(alice.roster(), expected);
    assert_eq!(bob.roster(), expected);
    assert_eq!((server.epoch(), alice.epoch(), bob.epoch()), (3, 3, 3));

    // An application message: the server reads only group, epoch and type.
    let m = alice.message(b"hi");
    let p = wire::private_prefix(&m).unwrap();
    assert_eq!(
        (p.group, p.epoch, p.content_type),
        (GID, 3, wire::CONTENT_APPLICATION)
    );
    assert_eq!(bob.read(&m), b"hi");
}

struct Setup {
    dir: Dir,
    alice: Device,
    bob: Device,
    server: Group,
}

/// Alice and Bob in a group at epoch 1.
fn setup() -> Setup {
    let mut dir = Dir::default();
    let mut alice = Device::new(1, account(1), &mut dir);
    let mut bob = Device::new(2, account(2), &mut dir);
    let server = server_create(&mut alice, &dir);
    let b = alice.add(&[bob.key_package()]);
    let server = apply(server, &alice, &b, &dir).unwrap();
    alice.merge();
    bob.join(&welcome_of(&b), &server.ratchet_tree().unwrap());
    Setup {
        dir,
        alice,
        bob,
        server,
    }
}

fn rebundle<'a>(b: &'a [u8], f: impl FnOnce(&mut Bundle<'a>)) -> Vec<u8> {
    let mut parts = Bundle::parse(b, usize::MAX).unwrap();
    f(&mut parts);
    parts.encode()
}

#[test]
fn a_commit_is_bound_to_the_device_that_sends_it() {
    let Setup {
        dir,
        mut alice,
        bob,
        server,
    } = setup();
    let b = alice.update();
    let err = server
        .apply_commit(&bob.id, &b, &dir, &Limits::default())
        .unwrap_err();
    assert!(matches!(err, GroupError::Sender), "{err:?}");
}

#[test]
fn added_devices_must_exist_and_be_new() {
    let Setup {
        dir,
        mut alice,
        bob,
        server,
    } = setup();
    let stranger = Device::unregistered(DeviceId::from_bytes(id_from(9, 0xEE)), account(9));
    let b = alice.add(&[stranger.key_package()]);
    let rec = server.record();
    let err = apply(server, &alice, &b, &dir).unwrap_err();
    assert!(matches!(err, GroupError::Credential), "{err:?}");
    alice.discard();

    // Bob's device ID again (new keys, so OpenMLS itself does not object), under a second
    // leaf, is a duplicate.
    let server = Group::load(rec).unwrap();
    let twin = Device::unregistered(bob.id, account(2));
    let b = alice.add(&[twin.key_package()]);
    let err = apply(server, &alice, &b, &dir).unwrap_err();
    assert!(
        matches!(err, GroupError::Duplicate | GroupError::Invalid),
        "{err:?}"
    );
}

#[test]
fn welcomes_must_match_the_added_devices_exactly() {
    let Setup {
        mut dir,
        mut alice,
        server,
        ..
    } = setup();
    let carol = Device::new(3, account(3), &mut dir);
    let dave = Device::new(4, account(4), &mut dir);
    let rec = server.record();

    let with_carol = alice.add(&[carol.key_package()]);
    alice.discard();
    let with_dave = alice.add(&[dave.key_package()]);

    // No Welcome at all.
    let none = rebundle(&with_dave, |b| b.welcome = None);
    let err = apply(Group::load(rec.clone()).unwrap(), &alice, &none, &dir).unwrap_err();
    assert!(matches!(err, GroupError::Welcome), "{err:?}");

    // Carol's Welcome on Dave's commit.
    let w = welcome_of(&with_carol);
    let swapped = rebundle(&with_dave, |b| b.welcome = Some(&w));
    let err = apply(Group::load(rec.clone()).unwrap(), &alice, &swapped, &dir).unwrap_err();
    assert!(matches!(err, GroupError::Welcome), "{err:?}");

    // A Welcome on a commit that adds nobody.
    alice.discard();
    let upd = alice.update();
    let extra = rebundle(&upd, |b| b.welcome = Some(&w));
    let err = apply(Group::load(rec.clone()).unwrap(), &alice, &extra, &dir).unwrap_err();
    assert!(matches!(err, GroupError::Welcome), "{err:?}");

    // The honest one passes.
    assert!(apply(Group::load(rec).unwrap(), &alice, &upd, &dir).is_ok());
}

#[test]
fn the_group_info_must_be_the_new_epochs_and_signed_by_the_committer() {
    let Setup {
        dir,
        mut alice,
        mut bob,
        server,
    } = setup();
    let rec = server.record();
    let old_info = alice.group_info();
    let b = alice.update();

    let stale = rebundle(&b, |p| p.group_info = &old_info);
    let err = apply(Group::load(rec.clone()).unwrap(), &alice, &stale, &dir).unwrap_err();
    assert!(matches!(err, GroupError::GroupInfo), "{err:?}");

    // Bob's GroupInfo (same epoch as the server now, signed by Bob) on Alice's commit.
    let bobs = bob.group_info();
    let other = rebundle(&b, |p| p.group_info = &bobs);
    let err = apply(Group::load(rec.clone()).unwrap(), &alice, &other, &dir).unwrap_err();
    assert!(matches!(err, GroupError::GroupInfo), "{err:?}");

    assert!(apply(Group::load(rec).unwrap(), &alice, &b, &dir).is_ok());
    let _ = bob.update();
}

#[test]
fn a_stale_commit_is_refused_with_the_current_epoch() {
    let Setup {
        dir,
        mut alice,
        mut bob,
        server,
    } = setup();
    let a = alice.update();
    let b = bob.update();
    let server = apply(server, &alice, &a, &dir).unwrap();
    let err = apply(server, &bob, &b, &dir).unwrap_err();
    assert!(
        matches!(err, GroupError::StaleEpoch { current: 2 }),
        "{err:?}"
    );
}

#[test]
fn groups_are_bounded_in_size() {
    let Setup {
        mut dir,
        mut alice,
        server,
        ..
    } = setup();
    let carol = Device::new(3, account(3), &mut dir);
    let b = alice.add(&[carol.key_package()]);
    let tight = Limits {
        max_members: 2,
        ..Limits::default()
    };
    let err = server
        .apply_commit(&alice.id, &b, &dir, &tight)
        .unwrap_err();
    assert!(matches!(err, GroupError::TooLarge { max: 2 }), "{err:?}");
    let small = Limits {
        max_bundle: b.len() - 1,
        ..Limits::default()
    };
    let Setup { server, .. } = setup();
    let err = server
        .apply_commit(&alice.id, &b, &dir, &small)
        .unwrap_err();
    assert!(
        matches!(err, GroupError::Wire(wire::WireError::TooLarge)),
        "{err:?}"
    );
}

#[test]
fn a_commit_from_a_forked_group_is_invalid() {
    let Setup {
        mut dir,
        alice,
        server,
        ..
    } = setup();
    // Mallory builds her own group under the same ID and the same device credential.
    let mut mallory = Device::unregistered(alice.id, account(1));
    let _ = mallory.create();
    let carol = Device::new(3, account(3), &mut dir);
    let b = mallory.add(&[carol.key_package()]);
    let err = apply(server, &alice, &b, &dir).unwrap_err();
    assert!(
        matches!(
            err,
            GroupError::StaleEpoch { .. } | GroupError::Sender | GroupError::Invalid
        ),
        "{err:?}"
    );
}

#[test]
fn an_application_message_is_not_a_commit() {
    let Setup {
        dir,
        mut alice,
        server,
        ..
    } = setup();
    let m = alice.message(b"x");
    let info = alice.group_info();
    let b = Bundle {
        commit: &m,
        welcome: None,
        group_info: &info,
        log: None,
    }
    .encode();
    let err = apply(server, &alice, &b, &dir).unwrap_err();
    assert!(matches!(err, GroupError::Kind), "{err:?}");
}

#[test]
fn external_commits_rejoin_an_accounts_devices_only() {
    let Setup {
        mut dir,
        alice,
        server,
        ..
    } = setup();
    let info = server.group_info().to_vec();
    let tree = server.ratchet_tree().unwrap();
    let rec = server.record();

    // A stranger cannot join by external commit.
    let mut eve = Device::new(5, account(5), &mut dir);
    let b = eve.rejoin(&info, &tree);
    let err = apply(Group::load(rec.clone()).unwrap(), &eve, &b, &dir).unwrap_err();
    assert!(matches!(err, GroupError::External), "{err:?}");

    // Alice's second device joins her account's group.
    let mut alice2 = Device::new(11, account(1), &mut dir);
    let b = alice2.rejoin(&info, &tree);
    let server = apply(Group::load(rec.clone()).unwrap(), &alice2, &b, &dir).unwrap();
    assert_eq!(server.roster().len(), 3);

    // Alice's device after losing its group state but not its keys resyncs: its old leaf goes.
    let mut restored = Device::restored(&alice);
    let b = restored.rejoin(&info, &tree);
    let server = apply(Group::load(rec.clone()).unwrap(), &restored, &b, &dir).unwrap();
    assert_eq!(server.roster().len(), 2);
    assert_eq!(
        server.roster().devices().filter(|d| *d == alice.id).count(),
        1
    );

    // The same device ID with new keys cannot add a second leaf for itself.
    let mut twin = Device::unregistered(alice.id, account(1));
    let b = twin.rejoin(&info, &tree);
    let err = apply(Group::load(rec).unwrap(), &twin, &b, &dir).unwrap_err();
    assert!(matches!(err, GroupError::Duplicate), "{err:?}");
}

#[test]
fn creation_is_checked() {
    let mut dir = Dir::default();
    let mut alice = Device::new(1, account(1), &mut dir);
    let bob = Device::new(2, account(2), &mut dir);
    let (gi, tree) = alice.create();
    let e = Group::create([0; 16], &alice.id, &gi, &tree, &dir, &Limits::default()).unwrap_err();
    assert!(matches!(e, GroupError::OtherGroup), "{e:?}");
    // Bob registering Alice's group: he is neither its owner (roles) nor its leaf.
    let e = Group::create(GID, &bob.id, &gi, &tree, &dir, &Limits::default()).unwrap_err();
    assert!(matches!(e, GroupError::Roles | GroupError::Sender), "{e:?}");
    let e = Group::create(
        GID,
        &alice.id,
        &gi,
        &tree,
        &Dir::default(),
        &Limits::default(),
    )
    .unwrap_err();
    assert!(matches!(e, GroupError::Credential), "{e:?}");
    assert!(Group::create(GID, &alice.id, &gi, &tree, &dir, &Limits::default()).is_ok());
}

#[test]
fn change_log_entries_are_the_committers_and_bound_to_their_commit() {
    let Setup {
        dir,
        mut alice,
        bob,
        server,
    } = setup();
    let rec = server.record();

    // Alice's update with her entry: accepted, and the entry comes back verified.
    let b = alice.commit_logged(Vec::new(), &[], None, b"sealed: alice updated");
    let (_, applied) = Group::load(rec.clone())
        .unwrap()
        .apply_commit(&alice.id, &b, &dir, &Limits::default())
        .unwrap();
    assert!(applied.log.is_some());
    alice.discard();

    // Bob's signature on Alice's commit: refused.
    let forged_sig = bob.sign_log(1, b"sealed: forged");
    let b = alice.update();
    let forged = with_log(&b, &LogEntry::encode(b"sealed: forged", &forged_sig));
    let e = Group::load(rec.clone())
        .unwrap()
        .apply_commit(&alice.id, &forged, &dir, &Limits::default())
        .unwrap_err();
    assert!(matches!(e, GroupError::LogSignature), "{e:?}");

    // Alice's own entry from another epoch, replayed: refused.
    let old_sig = alice.sign_log(0, b"sealed: replay");
    let replayed = with_log(&b, &LogEntry::encode(b"sealed: replay", &old_sig));
    let e = Group::load(rec)
        .unwrap()
        .apply_commit(&alice.id, &replayed, &dir, &Limits::default())
        .unwrap_err();
    assert!(matches!(e, GroupError::LogSignature), "{e:?}");
    alice.discard();
}

#[test]
fn a_stranger_joins_by_link_only_through_apply_join() {
    let Setup {
        mut dir,
        mut alice,
        server,
        ..
    } = setup();
    let limits = Limits::default();
    // Alice (an admin: the owner) publishes a link's proof key (D-0076).
    let link = LinkSecret::random();
    let b = alice.publish_link(&link);
    let server = apply(server, &alice, &b, &dir).unwrap();
    alice.merge();
    let info = server.group_info().to_vec();
    let tree = server.ratchet_tree().unwrap();
    let rec = server.record();

    // Without a link, a stranger's external commit is refused (as above); with one, the
    // delivery service lets it in (D-0071), with the group's default role.
    let mut eve = Device::new(5, account(5), &mut dir);
    let b = eve.join_by_link(&info, &tree, &link);
    let err = apply(Group::load(rec.clone()).unwrap(), &eve, &b, &dir).unwrap_err();
    assert!(matches!(err, GroupError::External), "{err:?}");
    let (server, applied) = Group::load(rec.clone())
        .unwrap()
        .apply_join(&eve.id, &b, &dir, &limits, &link.handle)
        .unwrap();
    assert_eq!(server.roster().len(), 3);
    assert!(
        applied.added.is_empty(),
        "an external commit has no Welcome"
    );
    let roles = server.roles().unwrap();
    assert_eq!(roles.role(&account(5)), roles.policy.default_role);

    // The members follow, and Eve reads the group from then on.
    alice.receive(&b);
    let msg = alice.message(b"welcome, eve");
    assert_eq!(eve.read(&msg), b"welcome, eve");

    // A join is an external commit: a member's ordinary commit is not one.

    let b = alice.update();
    let err = Group::load(server.record())
        .unwrap()
        .apply_join(&alice.id, &b, &dir, &limits, &link.handle)
        .unwrap_err();
    assert!(matches!(err, GroupError::Kind), "{err:?}");
}

#[test]
fn a_channel_has_its_own_size_limit() {
    let mut dir = Dir::default();
    let mut owner = Device::new(1, account(1), &mut dir);
    let limits = Limits {
        max_members: 2,
        max_channel_members: 3,
        ..Limits::default()
    };
    let subscribers: Vec<Device> = (2..=3)
        .map(|n| Device::new(n, account(n), &mut dir))
        .collect();
    let kps: Vec<_> = subscribers.iter().map(Device::key_package).collect();

    // A group of three is over the group limit...
    let (gi, tree) = owner.create();
    let group = Group::create(GID, &owner.id, &gi, &tree, &dir, &limits).unwrap();
    let b = owner.add(&kps);
    let err = group
        .apply_commit(&owner.id, &b, &dir, &limits)
        .unwrap_err();
    assert!(matches!(err, GroupError::TooLarge { max: 2 }), "{err:?}");

    // ...and within the channel limit, for a channel.
    let mut owner = Device::restored(&owner);
    let (gi, tree) = owner.create_with(songbird_groups::roles::Policy::CHANNEL);
    let channel = Group::create(GID, &owner.id, &gi, &tree, &dir, &limits).unwrap();
    let kps: Vec<_> = subscribers.iter().map(Device::key_package).collect();
    let b = owner.add(&kps);
    let (channel, _) = channel.apply_commit(&owner.id, &b, &dir, &limits).unwrap();
    assert_eq!(channel.roster().len(), 3);
    owner.merge();
    let fourth = Device::new(4, account(4), &mut dir);
    let b = owner.add(&[fourth.key_package()]);
    let err = channel
        .apply_commit(&owner.id, &b, &dir, &limits)
        .unwrap_err();
    assert!(matches!(err, GroupError::TooLarge { max: 3 }), "{err:?}");
}
