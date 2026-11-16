//! Invite-link proofs members check (D-0076): a join by link carries a signature by the key the
//! members published for that link. Each rule is checked on the server (`apply_join`) and on a
//! member running the apps' rule (`receive_join_checked`), including a server that would admit
//! someone without a link.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests: failing loudly is the point"
)]

use songbird_groups::links::ProofError;
use songbird_groups::roles::Denied;
use songbird_groups::{Group, GroupError, Limits};
use songbird_groups_harness::{Device, Dir, LinkSecret, id_from, server_create, welcome_of};
use songbird_types::{AccountId, DeviceId};

fn account(n: u16) -> AccountId {
    AccountId::from_bytes(id_from(n, 0xA0))
}

/// Alice (owner) and Bob (member) in a group whose roles publish `link`'s key.
struct Fixture {
    dir: Dir,
    alice: Device,
    bob: Device,
    server: Group,
    link: LinkSecret,
}

fn setup() -> Fixture {
    let mut dir = Dir::default();
    let mut alice = Device::new(1, account(1), &mut dir);
    let mut bob = Device::new(2, account(2), &mut dir);
    let server = server_create(&mut alice, &dir);
    let b = alice.add(&[bob.key_package()]);
    let (server, _) = server
        .apply_commit(&alice.id, &b, &dir, &Limits::default())
        .unwrap();
    alice.merge();
    bob.join(&welcome_of(&b), &server.ratchet_tree().unwrap());
    let link = LinkSecret::random();
    let b = alice.publish_link(&link);
    let (server, _) = server
        .apply_commit(&alice.id, &b, &dir, &Limits::default())
        .unwrap();
    alice.merge();
    bob.receive_checked(&b, &dir).unwrap();
    assert_eq!(
        bob.roles().links.get(&link.handle),
        Some(&link.public_key())
    );
    Fixture {
        dir,
        alice,
        bob,
        server,
        link,
    }
}

/// The server's answer to `bundle` as a join by `handle`.
fn join(f: &Fixture, who: &Device, bundle: &[u8], handle: &[u8; 16]) -> Result<Group, GroupError> {
    Group::load(f.server.record())
        .unwrap()
        .apply_join(&who.id, bundle, &f.dir, &Limits::default(), handle)
        .map(|(g, _)| g)
}

#[test]
fn a_join_by_link_carries_a_proof_members_check() {
    let mut f = setup();
    let mut eve = Device::new(5, account(5), &mut f.dir);
    let (info, tree) = (
        f.server.group_info().to_vec(),
        f.server.ratchet_tree().unwrap(),
    );
    let b = eve.join_by_link(&info, &tree, &f.link);
    let server = join(&f, &eve, &b, &f.link.handle).unwrap();
    assert_eq!(server.roster().len(), 3);
    // Members accept it: Eve's account is new, and her proof is under the published key.
    f.alice.receive_join_checked(&b, &f.dir).unwrap();
    f.bob.receive_join_checked(&b, &f.dir).unwrap();
    let msg = f.alice.message(b"welcome, eve");
    assert_eq!(eve.read(&msg), b"welcome, eve");
}

#[test]
fn joins_without_a_valid_proof_are_refused_by_the_server_and_members() {
    let mut f = setup();
    let (info, tree) = (
        f.server.group_info().to_vec(),
        f.server.ratchet_tree().unwrap(),
    );
    let unpublished = LinkSecret::random();
    let forged = LinkSecret {
        handle: f.link.handle,
        secret: [9; 32],
    };
    let elsewhere = DeviceId::from_bytes(id_from(99, 0xD0));
    // Each is presented as a join by the published link; the server knows which link was
    // counted, so a proof naming another handle is `OtherLink` there.
    for (n, what, server_says) in [
        (
            10,
            "no proof (a server admitting someone without a link)",
            ProofError::Missing,
        ),
        (
            11,
            "a link the members never published",
            ProofError::OtherLink,
        ),
        (
            12,
            "the published handle, signed with another secret",
            ProofError::Signature,
        ),
        (
            13,
            "a valid proof made out to another device",
            ProofError::Signature,
        ),
    ] {
        let mut eve = Device::new(n, account(n), &mut f.dir);
        let key = eve.signer.public().to_vec();
        let b = match n {
            10 => eve.rejoin(&info, &tree),
            11 => eve.join_by_link(&info, &tree, &unpublished),
            12 => eve.join_by_link(&info, &tree, &forged),
            _ => eve.rejoin_with_aad(&info, &tree, |g, e| f.link.prove(g, e, &elsewhere, &key)),
        };
        let e = join(&f, &eve, &b, &f.link.handle).unwrap_err();
        assert!(
            matches!(e, GroupError::LinkProof(p) if p == server_says),
            "{what}: {e:?}"
        );
        // A server that let it in anyway: members refuse to follow.
        let refused = f.alice.receive_join_checked(&b, &f.dir).unwrap_err();
        assert!(
            refused.contains("without a valid link proof"),
            "{what}: {refused}"
        );
    }
    // An unpublished link's proof counted against that link: unknown to the members.
    let mut zed = Device::new(30, account(30), &mut f.dir);
    let b = zed.join_by_link(&info, &tree, &unpublished);
    let e = join(&f, &zed, &b, &unpublished.handle).unwrap_err();
    assert!(
        matches!(e, GroupError::LinkProof(ProofError::UnknownLink)),
        "{e:?}"
    );
}

#[test]
fn a_rejoin_needs_no_proof() {
    // A lost device of an account already in the group rejoins without a link (D-0066): no
    // proof, and members accept it.
    let mut f = setup();
    let (info, tree) = (
        f.server.group_info().to_vec(),
        f.server.ratchet_tree().unwrap(),
    );
    let mut bob2 = Device::new(3, account(2), &mut f.dir);
    let b = bob2.rejoin(&info, &tree);
    let (_server, _) = Group::load(f.server.record())
        .unwrap()
        .apply_commit(&bob2.id, &b, &f.dir, &Limits::default())
        .unwrap();
    f.alice.receive_join_checked(&b, &f.dir).unwrap();
}

#[test]
fn only_the_links_role_publishes_link_keys() {
    let mut f = setup();
    let other = LinkSecret::random();
    // Bob, a member, may not (links are the admins' by default)...
    let b = f.bob.publish_link(&other);
    let e = Group::load(f.server.record())
        .unwrap()
        .apply_commit(&f.bob.id, &b, &f.dir, &Limits::default())
        .unwrap_err();
    assert!(matches!(e, GroupError::Forbidden(Denied::Role)), "{e:?}");
    let refused = f.alice.verify_commit(&b, &f.dir).unwrap_err();
    assert!(refused.contains("roles rule"), "{refused}");
    f.bob.discard();
    // ...nor withdraw one.
    let mut roles = f.bob.roles();
    roles.links.clear();
    let b = f.bob.set_roles(&roles);
    let e = Group::load(f.server.record())
        .unwrap()
        .apply_commit(&f.bob.id, &b, &f.dir, &Limits::default())
        .unwrap_err();
    assert!(matches!(e, GroupError::Forbidden(Denied::Role)), "{e:?}");
    f.bob.discard();
    // The owner withdraws it: joins by that link are refused from then on.
    let b = f.alice.set_roles(&roles);
    let (server, _) = Group::load(f.server.record())
        .unwrap()
        .apply_commit(&f.alice.id, &b, &f.dir, &Limits::default())
        .unwrap();
    f.alice.merge();
    f.server = server;
    let (info, tree) = (
        f.server.group_info().to_vec(),
        f.server.ratchet_tree().unwrap(),
    );
    let mut eve = Device::new(5, account(5), &mut f.dir);
    let b = eve.join_by_link(&info, &tree, &f.link);
    let e = join(&f, &eve, &b, &f.link.handle).unwrap_err();
    assert!(
        matches!(e, GroupError::LinkProof(ProofError::UnknownLink)),
        "{e:?}"
    );
}
