//! Server-proposed removals (D-0075): the delivery service as the MLS external sender every
//! group names, proposing to remove devices that left the directory. Each rule is checked on the
//! server (`Group`) and on a client running the apps' rule (`receive_server_proposal`, the
//! roles rule in `receive_checked`), with the negative cases: a server removal of a still-listed
//! device, any other external proposal, and groups that do not name exactly the service.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests: failing loudly is the point"
)]

use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{ExternalProposal, GroupEpoch, GroupId, SenderExtensionIndex};
use openmls_rust_crypto::OpenMlsRustCrypto;
use songbird_groups::external::DsSigner;
use songbird_groups::roles::Denied;
use songbird_groups::{Group, GroupError, Limits};
use songbird_groups_harness::{
    Device, Dir, GID, context_extensions, ds_client_signer, id_from, roles_extensions,
    server_create_with, welcome_of,
};
use songbird_types::AccountId;

const SEED: [u8; 32] = [0x42; 32];

fn ds() -> DsSigner {
    DsSigner::from_seed(&SEED).unwrap()
}

fn limits() -> Limits {
    Limits {
        external_sender: Some(ds().public_key()),
        ..Limits::default()
    }
}

fn account(n: u16) -> AccountId {
    AccountId::from_bytes(id_from(n, 0xA0))
}

const ALICE: usize = 0;
const BOB: usize = 1;
const CAROL: usize = 2;
const DAVE: usize = 3;

struct Fixture {
    dir: Dir,
    d: Vec<Device>,
    server: Group,
}

/// Alice (owner), Bob, Carol and Dave, one device each, in a group naming the service.
fn setup() -> Fixture {
    let mut dir = Dir::default();
    let mut d: Vec<Device> = (1..=4)
        .map(|n| Device::new(n, account(n), &mut dir))
        .collect();
    for x in &mut d {
        x.ds_key = Some(ds().public_key());
    }
    let server = server_create_with(&mut d[ALICE], &dir, &limits());
    let kps: Vec<_> = d[1..].iter().map(Device::key_package).collect();
    let b = d[ALICE].add(&kps);
    let (server, _) = server
        .apply_commit(&d[ALICE].id, &b, &dir, &limits())
        .unwrap();
    d[ALICE].merge();
    let tree = server.ratchet_tree().unwrap();
    for x in &mut d[1..] {
        x.join(&welcome_of(&b), &tree);
    }
    Fixture { dir, d, server }
}

/// `dir` without person `who`'s device (their account was deleted, or the device removed).
fn without(dir: &Dir, d: &Device) -> Dir {
    let mut out = dir.clone();
    out.0.remove(&d.id);
    out
}

#[test]
fn departed_devices_are_proposed_for_removal_and_go_with_the_next_commit() {
    let Fixture { dir, mut d, server } = setup();
    let after = without(&dir, &d[DAVE]);

    let (server, p) = server.propose_removals(&after, &ds()).unwrap();
    assert_eq!(
        (p.messages.len(), p.queued),
        (1, 1),
        "one proposal for Dave's leaf"
    );
    let msgs = p.messages;
    // Proposing again (another node, a retry) queues nothing, also from the stored record, and
    // answers the same bytes to fan out (a fan-out a crash interrupted is finished).
    let (server, again) = server.propose_removals(&after, &ds()).unwrap();
    assert_eq!((&again.messages, again.queued), (&msgs, 0));
    let server = Group::load(server.record()).unwrap();
    let (server, again) = server.propose_removals(&after, &ds()).unwrap();
    assert_eq!(
        (&again.messages, again.queued),
        (&msgs, 0),
        "the queued proposal is part of the stored state"
    );
    // The same leaf at the same epoch is the same bytes: one fan-out key per proposal.
    let fresh = setup().server.propose_removals(&after, &ds()).unwrap().1;
    assert_eq!(fresh.messages, msgs);

    // Members check it (Dave is gone from their view too) and keep it for their next commit.
    for i in [ALICE, BOB, CAROL] {
        d[i].receive_server_proposal(&msgs[0], &after).unwrap();
    }
    // Bob commits anything (a key update); the removal goes with it, and needs no role.
    let b = d[BOB].update();
    let (server, applied) = server
        .apply_commit(&d[BOB].id, &b, &after, &limits())
        .unwrap();
    d[BOB].merge();
    assert_eq!(applied.removed, vec![d[DAVE].id]);
    assert_eq!(server.roster().len(), 3);
    for i in [ALICE, CAROL] {
        d[i].receive_checked(&b, &after).unwrap();
        assert_eq!(
            d[i].roster(),
            server.roster().devices().collect::<Vec<_>>(),
            "every client has the server's roster"
        );
    }
    let (_, none) = server.propose_removals(&after, &ds()).unwrap();
    assert!(none.messages.is_empty(), "nothing left to remove");
}

#[test]
fn a_server_removal_of_a_listed_device_is_refused_by_members_and_the_server() {
    let Fixture { dir, mut d, server } = setup();
    // A server whose view is wrong (a stale snapshot, or a lie) proposes removing Carol, who
    // is still listed.
    let stale = without(&dir, &d[CAROL]);
    let (server, p) = server.propose_removals(&stale, &ds()).unwrap();
    let msgs = p.messages;
    assert_eq!(msgs.len(), 1);
    let refused = d[ALICE]
        .receive_server_proposal(&msgs[0], &dir)
        .unwrap_err();
    assert!(refused.contains("still listed"), "{refused}");

    // A member who stores it anyway and commits it is refused, by the server (with the true
    // directory) and by every other client: even the owner, whose role would allow removing
    // Carol herself.
    for committer in [BOB, ALICE] {
        d[committer].receive_proposal(&msgs[0]);
        let b = d[committer].update();
        let e = Group::load(server.record())
            .unwrap()
            .apply_commit(&d[committer].id, &b, &dir, &limits())
            .unwrap_err();
        assert!(
            matches!(e, GroupError::Forbidden(Denied::Listed)),
            "{committer}: {e:?}"
        );
        let other = if committer == BOB { CAROL } else { DAVE };
        d[other].receive_proposal(&msgs[0]);
        let client = d[other].verify_commit(&b, &dir).unwrap_err();
        assert!(client.contains("still listed"), "{client}");
        d[committer].discard();
    }
}

#[test]
fn the_service_may_only_propose_removals() {
    let Fixture { dir, mut d, server } = setup();
    // An external Add signed with the service's key: what a compromised server could try.
    let mut extra_dir = dir.clone();
    let eve = Device::new(9, account(9), &mut extra_dir);
    let add = ExternalProposal::new_add::<OpenMlsRustCrypto>(
        eve.key_package(),
        GroupId::from_slice(&GID),
        GroupEpoch::from(server.epoch()),
        &ds_client_signer(&SEED),
        SenderExtensionIndex::new(0),
    )
    .unwrap()
    .tls_serialize_detached()
    .unwrap();
    let e = d[ALICE]
        .receive_server_proposal(&add, &extra_dir)
        .unwrap_err();
    assert!(e.contains("only propose removals"), "{e}");
    // It is no member's proposal either.
    let e = Group::load(server.record())
        .unwrap()
        .apply_proposal(&d[ALICE].id, &add)
        .unwrap_err();
    assert!(matches!(e, GroupError::Sender), "{e:?}");
    // Committed by a member who stored it regardless: refused by the server and by clients.
    d[BOB].receive_proposal(&add);
    d[CAROL].receive_proposal(&add);
    let b = d[BOB].update();
    assert!(
        Group::load(server.record())
            .unwrap()
            .apply_commit(&d[BOB].id, &b, &extra_dir, &limits())
            .is_err()
    );
    let e = d[CAROL].verify_commit(&b, &extra_dir).unwrap_err();
    assert!(e.contains("outsider"), "{e}");
}

#[test]
fn groups_name_exactly_the_service() {
    let mut dir = Dir::default();
    // No external sender, while the server requires one.
    let mut plain = Device::new(1, account(1), &mut dir);
    let (gi, tree) = plain.create();
    let e = Group::create(GID, &plain.id, &gi, &tree, &dir, &limits()).unwrap_err();
    assert!(matches!(e, GroupError::Kind), "{e:?}");
    // Another key.
    let mut other = Device::new(2, account(2), &mut dir);
    other.ds_key = Some(DsSigner::from_seed(&[1; 32]).unwrap().public_key());
    let (gi, tree) = other.create();
    let e = Group::create(GID, &other.id, &gi, &tree, &dir, &limits()).unwrap_err();
    assert!(matches!(e, GroupError::Kind), "{e:?}");
    // The service's key on a server that names none.
    let mut named = Device::new(3, account(3), &mut dir);
    named.ds_key = Some(ds().public_key());
    let (gi, tree) = named.create();
    let e = Group::create(GID, &named.id, &gi, &tree, &dir, &Limits::default()).unwrap_err();
    assert!(matches!(e, GroupError::Kind), "{e:?}");
    let server = Group::create(GID, &named.id, &gi, &tree, &dir, &limits()).unwrap();

    // A commit may neither drop the service nor add a second external sender.
    let roles = named.roles();
    let dropped = named.commit_ext(Vec::new(), &[], false, Some(roles_extensions(&roles)));
    let e = Group::load(server.record())
        .unwrap()
        .apply_commit(&named.id, &dropped, &dir, &limits())
        .unwrap_err();
    assert!(matches!(e, GroupError::Proposal), "{e:?}");
    named.discard();
    let mut two = songbird_groups::ds::ds_external_senders(&ds().public_key());
    two.extend(songbird_groups::ds::ds_external_senders(
        &DsSigner::from_seed(&[1; 32]).unwrap().public_key(),
    ));
    let doubled = named.commit_ext(
        Vec::new(),
        &[],
        false,
        Some(context_extensions(&roles, Some(two))),
    );
    let e = Group::load(server.record())
        .unwrap()
        .apply_commit(&named.id, &doubled, &dir, &limits())
        .unwrap_err();
    assert!(matches!(e, GroupError::Proposal), "{e:?}");
    named.discard();
    // A signer the group does not name proposes nothing.
    let mut dead = dir.clone();
    dead.0.remove(&named.id);
    let (_, msgs) = server
        .propose_removals(&dead, &DsSigner::from_seed(&[1; 32]).unwrap())
        .unwrap();
    assert_eq!(msgs, songbird_groups::ds::ServerProposals::default());
}
