//! The permission matrix (Prompt 5, M2; D-0070): every cell a commit can carry, refused for the
//! roles that may not and accepted for one that may, **on the server** (`apply_commit`) **and
//! on a client** (`receive_checked`, the rule apps run).
//!
//! The cells no commit carries are tested where they are enforced:
//! - sending: the send path (`crates/send`, `gate_p05`);
//! - editing the info: `POST /v1/groups/meta` (`gate_p05`);
//! - links and join requests: M3;
//! - calls: Prompt 7;
//! - pinning and deleting others' messages: clients only (`roles` unit tests; D-0065 §6).
#![allow(
    clippy::unwrap_used,
    clippy::many_single_char_names,
    clippy::needless_pass_by_value,
    clippy::type_complexity,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests: failing loudly is the point"
)]

use songbird_groups::roles::{Denied, Policy, Role, Roles};
use songbird_groups::{Group, GroupError, Limits, Record};
use songbird_groups_harness::{Device, Dir, id_from, welcome_of};
use songbird_types::AccountId;

const OWNER: usize = 0;
const ADMIN: usize = 1;
const MODERATOR: usize = 2;
const MEMBER: usize = 3;
const OTHER: usize = 4;

struct Fixture {
    dir: Dir,
    d: Vec<Device>,
    record: Record,
    /// A sixth person, not in the group, to add.
    outsider: Device,
}

fn account(n: u16) -> AccountId {
    AccountId::from_bytes(id_from(n, 0xA0))
}

/// Owner, admin, moderator and two members, everyone at the same epoch, under `policy`.
fn fixture(policy: Policy) -> Fixture {
    let mut dir = Dir::default();
    let mut d: Vec<Device> = (1..=5)
        .map(|n| Device::new(n, account(n), &mut dir))
        .collect();
    let outsider = Device::new(6, account(6), &mut dir);
    let (info, tree) = d[OWNER].create_with(policy);
    let mut g = Group::create(
        songbird_groups_harness::GID,
        &d[OWNER].id,
        &info,
        &tree,
        &dir,
        &Limits::default(),
    )
    .unwrap();
    let kps: Vec<_> = d[1..].iter().map(Device::key_package).collect();
    let b = d[OWNER].add(&kps);
    g = g
        .apply_commit(&d[OWNER].id, &b, &dir, &Limits::default())
        .unwrap()
        .0;
    d[OWNER].merge();
    let tree = g.ratchet_tree().unwrap();
    for x in &mut d[1..] {
        x.join(&welcome_of(&b), &tree);
    }
    let mut roles = Roles::new(account(1), policy);
    roles.explicit.insert(account(2), Role::Admin);
    roles.explicit.insert(account(3), Role::Moderator);
    let b = d[OWNER].set_roles(&roles);
    g = g
        .apply_commit(&d[OWNER].id, &b, &dir, &Limits::default())
        .unwrap()
        .0;
    d[OWNER].merge();
    for x in &mut d[1..] {
        x.receive_checked(&b, &dir).unwrap();
    }
    Fixture {
        dir,
        d,
        record: g.record(),
        outsider,
    }
}

/// Builds a commit by `actor` with `make`, then asks the server and a bystander client.
/// Returns `(server, client)` verdicts; the actor's pending commit is discarded.
fn attempt(
    f: &mut Fixture,
    actor: usize,
    make: impl FnOnce(&mut Device, &Fixture) -> Vec<u8>,
) -> (Result<(), GroupError>, Result<(), String>) {
    let mut a = std::mem::replace(
        &mut f.d[actor],
        Device::new(99, account(99), &mut Dir::default()),
    );
    let b = make(&mut a, f);
    f.d[actor] = a;
    let server = Group::load(f.record.clone())
        .unwrap()
        .apply_commit(&f.d[actor].id, &b, &f.dir, &Limits::default())
        .map(|_| ());
    // The bystander is the other member, or the owner when that member is the actor.
    let by = if actor == OTHER { OWNER } else { OTHER };
    let mut bystander = std::mem::replace(
        &mut f.d[by],
        Device::new(98, account(98), &mut Dir::default()),
    );
    let client = bystander.verify_commit(&b, &f.dir);
    f.d[by] = bystander;
    f.d[actor].discard();
    (server, client)
}

fn refused(v: (Result<(), GroupError>, Result<(), String>), why: &str) {
    assert!(
        matches!(v.0, Err(GroupError::Forbidden(_))),
        "server accepted or refused for another reason: {why}: {:?}",
        v.0
    );
    assert!(
        v.1.as_ref().is_err_and(|e| e.contains("roles rule")),
        "client accepted: {why}: {:?}",
        v.1
    );
}

fn allowed(v: (Result<(), GroupError>, Result<(), String>), why: &str) {
    assert!(v.0.is_ok(), "server refused: {why}: {:?}", v.0);
    assert!(v.1.is_ok(), "client refused: {why}: {:?}", v.1);
}

fn leaf(f: &Fixture, who: usize) -> u32 {
    f.d[who].leaf()
}

#[test]
fn adding_people_follows_the_add_role() {
    // "Admin approval for new members" (the add role at Admin): members and moderators may not.
    let mut admins_add = Policy::GROUP;
    admins_add.add = Role::Admin;
    let mut f = fixture(admins_add);
    for who in [MEMBER, MODERATOR] {
        let r = attempt(&mut f, who, |a, f| a.add(&[f.outsider.key_package()]));
        refused(r, "add without the role");
    }
    let r = attempt(&mut f, ADMIN, |a, f| a.add(&[f.outsider.key_package()]));
    // The bystander cannot join the outsider (no Welcome for it), but accepts the commit.
    allowed(r, "an admin adds");
}

#[test]
fn removing_people_needs_an_outranking_admin() {
    let mut f = fixture(Policy::GROUP);
    let other = leaf(&f, OTHER);
    for who in [MEMBER, MODERATOR] {
        refused(
            attempt(&mut f, who, |a, _| a.remove(&[other])),
            "remove another person",
        );
    }
    let moderator = leaf(&f, MODERATOR);
    // Removing the moderator also drops its role entry.
    let drop_moderator = |a: &mut Device, _: &Fixture| {
        let mut r = a.roles();
        r.explicit.remove(&account(3));
        a.commit_with(Vec::new(), &[moderator], false, Some(&r))
    };
    refused(
        attempt(&mut f, MEMBER, drop_moderator),
        "a member removes the moderator",
    );
    allowed(
        attempt(&mut f, ADMIN, drop_moderator),
        "an admin removes the moderator",
    );
    let admin = leaf(&f, ADMIN);
    let drop_admin = |a: &mut Device, _: &Fixture| {
        let mut r = a.roles();
        r.explicit.remove(&account(2));
        a.commit_with(Vec::new(), &[admin], false, Some(&r))
    };
    refused(
        attempt(&mut f, MODERATOR, drop_admin),
        "a moderator removes the admin",
    );
    allowed(
        attempt(&mut f, OWNER, drop_admin),
        "the owner removes the admin",
    );
}

#[test]
fn people_leave_by_proposal_and_owners_have_successors() {
    let mut f = fixture(Policy::GROUP);
    // The admin leaves: its SelfRemove is queued, and a plain member commits the departure,
    // dropping the admin's entry. Server and clients accept.
    let p = f.d[ADMIN].leave();
    let (g, _) = Group::load(f.record.clone())
        .unwrap()
        .apply_proposal(&f.d[ADMIN].id, &p)
        .unwrap();
    for who in [OWNER, MODERATOR, MEMBER, OTHER] {
        f.d[who].receive_proposal(&p);
    }
    let mut r = f.d[MEMBER].roles();
    r.explicit.remove(&account(2));
    let b = f.d[MEMBER].set_roles(&r);
    let (g, applied) = g
        .apply_commit(&f.d[MEMBER].id, &b, &f.dir, &Limits::default())
        .unwrap();
    assert_eq!(applied.removed, vec![f.d[ADMIN].id]);
    assert!(
        f.d[OTHER].verify_commit(&b, &f.dir).is_ok(),
        "a client accepts the departure"
    );
    f.d[MEMBER].merge();
    for who in [OWNER, MODERATOR, OTHER] {
        f.d[who].receive_checked(&b, &f.dir).unwrap();
    }
    f.record = g.record();

    // The only owner leaves: committing it without naming a successor leaves no owner.
    let p = f.d[OWNER].leave();
    let (g, _) = Group::load(f.record.clone())
        .unwrap()
        .apply_proposal(&f.d[OWNER].id, &p)
        .unwrap();
    for who in [MODERATOR, MEMBER, OTHER] {
        f.d[who].receive_proposal(&p);
    }
    let mut orphaned = f.d[MEMBER].roles();
    orphaned.explicit.remove(&account(1));
    let b = f.d[MEMBER].set_roles(&orphaned);
    let rec = g.record();
    let e = Group::load(rec.clone())
        .unwrap()
        .apply_commit(&f.d[MEMBER].id, &b, &f.dir, &Limits::default())
        .unwrap_err();
    assert!(matches!(e, GroupError::Forbidden(Denied::NoOwner)), "{e:?}");
    assert!(f.d[OTHER].verify_commit(&b, &f.dir).is_err());
    f.d[MEMBER].discard();
    // Naming the moderator as the next owner is the committer's to do.
    let mut succeeded = orphaned.clone();
    succeeded.explicit.insert(account(3), Role::Owner);
    let b = f.d[MEMBER].set_roles(&succeeded);
    assert!(
        Group::load(rec)
            .unwrap()
            .apply_commit(&f.d[MEMBER].id, &b, &f.dir, &Limits::default())
            .is_ok()
    );
    assert!(f.d[OTHER].verify_commit(&b, &f.dir).is_ok());
}

#[test]
fn only_self_removal_is_a_standalone_proposal() {
    let mut f = fixture(Policy::GROUP);
    // A Remove proposal (even of oneself) is not taken standalone: removals by others travel
    // inline in commits, under the roles rule.
    let bytes = f.d[MEMBER].leave_by_remove();
    let e = Group::load(f.record.clone())
        .unwrap()
        .apply_proposal(&f.d[MEMBER].id, &bytes)
        .unwrap_err();
    assert!(matches!(e, GroupError::Proposal), "{e:?}");
    // Someone else's SelfRemove, sent by another device, is not theirs to send.
    let theirs = f.d[OTHER].leave();
    let e = Group::load(f.record.clone())
        .unwrap()
        .apply_proposal(&f.d[MEMBER].id, &theirs)
        .unwrap_err();
    assert!(matches!(e, GroupError::Sender), "{e:?}");
}

#[test]
fn only_admins_change_the_policy() {
    let mut f = fixture(Policy::GROUP);
    let changes: [(&str, fn(&mut Policy)); 5] = [
        ("only admins can send", |p| p.send = Role::Admin),
        ("only admins can edit group info", |p| {
            p.edit_info = Role::Admin;
        }),
        ("only admins can add", |p| p.add = Role::Admin),
        ("join approval", |p| {
            p.flags |= songbird_groups::roles::FLAG_APPROVAL;
        }),
        ("who starts calls", |p| p.call = Role::Admin),
    ];
    for (what, change) in changes {
        let edit = |a: &mut Device, _: &Fixture| {
            let mut r = a.roles();
            change(&mut r.policy);
            a.set_roles(&r)
        };
        for who in [MEMBER, MODERATOR] {
            refused(attempt(&mut f, who, edit), what);
        }
        allowed(attempt(&mut f, ADMIN, edit), what);
    }
}

#[test]
fn roles_change_only_downward_from_the_changer() {
    let mut f = fixture(Policy::GROUP);
    let set = |who: u16, role: Role| {
        move |a: &mut Device, _: &Fixture| {
            let mut r = a.roles();
            if role == Role::Member {
                r.explicit.remove(&account(who));
            } else {
                r.explicit.insert(account(who), role);
            }
            a.set_roles(&r)
        }
    };
    refused(
        attempt(&mut f, MEMBER, set(4, Role::Admin)),
        "self-promotion",
    );
    refused(
        attempt(&mut f, MEMBER, set(5, Role::Moderator)),
        "a member promotes",
    );
    refused(
        attempt(&mut f, MODERATOR, set(5, Role::Moderator)),
        "a moderator promotes",
    );
    allowed(
        attempt(&mut f, ADMIN, set(5, Role::Moderator)),
        "an admin makes a moderator",
    );
    refused(
        attempt(&mut f, ADMIN, set(5, Role::Admin)),
        "an admin makes an admin",
    );
    refused(
        attempt(&mut f, ADMIN, set(1, Role::Member)),
        "an admin demotes the owner",
    );
    allowed(
        attempt(&mut f, OWNER, set(5, Role::Admin)),
        "the owner makes an admin",
    );
    allowed(
        attempt(&mut f, OWNER, set(5, Role::Owner)),
        "the owner makes an owner",
    );
    allowed(
        attempt(&mut f, MODERATOR, set(3, Role::Member)),
        "stepping down",
    );
    // The last owner cannot step down.
    let v = attempt(&mut f, OWNER, set(1, Role::Admin));
    assert!(
        matches!(v.0, Err(GroupError::Forbidden(Denied::NoOwner))),
        "{:?}",
        v.0
    );
    assert!(v.1.is_err());
}

#[test]
fn a_removed_persons_role_cannot_linger() {
    let mut f = fixture(Policy::GROUP);
    let admin = leaf(&f, ADMIN);
    // The owner removes the admin but keeps its entry: a later rejoin would restore the role.
    let v = attempt(&mut f, OWNER, |a, _| a.remove(&[admin]));
    assert!(
        matches!(v.0, Err(GroupError::Forbidden(Denied::Stale))),
        "{:?}",
        v.0
    );
    assert!(v.1.is_err());
}

#[test]
fn a_channel_reads_only() {
    let mut f = fixture(Policy::CHANNEL);
    // Subscribers (default role ReadOnly) may not add anyone.
    refused(
        attempt(&mut f, MEMBER, |a, f| a.add(&[f.outsider.key_package()])),
        "a subscriber adds",
    );
    allowed(
        attempt(&mut f, ADMIN, |a, f| a.add(&[f.outsider.key_package()])),
        "an admin adds",
    );
    let roles = Group::load(f.record.clone()).unwrap().roles().unwrap();
    assert!(!roles.may_send(&account(4)) && roles.may_send(&account(2)));
}
