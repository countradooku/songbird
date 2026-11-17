//! Prompt 5, M4 (D-0072): what groups cost at 1,024, 2,048 and 5,000 members, X-Wing and
//! classical.
//! Bytes on the wire and in the registry; time on the client and in the delivery service.
//!
//! Ignored by default (minutes, and meaningful only optimised):
//!
//! ```text
//! cargo test --release -p songbird-groups-harness --test scale -- --ignored --nocapture
//! ```
//!
//! The delivery service accepts only X-Wing groups, so classical rows have client and wire
//! numbers only. The group is filled by batches of adds, which leave its parent nodes blank: a
//! full-path commit (update, remove) then encrypts to nearly every leaf, the worst case.
#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "a benchmark that prints its table"
)]

use std::time::{Duration, Instant};

use openmls::prelude::Ciphersuite;
use openmls::prelude::tls_codec::Serialize as _;
use songbird_groups::crypto::GROUP_CIPHERSUITE;
use songbird_groups::{Group, Limits, Record};
use songbird_groups_harness::{Device, Dir, id_from, server_create, set_suite, welcome_of};
use songbird_types::AccountId;

const BATCH: usize = 256;

fn account(n: u16) -> AccountId {
    AccountId::from_bytes(id_from(n, 0xA0))
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

fn kib(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap()) / 1_024.0
}

/// Times `f`.
fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let t = Instant::now();
    let v = f();
    (v, t.elapsed())
}

/// The delivery service's work for one commit: load the stored record, validate and merge,
/// store the new record. Returns the group and the three times.
fn serve(
    server: &Group,
    sender: &Device,
    bundle: &[u8],
    dir: &Dir,
    limits: &Limits,
) -> (Group, [Duration; 3], usize) {
    let bytes = server.record().encode().unwrap();
    let (loaded, load) = timed(|| Group::load(Record::decode(&bytes).unwrap()).unwrap());
    let ((g, _), validate) = timed(|| {
        loaded
            .apply_commit(&sender.id, bundle, dir, limits)
            .unwrap()
    });
    let (stored, store) = timed(|| g.record().encode().unwrap());
    (g, [load, validate, store], stored.len())
}

struct Row {
    suite: &'static str,
    members: usize,
    key_package: usize,
    tree: usize,
    group_info: usize,
    state: usize,
    add: Op,
    join: Duration,
    update: Op,
    remove: Op,
}

#[derive(Default)]
struct Op {
    commit: usize,
    welcome: usize,
    client: Duration,
    receive: Duration,
    server: Option<[Duration; 3]>,
}

fn measure(suite: Ciphersuite, label: &'static str, members: usize) -> Row {
    set_suite(suite);
    let served = suite == GROUP_CIPHERSUITE;
    let limits = Limits {
        max_members: members + 8,
        max_channel_members: members + 8,
        max_bundle: 64 << 20,
        ..Limits::default()
    };
    let mut dir = Dir::default();
    let mut owner = Device::new(0, account(0), &mut dir);
    let mut bob = Device::new(1, account(1), &mut dir);
    let mut server = if served {
        Some(server_create(&mut owner, &dir))
    } else {
        owner.create();
        None
    };

    // Fill the group to `members - 1` (owner, Bob, strangers) in batches; Bob joins first and
    // follows every commit, as a member would.
    let mut next: u16 = 2;
    let mut first = true;
    while owner.group.as_ref().unwrap().members().count() < members - 1 {
        let room = members - 1 - owner.group.as_ref().unwrap().members().count();
        let mut kps = Vec::new();
        if first {
            kps.push(bob.key_package());
        }
        while kps.len() < room.min(BATCH) {
            let d = Device::new(next, account(next), &mut dir);
            kps.push(d.key_package());
            next += 1;
        }
        let b = owner.add(&kps);
        if let Some(s) = server.take() {
            server = Some(serve(&s, &owner, &b, &dir, &limits).0);
        }
        owner.merge();
        if first {
            bob.join(&welcome_of(&b), &owner.tree());
            first = false;
        } else {
            bob.receive(&b);
        }
    }

    // Adding the last member: commit and Welcome; then the newcomer joins.
    let mut carol = Device::new(next, account(next), &mut dir);
    let kp = carol.key_package();
    let key_package = kp.tls_serialize_detached().unwrap().len();
    let (b, client) = timed(|| owner.add(&[kp]));
    let parts = songbird_groups::wire::Bundle::parse(&b, usize::MAX).unwrap();
    let mut add = Op {
        commit: parts.commit.len(),
        welcome: parts.welcome.map_or(0, <[u8]>::len),
        client,
        ..Op::default()
    };
    if let Some(s) = server.take() {
        let (g, t, _) = serve(&s, &owner, &b, &dir, &limits);
        add.server = Some(t);
        server = Some(g);
    }
    owner.merge();
    add.receive = timed(|| bob.receive(&b)).1;
    let tree_bytes = owner.tree();
    let join = timed(|| carol.join(&welcome_of(&b), &tree_bytes)).1;
    let group_info = owner.group_info().len();

    // A member's key update (a full path).
    let (b, client) = timed(|| bob.update());
    let mut update = Op {
        commit: songbird_groups::wire::Bundle::parse(&b, usize::MAX)
            .unwrap()
            .commit
            .len(),
        client,
        ..Op::default()
    };
    if let Some(s) = server.take() {
        let (g, t, _) = serve(&s, &bob, &b, &dir, &limits);
        update.server = Some(t);
        server = Some(g);
    }
    bob.merge();
    update.receive = timed(|| owner.receive(&b)).1;
    carol.receive(&b);

    // The owner removes the newcomer.
    let leaf = carol.leaf();
    let (b, client) = timed(|| owner.remove(&[leaf]));
    let mut remove = Op {
        commit: songbird_groups::wire::Bundle::parse(&b, usize::MAX)
            .unwrap()
            .commit
            .len(),
        client,
        ..Op::default()
    };
    let mut state = 0;
    if let Some(s) = server.take() {
        let (_, t, bytes) = serve(&s, &owner, &b, &dir, &limits);
        remove.server = Some(t);
        state = bytes;
    }
    owner.merge();
    remove.receive = timed(|| bob.receive(&b)).1;

    Row {
        suite: label,
        members,
        key_package,
        tree: tree_bytes.len(),
        group_info,
        state,
        add,
        join,
        update,
        remove,
    }
}

fn server_cell(t: Option<[Duration; 3]>) -> String {
    t.map_or_else(
        || "n/a".into(),
        |[l, v, s]| {
            format!(
                "{:.1} ({:.1} + {:.1} + {:.1})",
                ms(l + v + s),
                ms(l),
                ms(v),
                ms(s)
            )
        },
    )
}

#[test]
#[ignore = "minutes; run optimised with --ignored --nocapture"]
fn costs_at_scale() {
    let mut rows = Vec::new();
    for members in [1_024, 2_048, 5_000] {
        for (suite, label) in [
            (GROUP_CIPHERSUITE, "X-Wing (0x004F)"),
            (
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                "classical (0x0001)",
            ),
        ] {
            let (row, total) = timed(|| measure(suite, label, members));
            println!(
                "measured {label} at {members} in {:.1} s",
                total.as_secs_f64()
            );
            rows.push(row);
        }
    }

    println!();
    println!("Sizes (KiB)");
    println!(
        "| Suite | Members | KeyPackage | Ratchet tree | GroupInfo | Stored state | Add: commit | Add: Welcome | Update: commit | Remove: commit |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for r in &rows {
        println!(
            "| {} | {} | {:.2} | {:.0} | {:.2} | {} | {:.2} | {:.2} | {:.2} | {:.2} |",
            r.suite,
            r.members,
            kib(r.key_package),
            kib(r.tree),
            kib(r.group_info),
            if r.state == 0 {
                "n/a".into()
            } else {
                format!("{:.0}", kib(r.state))
            },
            kib(r.add.commit),
            kib(r.add.welcome),
            kib(r.update.commit),
            kib(r.remove.commit),
        );
    }
    println!();
    println!("Time (ms). Server: total (load + validate + store)");
    println!(
        "| Suite | Members | Add: client | Add: server | Add: member receives | Join from Welcome | Update: client | Update: server | Update: member receives | Remove: client | Remove: server |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for r in &rows {
        println!(
            "| {} | {} | {:.1} | {} | {:.1} | {:.1} | {:.1} | {} | {:.1} | {:.1} | {} |",
            r.suite,
            r.members,
            ms(r.add.client),
            server_cell(r.add.server),
            ms(r.add.receive),
            ms(r.join),
            ms(r.update.client),
            server_cell(r.update.server),
            ms(r.update.receive),
            ms(r.remove.client),
            server_cell(r.remove.server),
        );
    }
}
