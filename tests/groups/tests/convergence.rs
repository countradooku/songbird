//! Concurrent commits never fork a group, and every honest client ends at the server's epoch and
//! roster (Prompt 5's gate; property tests over random interleavings).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests: failing loudly is the point"
)]

use proptest::prelude::*;
use songbird_groups::{Group, GroupError, Limits, Record};
use songbird_groups_harness::{Device, Dir, id_from, server_create, welcome_of};
use songbird_types::AccountId;

/// The server as the registry sees it: the stored record is the only truth; a refused commit
/// leaves it untouched (the in-memory group is dropped and reloaded).
struct Server {
    record: Record,
    dir: Dir,
}

impl Server {
    fn submit(
        &mut self,
        sender: &Device,
        bundle: &[u8],
    ) -> Result<Vec<songbird_types::DeviceId>, GroupError> {
        let g = Group::load(self.record.clone()).unwrap();
        let (g, applied) = g.apply_commit(&sender.id, bundle, &self.dir, &Limits::default())?;
        // Compare-and-set on the epoch, as the registry does.
        assert_eq!(g.epoch(), self.record.epoch + 1);
        self.record = Record::decode(&g.record().encode().unwrap()).unwrap();
        Ok(applied.removed)
    }

    fn group(&self) -> Group {
        Group::load(self.record.clone()).unwrap()
    }
}

struct World {
    server: Server,
    members: Vec<Device>,
    next: u16,
}

impl World {
    fn new(n: usize) -> Self {
        let mut dir = Dir::default();
        let mut creator = Device::new(1, AccountId::from_bytes(id_from(1, 0xA0)), &mut dir);
        let record = server_create(&mut creator, &dir).record();
        let mut w = Self {
            server: Server { record, dir },
            members: vec![creator],
            next: 2,
        };
        for _ in 1..n {
            w.add(0);
        }
        w
    }

    /// Delivers an accepted commit to every member but its sender.
    fn fan_out(&mut self, from: usize, bundle: &[u8], removed: &[songbird_types::DeviceId]) {
        for (i, m) in self.members.iter_mut().enumerate() {
            if i != from && !removed.contains(&m.id) {
                m.receive(bundle);
            }
        }
        self.members.retain(|m| !removed.contains(&m.id));
    }

    fn add(&mut self, by: usize) {
        let n = self.next;
        self.next += 1;
        let mut d = Device::new(
            n,
            AccountId::from_bytes(id_from(n, 0xA0)),
            &mut self.server.dir,
        );
        let b = self.members[by].add(&[d.key_package()]);
        self.server.submit(&self.members[by], &b).unwrap();
        self.members[by].merge();
        self.fan_out(by, &b, &[]);
        d.join(
            &welcome_of(&b),
            &self.server.group().ratchet_tree().unwrap(),
        );
        self.members.push(d);
    }

    fn remove(&mut self, by: usize, target: usize) {
        let leaf = self.members[target].leaf();
        let b = self.members[by].remove(&[leaf]);
        let removed = self.server.submit(&self.members[by], &b).unwrap();
        self.members[by].merge();
        assert_eq!(removed, vec![self.members[target].id]);
        let by_id = self.members[by].id;
        self.fan_out(by, &b, &removed);
        let _ = by_id;
    }

    /// Every member in `racers` commits from the same epoch; the server takes them in `order`.
    /// Exactly one wins; the others are refused with the new epoch, take the winner's commit,
    /// and try again until all have committed.
    fn race(&mut self, racers: &[usize]) {
        let mut pending: Vec<usize> = racers.to_vec();
        while !pending.is_empty() {
            let bundles: Vec<Vec<u8>> = pending.iter().map(|&i| self.members[i].update()).collect();
            let epoch = self.server.record.epoch;
            let mut winner = None;
            for (k, &i) in pending.iter().enumerate() {
                match self.server.submit(&self.members[i], &bundles[k]) {
                    Ok(_) => {
                        assert!(winner.is_none(), "two commits won epoch {epoch}");
                        winner = Some(k);
                    }
                    Err(GroupError::StaleEpoch { current }) => assert_eq!(current, epoch + 1),
                    Err(e) => panic!("unexpected refusal {e:?}"),
                }
            }
            let w = winner.expect("one commit wins");
            let wi = pending[w];
            for (k, &i) in pending.iter().enumerate() {
                if k != w {
                    self.members[i].discard();
                }
            }
            self.members[wi].merge();
            self.fan_out(wi, &bundles[w], &[]);
            pending.remove(w);
        }
    }

    fn check(&mut self) {
        let g = self.server.group();
        let roster: Vec<_> = g.roster().devices().collect();
        for m in &self.members {
            assert_eq!(
                m.epoch(),
                g.epoch(),
                "a client forked from the server's epoch"
            );
            assert_eq!(
                m.roster(),
                roster,
                "a client's roster differs from the server's"
            );
        }
        // And they share keys: everyone reads everyone.
        for i in 0..self.members.len() {
            let msg = self.members[i].message(b"ping");
            for j in 0..self.members.len() {
                if i != j {
                    assert_eq!(self.members[j].read(&msg), b"ping");
                }
            }
        }
    }
}

#[test]
fn concurrent_commits_from_one_epoch_have_one_winner_and_never_fork() {
    let mut w = World::new(6);
    w.race(&[0, 1, 2, 3, 4, 5]);
    w.check();
    assert_eq!(w.server.record.epoch, 5 + 6);
}

#[derive(Debug, Clone)]
enum Op {
    Add(usize),
    Remove(
        #[allow(dead_code, reason = "kept for the generator's shape")] usize,
        usize,
    ),
    Race(Vec<usize>),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => any::<usize>().prop_map(Op::Add),
        1 => (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Op::Remove(a, b)),
        2 => proptest::collection::vec(any::<usize>(), 1..5).prop_map(Op::Race),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Over random sequences of adds, removals and races (in random server orders), every honest
    /// client stays at the server's epoch and roster, and all of them can talk.
    #[test]
    fn honest_clients_always_agree_with_the_server(ops in proptest::collection::vec(op(), 1..10)) {
        let mut w = World::new(3);
        for op in ops {
            let n = w.members.len();
            match op {
                Op::Add(by) if n < 12 => w.add(by % n),
                // Honest clients act within their roles (D-0070): the owner (the creator,
                // member 0) removes people; a member removes only themself (leaving is the
                // server's self-remove, covered in `matrix.rs`).
                Op::Remove(_, t) if n > 2 => {
                    let t = t % n;
                    if t != 0 {
                        w.remove(0, t);
                    }
                }
                Op::Race(r) => {
                    let mut idx: Vec<usize> = r.into_iter().map(|i| i % n).collect();
                    idx.dedup();
                    let mut seen = Vec::new();
                    idx.retain(|i| if seen.contains(i) { false } else { seen.push(*i); true });
                    w.race(&idx);
                }
                _ => {}
            }
            w.check();
        }
    }
}
