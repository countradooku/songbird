//! The log against the Certificate Transparency reference vectors (RFC 6962 trees of the
//! reference leaf set; the roots were recomputed with an independent Python implementation and
//! the size-8 root is the published reference value), and exhaustively: every inclusion and
//! consistency proof of every tree up to 70 leaves verifies, and a forked or rewritten log is
//! detected.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use songbird_kt::{
    Hash, KtError, MemoryStore, consistency_proof, inclusion_proof, leaf_hash, root,
    verify_consistency, verify_inclusion,
};

const ROOTS: [&str; 8] = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

fn reference_leaves() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x00],
        vec![0x10],
        vec![0x20, 0x21],
        vec![0x30, 0x31],
        vec![0x40, 0x41, 0x42, 0x43],
        (0x50..0x58).collect(),
        (0x60..0x70).collect(),
    ]
}

#[test]
fn reference_roots() {
    let mut s = MemoryStore::default();
    assert_eq!(
        hex::encode(root(&s, 0).unwrap()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    for (i, l) in reference_leaves().iter().enumerate() {
        s.append(leaf_hash(l)).unwrap();
        assert_eq!(
            hex::encode(root(&s, s.size()).unwrap()),
            ROOTS[i],
            "size {}",
            i + 1
        );
        // Every earlier size's root is still reachable from the same store.
        for (j, r) in ROOTS.iter().enumerate().take(i + 1) {
            assert_eq!(
                hex::encode(root(&s, u64::try_from(j).unwrap() + 1).unwrap()),
                *r
            );
        }
    }
}

fn leaf(i: u64, salt: u8) -> Hash {
    leaf_hash(&[&i.to_be_bytes()[..], &[salt]].concat())
}

fn tree(n: u64, salt: u8) -> MemoryStore {
    let mut s = MemoryStore::default();
    for i in 0..n {
        s.append(leaf(i, salt)).unwrap();
    }
    s
}

#[test]
fn every_proof_of_every_tree_up_to_70_leaves_verifies_and_tampering_fails() {
    let s = tree(70, 0);
    for n in 1..=70u64 {
        let r = root(&s, n).unwrap();
        for i in 0..n {
            let p = inclusion_proof(&s, i, n).unwrap();
            assert_eq!(
                verify_inclusion(&leaf(i, 0), i, n, &p, &r),
                Ok(()),
                "{i}/{n}"
            );
            // Another leaf, another index, another size, a changed proof hash.
            assert!(verify_inclusion(&leaf(i, 1), i, n, &p, &r).is_err());
            if n > 1 {
                assert!(verify_inclusion(&leaf(i, 0), (i + 1) % n, n, &p, &r).is_err());
            }
            if let Some(first) = p.first() {
                let mut q = p.clone();
                q[0] = leaf_hash(first);
                assert!(verify_inclusion(&leaf(i, 0), i, n, &q, &r).is_err());
            }
        }
        assert_eq!(
            verify_inclusion(&leaf(0, 0), n, n, &[], &r),
            Err(KtError::Malformed)
        );
        for m in 1..=n {
            let p = consistency_proof(&s, m, n).unwrap();
            let old = root(&s, m).unwrap();
            assert_eq!(verify_consistency(m, n, &old, &r, &p), Ok(()), "{m}->{n}");
            if m < n {
                let mut q = p.clone();
                q.pop();
                assert!(verify_consistency(m, n, &old, &r, &q).is_err());
            }
        }
    }
}

#[test]
fn a_forked_or_rewritten_log_is_detected() {
    // Two logs agree on their first 20 leaves, then diverge (a server showing two people
    // different histories): no consistency proof joins a head of one to a head of the other.
    let honest = tree(40, 0);
    let mut fork = tree(20, 0);
    for i in 20..40 {
        fork.append(leaf(i, 9)).unwrap();
    }
    for m in 1..=40u64 {
        for n in m.max(21)..=40 {
            let old_fork = root(&fork, m).unwrap();
            let new_honest = root(&honest, n).unwrap();
            let p = consistency_proof(&honest, m, n).unwrap();
            let joined = verify_consistency(m, n, &old_fork, &new_honest, &p).is_ok();
            assert_eq!(joined, m <= 20, "{m}->{n}");
        }
    }
    // A rewritten leaf: the old head no longer matches, and the leaf's inclusion fails.
    let mut rewritten = tree(10, 0);
    rewritten.append(leaf(10, 5)).unwrap();
    let honest11 = tree(11, 0);
    let r = root(&honest11, 11).unwrap();
    let p = inclusion_proof(&rewritten, 10, 11).unwrap();
    assert!(verify_inclusion(&leaf(10, 5), 10, 11, &p, &r).is_err());
}
