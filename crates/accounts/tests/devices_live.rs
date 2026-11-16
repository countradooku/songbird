//! Devices (Prompt 3, M4, D-0052) against a real SurrealDB: link tokens, linking, the signed
//! list's rules, removal and the device limit under races. Runs as `registry_live` does.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::many_single_char_names,
    reason = "tests"
)]

use std::sync::Arc;
use std::time::Duration;

use songbird_accounts::devices::ListEntry;
use songbird_accounts::{Db, KeysUpdate, NewAccount, Registry, RegistryError};
use songbird_jobs::{Job, Outbox as _, Work};
use songbird_types::{AccountId, DeviceId};

async fn registry() -> Option<Registry> {
    let Ok(addr) = std::env::var("SONGBIRD_TEST_SURREALDB") else {
        assert!(
            std::env::var("SONGBIRD_REQUIRE_SURREALDB").is_err(),
            "SONGBIRD_REQUIRE_SURREALDB is set but SONGBIRD_TEST_SURREALDB is not"
        );
        return None;
    };
    let cfg = songbird_surreal::Config {
        addr,
        host: "localhost".into(),
        tls: None,
        user: std::env::var("SONGBIRD_TEST_SURREALDB_USER").unwrap_or_else(|_| "root".into()),
        pass: std::env::var("SONGBIRD_TEST_SURREALDB_PASS").expect("SONGBIRD_TEST_SURREALDB_PASS"),
        namespace: "test".into(),
        database: format!(
            "devices_{}",
            DeviceId::random().unwrap().to_hex_unredacted()
        ),
        timeout: Duration::from_secs(30),
        max_message_bytes: 16 << 20,
    };
    Some(
        Registry::connect(Db::connect(cfg).await.unwrap())
            .await
            .unwrap(),
    )
}

const TTL: Duration = Duration::from_secs(600);

fn rand32() -> [u8; 32] {
    let mut c = [0u8; 32];
    getrandom::fill(&mut c).unwrap();
    c
}

fn ik(b: u8) -> [u8; 33] {
    let mut k = [b; 33];
    k[0] = 5;
    k
}

/// A registered account whose primary has uploaded its identity key `ik(1)`.
async fn account(r: &Registry) -> NewAccount {
    let n = NewAccount {
        account: AccountId::random().unwrap(),
        identity: [9; 32],
        device: DeviceId::random().unwrap(),
        auth_key: rand32(),
        allowance: 0,
    };
    r.register(&n, None).await.unwrap();
    r.put_keys(
        &n.device,
        &KeysUpdate {
            identity: Some(ik(1)),
            signed: Some(vec![1]),
            last_resort: Some(vec![2]),
            ..KeysUpdate::default()
        },
        10,
    )
    .await
    .unwrap();
    n
}

/// Links a new device to `n`'s account: (device, auth key, token hash used).
async fn link(
    r: &Registry,
    n: &NewAccount,
    max: u32,
) -> Result<(DeviceId, [u8; 32]), RegistryError> {
    let t = rand32();
    let d = DeviceId::random().unwrap();
    r.create_link_token(&n.device, &t, &d, TTL, max).await?;
    let k = rand32();
    r.link_device(&t, &d, &k, &ik(2), &[7; 32], max).await?;
    Ok((d, k))
}

fn primary_entry(n: &NewAccount) -> ListEntry {
    ListEntry {
        device: n.device,
        auth_key: n.auth_key,
        identity: ik(1),
        primary: true,
    }
}

fn job(a: &AccountId) -> Job {
    Job::new(Work::DeleteDevices { account: *a }).unwrap()
}

#[tokio::test]
async fn link_tokens_are_single_use_bound_to_their_device_and_only_for_the_primary() {
    let Some(r) = registry().await else { return };
    let n = account(&r).await;
    let t = rand32();
    let d = DeviceId::random().unwrap();
    assert_eq!(
        r.create_link_token(&n.device, &t, &d, TTL, 6)
            .await
            .unwrap(),
        n.account
    );
    // Another device ID with this token, an unknown token: one refusal.
    let k = rand32();
    let other = DeviceId::random().unwrap();
    assert!(matches!(
        r.link_device(&t, &other, &k, &ik(2), &[0; 32], 6).await,
        Err(RegistryError::LinkToken)
    ));
    assert!(matches!(
        r.link_device(&rand32(), &d, &k, &ik(2), &[0; 32], 6).await,
        Err(RegistryError::LinkToken)
    ));
    // The right device links once, pending, with its keys and confirmation tag.
    assert_eq!(
        r.link_device(&t, &d, &k, &ik(2), &[7; 32], 6)
            .await
            .unwrap(),
        n.account
    );
    assert!(matches!(
        r.link_device(&t, &d, &k, &ik(2), &[7; 32], 6).await,
        Err(RegistryError::LinkToken)
    ));
    let devs = r.devices_of(&n.account).await.unwrap();
    let new = devs.iter().find(|x| x.device == d).unwrap();
    assert!(new.pending && !new.primary);
    assert_eq!(
        (new.auth_key, new.identity, new.confirm),
        (k, Some(ik(2)), Some([7; 32]))
    );
    assert!(devs.iter().find(|x| x.device == n.device).unwrap().primary);
    assert_eq!(r.pending_devices().await.unwrap(), vec![d]);
    // A linked device cannot ask for tokens; nor can a device ID already in use be reserved.
    assert!(matches!(
        r.create_link_token(&d, &rand32(), &DeviceId::random().unwrap(), TTL, 6)
            .await,
        Err(RegistryError::NotPrimary)
    ));
    assert!(matches!(
        r.create_link_token(&n.device, &rand32(), &d, TTL, 6).await,
        Err(RegistryError::Exists)
    ));
    // An expired token is refused.
    let t2 = rand32();
    let d2 = DeviceId::random().unwrap();
    r.create_link_token(&n.device, &t2, &d2, TTL, 6)
        .await
        .unwrap();
    r.db()
        .exec(
            "UPDATE ltoken SET expires = time::now() - 1s RETURN NONE;",
            Vec::new(),
        )
        .await
        .unwrap();
    assert!(matches!(
        r.link_device(&t2, &d2, &k, &ik(2), &[0; 32], 6).await,
        Err(RegistryError::LinkToken)
    ));
    r.delete_expired_link_tokens(100).await.unwrap();
    let left: i64 = r
        .db()
        .query1("RETURN count(SELECT id FROM ltoken);", Vec::new())
        .await
        .unwrap()
        .as_i64()
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn the_device_limit_counts_outstanding_tokens() {
    let Some(r) = registry().await else { return };
    let n = account(&r).await;
    // Primary + 2 linked = 3; a fourth token is refused while one is outstanding.
    link(&r, &n, 4).await.unwrap();
    link(&r, &n, 4).await.unwrap();
    r.create_link_token(&n.device, &rand32(), &DeviceId::random().unwrap(), TTL, 4)
        .await
        .unwrap();
    assert!(matches!(
        r.create_link_token(&n.device, &rand32(), &DeviceId::random().unwrap(), TTL, 4)
            .await,
        Err(RegistryError::DeviceLimit)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn racing_token_requests_never_exceed_the_device_limit() {
    let Some(first) = registry().await else {
        return;
    };
    let n = account(&first).await;
    let mut conns = vec![Arc::new(first)];
    for _ in 1..8 {
        let cfg = conns[0].db().config_clone().unwrap();
        conns.push(Arc::new(
            Registry::connect(Db::connect(cfg).await.unwrap())
                .await
                .unwrap(),
        ));
    }
    // 40 concurrent requests for a limit of 6 (primary + 5): exactly 5 succeed.
    let tasks: Vec<_> = (0..40)
        .map(|i| {
            let r = Arc::clone(&conns[i % conns.len()]);
            let primary = n.device;
            tokio::spawn(async move {
                r.create_link_token(&primary, &rand32(), &DeviceId::random().unwrap(), TTL, 6)
                    .await
            })
        })
        .collect();
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(RegistryError::DeviceLimit) => {}
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert_eq!(ok, 5, "tokens granted beyond the limit");
}

#[tokio::test]
async fn lists_only_grow_name_exact_keys_and_remove_what_they_leave_out() {
    let Some(r) = registry().await else { return };
    let n = account(&r).await;
    let (d2, k2) = link(&r, &n, 6).await.unwrap();
    let (d3, k3) = link(&r, &n, 6).await.unwrap();
    let e2 = ListEntry {
        device: d2,
        auth_key: k2,
        identity: ik(2),
        primary: false,
    };
    let e3 = ListEntry {
        device: d3,
        auth_key: k3,
        identity: ik(2),
        primary: false,
    };
    let a = n.account;
    // Version 1 names all three: nothing removed, none pending any more.
    let c = r
        .put_device_list(
            &a,
            1,
            &[primary_entry(&n), e2.clone(), e3.clone()],
            b"v1",
            &job(&a),
        )
        .await
        .unwrap();
    assert!(c.removed.is_empty());
    assert_eq!(c.remaining.len(), 3);
    assert!(r.pending_devices().await.unwrap().is_empty());
    assert!(
        r.devices_of(&a)
            .await
            .unwrap()
            .iter()
            .all(|d| d.confirm.is_none())
    );
    assert_eq!(r.device_list(&a).await.unwrap().unwrap().1, 1);
    // The same version again, or a lower one: rollback.
    for v in [0, 1] {
        assert!(matches!(
            r.put_device_list(&a, v, &[primary_entry(&n)], b"old", &job(&a))
                .await,
            Err(RegistryError::Rollback)
        ));
    }
    // Wrong keys, a device of another account, an unknown device, a second primary, the
    // primary demoted: each a mismatch, and nothing changed.
    let mut wrong = e2.clone();
    wrong.auth_key = rand32();
    let other = account(&r).await;
    let foreign = primary_entry(&other);
    let mut unknown = e2.clone();
    unknown.device = DeviceId::random().unwrap();
    let mut two = e2.clone();
    two.primary = true;
    let mut demoted = primary_entry(&n);
    demoted.primary = false;
    for bad in [
        vec![primary_entry(&n), wrong],
        vec![primary_entry(&n), foreign],
        vec![primary_entry(&n), unknown],
        vec![primary_entry(&n), two],
        vec![demoted, e2.clone()],
    ] {
        assert!(matches!(
            r.put_device_list(&a, 5, &bad, b"bad", &job(&a)).await,
            Err(RegistryError::ListMismatch)
        ));
    }
    assert_eq!(
        r.device_list(&a).await.unwrap().unwrap(),
        (b"v1".to_vec().into(), 1)
    );
    // Version 7 leaves d3 out: disabled, a deletion job in the outbox, the directory changed.
    let dir = r.directory_version().await.unwrap();
    let j = job(&a);
    let c = r
        .put_device_list(&a, 7, &[primary_entry(&n), e2], b"v7", &j)
        .await
        .unwrap();
    assert_eq!(c.removed, vec![d3]);
    assert_eq!(c.remaining.len(), 2);
    assert!(r.device(&d3).await.unwrap().unwrap().disabled);
    assert!(r.directory_version().await.unwrap() > dir);
    assert!(r.outbox_take_all().await.iter().any(|x| x.id == j.id));
    assert_eq!(r.removed_devices(&a).await.unwrap(), vec![d3]);
    // A removed device cannot come back in a later list.
    assert!(matches!(
        r.put_device_list(&a, 8, &[primary_entry(&n), e3], b"v8", &job(&a))
            .await,
        Err(RegistryError::ListMismatch)
    ));
    // The worker's deletion: rows gone, the enabled devices untouched.
    r.delete_device_rows(&[d3, n.device]).await.unwrap();
    assert_eq!(r.device_remnants(&[d3]).await.unwrap(), 0);
    assert!(r.device(&n.device).await.unwrap().is_some());
    assert!(r.removed_devices(&a).await.unwrap().is_empty());
}

#[tokio::test]
async fn linked_devices_remove_themselves_the_primary_cannot() {
    let Some(r) = registry().await else { return };
    let n = account(&r).await;
    let (d2, _) = link(&r, &n, 6).await.unwrap();
    let j = job(&n.account);
    assert!(matches!(
        r.remove_device(&n.device, &j).await,
        Err(RegistryError::NotPrimary)
    ));
    let (a, remaining) = r.remove_device(&d2, &j).await.unwrap();
    assert_eq!((a, remaining), (n.account, vec![n.device]));
    assert!(r.device(&d2).await.unwrap().unwrap().disabled);
    assert!(r.outbox_take_all().await.iter().any(|x| x.id == j.id));
    // Account deletion stops removals' job from touching anything, and takes tokens with it.
    r.create_link_token(&n.device, &rand32(), &DeviceId::random().unwrap(), TTL, 6)
        .await
        .unwrap();
    let del = Job::new(Work::DeleteAccount { account: n.account }).unwrap();
    r.begin_account_deletion(&n.account, &del).await.unwrap();
    assert!(r.removed_devices(&n.account).await.unwrap().is_empty());
    r.delete_account_rows(&n.account).await.unwrap();
    assert!(
        r.remnants(&n.account, &[n.device, d2], &[])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn pending_devices_get_no_key_fetches() {
    let Some(r) = registry().await else { return };
    let n = account(&r).await;
    let (d2, _) = link(&r, &n, 6).await.unwrap();
    r.put_keys(
        &d2,
        &KeysUpdate {
            identity: Some(ik(2)),
            signed: Some(vec![3]),
            last_resort: Some(vec![4]),
            ..KeysUpdate::default()
        },
        10,
    )
    .await
    .unwrap();
    // A link-time identity key cannot be replaced by an upload.
    assert!(matches!(
        r.put_keys(
            &d2,
            &KeysUpdate {
                identity: Some(ik(3)),
                ..KeysUpdate::default()
            },
            10
        )
        .await,
        Err(RegistryError::IdentityMismatch)
    ));
    let stranger = DeviceId::random().unwrap();
    let served = |b: Vec<songbird_accounts::ClaimedKeys>| -> Vec<DeviceId> {
        b.into_iter().map(|k| k.device).collect()
    };
    assert_eq!(
        served(
            r.claim_bundles(&n.account, None, &stranger, false)
                .await
                .unwrap()
        ),
        vec![n.device]
    );
    let e2 = ListEntry {
        device: d2,
        auth_key: r.device(&d2).await.unwrap().unwrap().key,
        identity: ik(2),
        primary: false,
    };
    r.put_device_list(
        &n.account,
        1,
        &[primary_entry(&n), e2],
        b"v1",
        &job(&n.account),
    )
    .await
    .unwrap();
    let mut got = served(
        r.claim_bundles(&n.account, None, &stranger, false)
            .await
            .unwrap(),
    );
    got.sort();
    let mut want = vec![n.device, d2];
    want.sort();
    assert_eq!(got, want);
}

trait TakeAll {
    async fn outbox_take_all(&self) -> Vec<Job>;
}

impl TakeAll for Registry {
    async fn outbox_take_all(&self) -> Vec<Job> {
        self.take(1000).await.unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn racing_pin_guesses_never_exceed_the_free_attempts() {
    let Some(first) = registry().await else {
        return;
    };
    let n = account(&first).await;
    first.set_pin(&n.account, Some(&[1; 48])).await.unwrap();
    let mut conns = vec![Arc::new(first)];
    for _ in 1..8 {
        let cfg = conns[0].db().config_clone().unwrap();
        conns.push(Arc::new(
            Registry::connect(Db::connect(cfg).await.unwrap())
                .await
                .unwrap(),
        ));
    }
    // 40 parallel guesses, 3 free attempts, lock after: exactly 4 attempts get to check the
    // PIN (the fourth starts the lock), the rest are refused before any check.
    let tasks: Vec<_> = (0..40)
        .map(|i| {
            let r = Arc::clone(&conns[i % conns.len()]);
            let a = n.account;
            tokio::spawn(async move {
                r.spend_pin_attempt(&a, 3, Duration::from_secs(60), 10)
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut checked = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(v) => {
                assert_eq!(v, vec![1; 48]);
                checked += 1;
            }
            Err(songbird_accounts::devices::PinRefusal::Locked(Some(_))) => {}
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(checked, 4, "PIN checks beyond the limit");
    let f = conns[0].factors(&n.account).await.unwrap();
    assert!(f.pin && f.pin_locked.is_some() && f.pin_tries == 4);
    // A correct PIN clears it; no PIN refuses.
    conns[0].pin_ok(&n.account).await.unwrap();
    assert!(
        conns[0]
            .factors(&n.account)
            .await
            .unwrap()
            .pin_locked
            .is_none()
    );
    conns[0].set_pin(&n.account, None).await.unwrap();
    assert_eq!(
        conns[0]
            .spend_pin_attempt(&n.account, 3, Duration::from_secs(60), 10)
            .await
            .unwrap(),
        Err(songbird_accounts::devices::PinRefusal::NoPin)
    );
}

/// A registry roster (format 2): the policy, then each device with role 1.
fn roster(devices: &[DeviceId]) -> Vec<u8> {
    let mut r = vec![2, 1, 1, 1, 3, 1, 1, 0];
    for d in devices {
        r.extend_from_slice(d.as_bytes());
        r.push(1);
    }
    r
}

#[tokio::test]
async fn departing_devices_mark_the_groups_that_hold_them() {
    // D-0075: every way a device leaves the directory marks the groups holding it (with that
    // group's departed devices only), for `api` to propose their removal; the marks are
    // forgotten only if no later mark came, and deletion strips the device IDs from them.
    let Some(r) = registry().await else { return };
    let n = account(&r).await;
    let (d2, k2) = link(&r, &n, 6).await.unwrap();
    let (d3, k3) = link(&r, &n, 6).await.unwrap();
    let other = account(&r).await;
    let (g1, g2, g3) = ([1u8; 16], [2u8; 16], [3u8; 16]);
    r.create_group(&g1, b"state", &roster(&[n.device, d2]))
        .await
        .unwrap();
    r.create_group(&g2, b"state", &roster(&[d3, other.device]))
        .await
        .unwrap();
    r.create_group(&g3, b"state", &roster(&[other.device]))
        .await
        .unwrap();
    let a = n.account;
    let entry = |device, auth_key| ListEntry {
        device,
        auth_key,
        identity: ik(2),
        primary: false,
    };
    r.put_device_list(
        &a,
        1,
        &[primary_entry(&n), entry(d2, k2), entry(d3, k3)],
        b"v1",
        &job(&a),
    )
    .await
    .unwrap();
    assert!(r.groups_to_prune(10).await.unwrap().is_empty());

    // The primary's list leaves d3 out: only g2 is marked, naming d3.
    r.put_device_list(&a, 2, &[primary_entry(&n), entry(d2, k2)], b"v2", &job(&a))
        .await
        .unwrap();
    let marks = r.groups_to_prune(10).await.unwrap();
    assert_eq!(marks.len(), 1);
    assert_eq!((marks[0].group, &marks[0].gone[..]), (g2, &[d3][..]));
    // d2 removes itself: g1 is marked too.
    r.remove_device(&d2, &job(&a)).await.unwrap();
    let marks = r.groups_to_prune(10).await.unwrap();
    assert_eq!(marks.len(), 2);
    let m1 = marks.iter().find(|m| m.group == g1).unwrap().clone();
    assert_eq!(m1.gone, vec![d2]);
    // A later mark survives forgetting an earlier read of it.
    let del = Job::new(Work::DeleteAccount { account: a }).unwrap();
    r.begin_account_deletion(&a, &del).await.unwrap();
    r.group_pruned(&g1, m1.n).await.unwrap();
    let marks = r.groups_to_prune(10).await.unwrap();
    let again = marks.iter().find(|m| m.group == g1).unwrap();
    assert!(again.n > m1.n);
    assert!(again.gone.contains(&n.device) && again.gone.contains(&d2));
    r.group_pruned(&g1, again.n).await.unwrap();
    assert!(
        r.groups_to_prune(10)
            .await
            .unwrap()
            .iter()
            .all(|m| m.group != g1)
    );
    // Deletion strips the devices from the marks that remain: nothing names them after.
    r.delete_device_rows(&[d3]).await.unwrap();
    r.delete_account_rows(&a).await.unwrap();
    let left = r.remnants(&a, &[n.device, d2, d3], &[]).await.unwrap();
    assert!(left.is_empty(), "{left:?}");
    let g2_mark = r.groups_to_prune(10).await.unwrap();
    assert_eq!(g2_mark.len(), 1);
    assert!(
        g2_mark[0].gone.is_empty(),
        "the mark keeps the group, not the device"
    );
}
