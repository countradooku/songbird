use proptest::prelude::*;

use super::*;

fn acct(n: u8) -> AccountId {
    AccountId::from_bytes([n; 16])
}

fn row(n: u8, level: u8, last_day: u32) -> EntRow {
    EntRow {
        account: acct(n),
        level,
        last_day,
        source: songbird_accounts::entitlements::Source::Grant,
    }
}

#[test]
fn the_default_catalogue_is_the_owners_table_and_valid() {
    let c = Catalog::default();
    c.validate().unwrap();
    assert_eq!(c.free.limits.devices(), 6, "primary + 5 (D-0047)");
    assert_eq!(c.plus.limits.devices(), 11, "primary + 10 (D-0126 §3)");
    assert_eq!(c.free.limits.file_bytes, 2 << 30);
    assert_eq!(c.plus.limits.file_bytes, 4 << 30);
    assert_eq!(c.free.limits.vault_bytes, 5 << 30, "D-0119's vault quota");
    assert_eq!(c.plus.limits.vault_bytes, 50 << 30);
    assert_eq!(c.free.limits.packs_per_month, 5);
    assert_eq!(c.plus.limits.packs_per_month, 50);
    assert_eq!(c.free.flags, Flags::default());
    assert!(c.plus.flags.app_icons && c.plus.flags.chat_themes && c.plus.flags.priority_support);
    assert_eq!(c.ceiling(), c.plus.limits);
}

#[test]
fn a_catalogue_from_configuration_is_strict() {
    let c: Catalog = toml::from_str(
        "version = 3
         [free.limits]
         linked_devices = 4
         file_bytes = 1073741824
         upload_bytes_per_day = 1073741824
         vault_bytes = 1073741824
         vault_chunks = 1000
         packs_per_month = 2
         [plus.limits]
         linked_devices = 8
         file_bytes = 2147483648
         upload_bytes_per_day = 2147483648
         vault_bytes = 2147483648
         vault_chunks = 2000
         packs_per_month = 20
         [plus.flags]
         app_icons = true",
    )
    .unwrap();
    c.validate().unwrap();
    assert_eq!(c.version, 3);
    assert!(c.plus.flags.app_icons && !c.plus.flags.chat_themes);
    // Unknown fields are refused: no flag can be invented by a typo.
    assert!(toml::from_str::<Catalog>("[plus.flags]\nencryption = true").is_err());
    // A plan without every limit is refused.
    assert!(toml::from_str::<Catalog>("[plus.limits]\nlinked_devices = 8").is_err());
}

#[test]
fn a_higher_level_never_allows_less() {
    let mut c = Catalog::default();
    c.plus.limits.vault_bytes = c.free.limits.vault_bytes - 1;
    assert_eq!(c.validate(), Err(CatalogError::NotMonotone));
    let mut c = Catalog::default();
    c.free.flags.chat_themes = true;
    c.plus.flags.chat_themes = false;
    assert_eq!(c.validate(), Err(CatalogError::NotMonotone));
    let mut c = Catalog::default();
    c.plus.limits.linked_devices = 16;
    assert_eq!(c.validate(), Err(CatalogError::Bounds("linked_devices")));
    let c = Catalog {
        version: 0,
        ..Catalog::default()
    };
    assert_eq!(c.validate(), Err(CatalogError::Bounds("version")));
}

#[test]
fn an_entry_expires_by_date_at_the_reader() {
    let s = Snapshot::from_rows(7, &[row(1, 1, 100), row(2, 1, 99), row(3, 9, 1_000)]);
    assert_eq!(s.version(), 7);
    // Held through its last day, inclusive.
    assert_eq!(s.level(&acct(1), 100), Level::Plus);
    assert_eq!(
        s.level(&acct(1), 101),
        Level::Free,
        "past the last day: Free, no sweep needed"
    );
    assert_eq!(s.level(&acct(2), 100), Level::Free);
    // A level this build does not know is never promoted.
    assert_eq!(s.level(&acct(3), 100), Level::Free);
    assert_eq!(s.len(), 2);
    // Everyone else is Free.
    assert_eq!(s.level(&acct(9), 0), Level::Free);
}

#[test]
fn a_stale_snapshot_never_extends_an_entitlement() {
    // The worker is stopped and the registry unreachable: the live snapshot is never replaced,
    // and still reads Free once the day passes.
    let live = Live::from(Snapshot::from_rows(1, &[row(1, 1, today() - 1)]));
    assert_eq!(live.level(&acct(1)), Level::Free);
    let live = Live::from(Snapshot::from_rows(1, &[row(1, 1, today())]));
    assert_eq!(live.level(&acct(1)), Level::Plus);
    live.store(Snapshot::from_rows(2, &[]));
    assert_eq!(
        live.level(&acct(1)),
        Level::Free,
        "a revocation applies at the next reload"
    );
}

#[test]
fn days_are_utc() {
    assert_eq!(day_of(UNIX_EPOCH), 0);
    assert_eq!(day_of(UNIX_EPOCH + Duration::from_secs(86_399)), 0);
    assert_eq!(day_of(UNIX_EPOCH + Duration::from_hours(24)), 1);
    assert_eq!(end_of_day(0), 86_400);
    assert_eq!(Level::parse("plus"), Some(Level::Plus));
    assert_eq!(Level::parse("Plus"), None);
    assert_eq!(Level::from_u8(Level::Plus.as_u8()), Some(Level::Plus));
}

fn limits() -> impl Strategy<Value = Limits> {
    (
        bounds::LINKED_DEVICES,
        bounds::FILE_BYTES,
        bounds::UPLOAD_BYTES_PER_DAY,
        bounds::VAULT_BYTES,
        bounds::VAULT_CHUNKS,
        bounds::PACKS_PER_MONTH,
    )
        .prop_map(|(a, b, c, d, e, f)| Limits {
            linked_devices: a,
            file_bytes: b,
            upload_bytes_per_day: c,
            vault_bytes: d,
            vault_chunks: e,
            packs_per_month: f,
        })
}

proptest! {
    #[test]
    fn validation_accepts_exactly_the_monotone_catalogues(free in limits(), plus in limits()) {
        let mut c = Catalog::default();
        c.free.limits = free;
        c.plus.limits = plus;
        let monotone = free.le(&plus);
        prop_assert_eq!(c.validate().is_ok(), monotone);
        if monotone {
            // The ceiling is the highest level's limits, and every level is under it.
            prop_assert_eq!(c.ceiling(), plus);
            for l in Level::ALL {
                prop_assert!(c.limits(l).le(&c.ceiling()));
            }
        }
    }

    #[test]
    fn a_level_is_held_exactly_through_its_last_day(last in 0u32..100_000, today in 0u32..100_000) {
        let s = Snapshot::from_rows(1, &[row(1, 1, last)]);
        prop_assert_eq!(s.level(&acct(1), today) == Level::Plus, today <= last);
    }
}

#[test]
fn standings_hold_through_their_day_and_moderators_have_no_end() {
    let s = Snapshot::from_rows(1, &[]).with_standings([
        (acct(1), Standing::Limited, Some(100)),
        (acct(2), Standing::Suspended, None),
        (acct(3), Standing::Good, None),
    ]);
    assert_eq!(s.standing(&acct(1), 100), Standing::Limited);
    assert_eq!(s.standing(&acct(1), 101), Standing::Good);
    assert_eq!(s.standing(&acct(2), u32::MAX), Standing::Suspended);
    assert_eq!(s.standing(&acct(3), 0), Standing::Good);
    assert_eq!(s.standing(&acct(4), 0), Standing::Good);
    assert_eq!(Standing::parse("suspended"), Some(Standing::Suspended));
    assert_eq!(Standing::parse("good"), None);
}
