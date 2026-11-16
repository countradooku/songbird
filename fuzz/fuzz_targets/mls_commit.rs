//! Commit bundles against a real group (Prompt 5, `songbird-groups::Group::apply_commit`): a
//! two-member post-quantum group built once by the client harness; arbitrary bundles from either
//! member never panic, and stored records that fail to decode are refused, not trusted.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use songbird_groups::{Group, Limits, Record};
use songbird_groups_harness::{Device, Dir, id_from, server_create, welcome_of};
use songbird_types::AccountId;

struct Fixture {
    record: Record,
    dir: Dir,
    senders: [songbird_types::DeviceId; 2],
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let mut dir = Dir::default();
        let mut a = Device::new(1, AccountId::from_bytes(id_from(1, 0xA0)), &mut dir);
        let mut b = Device::new(2, AccountId::from_bytes(id_from(2, 0xA0)), &mut dir);
        let g = server_create(&mut a, &dir);
        let bundle = a.add(&[b.key_package()]);
        let (g, _) = g
            .apply_commit(&a.id, &bundle, &dir, &Limits::default())
            .unwrap();
        b.join(&welcome_of(&bundle), &g.ratchet_tree().unwrap());
        Fixture {
            record: g.record(),
            senders: [a.id, b.id],
            dir,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&who, rest)) = data.split_first() else {
        return;
    };
    let sender = &f.senders[usize::from(who & 1)];
    let g = Group::load(f.record.clone()).unwrap();
    if let Ok((g, _)) = g.apply_commit(sender, rest, &f.dir, &Limits::default()) {
        // Only a real member's validly signed commit can get here.
        assert_eq!(g.epoch(), f.record.epoch + 1);
    }
    if let Ok(r) = Record::decode(rest) {
        let _ = Group::load(r);
    }
});
