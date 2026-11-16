//! Roles and permissions (Prompt 5, M2; D-0070): the group-context extension every client verifies
//! and the server mirrors.
//!
//! The extension (`ROLES_EXTENSION`, MLS private-use type `0xF5B0`) holds the group's policy and
//! the roles that differ from the default:
//!
//! ```text
//! version u8 (1) | send u8 | add u8 | edit_info u8 | links u8 | call u8 | default_role u8 |
//! flags u8 | n u16 | n × (account [16] | role u8)      accounts strictly ascending
//! ```
//!
//! Roles are per account (a person), not per device: every device of an account has its
//! account's role. An account the list does not name has `default_role`. That is `Member` in a
//! group and `ReadOnly` in a channel, so adding someone never needs a role entry, and external
//! commits (which may not change extensions, RFC 9420 §12.4.3.2) still work.
//!
//! [`authorize`] is the whole permission matrix for what a commit changes. The server runs it
//! before merging (refusing the commit) and every client runs it before accepting one. The
//! cells a commit cannot carry are pure functions here as well:
//! - sending is checked on the send path, from the roster;
//! - pinning and deleting others' messages are checked by clients only, inside the ciphertext
//!   (D-0065 §6);
//! - starting a call is checked when Prompt 7 issues call tokens.

use std::collections::{BTreeMap, BTreeSet};

use songbird_types::AccountId;

/// The extension's type: MLS private use (RFC 9420 §17.3, `0xF000`–`0xFFFF`).
pub const ROLES_EXTENSION: u16 = 0xF5B0;
/// The encoding without invite-link keys.
pub const ROLES_V1: u8 = 1;
/// The encoding with invite-link keys (D-0076).
pub const ROLES_V2: u8 = 2;
/// Most explicit role entries (a group's 1,024 leaves are at most 1,024 accounts).
pub const MAX_ENTRIES: usize = 1_024;

/// A role, in ascending order of power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Role {
    /// Reads only (a channel's subscribers).
    ReadOnly = 0,
    Member = 1,
    Moderator = 2,
    Admin = 3,
    Owner = 4,
}

impl Role {
    /// From its byte.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::ReadOnly),
            1 => Some(Self::Member),
            2 => Some(Self::Moderator),
            3 => Some(Self::Admin),
            4 => Some(Self::Owner),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ReadOnly => 0,
            Self::Member => 1,
            Self::Moderator => 2,
            Self::Admin => 3,
            Self::Owner => 4,
        }
    }
}

/// The group's policy: the least role for each action the matrix leaves to the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Send messages ("only admins can send": `Admin`).
    pub send: Role,
    /// Add another person.
    pub add: Role,
    /// Edit the group's info (the encrypted metadata) ("only admins can edit group info").
    pub edit_info: Role,
    /// Manage invite links (join requests are the `add` role's: approving one is adding).
    pub links: Role,
    /// Start a group call (Prompt 7).
    pub call: Role,
    /// The role of an account the list does not name.
    pub default_role: Role,
    /// [`FLAG_CHANNEL`] and others.
    pub flags: u8,
}

/// The group is a channel (Prompt 5, M4): admins post, subscribers read.
pub const FLAG_CHANNEL: u8 = 0x01;
/// Joining requires an admin's approval, even with a link (M3).
pub const FLAG_APPROVAL: u8 = 0x02;
const KNOWN_FLAGS: u8 = FLAG_CHANNEL | FLAG_APPROVAL;

impl Policy {
    /// A group: everyone may send, add, edit the info and call; admins manage links.
    pub const GROUP: Self = Self {
        send: Role::Member,
        add: Role::Member,
        edit_info: Role::Member,
        links: Role::Admin,
        call: Role::Member,
        default_role: Role::Member,
        flags: 0,
    };

    /// A channel: admins post, add, edit and manage links; subscribers read only.
    pub const CHANNEL: Self = Self {
        send: Role::Admin,
        add: Role::Admin,
        edit_info: Role::Admin,
        links: Role::Admin,
        call: Role::Admin,
        default_role: Role::ReadOnly,
        flags: FLAG_CHANNEL,
    };

    #[must_use]
    pub const fn is_channel(&self) -> bool {
        self.flags & FLAG_CHANNEL != 0
    }

    /// The bytes the registry keeps for the send path and `api` (the policy part of the
    /// extension).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 7] {
        [
            self.send.as_u8(),
            self.add.as_u8(),
            self.edit_info.as_u8(),
            self.links.as_u8(),
            self.call.as_u8(),
            self.default_role.as_u8(),
            self.flags,
        ]
    }

    /// Parses [`Policy::to_bytes`].
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 7]) -> Option<Self> {
        let [send, add, edit_info, links, call, default_role, flags] = *bytes;
        if flags & !KNOWN_FLAGS != 0 {
            return None;
        }
        Some(Self {
            send: Role::from_u8(send)?,
            add: Role::from_u8(add)?,
            edit_info: Role::from_u8(edit_info)?,
            links: Role::from_u8(links)?,
            call: Role::from_u8(call)?,
            default_role: Role::from_u8(default_role)?,
            flags,
        })
    }
}

/// The roles extension's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roles {
    pub policy: Policy,
    /// Accounts whose role is not the default.
    pub explicit: BTreeMap<AccountId, Role>,
    /// Invite links' proof keys (D-0076): handle → Ed25519 public key. A join by a link carries
    /// a proof under that link's key (`crate::links`). Changed only by the `links` role.
    pub links: BTreeMap<[u8; 16], [u8; 32]>,
}

/// Why roles or a change to them were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    #[error("malformed roles extension")]
    Malformed,
    #[error("the actor's role does not allow this")]
    Role,
    #[error("a group must keep an owner")]
    NoOwner,
    #[error("a role entry names an account that is not in the group")]
    Stale,
    #[error("the actor is not in the group")]
    NotMember,
    /// A server (external sender) proposal removes a device its account still lists (D-0075).
    #[error("a server proposal removes a device that is still listed")]
    Listed,
}

impl Roles {
    /// A new group's roles: `owner` is the only owner, with the policy given.
    #[must_use]
    pub fn new(owner: AccountId, policy: Policy) -> Self {
        Self {
            policy,
            explicit: BTreeMap::from([(owner, Role::Owner)]),
            links: BTreeMap::new(),
        }
    }

    /// The role of `account` (members not named have the default).
    #[must_use]
    pub fn role(&self, account: &AccountId) -> Role {
        self.explicit
            .get(account)
            .copied()
            .unwrap_or(self.policy.default_role)
    }

    /// The extension's bytes: version 1 without link keys, version 2 (the same, then the link
    /// keys) with them, so each value has one encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(11 + self.explicit.len() * 17 + self.links.len() * 48);
        out.push(if self.links.is_empty() {
            ROLES_V1
        } else {
            ROLES_V2
        });
        out.extend_from_slice(&self.policy.to_bytes());
        out.extend_from_slice(
            &u16::try_from(self.explicit.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        for (a, r) in &self.explicit {
            out.extend_from_slice(a.as_bytes());
            out.push(r.as_u8());
        }
        if !self.links.is_empty() {
            out.push(u8::try_from(self.links.len()).unwrap_or(u8::MAX));
            for (handle, key) in &self.links {
                out.extend_from_slice(handle);
                out.extend_from_slice(key);
            }
        }
        out
    }

    /// Parses the extension: one encoding only (ascending accounts, no default-role entries,
    /// in version 2 one to [`crate::links::MAX_LINK_KEYS`] link keys by ascending handle, no
    /// trailing bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self, Denied> {
        let (head, rest) = bytes.split_at_checked(10).ok_or(Denied::Malformed)?;
        let [version, policy @ .., count_hi, count_lo] = head else {
            return Err(Denied::Malformed);
        };
        if *version != ROLES_V1 && *version != ROLES_V2 {
            return Err(Denied::Malformed);
        }
        let policy: [u8; 7] = policy.try_into().map_err(|_| Denied::Malformed)?;
        let policy = Policy::from_bytes(&policy).ok_or(Denied::Malformed)?;
        let count = usize::from(u16::from_be_bytes([*count_hi, *count_lo]));
        if count > MAX_ENTRIES {
            return Err(Denied::Malformed);
        }
        let (rest, link_part) = rest.split_at_checked(count * 17).ok_or(Denied::Malformed)?;
        let links = if *version == ROLES_V2 {
            decode_links(link_part)?
        } else if link_part.is_empty() {
            BTreeMap::new()
        } else {
            return Err(Denied::Malformed);
        };
        let (entries, tail) = rest.as_chunks::<17>();
        if entries.len() != count || !tail.is_empty() {
            return Err(Denied::Malformed);
        }
        let mut explicit = BTreeMap::new();
        let mut previous: Option<AccountId> = None;
        for entry in entries {
            let (account, role) = entry.split_at(16);
            let account = AccountId::from_slice(account).map_err(|_| Denied::Malformed)?;
            let role = role
                .first()
                .copied()
                .and_then(Role::from_u8)
                .ok_or(Denied::Malformed)?;
            if previous.is_some_and(|p| p >= account) || role == policy.default_role {
                return Err(Denied::Malformed);
            }
            previous = Some(account);
            explicit.insert(account, role);
        }
        Ok(Self {
            policy,
            explicit,
            links,
        })
    }

    fn owners(&self, present: &BTreeSet<AccountId>) -> usize {
        present
            .iter()
            .filter(|a| self.role(a) == Role::Owner)
            .count()
    }
}

/// Version 2's link keys: `m u8 | m × (handle [16] | key [32])`, 1 ≤ m ≤ 16, handles strictly
/// ascending, nothing after.
fn decode_links(b: &[u8]) -> Result<BTreeMap<[u8; 16], [u8; 32]>, Denied> {
    let (&m, rest) = b.split_first().ok_or(Denied::Malformed)?;
    let m = usize::from(m);
    let (keys, tail) = rest.as_chunks::<48>();
    if m == 0 || m > crate::links::MAX_LINK_KEYS || keys.len() != m || !tail.is_empty() {
        return Err(Denied::Malformed);
    }
    let mut out = BTreeMap::new();
    let mut previous: Option<[u8; 16]> = None;
    for k in keys {
        let (handle, key) = k.split_at(16);
        let handle: [u8; 16] = handle.try_into().map_err(|_| Denied::Malformed)?;
        let key: [u8; 32] = key.try_into().map_err(|_| Denied::Malformed)?;
        if previous.is_some_and(|p| p >= handle) {
            return Err(Denied::Malformed);
        }
        previous = Some(handle);
        out.insert(handle, key);
    }
    Ok(out)
}

/// What a commit changes, in accounts (the device-level checks are `ds`'s).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Change {
    /// Accounts in the group before the commit.
    pub before: BTreeSet<AccountId>,
    /// Accounts in the group after it.
    pub after: BTreeSet<AccountId>,
    /// Accounts that gained a device in this commit (new accounts and existing ones).
    pub gained: BTreeSet<AccountId>,
    /// Accounts that lost a device the committer removed, except dead devices (no longer
    /// listed).
    pub lost: BTreeSet<AccountId>,
    /// Accounts whose devices left by their own proposal (leaving the group): authorized by
    /// the leaver, not the committer.
    pub left: BTreeSet<AccountId>,
    /// Accounts with a device that a server proposal (the delivery service as an MLS external
    /// sender, D-0075) removes although the account still lists it. Any is refused: the server
    /// may only propose removing devices that left the directory.
    pub external: BTreeSet<AccountId>,
}

/// The permission matrix for a commit by `actor`, from roles `old` to roles `new`.
///
/// - **Add a person** (an account not in the group): the actor's role is at least `add`.
///   Adding a device to an account already in the group: any member who may send (`ReadOnly`
///   subscribers may add only their own devices).
/// - **Remove another person's device**: an admin or owner who outranks that person. Anyone may
///   remove their own account's devices (and leave), and anyone may remove a dead device
///   (`ds` leaves those out of `lost`).
/// - **Change the policy** ("only admins can send", "only admins can edit group info", approval,
///   link and call roles): `Admin` or above.
/// - **Change a person's role**: an admin who outranks both the person's old role and the new
///   one, or an owner (who may make other owners). Lowering one's own role is always allowed.
/// - Afterwards the group keeps at least one owner while it has members, and the list names
///   only accounts still in the group.
/// - **Server removals** (D-0075): a removal proposed by the delivery service (an MLS external
///   sender) is committed only for a device no longer in its account's signed device list. One
///   for a listed device refuses the whole commit, whoever commits it.
pub fn authorize(
    actor: &AccountId,
    old: &Roles,
    new: &Roles,
    change: &Change,
) -> Result<(), Denied> {
    if !change.before.contains(actor) {
        return Err(Denied::NotMember);
    }
    if !change.external.is_empty() {
        return Err(Denied::Listed);
    }
    let r = old.role(actor);

    for a in &change.gained {
        if a == actor {
            continue;
        }
        let need = if change.before.contains(a) {
            Role::Member
        } else {
            old.policy.add
        };
        if r < need {
            return Err(Denied::Role);
        }
    }
    for a in &change.lost {
        if a == actor {
            continue;
        }
        if r < Role::Admin || r <= old.role(a) {
            return Err(Denied::Role);
        }
    }
    if new.policy != old.policy && r < Role::Admin {
        return Err(Denied::Role);
    }
    // Invite links' proof keys (D-0076) are the `links` role's, as the links themselves are.
    if new.links != old.links && r < old.policy.links {
        return Err(Denied::Role);
    }
    // Succession: when no owner is left in the group (every owner left, or their devices are
    // gone), the committer names the next owner(s), from the highest role that remains.
    let succession = old.owners(&change.after) == 0;
    let heir_rank = change
        .after
        .iter()
        .map(|a| old.role(a))
        .max()
        .unwrap_or(Role::ReadOnly);
    // Whose role may change: the accounts named either side, and, when the default role
    // changes, everyone else too (each unnamed member's role moves with it).
    let mut accounts: BTreeSet<&AccountId> =
        old.explicit.keys().chain(new.explicit.keys()).collect();
    if old.policy.default_role != new.policy.default_role {
        accounts.extend(change.before.iter().chain(change.after.iter()));
    }
    for a in accounts {
        let (from, to) = (old.role(a), new.role(a));
        if from == to {
            continue;
        }
        // A departed account's entry may be dropped by whoever commits its departure.
        if !change.after.contains(a) && !new.explicit.contains_key(a) {
            continue;
        }
        let lowering_self = a == actor && to < from;
        let allowed = lowering_self
            || r == Role::Owner && from < Role::Owner
            || r >= Role::Admin && from < r && to < r
            || succession
                && to == Role::Owner
                && change.after.contains(a)
                && old.role(a) == heir_rank;
        if !allowed {
            return Err(Denied::Role);
        }
    }
    if !change.after.is_empty() && new.owners(&change.after) == 0 {
        return Err(Denied::NoOwner);
    }
    if new.explicit.keys().any(|a| !change.after.contains(a)) {
        return Err(Denied::Stale);
    }
    Ok(())
}

/// The cells no commit carries, as client and server rules.
impl Roles {
    /// Send a message (the send path checks it from the roster).
    #[must_use]
    pub fn may_send(&self, account: &AccountId) -> bool {
        self.role(account) >= self.policy.send
    }

    /// Edit the group's info (`api` checks it when the metadata is replaced).
    #[must_use]
    pub fn may_edit_info(&self, account: &AccountId) -> bool {
        self.role(account) >= self.policy.edit_info
    }

    /// Manage invite links (`api`, M3).
    #[must_use]
    pub fn may_manage_links(&self, account: &AccountId) -> bool {
        self.role(account) >= self.policy.links
    }

    /// Start a group call (Prompt 7's call tokens).
    #[must_use]
    pub fn may_start_call(&self, account: &AccountId) -> bool {
        self.role(account) >= self.policy.call
    }

    /// Pin a message: clients only (inside the ciphertext).
    #[must_use]
    pub fn may_pin(&self, account: &AccountId) -> bool {
        self.role(account) >= Role::Moderator
    }

    /// Delete another person's message for everyone: clients only.
    #[must_use]
    pub fn may_delete_others(&self, account: &AccountId) -> bool {
        self.role(account) >= Role::Moderator
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::many_single_char_names,
        reason = "tests: short names for roles and changes"
    )]
    use super::*;

    fn acc(n: u8) -> AccountId {
        AccountId::from_bytes([n; 16])
    }

    fn set(v: &[u8]) -> BTreeSet<AccountId> {
        v.iter().map(|n| acc(*n)).collect()
    }

    /// Owner 1, admin 2, moderator 3, members 4 and 5.
    fn roles() -> Roles {
        let mut r = Roles::new(acc(1), Policy::GROUP);
        r.explicit.insert(acc(2), Role::Admin);
        r.explicit.insert(acc(3), Role::Moderator);
        r
    }

    fn change() -> Change {
        Change {
            before: set(&[1, 2, 3, 4, 5]),
            after: set(&[1, 2, 3, 4, 5]),
            ..Change::default()
        }
    }

    #[test]
    fn the_extension_has_one_encoding() {
        let r = roles();
        assert_eq!(Roles::decode(&r.encode()), Ok(r.clone()));
        let mut b = r.encode();
        b.push(0);
        assert_eq!(Roles::decode(&b), Err(Denied::Malformed));
        // Entries out of order, or naming the default role, are refused.
        let mut swapped = r.encode();
        let (x, y) = (10..27, 27..44);
        let first: Vec<u8> = swapped[x.clone()].to_vec();
        let second: Vec<u8> = swapped[y.clone()].to_vec();
        swapped[x].copy_from_slice(&second);
        swapped[y].copy_from_slice(&first);
        assert_eq!(Roles::decode(&swapped), Err(Denied::Malformed));
        let mut d = Roles::new(acc(1), Policy::GROUP).encode();
        d.extend_from_slice(acc(9).as_bytes());
        d.push(Role::Member.as_u8());
        d[9] = 2;
        assert_eq!(Roles::decode(&d), Err(Denied::Malformed));
        for cut in 0..r.encode().len() {
            assert!(Roles::decode(&r.encode()[..cut]).is_err());
        }
        let mut bad_flag = r.encode();
        bad_flag[7] = 0x80;
        assert_eq!(Roles::decode(&bad_flag), Err(Denied::Malformed));
    }

    #[test]
    fn adding_people_follows_the_add_role() {
        let r = roles();
        let mut c = change();
        c.gained = set(&[9]);
        c.after.insert(acc(9));
        assert_eq!(
            authorize(&acc(4), &r, &r, &c),
            Ok(()),
            "members add by default"
        );
        let mut admins_only = r.clone();
        admins_only.policy.add = Role::Admin;
        assert_eq!(
            authorize(&acc(4), &admins_only, &admins_only, &c),
            Err(Denied::Role)
        );
        assert_eq!(
            authorize(&acc(3), &admins_only, &admins_only, &c),
            Err(Denied::Role)
        );
        assert_eq!(authorize(&acc(2), &admins_only, &admins_only, &c), Ok(()));
        // Anyone adds their own new device.
        let mut own = change();
        own.gained = set(&[4]);
        assert_eq!(authorize(&acc(4), &admins_only, &admins_only, &own), Ok(()));
    }

    #[test]
    fn removing_people_needs_an_outranking_admin() {
        let r = roles();
        // Removing someone also drops their role entry (else the commit is `Stale`).
        let rm = |r: &Roles, who: u8| {
            let mut c = change();
            c.lost = set(&[who]);
            c.after.remove(&acc(who));
            let mut n = r.clone();
            n.explicit.remove(&acc(who));
            (c, n)
        };
        let check = |r: &Roles, actor: u8, who: u8| {
            let (c, n) = rm(r, who);
            authorize(&acc(actor), r, &n, &c)
        };
        assert_eq!(check(&r, 4, 5), Err(Denied::Role), "member removes member");
        assert_eq!(
            check(&r, 3, 5),
            Err(Denied::Role),
            "moderator removes member"
        );
        assert_eq!(check(&r, 2, 5), Ok(()), "admin removes member");
        assert_eq!(check(&r, 2, 3), Ok(()), "admin removes moderator");
        let mut r2 = r.clone();
        r2.explicit.insert(acc(4), Role::Admin);
        assert_eq!(check(&r2, 2, 4), Err(Denied::Role), "admin removes admin");
        assert_eq!(check(&r, 1, 2), Ok(()), "owner removes admin");
        // Leaving: anyone removes their own devices.
        assert_eq!(check(&r, 5, 5), Ok(()));
        assert_eq!(check(&r, 3, 3), Ok(()), "a moderator leaves");
    }

    #[test]
    fn the_policy_is_the_admins() {
        let r = roles();
        let mut announce = r.clone();
        announce.policy.send = Role::Admin;
        let mut info = r.clone();
        info.policy.edit_info = Role::Admin;
        for new in [&announce, &info] {
            assert_eq!(authorize(&acc(4), &r, new, &change()), Err(Denied::Role));
            assert_eq!(authorize(&acc(3), &r, new, &change()), Err(Denied::Role));
            assert_eq!(authorize(&acc(2), &r, new, &change()), Ok(()));
        }
        assert!(!announce.may_send(&acc(4)) && announce.may_send(&acc(2)));
        assert!(!info.may_edit_info(&acc(3)) && info.may_edit_info(&acc(2)));
    }

    #[test]
    fn roles_change_only_downward_from_the_changer() {
        let r = roles();
        let promote = |who: u8, to: Role| {
            let mut n = r.clone();
            if to == Role::Member {
                n.explicit.remove(&acc(who));
            } else {
                n.explicit.insert(acc(who), to);
            }
            n
        };
        assert_eq!(
            authorize(&acc(4), &r, &promote(5, Role::Moderator), &change()),
            Err(Denied::Role)
        );
        assert_eq!(
            authorize(&acc(3), &r, &promote(5, Role::Moderator), &change()),
            Err(Denied::Role)
        );
        assert_eq!(
            authorize(&acc(2), &r, &promote(5, Role::Moderator), &change()),
            Ok(())
        );
        assert_eq!(
            authorize(&acc(2), &r, &promote(5, Role::Admin), &change()),
            Err(Denied::Role),
            "admins do not make admins"
        );
        assert_eq!(
            authorize(&acc(1), &r, &promote(5, Role::Admin), &change()),
            Ok(())
        );
        assert_eq!(
            authorize(&acc(1), &r, &promote(5, Role::Owner), &change()),
            Ok(()),
            "owners make owners"
        );
        assert_eq!(
            authorize(&acc(2), &r, &promote(1, Role::Member), &change()),
            Err(Denied::Role),
            "admin demotes owner"
        );
        assert_eq!(
            authorize(&acc(4), &r, &promote(4, Role::Admin), &change()),
            Err(Denied::Role),
            "self-promotion"
        );
        assert_eq!(
            authorize(&acc(3), &r, &promote(3, Role::Member), &change()),
            Ok(()),
            "stepping down"
        );
        // The last owner cannot step down or leave without another owner.
        assert_eq!(
            authorize(&acc(1), &r, &promote(1, Role::Admin), &change()),
            Err(Denied::NoOwner)
        );
        let mut leave = change();
        leave.lost = set(&[1]);
        leave.after.remove(&acc(1));
        let mut gone = r.clone();
        gone.explicit.remove(&acc(1));
        assert_eq!(authorize(&acc(1), &r, &gone, &leave), Err(Denied::NoOwner));
    }

    #[test]
    fn leaving_is_the_leavers_and_owners_have_successors() {
        let r = roles();
        // The admin leaves by its own proposal; a member commits it and drops the entry.
        let mut c = change();
        c.left = set(&[2]);
        c.after.remove(&acc(2));
        let mut n = r.clone();
        n.explicit.remove(&acc(2));
        assert_eq!(authorize(&acc(4), &r, &n, &c), Ok(()));
        // The owner leaves: the committing member names a successor; without one, refused.
        let mut c = change();
        c.left = set(&[1]);
        c.after.remove(&acc(1));
        let mut n = r.clone();
        n.explicit.remove(&acc(1));
        assert_eq!(authorize(&acc(4), &r, &n, &c), Err(Denied::NoOwner));
        // The heir comes from the highest role left (the admin), not whoever commits.
        let mut member_heir = n.clone();
        member_heir.explicit.insert(acc(5), Role::Owner);
        assert_eq!(authorize(&acc(4), &r, &member_heir, &c), Err(Denied::Role));
        n.explicit.insert(acc(2), Role::Owner);
        assert_eq!(authorize(&acc(4), &r, &n, &c), Ok(()));
        // No succession while an owner stays: a member still cannot make owners.
        let mut grab = r.clone();
        grab.explicit.insert(acc(5), Role::Owner);
        assert_eq!(authorize(&acc(4), &r, &grab, &change()), Err(Denied::Role));
    }

    #[test]
    fn a_vanished_owner_has_successors_too() {
        // The only owner's devices are gone (account deleted): neither side counts them, so the
        // group would otherwise be stuck. The entry is dropped and the admin succeeds.
        let r = roles();
        let mut c = change();
        c.before.remove(&acc(1));
        c.after.remove(&acc(1));
        let mut n = r.clone();
        n.explicit.remove(&acc(1));
        n.explicit.insert(acc(2), Role::Owner);
        assert_eq!(authorize(&acc(4), &r, &n, &c), Ok(()));
        let mut stuck = r.clone();
        stuck.explicit.remove(&acc(1));
        assert_eq!(authorize(&acc(4), &r, &stuck, &c), Err(Denied::NoOwner));
    }

    #[test]
    fn the_default_role_moves_everyone_it_names() {
        // Review finding (D-0074): changing the default role changes every unnamed member's
        // role, so each of them is checked as a role change.
        let r = roles();
        let mut up = r.clone();
        up.policy.default_role = Role::Owner;
        up.explicit.remove(&acc(1));
        assert_eq!(
            authorize(&acc(2), &r, &up, &change()),
            Err(Denied::Role),
            "an admin makes every member an owner"
        );
        // Lowering the default moves an unnamed owner too.
        let mut owners = r.clone();
        owners.policy.default_role = Role::Owner;
        owners.explicit.clear();
        owners.explicit.insert(acc(2), Role::Admin);
        let mut down = owners.clone();
        down.policy.default_role = Role::Member;
        down.explicit.insert(acc(3), Role::Owner);
        assert_eq!(
            authorize(&acc(2), &owners, &down, &change()),
            Err(Denied::Role),
            "an admin demotes the owners"
        );
        // An admin may make the default read-only (below its own role); an owner may do more.
        let mut quiet = r.clone();
        quiet.policy.default_role = Role::ReadOnly;
        assert_eq!(authorize(&acc(2), &r, &quiet, &change()), Ok(()));
        let mut mods = r.clone();
        mods.policy.default_role = Role::Moderator;
        mods.explicit.remove(&acc(3));
        assert_eq!(authorize(&acc(1), &r, &mods, &change()), Ok(()));
        assert_eq!(authorize(&acc(2), &r, &mods, &change()), Ok(()));
    }

    #[test]
    fn entries_follow_their_accounts_out() {
        let r = roles();
        let mut c = change();
        c.lost = set(&[3]);
        c.after.remove(&acc(3));
        assert_eq!(
            authorize(&acc(1), &r, &r, &c),
            Err(Denied::Stale),
            "the moderator entry stays"
        );
        let mut n = r.clone();
        n.explicit.remove(&acc(3));
        assert_eq!(authorize(&acc(1), &r, &n, &c), Ok(()));
        assert_eq!(authorize(&acc(9), &r, &n, &c), Err(Denied::NotMember));
    }

    #[test]
    fn link_keys_have_one_encoding_and_are_the_links_roles() {
        // D-0076: version 2 carries the link keys; without any it is version 1, byte for byte.
        let r = roles();
        let mut l = r.clone();
        l.links.insert([2; 16], [7; 32]);
        l.links.insert([1; 16], [8; 32]);
        let b = l.encode();
        assert_eq!(b.first(), Some(&ROLES_V2));
        assert_eq!(Roles::decode(&b), Ok(l.clone()));
        assert_eq!(r.encode().first(), Some(&ROLES_V1));
        for cut in 0..b.len() {
            assert!(Roles::decode(&b[..cut]).is_err(), "{cut}");
        }
        // Version 2 with no keys, version 1 with keys, handles out of order, too many keys.
        let mut empty = r.encode();
        empty[0] = ROLES_V2;
        empty.push(0);
        assert_eq!(Roles::decode(&empty), Err(Denied::Malformed));
        let mut v1 = b.clone();
        v1[0] = ROLES_V1;
        assert_eq!(Roles::decode(&v1), Err(Denied::Malformed));
        let mut swapped = b.clone();
        let at = b.len() - 96;
        swapped[at..at + 16].copy_from_slice(&[2; 16]);
        swapped[at + 48..at + 64].copy_from_slice(&[1; 16]);
        assert_eq!(Roles::decode(&swapped), Err(Denied::Malformed));
        let mut many = r.clone();
        for i in 0..17u8 {
            many.links.insert([i; 16], [i; 32]);
        }
        assert_eq!(Roles::decode(&many.encode()), Err(Denied::Malformed));

        // Publishing or withdrawing a key needs the `links` role (admins, by default).
        assert_eq!(authorize(&acc(4), &r, &l, &change()), Err(Denied::Role));
        assert_eq!(authorize(&acc(3), &r, &l, &change()), Err(Denied::Role));
        assert_eq!(authorize(&acc(2), &r, &l, &change()), Ok(()));
        assert_eq!(authorize(&acc(4), &l, &r, &change()), Err(Denied::Role));
        assert_eq!(authorize(&acc(1), &l, &r, &change()), Ok(()));
        let mut open = r.clone();
        open.policy.links = Role::Member;
        let mut open_l = l.clone();
        open_l.policy.links = Role::Member;
        assert_eq!(authorize(&acc(4), &open, &open_l, &change()), Ok(()));
    }

    #[test]
    fn server_removals_are_only_for_devices_that_left() {
        // D-0075: a server proposal removing a still-listed device refuses the commit, even an
        // owner's (`ds` and clients put such accounts in `external`).
        let r = roles();
        let mut c = change();
        c.external = set(&[5]);
        assert_eq!(authorize(&acc(1), &r, &r, &c), Err(Denied::Listed));
        assert_eq!(authorize(&acc(4), &r, &r, &c), Err(Denied::Listed));
        // A device that left the directory has no account here: removing it needs no role.
        let mut gone = change();
        gone.before.remove(&acc(5));
        gone.after.remove(&acc(5));
        assert_eq!(authorize(&acc(4), &r, &r, &gone), Ok(()));
    }

    #[test]
    fn the_client_only_cells() {
        let r = roles();
        assert!(!r.may_pin(&acc(4)) && r.may_pin(&acc(3)));
        assert!(!r.may_delete_others(&acc(4)) && r.may_delete_others(&acc(3)));
        let mut calls = r.clone();
        calls.policy.call = Role::Admin;
        assert!(!calls.may_start_call(&acc(3)) && calls.may_start_call(&acc(2)));
        assert!(!r.may_manage_links(&acc(3)) && r.may_manage_links(&acc(2)));
        let ch = Roles::new(acc(1), Policy::CHANNEL);
        assert_eq!(ch.role(&acc(7)), Role::ReadOnly);
        assert!(!ch.may_send(&acc(7)));
    }
}
