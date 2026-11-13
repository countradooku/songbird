//! The deletion journal (D-0041): a deleted account must stay deleted after a restore.
//!
//! Before deleting anything, the worker writes a **tombstone** to the off-site backup bucket: an
//! empty, write-once object named `deletions/<YYYYMMDDTHHMMSSZ>-<tag>`, where `tag` is
//! HMAC-SHA256(journal key, account ID). After restoring a backup, `songbird-admin backup
//! restore` lists the tombstones stored since that backup and starts the deletion again for
//! every restored account whose tag matches.
//!
//! The tombstone holds no account ID: without the journal key a reader of the bucket learns only
//! that some account was deleted at some time. It is locked (compliance mode) for
//! [`RETENTION`], longer than any backup that can still contain the account.

use std::time::Duration;

use aws_lc_rs::hmac;
use songbird_types::AccountId;

/// Key prefix of tombstones in the backup bucket.
pub const PREFIX: &str = "deletions/";

/// How long a tombstone is locked: the longest backup retention (93 days, monthly tier).
pub const RETENTION: Duration = Duration::from_hours(93 * 24);

/// An account's tag: HMAC-SHA256 under the journal key.
#[must_use]
pub fn tag(key: &[u8; 32], account: &AccountId) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(b"songbird deletion journal v1");
    ctx.update(account.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// A tombstone's object name; `stamp` is `YYYYMMDDTHHMMSSZ` (the time it is written).
#[must_use]
pub fn tombstone_name(stamp: &str, tag: &[u8; 32]) -> String {
    let mut name = String::with_capacity(PREFIX.len() + stamp.len() + 1 + 64);
    name.push_str(PREFIX);
    name.push_str(stamp);
    name.push('-');
    for b in tag {
        name.push(nibble(b >> 4));
        name.push(nibble(b & 0xf));
    }
    name
}

fn nibble(n: u8) -> char {
    char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
}

/// The tag of a tombstone's object name, or `None` for anything else.
#[must_use]
pub fn parse_tombstone(name: &str) -> Option<[u8; 32]> {
    let rest = name.strip_prefix(PREFIX)?;
    let (stamp, hex) = rest.split_once('-')?;
    if stamp.len() != 16 || hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (o, [hi, lo]) in out.iter_mut().zip(pairs) {
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        *o = (nib(*hi)? << 4) | nib(*lo)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tombstones_name_a_tag_and_parse_back() {
        let a = AccountId::from_bytes([1; 16]);
        let t = tag(&[7; 32], &a);
        assert_ne!(t, tag(&[8; 32], &a), "the key matters");
        assert_ne!(t, tag(&[7; 32], &AccountId::from_bytes([2; 16])));
        let n = tombstone_name("20261113T120000Z", &t);
        assert!(n.starts_with("deletions/20261113T120000Z-"));
        assert_eq!(parse_tombstone(&n), Some(t));
        // No account ID in the name, raw or hex.
        assert!(!n.contains(&"01".repeat(16)));
        for bad in [
            "registry/x",
            "deletions/20261113T120000Z",
            "deletions/20261113T120000Z-zz",
            &n.to_uppercase(),
        ] {
            assert_eq!(parse_tombstone(bad), None, "{bad}");
        }
    }
}
