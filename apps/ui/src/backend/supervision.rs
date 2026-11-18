//! Parental supervision, the apps' side (Prompt 9, M6; PROTOCOL §10.6,
//! D-0105).
//!
//! - **The parent's device** makes a fresh Ed25519 policy key for this
//!   child (never linked to the parent's account) and a 32-byte link
//!   secret, kept only on this device, and shows both as a QR code. Both
//!   screens show the same six-digit [`code`]. Rules become a signed
//!   [`Policy`]: what the server enforces as flags, the rest
//!   ([`ClientRules`]) encrypted under the link secret.
//! - **The child's primary** uploads the first policy (`PUT
//!   /v1/supervision`); later ones (rule changes, unlinking) come from the
//!   parent's device, authorized by the parent's signature alone.
//! - **The child's device** reads the policy in force (`GET
//!   /v1/supervision`), checks the signature against the key it scanned,
//!   opens the client rules and shows every rule, and the date supervision
//!   ends by itself, computed on the child's device from the age the child
//!   entered and the country's age of digital consent. The birth date never
//!   leaves the device.
//!
//! The parent never sees messages, calls or contacts: a policy is the only
//! thing the parent writes.

use nsh_core::storage::Storage;
use serde_json::{Value, json};
use songbird_content::supervision::{
    ClientRules, PolicyKey, consent_age, link_code, open_rules, seal_rules, unlink_at,
};
use songbird_proto::supervision::{GROUP_APPROVAL, HIDDEN, NO_REQUESTS, Policy, UNLINK};
use songbird_types::AccountId;

use super::{Problem, wire};
use crate::store::{ChildContact, ParentalRules};

const K_PARENT: &str = "sb.supervision_parent";
const K_CHILD: &str = "sb.supervision_child";

/// The parent's side of one link (device-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentLink {
    pub seed: [u8; 32],
    pub secret: [u8; 32],
    pub child: [u8; 16],
    /// The last policy version signed.
    pub version: u64,
    /// When supervision ends by itself (seconds), from the child's age.
    pub unlink_at_s: u64,
}

/// The child's side: the key and secret scanned from the parent's code,
/// and the age they entered (device-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildLink {
    pub policy_key: [u8; 32],
    pub secret: [u8; 32],
    pub birth_year: i32,
    pub birth_month: u32,
    pub country: String,
}

fn arr<const N: usize>(v: &Value) -> Option<[u8; N]> {
    wire::unhex(v.as_str()?)?.try_into().ok()
}

fn put(key: &str, v: &Value) {
    if let Err(e) = Storage::set_item(key, v.to_string()) {
        log::warn!("supervision storage: {e}");
    }
}

pub fn parent_link() -> Option<ParentLink> {
    let v: Value = serde_json::from_str(&Storage::get_item(K_PARENT)?).ok()?;
    Some(ParentLink {
        seed: arr(&v["seed"])?,
        secret: arr(&v["secret"])?,
        child: arr(&v["child"])?,
        version: v["version"].as_u64()?,
        unlink_at_s: v["unlink_at_s"].as_u64().unwrap_or(0),
    })
}

/// Saves the parent's side (a changed unlink date before the first policy).
pub fn save_parent_link(l: &ParentLink) {
    save_parent(l);
}

fn save_parent(l: &ParentLink) {
    put(
        K_PARENT,
        &json!({
            "seed": wire::hex(&l.seed),
            "secret": wire::hex(&l.secret),
            "child": wire::hex(&l.child),
            "version": l.version,
            "unlink_at_s": l.unlink_at_s,
        }),
    );
}

/// A fresh policy key and link secret for `child`, saved on this device.
pub fn start_link(child: [u8; 16], unlink_at_s: u64) -> ParentLink {
    let l = ParentLink {
        seed: wire::random(),
        secret: wire::random(),
        child,
        version: 0,
        unlink_at_s,
    };
    save_parent(&l);
    l
}

/// Forgets the link on the parent's device (after unlinking).
pub fn forget_parent() {
    Storage::remove_item(K_PARENT);
}

pub fn child_link() -> Option<ChildLink> {
    let v: Value = serde_json::from_str(&Storage::get_item(K_CHILD)?).ok()?;
    Some(ChildLink {
        policy_key: arr(&v["policy_key"])?,
        secret: arr(&v["secret"])?,
        birth_year: i32::try_from(v["birth_year"].as_i64()?).ok()?,
        birth_month: u32::try_from(v["birth_month"].as_u64()?).ok()?,
        country: v["country"].as_str()?.to_string(),
    })
}

pub fn save_child(l: &ChildLink) {
    put(
        K_CHILD,
        &json!({
            "policy_key": wire::hex(&l.policy_key),
            "secret": wire::hex(&l.secret),
            "birth_year": l.birth_year,
            "birth_month": l.birth_month,
            "country": l.country,
        }),
    );
}

/// The policy's public key.
pub fn public(l: &ParentLink) -> Option<[u8; 32]> {
    PolicyKey::from_seed(&l.seed).ok().map(|k| k.public())
}

/// What the parent's QR code holds: the policy key and the link secret.
/// mock: the QR drawing is a stand-in (`ui::qr_code`), and the child
/// scans it with a camera the host projects add.
pub fn qr_payload(l: &ParentLink) -> String {
    format!(
        "songbird://supervise#{}.{}",
        wire::hex(&public(l).unwrap_or_default()),
        wire::hex(&l.secret)
    )
}

/// The six digits both screens show.
pub fn code(l: &ParentLink) -> String {
    link_code(&public(l).unwrap_or_default(), &l.secret, &l.child)
}

// ---------------------------------------------------------------- the dates

/// (year, month) of a day count since 1970-01-01 (Howard Hinnant's).
fn civil(days: i64) -> (i32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y as i32, m as u32)
}

/// The birth year and month for a child who is `age` now (the month they
/// enter it counts as their birthday, so the date is never later than the
/// real one).
pub fn born(age: u8, now_ms: u64) -> (i32, u32) {
    let (y, m) = civil((now_ms / 86_400_000) as i64);
    (y - i32::from(age), m)
}

/// When supervision ends for a child born then, in `country`.
pub fn ends(birth_year: i32, birth_month: u32, country: &str) -> Option<u64> {
    unlink_at(birth_year, birth_month, consent_age(country))
}

/// "1 March 2031".
pub fn date_label(at_s: u64) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let days = (at_s / 86_400) as i64;
    let (y, m) = civil(days);
    let first = first_of_month(y, m);
    let d = days - first + 1;
    format!("{d} {} {y}", MONTHS[(m as usize).saturating_sub(1) % 12])
}

fn first_of_month(y: i32, m: u32) -> i64 {
    // Days from the epoch to the 1st (the inverse of `civil` on day one).
    let y = i64::from(if m <= 2 { y - 1 } else { y });
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------- the policy

/// "21:00–07:00" as minutes after midnight.
fn quiet(q: Option<&str>) -> (u32, u32) {
    let parse = |t: &str| -> Option<u32> {
        let (h, m) = t.trim().split_once(':')?;
        Some(h.parse::<u32>().ok()? * 60 + m.parse::<u32>().ok()?)
    };
    q.and_then(|q| {
        let (a, b) = q.split_once('–').or_else(|| q.split_once('-'))?;
        Some((parse(a)?, parse(b)?))
    })
    .unwrap_or((0, 0))
}

/// The flags the server enforces for these rules.
pub fn flags(r: &ParentalRules) -> u8 {
    let mut f = 0;
    if r.who_can_message == ChildContact::ApprovedOnly {
        f |= NO_REQUESTS;
    }
    if r.groups_need_approval {
        f |= GROUP_APPROVAL;
    }
    if !r.discoverable {
        f |= HIDDEN;
    }
    f
}

/// The rules only the apps enforce.
pub fn client_rules(r: &ParentalRules) -> ClientRules {
    let (from, to) = quiet(r.quiet_hours);
    ClientRules {
        approved_contacts_only: r.who_can_message == ChildContact::ApprovedOnly,
        block_unknown_calls: r.block_unknown_calls,
        nudges_off: !r.nudges,
        quiet_from_min: from,
        quiet_to_min: to,
    }
}

/// The policy `version` for these rules (or the unlinking one), signed by
/// the parent's key.
pub fn sign_policy(
    l: &ParentLink,
    r: &ParentalRules,
    unlink: bool,
    version: u64,
) -> Option<Policy> {
    let key = PolicyKey::from_seed(&l.seed).ok()?;
    let mut p = Policy {
        child: AccountId::from_bytes(l.child),
        policy_key: key.public(),
        policy_version: version,
        flags: flags(r) | if unlink { UNLINK } else { 0 },
        unlink_at_s: l.unlink_at_s,
        client_rules: seal_rules(&l.secret, &l.child, version, &client_rules(r)).ok()?,
        signature: [0; 64],
    };
    key.sign(&mut p);
    Some(p)
}

/// The next policy for these rules (or the unlinking one). Advances the
/// saved version.
pub fn next_policy(l: &mut ParentLink, r: &ParentalRules, unlink: bool) -> Option<Policy> {
    let p = sign_policy(l, r, unlink, l.version + 1)?;
    l.version = p.policy_version;
    save_parent(l);
    Some(p)
}

/// Whether `p` is signed by the key it names, and that key is the one this
/// device scanned (when it has one).
pub fn verify(p: &Policy, scanned: Option<&[u8; 32]>) -> bool {
    scanned.is_none_or(|k| *k == p.policy_key)
        && songbird_keys::ed25519_verify(&p.policy_key, &p.signed_bytes(), &p.signature)
}

/// Every rule a verified policy puts in force, in plain words.
pub fn rules_in_force(p: &Policy, secret: Option<&[u8; 32]>) -> Vec<String> {
    let mut out = Vec::new();
    if p.flags & UNLINK != 0 {
        out.push("Supervision has ended. The settings stay for you to change.".into());
        return out;
    }
    if p.flags & NO_REQUESTS != 0 {
        out.push("Only people you know can message you: no message requests".into());
    }
    if p.flags & GROUP_APPROVAL != 0 {
        out.push("Group invites need your parent's approval".into());
    }
    if p.flags & HIDDEN != 0 {
        out.push("People can't find you by username".into());
    }
    let child = *p.child.as_bytes();
    match secret.and_then(|s| open_rules(s, &child, p.policy_version, &p.client_rules).ok()) {
        Some(c) => {
            if c.approved_contacts_only {
                out.push("Each new contact needs your parent's approval".into());
            }
            if c.block_unknown_calls {
                out.push("Calls only from your contacts".into());
            }
            if c.nudges_off {
                out.push("Nudges are off".into());
            }
            if c.quiet_from_min != c.quiet_to_min {
                let t = |m: u32| format!("{:02}:{:02}", m / 60, m % 60);
                out.push(format!(
                    "Quiet hours {}–{}: no notifications",
                    t(c.quiet_from_min),
                    t(c.quiet_to_min)
                ));
            }
        }
        None if !p.client_rules.is_empty() => {
            out.push("Some rules couldn't be read on this device.".into());
        }
        None => {}
    }
    if p.unlink_at_s > 0 {
        out.push(format!(
            "Supervision ends by itself on {}",
            date_label(p.unlink_at_s)
        ));
    }
    out
}

// ---------------------------------------------------------------- the server

/// `PUT /v1/supervision`: the first policy (from the child's primary) or a
/// later one (from any signed device; the parent's signature authorizes it).
pub async fn upload(p: &Policy) -> Result<(), Problem> {
    let (status, body) = super::signed("PUT", "/v1/supervision", Some(p.encode()), false).await?;
    match status {
        200..=299 => Ok(()),
        409 => Err(Problem(
            "A newer set of rules is already in force. Open the rules again.".into(),
        )),
        403 if body.windows(9).any(|w| w == b"signature") => Err(Problem(
            "The rules' signature didn't check out, so they weren't changed.".into(),
        )),
        _ => Err(super::explain(status, &body)),
    }
}

/// `GET /v1/supervision`: the policy in force (`None`: not supervised).
pub async fn fetch() -> Result<Option<Policy>, Problem> {
    let (status, body) = super::signed("GET", "/v1/supervision", None, false).await?;
    match status {
        404 => Ok(None),
        200 => Policy::decode(&body)
            .map(Some)
            .map_err(|_| Problem("The server's copy of the rules is damaged.".into())),
        _ => Err(super::explain(status, &body)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> ParentalRules {
        ParentalRules::default()
    }

    fn link() -> ParentLink {
        ParentLink {
            seed: [3; 32],
            secret: [4; 32],
            child: [5; 16],
            version: 0,
            unlink_at_s: ends(2014, 6, "RO").unwrap_or(0),
        }
    }

    /// `next_policy` without the device storage it saves to.
    fn sign(l: &mut ParentLink, r: &ParentalRules, unlink: bool) -> Policy {
        l.version += 1;
        sign_policy(l, r, unlink, l.version).expect("signed")
    }

    #[test]
    fn rules_become_server_flags_and_sealed_client_rules() {
        let mut r = rules();
        assert_eq!(flags(&r), NO_REQUESTS | GROUP_APPROVAL | HIDDEN);
        r.who_can_message = ChildContact::ContactsAndRequests;
        r.groups_need_approval = false;
        r.discoverable = true;
        assert_eq!(flags(&r), 0);
        let c = client_rules(&rules());
        assert_eq!((c.quiet_from_min, c.quiet_to_min), (21 * 60, 7 * 60));
        assert!(c.nudges_off && c.block_unknown_calls && c.approved_contacts_only);
    }

    #[test]
    fn the_child_verifies_and_lists_every_rule() {
        let mut l = link();
        let p = sign(&mut l, &rules(), false);
        let decoded = Policy::decode(&p.encode()).expect("decodes");
        let key = public(&l).expect("public");
        assert!(verify(&decoded, Some(&key)));
        // A key the child didn't scan, or a changed byte, fails.
        assert!(!verify(&decoded, Some(&[0; 32])));
        let mut bad = decoded.clone();
        bad.flags ^= HIDDEN;
        assert!(!verify(&bad, None));
        let shown = rules_in_force(&decoded, Some(&l.secret));
        assert_eq!(shown.len(), 8, "{shown:?}");
        assert!(shown.iter().any(|r| r.contains("Quiet hours 21:00–07:00")));
        assert!(
            shown
                .iter()
                .any(|r| r.starts_with("Supervision ends by itself on 1 July 2030"))
        );
        // Without the link secret the client rules are not readable.
        assert!(
            rules_in_force(&decoded, Some(&[9; 32]))
                .iter()
                .any(|r| r.contains("couldn't be read"))
        );
    }

    #[test]
    fn unlinking_is_a_newer_signed_policy() {
        let mut l = link();
        let first = sign(&mut l, &rules(), false);
        let last = sign(&mut l, &rules(), true);
        assert!(last.policy_version > first.policy_version);
        assert!(verify(&last, None));
        assert_eq!(rules_in_force(&last, Some(&l.secret)).len(), 1);
    }

    #[test]
    fn the_link_code_matches_on_both_sides() {
        let l = link();
        let key = public(&l).expect("public");
        assert_eq!(code(&l), link_code(&key, &l.secret, &l.child));
        assert_eq!(code(&l).len(), 6);
        assert!(qr_payload(&l).contains(&wire::hex(&l.secret)));
    }

    #[test]
    fn dates() {
        // 2026-11-18 is 20,775 days after the epoch.
        assert_eq!(civil(20_775), (2026, 11));
        assert_eq!(born(12, 20_775 * 86_400_000), (2014, 11));
        // Romania's age of consent is 16: the first of the month after.
        assert_eq!(
            date_label(ends(2014, 6, "RO").expect("date")),
            "1 July 2030"
        );
        assert_eq!(
            date_label(ends(2014, 12, "DE").expect("date")),
            "1 January 2031"
        );
    }
}
