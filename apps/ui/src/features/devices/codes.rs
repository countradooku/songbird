//! What the camera may read (D-0110): the link code a new device shows (PROTOCOL §4.6), a
//! contact's safety-number code, and the two codes of parental linking (PROTOCOL §10.6, D-0107):
//! the parent's and the child's. Each has its own scheme, so a code made to look like one is
//! never taken for the other, and anything else the camera sees is ignored.
//!
//! Codes are upper case so QR codes hold them in alphanumeric mode (smaller codes; version 5
//! for a link code). Parsing ignores case and is otherwise strict.

/// The scheme of a link code: `SONGBIRD:LINK:<channel hex>:<provisioning key hex>`.
pub const LINK: &str = "SONGBIRD:LINK:";
/// The scheme of a safety-number code: `SONGBIRD:SAFETY:<digits>`.
pub const SAFETY: &str = "SONGBIRD:SAFETY:";
/// The parent's code: `SONGBIRD:SUPERVISE:<policy key hex>:<link secret hex>`.
pub const SUPERVISE: &str = "SONGBIRD:SUPERVISE:";
/// The child's code: `SONGBIRD:CHILD:<account hex>:<unlink date, seconds>:<channel hex>:<key hex>`.
pub const CHILD: &str = "SONGBIRD:CHILD:";
/// The longest channel ID a link code carries, in bytes (as the provisioning parser accepts).
pub const MAX_CHANNEL: usize = 64;

/// A code the camera read and the app understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scanned {
    /// A new device's link code: its channel and provisioning public key.
    Link {
        /// The provisioning channel ID.
        channel: Vec<u8>,
        /// The new device's X25519 provisioning public key.
        key: [u8; 32],
    },
    /// A contact's safety number, digits only.
    Safety(String),
    /// A parent's code: the policy key for this child and the link secret.
    Supervise {
        /// The parent's Ed25519 policy key.
        key: [u8; 32],
        /// The link secret the client rules are sealed under.
        secret: [u8; 32],
    },
    /// A child's code: their account, the date supervision ends (computed on their phone),
    /// and the provisioning channel and key the first policy is sealed to.
    Child {
        /// The child's account ID.
        account: [u8; 16],
        /// When supervision ends by itself (seconds since 1970).
        unlink_at_s: u64,
        /// The provisioning channel ID.
        channel: Vec<u8>,
        /// The child device's X25519 provisioning public key.
        key: [u8; 32],
    },
}

/// The link code a new device shows.
#[must_use]
pub fn link_code(channel: &[u8], key: &[u8; 32]) -> String {
    format!("{LINK}{}:{}", hex_upper(channel), hex_upper(key))
}

/// The code for a safety number (its digits; spaces and grouping dropped).
#[must_use]
pub fn safety_code(number: &str) -> String {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    format!("{SAFETY}{digits}")
}

/// The parent's code (parental linking).
#[must_use]
pub fn supervise_code(key: &[u8; 32], secret: &[u8; 32]) -> String {
    format!("{SUPERVISE}{}:{}", hex_upper(key), hex_upper(secret))
}

/// The child's code (parental linking).
#[must_use]
pub fn child_code(account: &[u8; 16], unlink_at_s: u64, channel: &[u8], key: &[u8; 32]) -> String {
    format!(
        "{CHILD}{}:{unlink_at_s}:{}:{}",
        hex_upper(account),
        hex_upper(channel),
        hex_upper(key)
    )
}

/// What `text` is, if it is a code the app understands.
#[must_use]
pub fn parse(text: &str) -> Option<Scanned> {
    let text = text.trim();
    if let Some(rest) = strip_prefix_ignore_case(text, LINK) {
        let (channel, key) = rest.split_once(':')?;
        let channel = unhex(channel).filter(|c| !c.is_empty() && c.len() <= MAX_CHANNEL)?;
        let key: [u8; 32] = unhex(key)?.try_into().ok()?;
        return Some(Scanned::Link { channel, key });
    }
    if let Some(rest) = strip_prefix_ignore_case(text, SUPERVISE) {
        let (key, secret) = rest.split_once(':')?;
        let key: [u8; 32] = unhex(key)?.try_into().ok()?;
        let secret: [u8; 32] = unhex(secret)?.try_into().ok()?;
        return Some(Scanned::Supervise { key, secret });
    }
    if let Some(rest) = strip_prefix_ignore_case(text, CHILD) {
        let mut parts = rest.split(':');
        let account: [u8; 16] = unhex(parts.next()?)?.try_into().ok()?;
        let date = parts.next()?;
        if date.is_empty() || date.len() > 12 || !date.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let unlink_at_s = date.parse().ok()?;
        let channel = unhex(parts.next()?).filter(|c| !c.is_empty() && c.len() <= MAX_CHANNEL)?;
        let key: [u8; 32] = unhex(parts.next()?)?.try_into().ok()?;
        if parts.next().is_some() {
            return None;
        }
        return Some(Scanned::Child {
            account,
            unlink_at_s,
            channel,
            key,
        });
    }
    if let Some(digits) = strip_prefix_ignore_case(text, SAFETY)
        && digits.len() == 60
        && digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Some(Scanned::Safety(digits.to_owned()));
    }
    None
}

/// Whether a scanned safety code is the number shown for this contact.
#[must_use]
pub fn safety_matches(scanned: &str, number: &str) -> bool {
    let ours: String = number.chars().filter(char::is_ascii_digit).collect();
    !ours.is_empty() && scanned == ours
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02X}");
            s
        })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.len() > 2 * MAX_CHANNEL.max(32) {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16);
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| u8::try_from(digit(hi)? * 16 + digit(lo)?).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_code_round_trips_in_either_case() {
        let channel = [0xAB; 16];
        let key = [0x3C; 32];
        let code = link_code(&channel, &key);
        assert_eq!(
            code,
            format!("SONGBIRD:LINK:{}:{}", "AB".repeat(16), "3C".repeat(32))
        );
        let want = Some(Scanned::Link {
            channel: channel.to_vec(),
            key,
        });
        assert_eq!(parse(&code), want);
        assert_eq!(parse(&code.to_lowercase()), want);
        assert_eq!(parse(&format!("  {code}\n")), want);
    }

    #[test]
    fn anything_else_is_not_a_link() {
        let key = "3C".repeat(32);
        for bad in [
            format!("SONGBIRD:LINK::{key}"),                    // no channel
            format!("SONGBIRD:LINK:ABC:{key}"),                 // odd hex
            format!("SONGBIRD:LINK:AB:{}", "3C".repeat(31)),    // short key
            format!("SONGBIRD:LINK:AB:{key}00"),                // long key
            format!("SONGBIRD:LINK:{}:{key}", "AB".repeat(65)), // long channel
            format!("SONGBIRD:LINK:AB:{key}:extra"),            // a third field
            format!("SONGBIRD:LINK:ZZ:{key}"),                  // not hex
            format!("songbird-link:ab:{}", key.to_lowercase()), // the old scheme
            format!("https://songbird.chat/g/abc#SONGBIRD:LINK:AB:{key}"), // a link around it
            "SONGBIRD:LINK:".to_string(),
            "SONGBIRD:LIN".to_string(),
            "ſONGBIRD:LINK:AB:CD".to_string(), // a non-ASCII look-alike
        ] {
            assert_eq!(parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn safety_codes_carry_sixty_digits() {
        let number = "05219 47384 60128 57391 02647 38190 57382 91046 38572 91055 12345 67890";
        let code = safety_code(number);
        let Some(Scanned::Safety(digits)) = parse(&code) else {
            panic!("{code}")
        };
        assert!(safety_matches(&digits, number));
        assert!(!safety_matches(&digits, "1"));
        assert_eq!(parse("SONGBIRD:SAFETY:123"), None);
        assert_eq!(parse(&format!("{SAFETY}{}x", "1".repeat(59))), None);
    }

    #[test]
    fn parental_codes_round_trip_and_stay_apart() {
        let code = supervise_code(&[1; 32], &[2; 32]);
        assert_eq!(
            parse(&code.to_lowercase()),
            Some(Scanned::Supervise {
                key: [1; 32],
                secret: [2; 32]
            })
        );
        let child = child_code(&[3; 16], 1_900_000_000, &[4; 16], &[5; 32]);
        assert_eq!(
            parse(&child),
            Some(Scanned::Child {
                account: [3; 16],
                unlink_at_s: 1_900_000_000,
                channel: vec![4; 16],
                key: [5; 32]
            })
        );
        // Neither is ever read as a link code, nor the other way round.
        assert!(!matches!(parse(&code), Some(Scanned::Link { .. })));
        assert!(!matches!(parse(&child), Some(Scanned::Link { .. })));
        let link = link_code(&[4; 16], &[5; 32]);
        assert!(matches!(parse(&link), Some(Scanned::Link { .. })));
        for bad in [
            format!("{SUPERVISE}{}:{}", "01".repeat(32), "02".repeat(31)),
            format!("{SUPERVISE}{}", "01".repeat(32)),
            format!(
                "{CHILD}{}:-1:{}:{}",
                "03".repeat(16),
                "04".repeat(16),
                "05".repeat(32)
            ),
            format!(
                "{CHILD}{}:1:{}:{}:x",
                "03".repeat(16),
                "04".repeat(16),
                "05".repeat(32)
            ),
            format!("{CHILD}{}:1:{}", "03".repeat(16), "04".repeat(16)),
            format!(
                "{CHILD}{}:1234567890123:{}:{}",
                "03".repeat(16),
                "04".repeat(16),
                "05".repeat(32)
            ),
        ] {
            assert_eq!(parse(&bad), None, "{bad}");
        }
    }
}
