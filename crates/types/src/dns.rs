//! DNS host-name validation shared by the proxy (SNI, proxy links) and the internal CA (SANs).

/// Longest host name accepted, in bytes.
pub const MAX_HOST_LEN: usize = 253;

/// Whether `name` is a DNS host name: 1..=253 bytes, dot-separated labels of 1..=63 bytes of
/// `[A-Za-z0-9-]`, no label starting or ending with `-`, no empty label (so no trailing dot).
#[must_use]
pub fn is_valid_host(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST_LEN
        && name.split(|b| *b == b'.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        let max = vec!["a"; 127].join("."); // 253 bytes, the limit
        for ok in [
            "a",
            "chat.songbird.example",
            "x-1.songbird.internal",
            "A.B",
            &max,
        ] {
            assert!(is_valid_host(ok.as_bytes()), "{ok}");
        }
        let long_label = "a".repeat(64);
        let too_long = vec!["a"; 128].join("."); // 255 bytes
        for bad in [
            "",
            ".",
            "a..b",
            "a.",
            "-a",
            "a-",
            "a_b",
            "a b",
            "ä.example",
            &long_label,
            &too_long,
        ] {
            assert!(!is_valid_host(bad.as_bytes()), "{bad}");
        }
    }
}
