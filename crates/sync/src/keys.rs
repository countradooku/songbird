//! Logical keys (PROTOCOL §10.2). They live inside the ciphertext only; the server never sees
//! them.
//!
//! | Prefix | Holds |
//! | --- | --- |
//! | `s/<name>` | An account-wide setting (`s/theme`, `s/read_receipts`) |
//! | `c/<chat>/<name>` | A per-chat preference; `<chat>` is the hex of the peer's account ID or the group ID |
//! | `k/<id>` | A saved contact (name, notes, buddy-list groups) |
//! | `l/<id>` | A custom chat list |
//! | `b/<id>` | A broadcast list |
//! | `x/<id>` | A starred message |
//! | `p/<id>` | An installed pack |

use std::fmt::Write as _;

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// An account-wide setting.
#[must_use]
pub fn setting(name: &str) -> String {
    format!("s/{name}")
}

/// A per-chat preference.
#[must_use]
pub fn chat(chat_id: &[u8], name: &str) -> String {
    format!("c/{}/{name}", hex(chat_id))
}

/// A saved contact.
#[must_use]
pub fn contact(id: &[u8; 16]) -> String {
    format!("k/{}", hex(id))
}

/// A custom chat list.
#[must_use]
pub fn list(id: &[u8; 16]) -> String {
    format!("l/{}", hex(id))
}

/// A broadcast list.
#[must_use]
pub fn broadcast(id: &[u8; 16]) -> String {
    format!("b/{}", hex(id))
}

/// A starred message.
#[must_use]
pub fn starred(message_id: &[u8]) -> String {
    format!("x/{}", hex(message_id))
}

/// An installed pack.
#[must_use]
pub fn pack(pack_id: &[u8; 16]) -> String {
    format!("p/{}", hex(pack_id))
}

#[cfg(test)]
mod tests {
    #[test]
    fn keys_are_namespaced() {
        assert_eq!(super::setting("theme"), "s/theme");
        assert_eq!(super::chat(&[0xab, 1], "mute"), "c/ab01/mute");
        assert_eq!(super::contact(&[0; 16]).len(), 2 + 32);
    }
}
