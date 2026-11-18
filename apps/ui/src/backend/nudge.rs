//! Nudges on the real backend (Prompt 9, M6; PROTOCOL §10.5, D-0104).
//!
//! A nudge is `Content.attention {NUDGE}`, sent identified on the delivery
//! connection in the server's attention class (frame `0x04`), one device at
//! a time: `songbird_client::Client::attention(device, payload)`. The server
//! holds it to budgets per pair of accounts and per sender and drops it
//! silently when over a budget, blocked or offline: a nudge to an offline
//! contact is lost, as Yahoo's buzz was. It learns that a nudge happened
//! between two accounts, never what it is.
//!
//! mock: the payload must be sealed for each of the contact's devices over
//! an end-to-end session (app-core, A2), and contacts have no known devices
//! until then, so [`send`] returns without sending. The delivery client
//! lives in `backend::ws`, which hands it out once app-core encrypts.
//!
//! **Never by surprise** (D-0101 question 9): the first nudge this device
//! ever sends is confirmed first; the answer is kept on this device.

use nsh_core::storage::Storage;
use songbird_content::{
    Content,
    presence::{Attention, AttentionKind},
    schema::content::Body,
};

use super::presence::Peer;

const K_CONFIRMED: &str = "sb.nudge_confirmed";

/// What became of a nudge on the real backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// The account isn't live: the mock shows it.
    Offline,
    /// No device of the contact is known (until app-core): nothing sent.
    NoDevices,
}

/// The plaintext of a nudge (`Content.attention {NUDGE}`), padded as every
/// content is; what app-core seals for each device.
pub fn content() -> Option<Vec<u8>> {
    let c = Content {
        version: songbird_content::VERSION,
        message_id: super::wire::random::<16>().to_vec(),
        sent_at_ms: nsh_core::time::unix_ms().max(0.0) as u64,
        body: Some(Body::Attention(Attention {
            kind: i32::from(AttentionKind::Nudge),
        })),
        ..Content::default()
    };
    songbird_content::seal(&c, None)
        .ok()
        .map(|(bytes, _)| bytes)
}

/// Sends a nudge to `peer`'s devices when the account is live.
pub fn send(peer: Option<&Peer>) -> Sent {
    decide(super::is_live() && super::registered(), peer)
}

fn decide(live: bool, peer: Option<&Peer>) -> Sent {
    if !live {
        return Sent::Offline;
    }
    let Some(peer) = peer.filter(|p| !p.devices.is_empty()) else {
        return Sent::NoDevices;
    };
    // mock: app-core seals `content()` for each device and calls
    // `Client::attention(device, sealed)`; nothing is sent in the clear.
    let _ = content();
    let _ = peer;
    Sent::NoDevices
}

/// Whether the user already agreed to send nudges (asked once, ever).
pub fn confirmed() -> bool {
    Storage::get_item(K_CONFIRMED).is_some()
}

pub fn set_confirmed() {
    if let Err(e) = Storage::set_item(K_CONFIRMED, "1") {
        log::warn!("nudge storage: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nudge_is_an_attention_content() {
        let bytes = content().expect("encodes");
        let opened = songbird_content::open(&bytes).expect("opens");
        assert!(matches!(
            opened.content.body,
            Some(Body::Attention(Attention { kind })) if kind == i32::from(AttentionKind::Nudge)
        ));
    }

    #[test]
    fn nothing_is_sent_without_known_devices() {
        let peer = Peer {
            account: [1; 16],
            devices: Vec::new(),
            access_key: [0; 16],
        };
        assert_eq!(decide(false, Some(&peer)), Sent::Offline);
        assert_eq!(decide(true, Some(&peer)), Sent::NoDevices);
        assert_eq!(decide(true, None), Sent::NoDevices);
        // Even with devices, nothing goes out until app-core can seal it.
        let known = Peer {
            devices: vec![[2; 16]],
            ..peer
        };
        assert_eq!(decide(true, Some(&known)), Sent::NoDevices);
    }
}
