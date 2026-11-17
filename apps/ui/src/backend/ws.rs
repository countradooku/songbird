//! The delivery connection (`crates/client`): authenticated with this
//! device's key, reconnecting with backoff, its state shown live.
//!
//! Envelopes are end-to-end ciphertext that only app-core (A2) can open.
//! Until it exists they are counted and **left on the server** (never
//! acknowledged), so nothing is lost when the real client arrives.

use std::cell::RefCell;

use nsh_core::prelude::*;
use songbird_client::{Client, ClientConfig, DeviceKey, Event, ResumeState};
use songbird_types::DeviceId;

use super::{Link, device_key, live};

thread_local! {
    /// The running client (dropping it stops it).
    static CLIENT: RefCell<Option<Client>> = const { RefCell::new(None) };
    /// The task that starts the client and reads its events.
    static READER: RefCell<Option<Spawned<()>>> = const { RefCell::new(None) };
}

/// Connects (again) with this device's key. Does nothing when the device
/// has no account.
pub fn connect() {
    disconnect();
    let Some((device, seed)) = device_key() else { return };
    let endpoint = live().with_untracked(|l| l.endpoint.clone());
    let Ok(key) = DeviceKey::from_seed(DeviceId::from_bytes(device), &seed) else {
        live().update(|l| l.problem = Some("This device's key is damaged.".into()));
        return;
    };
    live().update(|l| {
        l.link = Link::Connecting;
        l.waiting = 0;
    });
    let mut cfg = ClientConfig::new(endpoint.ws_addr, endpoint.ws_name);
    // Right after registration delivery's device directory may lag a poll.
    cfg.new_device_grace = std::time::Duration::from_secs(10);
    let task = spawn(async move {
        // The client spawns on tokio; NSH's `background` runs on its tokio
        // runtime, and the client's tasks stay there.
        let Ok((client, mut events)) =
            background(async move { Client::start(cfg, key, ResumeState::default()) }).await
        else {
            live().update(|l| l.link = Link::Off);
            return;
        };
        CLIENT.with_borrow_mut(|c| *c = Some(client));
        while let Some(event) = events.recv().await {
            match event {
                Event::Connected { .. } => live().update(|l| {
                    l.link = Link::Connected;
                    l.problem = None;
                }),
                // mock: app-core decrypts, stores durably, then `ack`s.
                Event::Deliver { .. } => live().update(|l| l.waiting += 1),
                Event::Disconnected { .. } => live().update(|l| l.link = Link::Retrying),
                Event::Failed { code } => {
                    live().update(|l| {
                        l.link = Link::Refused(code);
                        l.problem = Some(format!(
                            "The server closed the connection for this device (code {code})."
                        ));
                    });
                    break;
                }
                _ => {}
            }
        }
    });
    READER.with_borrow_mut(|r| *r = Some(task));
}

/// Closes the connection.
pub fn disconnect() {
    if let Some(t) = READER.with_borrow_mut(Option::take) {
        t.cancel();
    }
    drop(CLIENT.with_borrow_mut(Option::take));
    if live().with_untracked(|l| l.link != Link::Off) {
        live().update(|l| l.link = Link::Off);
    }
}
