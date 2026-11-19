//! `songbird-admin support` (Prompt 11, M6; D-0132): staff's side of the support channel.
//!
//! Tickets are sealed to the support key (X25519), whose private half this tool holds:
//!
//! - `keygen` writes a new private key (mode 0600) and prints the public key for
//!   `[api.support] key`;
//! - `list` shows open tickets, priority first: ID, kind, whether an account is attached, the
//!   number of messages, the last day it changed (contents stay sealed);
//! - `open` decrypts one ticket's messages from its user and prints them as JSON lines (staff's
//!   own replies are sealed to the user's reply key and show as such);
//! - `reply` seals a reply to the ticket's reply key and adds it;
//! - `close` deletes the ticket and every message (needs `--confirm`, audit-logged).
//!
//! The user's bearer never reaches staff: staff act through the registry, the user through it.

use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow};
use clap::Subcommand;
use songbird_accounts::support::TicketRow;
use songbird_keys::provisioning::{Domain, open_with, seal_with};

use crate::{audit, store};

#[derive(Debug, Subcommand)]
pub(crate) enum SupportCmd {
    /// Generate the support key: the private key goes to `--out` (mode 0600), the public key is
    /// printed for `[api.support] key`.
    Keygen {
        /// The private key file to create (must not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// List open tickets, priority first, then the oldest change.
    List {
        #[command(flatten)]
        store: store::StoreArgs,
        /// At most this many.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Decrypt one ticket's messages and print them as JSON lines. Audit-logged.
    Open {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The support private key file (`keygen`).
        #[arg(long)]
        key: PathBuf,
        /// The ticket ID (`list`).
        #[arg(long)]
        ticket: String,
    },
    /// Reply to a ticket (sealed to its reply key). Audit-logged.
    Reply {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The ticket ID.
        #[arg(long)]
        ticket: String,
        /// A file holding the reply's text (UTF-8, at most 8 KiB).
        #[arg(long)]
        file: PathBuf,
    },
    /// Close a ticket: it and every message are deleted. Audit-logged.
    Close {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The ticket ID.
        #[arg(long)]
        ticket: String,
    },
}

fn ticket_id(s: &str) -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    hex::decode_to_slice(s, &mut id).context("--ticket is 32 hex characters")?;
    Ok(id)
}

/// The reply as the app reads it.
pub(crate) fn reply_body(text: &str) -> Result<Vec<u8>> {
    if text.trim().is_empty() || text.len() > 8 * 1024 {
        return Err(anyhow!("a reply is 1 byte to 8 KiB of text"));
    }
    Ok(serde_json::to_vec(&serde_json::json!({ "text": text }))?)
}

fn line(t: &TicketRow) -> String {
    format!(
        "{} {} {} {} messages, day {}{}",
        hex::encode(t.id),
        t.kind,
        if t.account.is_some() {
            "account"
        } else {
            "anonymous"
        },
        t.messages,
        t.touched,
        if t.priority { " priority" } else { "" }
    )
}

#[allow(clippy::too_many_lines, reason = "one arm per subcommand")]
pub(crate) fn run(cmd: SupportCmd) -> Result<()> {
    if let SupportCmd::Keygen { out } = &cmd {
        return crate::reports::keygen(out);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cmd {
            SupportCmd::Keygen { .. } => {}
            SupportCmd::List { store, limit } => {
                for t in store.registry().await?.tickets(limit).await? {
                    println!("{}", line(&t));
                }
            }
            SupportCmd::Open {
                store,
                guard,
                key,
                ticket,
            } => {
                let id = ticket_id(&ticket)?;
                let key = crate::reports::read_key(&key)?;
                // Reading a user's words is recorded, as every decision is (D-0134).
                let entry = guard.begin(
                    "support open",
                    &crate::target(&store),
                    &format!("ticket {ticket}"),
                )?;
                let r = async {
                    let registry = store.registry().await?;
                    let row = registry
                        .ticket(&id)
                        .await?
                        .ok_or_else(|| anyhow!("no such ticket"))?;
                    let (kind, msgs) = registry.ticket_read(&id, None).await?;
                    anyhow::Ok((row, kind, msgs))
                }
                .await;
                entry.end(&r, "")?;
                let (row, kind, msgs) = r?;
                println!(
                    "{}",
                    serde_json::json!({
                        "ticket": ticket,
                        "kind": kind,
                        "account": row.account.as_ref().map(crate::account_hex),
                    })
                );
                for m in msgs {
                    let body = if m.from == "user" {
                        open_with(Domain::Support, &key, &m.sealed)
                            .ok()
                            .and_then(|p| serde_json::from_slice::<serde_json::Value>(&p).ok())
                            .unwrap_or_else(|| serde_json::json!("does not open with this key"))
                    } else {
                        serde_json::json!("(your reply, sealed to the user)")
                    };
                    println!(
                        "{}",
                        serde_json::json!({ "from": m.from, "day": m.day, "message": body })
                    );
                }
            }
            SupportCmd::Reply {
                store,
                guard,
                ticket,
                file,
            } => {
                let id = ticket_id(&ticket)?;
                let text = std::fs::read_to_string(&file).context("reading the reply")?;
                let body = reply_body(&text)?;
                let entry = guard.begin(
                    "support reply",
                    &crate::target(&store),
                    &format!("ticket {ticket}"),
                )?;
                let r = async {
                    let registry = store.registry().await?;
                    let t = registry
                        .ticket(&id)
                        .await?
                        .ok_or_else(|| anyhow!("no such ticket"))?;
                    let sealed = seal_with(Domain::SupportReply, &t.reply_key, &body)
                        .map_err(|_| anyhow!("the ticket's reply key is not usable"))?;
                    registry
                        .ticket_post(&id, None, &sealed, songbird_entitlements::today())
                        .await
                        .map_err(anyhow::Error::from)
                }
                .await;
                entry.end(&r, "")?;
                r?;
                println!("replied");
            }
            SupportCmd::Close {
                store,
                guard,
                ticket,
            } => {
                let id = ticket_id(&ticket)?;
                let entry = guard.begin(
                    "support close",
                    &crate::target(&store),
                    &format!("ticket {ticket}"),
                )?;
                let r = async {
                    store
                        .registry()
                        .await?
                        .ticket_close(&id, None)
                        .await
                        .map_err(anyhow::Error::from)
                }
                .await;
                entry.end(&r, "")?;
                r?;
                println!("closed: the ticket and its messages are deleted");
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;
    use songbird_keys::provisioning::ProvisioningKey;

    #[test]
    fn a_reply_opens_only_with_the_tickets_reply_key() {
        let reply = ProvisioningKey::generate().unwrap();
        let other = ProvisioningKey::generate().unwrap();
        let sealed = seal_with(
            Domain::SupportReply,
            &reply.public(),
            &reply_body("hello").unwrap(),
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&open_with(Domain::SupportReply, &reply, &sealed).unwrap())
                .unwrap();
        assert_eq!(v["text"], "hello");
        assert!(open_with(Domain::SupportReply, &other, &sealed).is_err());
        assert!(open_with(Domain::Support, &reply, &sealed).is_err());
        assert!(reply_body(" ").is_err());
        assert!(reply_body(&"x".repeat(8 * 1024 + 1)).is_err());
    }
}
