//! `songbird-admin reports` (Prompt 4, D-0063): the moderators' side of reporting.
//!
//! Reports are queued sealed to the moderation key (X25519); the servers hold only its public
//! half. This tool holds the private half, offline:
//!
//! - `keygen` writes a new private key (mode 0600) and prints the public key for
//!   `[api.reports] moderation_key`;
//! - `list` shows queued reports' IDs and times (their contents stay sealed);
//! - `open` decrypts them with the private key and prints each as JSON, with the reported
//!   content decoded (`songbird_content`; this tool is not a service);
//! - `delete` removes one once dealt with (needs `--confirm`, audit-logged).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow};
use clap::Subcommand;
use songbird_keys::provisioning::{ProvisioningKey, open_with};

use crate::{audit, store};

/// The domain reports are sealed under (`songbird_api::reports::SEAL_DOMAIN`).
const SEAL_DOMAIN: &[u8] = b"songbird.v1/report";

#[derive(Debug, Subcommand)]
pub(crate) enum ReportsCmd {
    /// Generate a moderation key: the private key goes to `--out` (mode 0600, keep it offline),
    /// the public key is printed for `[api.reports] moderation_key`.
    Keygen {
        /// The private key file to create (must not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// List queued reports: IDs and arrival times (contents stay sealed).
    List {
        #[command(flatten)]
        store: store::StoreArgs,
        /// At most this many, oldest first.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Decrypt queued reports with the moderation key and print them as JSON lines.
    Open {
        #[command(flatten)]
        store: store::StoreArgs,
        /// The moderation private key file (`keygen`).
        #[arg(long)]
        key: PathBuf,
        /// At most this many, oldest first.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Delete a report once dealt with. Needs `--confirm <namespace>/<database>`; audit-logged.
    Delete {
        #[command(flatten)]
        store: store::StoreArgs,
        #[command(flatten)]
        guard: audit::Guard,
        /// The report ID (`list`).
        #[arg(long)]
        id: String,
    },
}

fn read_key(path: &Path) -> Result<ProvisioningKey> {
    let text = std::fs::read_to_string(path).context("reading the moderation key")?;
    let mut k = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut k).context("the moderation key is 64 hex characters")?;
    ProvisioningKey::from_private(&k).map_err(|_| anyhow!("not an X25519 private key"))
}

fn keygen(out: &Path) -> Result<()> {
    let mut k = [0u8; 32];
    aws_lc_rs::rand::fill(&mut k).map_err(|_| anyhow!("random source failed"))?;
    let key = ProvisioningKey::from_private(&k).map_err(|_| anyhow!("key generation failed"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(out)
        .context("creating the key file (it must not exist)")?
        .write_all(hex::encode(k).as_bytes())?;
    println!("{}", hex::encode(key.public()));
    Ok(())
}

/// A moderator's view of the reported content: what kind of message, and its text if it has one.
fn render(content: &[u8]) -> serde_json::Value {
    use songbird_content::schema::{content::Body, data_message::Kind};
    let Ok(c) = songbird_content::decode_content(content) else {
        return serde_json::json!({ "kind": "undecodable" });
    };
    let (kind, text, attachments) = match &c.body {
        Some(Body::Data(d)) => match &d.kind {
            Some(Kind::Message(m)) => (
                "message",
                m.text.as_ref().map(|t| t.body.clone()),
                m.attachments.len(),
            ),
            Some(Kind::Edit(e)) => ("edit", e.text.as_ref().map(|t| t.body.clone()), 0),
            Some(Kind::Reaction(r)) => ("reaction", Some(r.emoji.clone()), 0),
            Some(_) => ("other chat message", None, 0),
            None => ("unknown chat message", None, 0),
        },
        Some(_) => ("not a chat message", None, 0),
        None => ("unknown", None, 0),
    };
    serde_json::json!({ "kind": kind, "text": text, "attachments": attachments })
}

pub(crate) fn run(cmd: ReportsCmd) -> Result<()> {
    if let ReportsCmd::Keygen { out } = &cmd {
        return keygen(out);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cmd {
            ReportsCmd::Keygen { .. } => Ok(()),
            ReportsCmd::List { store, limit } => {
                let registry = store.registry().await?;
                for r in registry.queued_reports(limit).await? {
                    println!("{} {}", hex::encode(r.id), r.at);
                }
                Ok(())
            }
            ReportsCmd::Open { store, key, limit } => {
                let key = read_key(&key)?;
                let registry = store.registry().await?;
                for r in registry.queued_reports(limit).await? {
                    let plain = open_with(SEAL_DOMAIN, &key, &r.sealed).map_err(|_| {
                        anyhow!("report {} does not open with this key", hex::encode(r.id))
                    })?;
                    let mut v: serde_json::Value = serde_json::from_slice(&plain)?;
                    let content = v
                        .get("content")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|h| hex::decode(h).ok())
                        .unwrap_or_default();
                    if let Some(o) = v.as_object_mut() {
                        o.insert("id".into(), hex::encode(r.id).into());
                        o.insert("queued_at".into(), r.at.into());
                        o.insert("decoded".into(), render(&content));
                    }
                    println!("{v}");
                }
                Ok(())
            }
            ReportsCmd::Delete { store, guard, id } => {
                let mut bytes = [0u8; 16];
                hex::decode_to_slice(&id, &mut bytes).context("the ID is 32 hex characters")?;
                let entry = guard.begin("reports delete", &crate::target(&store), &id)?;
                let r = async {
                    store.registry().await?.delete_report(&bytes).await?;
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                entry.end(&r, &id)?;
                r
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn a_report_sealed_by_api_opens_with_the_moderation_key_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("moderation.key");
        keygen(&path).unwrap();
        let key = read_key(&path).unwrap();
        let sealed = songbird_keys::provisioning::seal_with(
            SEAL_DOMAIN,
            &key.public(),
            b"{\"reason\":\"spam\"}",
        )
        .unwrap();
        assert_eq!(
            open_with(SEAL_DOMAIN, &key, &sealed).unwrap(),
            b"{\"reason\":\"spam\"}"
        );
        let other = ProvisioningKey::generate().unwrap();
        assert!(open_with(SEAL_DOMAIN, &other, &sealed).is_err());
        assert!(keygen(&path).is_err(), "never overwrites a key");
    }

    #[test]
    fn moderators_see_the_message_kind_and_text() {
        use prost::Message as _;
        use songbird_content::schema::{
            Content, DataMessage, Message, Text, content::Body, data_message::Kind,
        };
        let c = Content {
            version: 1,
            message_id: vec![1; 16],
            body: Some(Body::Data(DataMessage {
                kind: Some(Kind::Message(Message {
                    text: Some(Text {
                        body: "the words".into(),
                        spans: vec![],
                    }),
                    ..Message::default()
                })),
                ..DataMessage::default()
            })),
            ..Content::default()
        };
        let v = render(&c.encode_to_vec());
        assert_eq!(v["kind"], "message");
        assert_eq!(v["text"], "the words");
        assert_eq!(render(b"\xff")["kind"], "undecodable");
    }
}
