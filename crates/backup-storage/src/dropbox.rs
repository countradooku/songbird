//! Dropbox, an app with the "App folder" access type: the app sees only
//! `/Apps/<app name>/`, and paths below are relative to it (API v2).
//!
//! Layout: `/chunks/<64 hex>` and `/manifest`. The manifest's compare-and-swap is Dropbox's own:
//! `files/upload` with `mode: add` (refused if the file exists) for the first, `mode: update`
//! with the revision read (refused if it changed) after; both are atomic on the server, so this
//! store keeps [`BackupStore::atomic_swap`].

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use songbird_backup_format::ChunkName;

use crate::http::{Http, Request, Response};
use crate::oauth::{TokenSource, send_authorized};
use crate::store::{BackupStore, StoreError, check_next, generation_of, status_error};

/// The API hosts (tests point both at an emulator).
#[derive(Debug, Clone)]
pub struct DropboxHosts {
    /// `https://api.dropboxapi.com`.
    pub api: String,
    /// `https://content.dropboxapi.com`.
    pub content: String,
}

impl Default for DropboxHosts {
    fn default() -> Self {
        Self {
            api: "https://api.dropboxapi.com".into(),
            content: "https://content.dropboxapi.com".into(),
        }
    }
}

/// A backup in a Dropbox app folder.
pub struct DropboxStore {
    http: Arc<dyn Http>,
    tokens: Arc<dyn TokenSource>,
    hosts: DropboxHosts,
    root: String,
}

impl std::fmt::Debug for DropboxStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DropboxStore { .. }")
    }
}

/// Dropbox's `Dropbox-API-Arg` header must be ASCII: non-ASCII characters escaped as `\uXXXX`.
fn api_arg(v: &Value) -> String {
    let s = v.to_string();
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{u:04x}"));
            }
        }
    }
    out
}

/// The error summary of a 409 (`path/not_found/..`, `path/conflict/file/..`).
fn summary(r: &Response) -> String {
    serde_json::from_slice::<Value>(&r.body)
        .ok()
        .and_then(|v| {
            v.get("error_summary")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn error(r: &Response) -> StoreError {
    match r.status {
        409 if summary(r).contains("not_found") => StoreError::NotFound,
        409 if summary(r).contains("insufficient_space") => StoreError::Full,
        429 => StoreError::Throttled {
            retry_after_ms: r
                .header("retry-after")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1)
                .saturating_mul(1000),
        },
        s => status_error(s),
    }
}

impl DropboxStore {
    /// A store in the app folder, under `root` (e.g. `/<vault id>`; empty for the folder itself).
    #[must_use]
    pub fn new(
        http: Arc<dyn Http>,
        tokens: Arc<dyn TokenSource>,
        hosts: DropboxHosts,
        root: &str,
    ) -> Self {
        Self {
            http,
            tokens,
            hosts,
            root: root.trim_end_matches('/').to_owned(),
        }
    }

    fn path(&self, rel: &str) -> String {
        format!("{}/{rel}", self.root)
    }

    async fn rpc(&self, endpoint: &str, arg: &Value) -> Result<Response, StoreError> {
        let req = Request::new("POST", format!("{}/2/{endpoint}", self.hosts.api))
            .header("content-type", "application/json")
            .body(arg.to_string().into_bytes());
        send_authorized(self.http.as_ref(), self.tokens.as_ref(), req).await
    }

    async fn upload(
        &self,
        path: &str,
        mode: &Value,
        body: Vec<u8>,
    ) -> Result<Response, StoreError> {
        let arg = json!({"path": path, "mode": mode, "autorename": false, "mute": true, "strict_conflict": true});
        let req = Request::new("POST", format!("{}/2/files/upload", self.hosts.content))
            .header("dropbox-api-arg", api_arg(&arg))
            .header("content-type", "application/octet-stream")
            .body(body);
        send_authorized(self.http.as_ref(), self.tokens.as_ref(), req).await
    }

    async fn download(&self, path: &str) -> Result<Response, StoreError> {
        let req = Request::new("POST", format!("{}/2/files/download", self.hosts.content))
            .header("dropbox-api-arg", api_arg(&json!({"path": path})));
        send_authorized(self.http.as_ref(), self.tokens.as_ref(), req).await
    }

    /// The current manifest's generation and revision.
    async fn current(&self) -> Result<(u64, Option<String>), StoreError> {
        let r = self.download(&self.path("manifest")).await?;
        if r.ok() {
            let rev = r
                .header("dropbox-api-result")
                .and_then(|h| serde_json::from_str::<Value>(h).ok())
                .and_then(|v| v.get("rev").and_then(Value::as_str).map(str::to_owned));
            return Ok((generation_of(&r.body)?, rev));
        }
        match error(&r) {
            StoreError::NotFound => Ok((0, None)),
            e => Err(e),
        }
    }

    async fn delete_path(&self, path: &str) -> Result<(), StoreError> {
        let r = self.rpc("files/delete_v2", &json!({"path": path})).await?;
        if r.ok() {
            return Ok(());
        }
        match error(&r) {
            StoreError::NotFound => Ok(()),
            e => Err(e),
        }
    }
}

#[async_trait]
impl BackupStore for DropboxStore {
    fn kind(&self) -> &'static str {
        "dropbox"
    }

    async fn open(&self) -> Result<(), StoreError> {
        // Uploads create folders as needed; this checks the token reaches the app folder.
        let r = self
            .rpc("files/list_folder", &json!({"path": "", "limit": 1}))
            .await?;
        if r.ok() { Ok(()) } else { Err(error(&r)) }
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        let r = self
            .upload(
                &self.path(&format!("chunks/{}", name.to_hex())),
                &json!("overwrite"),
                object,
            )
            .await?;
        if r.ok() { Ok(()) } else { Err(error(&r)) }
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        let r = self
            .download(&self.path(&format!("chunks/{}", name.to_hex())))
            .await?;
        if r.ok() { Ok(r.body) } else { Err(error(&r)) }
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        let mut out = vec![];
        let mut r = self
            .rpc(
                "files/list_folder",
                &json!({"path": self.path("chunks"), "limit": 2000}),
            )
            .await?;
        loop {
            if !r.ok() {
                return match error(&r) {
                    StoreError::NotFound => Ok(out),
                    e => Err(e),
                };
            }
            let v: Value =
                serde_json::from_slice(&r.body).map_err(|_| StoreError::Protocol("list"))?;
            for e in v
                .get("entries")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if e.get(".tag").and_then(Value::as_str) == Some("file")
                    && let Some(n) = e
                        .get("name")
                        .and_then(Value::as_str)
                        .and_then(ChunkName::from_hex)
                {
                    out.push(n);
                }
            }
            if v.get("has_more").and_then(Value::as_bool) != Some(true) {
                out.sort();
                out.dedup();
                return Ok(out);
            }
            let cursor = v
                .get("cursor")
                .and_then(Value::as_str)
                .ok_or(StoreError::Protocol("cursor"))?
                .to_owned();
            r = self
                .rpc("files/list_folder/continue", &json!({"cursor": cursor}))
                .await?;
        }
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        for n in names {
            self.delete_path(&self.path(&format!("chunks/{}", n.to_hex())))
                .await?;
        }
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let r = self.download(&self.path("manifest")).await?;
        if r.ok() {
            return Ok(Some(r.body));
        }
        match error(&r) {
            StoreError::NotFound => Ok(None),
            e => Err(e),
        }
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        check_next(expected, &object)?;
        let mode = if expected == 0 {
            json!("add")
        } else {
            let (current, rev) = self.current().await?;
            if current != expected {
                return Err(StoreError::Conflict { current });
            }
            json!({".tag": "update", "update": rev.ok_or(StoreError::Protocol("no rev"))?})
        };
        let r = self.upload(&self.path("manifest"), &mode, object).await?;
        if r.ok() {
            return Ok(());
        }
        if r.status == 409 && summary(&r).contains("conflict") {
            return Err(StoreError::Conflict {
                current: self.current().await?.0,
            });
        }
        Err(error(&r))
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        if self.root.is_empty() {
            self.delete_path("/chunks").await?;
            self.delete_path("/manifest").await
        } else {
            self.delete_path(&self.root).await
        }
    }
}
