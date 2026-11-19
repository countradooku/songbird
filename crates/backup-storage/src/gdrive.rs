//! Google Drive's hidden app data folder (`appDataFolder`, scope `drive.appdata`): the user's
//! Drive keeps it, only this app can read it, and it does not show in the Drive interface.
//!
//! Drive names files by ID; names may repeat. Layout, flat in the folder (under a name prefix):
//! `<prefix>c.<64 hex>` per chunk, and `<prefix>m.<generation, 20 digits>.<16 random hex>` per
//! manifest. Drive v3 has **no conditional write** (D-0119 §9, D-0122), so the manifest's swap is
//! optimistic: check the newest generation is `expected`, create the next one's file, list that
//! generation, and keep the file whose name sorts first; a writer whose file is not first deletes
//! it and reports a conflict. Every writer applies the same rule, so they agree on the winner
//! once their files are listed, but a writer that listed before a slower racer's file appeared
//! may also believe it won. So this store says [`BackupStore::atomic_swap`] is `false`: the run
//! reads the manifest back, and the hash chain reports a fork instead of losing a backup. Only
//! the primary writes, so a race needs two primaries (an account recovery, briefly).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};
use songbird_backup_format::ChunkName;

use crate::http::{Http, Request, Response, encode};
use crate::oauth::{TokenSource, send_authorized};
use crate::store::{BackupStore, StoreError, check_next, generation_of, status_error};

/// A backup in a Google Drive app data folder.
pub struct GoogleDriveStore {
    http: Arc<dyn Http>,
    tokens: Arc<dyn TokenSource>,
    base: String,
    prefix: String,
    ids: Mutex<HashMap<String, String>>,
}

impl std::fmt::Debug for GoogleDriveStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GoogleDriveStore { .. }")
    }
}

fn error(r: &Response) -> StoreError {
    let reason = serde_json::from_slice::<Value>(&r.body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/errors/0/reason")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    match (r.status, reason.as_str()) {
        (403, "storageQuotaExceeded") => StoreError::Full,
        (403, "userRateLimitExceeded" | "rateLimitExceeded") | (429, _) => StoreError::Throttled {
            retry_after_ms: 1_000,
        },
        (s, _) => status_error(s),
    }
}

/// The multipart body of a create: metadata, then the content.
fn multipart(meta: &Value, content: &[u8], boundary: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(content.len() + 256);
    b.extend_from_slice(
        format!("--{boundary}\r\ncontent-type: application/json; charset=UTF-8\r\n\r\n").as_bytes(),
    );
    b.extend_from_slice(meta.to_string().as_bytes());
    b.extend_from_slice(
        format!("\r\n--{boundary}\r\ncontent-type: application/octet-stream\r\n\r\n").as_bytes(),
    );
    b.extend_from_slice(content);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    b
}

impl GoogleDriveStore {
    /// A store in the app data folder, its files named with `prefix` (e.g. the vault ID's first
    /// 16 hex characters and a dot), on `base` (`https://www.googleapis.com`).
    #[must_use]
    pub fn new(
        http: Arc<dyn Http>,
        tokens: Arc<dyn TokenSource>,
        base: &str,
        prefix: &str,
    ) -> Self {
        Self {
            http,
            tokens,
            base: base.trim_end_matches('/').to_owned(),
            prefix: prefix.to_owned(),
            ids: Mutex::new(HashMap::new()),
        }
    }

    async fn send(&self, req: Request) -> Result<Response, StoreError> {
        send_authorized(self.http.as_ref(), self.tokens.as_ref(), req).await
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every `(name, id)` whose name starts with `start`, oldest first.
    async fn files(&self, start: &str) -> Result<Vec<(String, String)>, StoreError> {
        let q = format!(
            "'appDataFolder' in parents and trashed = false and name contains '{}'",
            start.replace('\\', "\\\\").replace('\'', "\\'")
        );
        let mut out = vec![];
        let mut token: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/drive/v3/files?spaces=appDataFolder&pageSize=1000&fields={}&q={}",
                self.base,
                encode("nextPageToken,files(id,name)"),
                encode(&q)
            );
            if let Some(t) = &token {
                url.push_str("&pageToken=");
                url.push_str(&encode(t));
            }
            let r = self.send(Request::new("GET", url)).await?;
            if !r.ok() {
                return Err(error(&r));
            }
            let v: Value =
                serde_json::from_slice(&r.body).map_err(|_| StoreError::Protocol("list"))?;
            for f in v
                .get("files")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let (Some(n), Some(id)) = (
                    f.get("name").and_then(Value::as_str),
                    f.get("id").and_then(Value::as_str),
                ) && n.starts_with(start)
                {
                    out.push((n.to_owned(), id.to_owned()));
                }
            }
            token = v
                .get("nextPageToken")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if token.is_none() {
                return Ok(out);
            }
        }
    }

    async fn create(&self, name: &str, content: Vec<u8>) -> Result<String, StoreError> {
        let mut r = [0u8; 12];
        let _ = getrandom::fill(&mut r);
        let boundary = format!("songbird{}", hex::encode(r));
        let body = multipart(
            &json!({"name": name, "parents": ["appDataFolder"]}),
            &content,
            &boundary,
        );
        let resp = self
            .send(
                Request::new(
                    "POST",
                    format!(
                        "{}/upload/drive/v3/files?uploadType=multipart&fields=id",
                        self.base
                    ),
                )
                .header(
                    "content-type",
                    format!("multipart/related; boundary={boundary}"),
                )
                .body(body),
            )
            .await?;
        if !resp.ok() {
            return Err(error(&resp));
        }
        let v: Value =
            serde_json::from_slice(&resp.body).map_err(|_| StoreError::Protocol("create"))?;
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .ok_or(StoreError::Protocol("create"))?
            .to_owned();
        self.cache().insert(name.to_owned(), id.clone());
        Ok(id)
    }

    async fn download(&self, id: &str) -> Result<Response, StoreError> {
        self.send(Request::new(
            "GET",
            format!("{}/drive/v3/files/{}?alt=media", self.base, encode(id)),
        ))
        .await
    }

    async fn remove(&self, id: &str) -> Result<(), StoreError> {
        let r = self
            .send(Request::new(
                "DELETE",
                format!("{}/drive/v3/files/{}", self.base, encode(id)),
            ))
            .await?;
        if r.ok() || r.status == 404 {
            Ok(())
        } else {
            Err(error(&r))
        }
    }

    fn chunk(&self, n: &ChunkName) -> String {
        format!("{}c.{}", self.prefix, n.to_hex())
    }

    fn manifests_start(&self) -> String {
        format!("{}m.", self.prefix)
    }

    /// The newest manifest: the highest generation, the first name among its files.
    async fn newest(&self) -> Result<Option<(u64, String, String)>, StoreError> {
        let start = self.manifests_start();
        let mut best: Option<(u64, String, String)> = None;
        for (name, id) in self.files(&start).await? {
            let Some(g) = name
                .get(start.len()..)
                .and_then(|r| r.split('.').next())
                .and_then(|g| g.parse::<u64>().ok())
            else {
                continue;
            };
            let better = match &best {
                None => true,
                Some((bg, bn, _)) => g > *bg || (g == *bg && name < *bn),
            };
            if better {
                best = Some((g, name, id));
            }
        }
        Ok(best)
    }
}

#[async_trait]
impl BackupStore for GoogleDriveStore {
    fn kind(&self) -> &'static str {
        "gdrive"
    }

    fn atomic_swap(&self) -> bool {
        false
    }

    async fn open(&self) -> Result<(), StoreError> {
        let all = self.files(&self.prefix).await?;
        let mut c = self.cache();
        for (n, id) in all {
            c.insert(n, id);
        }
        Ok(())
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        // A second file of the same name holds the same plaintext; listing deduplicates.
        if self.cache().contains_key(&self.chunk(name)) {
            return Ok(());
        }
        self.create(&self.chunk(name), object).await.map(|_| ())
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        let key = self.chunk(name);
        let cached = self.cache().get(&key).cloned();
        let id = match cached {
            Some(id) => id,
            None => self
                .files(&key)
                .await?
                .into_iter()
                .find(|(n, _)| *n == key)
                .map(|(_, id)| id)
                .ok_or(StoreError::NotFound)?,
        };
        let r = self.download(&id).await?;
        if r.ok() {
            Ok(r.body)
        } else {
            if r.status == 404 {
                self.cache().remove(&key);
            }
            Err(error(&r))
        }
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        let start = format!("{}c.", self.prefix);
        let files = self.files(&start).await?;
        let mut out: Vec<ChunkName> = files
            .iter()
            .filter_map(|(n, _)| n.get(start.len()..).and_then(ChunkName::from_hex))
            .collect();
        {
            let mut c = self.cache();
            for (n, id) in files {
                c.insert(n, id);
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        for n in names {
            let key = self.chunk(n);
            for (name, id) in self.files(&key).await? {
                if name == key {
                    self.remove(&id).await?;
                }
            }
            self.cache().remove(&key);
        }
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let Some((_, _, id)) = self.newest().await? else {
            return Ok(None);
        };
        let r = self.download(&id).await?;
        if r.ok() {
            Ok(Some(r.body))
        } else {
            Err(error(&r))
        }
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        let next = check_next(expected, &object)?;
        let newest = self.newest().await?;
        let current = match &newest {
            Some((_, _, id)) => {
                let r = self.download(id).await?;
                if !r.ok() {
                    return Err(error(&r));
                }
                generation_of(&r.body)?
            }
            None => 0,
        };
        if current != expected {
            return Err(StoreError::Conflict { current });
        }
        let mut r = [0u8; 8];
        let _ = getrandom::fill(&mut r);
        let name = format!("{}{next:020}.{}", self.manifests_start(), hex::encode(r));
        let mine = self.create(&name, object).await?;
        // The first name of this generation wins; every writer applies the same rule.
        let rivals = self
            .files(&format!("{}{next:020}.", self.manifests_start()))
            .await?;
        let first = rivals
            .iter()
            .map(|(n, _)| n.as_str())
            .min()
            .unwrap_or(name.as_str());
        if first != name {
            self.remove(&mine).await?;
            return Err(StoreError::Conflict { current: next });
        }
        // Older manifests are no longer needed.
        for (n, id) in self.files(&self.manifests_start()).await? {
            let older = n
                .get(self.manifests_start().len()..)
                .and_then(|r| r.split('.').next())
                .and_then(|g| g.parse::<u64>().ok())
                .is_some_and(|g| g < next);
            if older {
                let _ = self.remove(&id).await;
            }
        }
        Ok(())
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        for (_, id) in self.files(&self.prefix).await? {
            self.remove(&id).await?;
        }
        self.cache().clear();
        Ok(())
    }
}
