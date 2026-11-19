//! OneDrive's app folder through Microsoft Graph (`/me/drive/special/approot`): the app sees
//! only `Apps/<app name>/` (scope `Files.ReadWrite.AppFolder`).
//!
//! Layout: `chunks/<64 hex>` and `manifest`. Chunks up to 4 MiB go in one `PUT …:/content`;
//! larger ones through an upload session in one fragment (Graph's simple upload is documented
//! for small files). Downloads follow Graph's redirect to a pre-authenticated URL **without**
//! the bearer token. The manifest's compare-and-swap: `@microsoft.graph.conflictBehavior=fail`
//! for the first, `If-Match: <eTag>` after reading the item; Graph checks it on the server, so
//! this store keeps [`BackupStore::atomic_swap`].

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use songbird_backup_format::ChunkName;

use crate::http::{Http, Request, Response};
use crate::oauth::{TokenSource, send_authorized};
use crate::store::{BackupStore, StoreError, check_next, generation_of, status_error};

/// Largest body sent in one simple upload.
const SIMPLE: usize = 4 << 20;

/// A backup in a OneDrive app folder.
pub struct OneDriveStore {
    http: Arc<dyn Http>,
    tokens: Arc<dyn TokenSource>,
    graph: String,
    root: String,
}

impl std::fmt::Debug for OneDriveStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OneDriveStore { .. }")
    }
}

fn error(r: &Response) -> StoreError {
    match r.status {
        429 | 503 if r.header("retry-after").is_some() => StoreError::Throttled {
            retry_after_ms: r
                .header("retry-after")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1)
                .saturating_mul(1000),
        },
        507 => StoreError::Full,
        s => status_error(s),
    }
}

impl OneDriveStore {
    /// A store under `root` in the app folder (e.g. `<vault id>`; empty for the folder itself),
    /// on `graph` (`https://graph.microsoft.com/v1.0`).
    #[must_use]
    pub fn new(http: Arc<dyn Http>, tokens: Arc<dyn TokenSource>, graph: &str, root: &str) -> Self {
        Self {
            http,
            tokens,
            graph: graph.trim_end_matches('/').to_owned(),
            root: root.trim_matches('/').to_owned(),
        }
    }

    /// `…/special/approot:/<root>/<rel>:` (the item addressed by path).
    fn item(&self, rel: &str) -> String {
        let p = if self.root.is_empty() {
            rel.to_owned()
        } else if rel.is_empty() {
            self.root.clone()
        } else {
            format!("{}/{rel}", self.root)
        };
        if p.is_empty() {
            format!("{}/me/drive/special/approot", self.graph)
        } else {
            format!("{}/me/drive/special/approot:/{p}:", self.graph)
        }
    }

    async fn send(&self, req: Request) -> Result<Response, StoreError> {
        send_authorized(self.http.as_ref(), self.tokens.as_ref(), req).await
    }

    /// Reads content, following the redirect to the pre-authenticated URL.
    async fn content(&self, rel: &str) -> Result<Response, StoreError> {
        let r = self
            .send(Request::new("GET", format!("{}/content", self.item(rel))))
            .await?;
        if matches!(r.status, 301 | 302 | 303 | 307) {
            let loc = r
                .header("location")
                .ok_or(StoreError::Protocol("redirect"))?;
            // The URL carries its own short-lived authorization; the bearer token never goes there.
            return self.http.send(Request::new("GET", loc)).await;
        }
        Ok(r)
    }

    async fn upload(
        &self,
        rel: &str,
        body: Vec<u8>,
        cond: Option<(&str, String)>,
        create_only: bool,
    ) -> Result<Response, StoreError> {
        if body.len() <= SIMPLE {
            let mut url = format!("{}/content", self.item(rel));
            if create_only {
                url.push_str("?@microsoft.graph.conflictBehavior=fail");
            }
            let mut req = Request::new("PUT", url)
                .header("content-type", "application/octet-stream")
                .body(body);
            if let Some((h, v)) = cond {
                req = req.header(h, v);
            }
            return self.send(req).await;
        }
        let behavior = if create_only { "fail" } else { "replace" };
        let mut req = Request::new("POST", format!("{}/createUploadSession", self.item(rel)))
            .header("content-type", "application/json")
            .body(
                json!({"item": {"@microsoft.graph.conflictBehavior": behavior}})
                    .to_string()
                    .into_bytes(),
            );
        if let Some((h, v)) = cond {
            req = req.header(h, v);
        }
        let s = self.send(req).await?;
        if !s.ok() {
            return Ok(s);
        }
        let v: Value =
            serde_json::from_slice(&s.body).map_err(|_| StoreError::Protocol("session"))?;
        let url = v
            .get("uploadUrl")
            .and_then(Value::as_str)
            .ok_or(StoreError::Protocol("session"))?;
        let n = body.len();
        // The upload URL is pre-authenticated: no bearer token.
        self.http
            .send(
                Request::new("PUT", url)
                    .header(
                        "content-range",
                        format!("bytes 0-{}/{n}", n.saturating_sub(1)),
                    )
                    .body(body),
            )
            .await
    }

    async fn current(&self) -> Result<(u64, Option<String>), StoreError> {
        let meta = self
            .send(Request::new("GET", self.item("manifest")))
            .await?;
        match meta.status {
            200 => {}
            404 => return Ok((0, None)),
            _ => return Err(error(&meta)),
        }
        let etag = serde_json::from_slice::<Value>(&meta.body)
            .ok()
            .and_then(|v| v.get("eTag").and_then(Value::as_str).map(str::to_owned));
        let r = self.content("manifest").await?;
        if !r.ok() {
            return Err(error(&r));
        }
        Ok((generation_of(&r.body)?, etag))
    }
}

#[async_trait]
impl BackupStore for OneDriveStore {
    fn kind(&self) -> &'static str {
        "onedrive"
    }

    async fn open(&self) -> Result<(), StoreError> {
        // Reading the app folder creates it on first use (Graph's documented behaviour).
        let r = self.send(Request::new("GET", self.item(""))).await?;
        if r.ok() || r.status == 404 {
            Ok(())
        } else {
            Err(error(&r))
        }
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        let r = self
            .upload(&format!("chunks/{}", name.to_hex()), object, None, false)
            .await?;
        if r.ok() { Ok(()) } else { Err(error(&r)) }
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        let r = self.content(&format!("chunks/{}", name.to_hex())).await?;
        if r.ok() { Ok(r.body) } else { Err(error(&r)) }
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        let mut out = vec![];
        let mut url = format!("{}/children?$select=name&$top=1000", self.item("chunks"));
        loop {
            let r = self.send(Request::new("GET", url.clone())).await?;
            match r.status {
                200 => {}
                404 => return Ok(out),
                _ => return Err(error(&r)),
            }
            let v: Value =
                serde_json::from_slice(&r.body).map_err(|_| StoreError::Protocol("list"))?;
            for e in v
                .get("value")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(n) = e
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(ChunkName::from_hex)
                {
                    out.push(n);
                }
            }
            let Some(next) = v.get("@odata.nextLink").and_then(Value::as_str) else {
                out.sort();
                out.dedup();
                return Ok(out);
            };
            next.clone_into(&mut url);
        }
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        for n in names {
            let r = self
                .send(Request::new(
                    "DELETE",
                    self.item(&format!("chunks/{}", n.to_hex())),
                ))
                .await?;
            if !(r.ok() || r.status == 404) {
                return Err(error(&r));
            }
        }
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let r = self.content("manifest").await?;
        match r.status {
            200 => Ok(Some(r.body)),
            404 => Ok(None),
            _ => Err(error(&r)),
        }
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        check_next(expected, &object)?;
        let r = if expected == 0 {
            self.upload("manifest", object, None, true).await?
        } else {
            let (current, etag) = self.current().await?;
            if current != expected {
                return Err(StoreError::Conflict { current });
            }
            let etag = etag.ok_or(StoreError::Protocol("no etag"))?;
            self.upload("manifest", object, Some(("if-match", etag)), false)
                .await?
        };
        match r.status {
            200..=299 => Ok(()),
            409 | 412 => Err(StoreError::Conflict {
                current: self.current().await?.0,
            }),
            _ => Err(error(&r)),
        }
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        let targets: Vec<String> = if self.root.is_empty() {
            vec!["chunks".into(), "manifest".into()]
        } else {
            vec![String::new()]
        };
        for t in targets {
            let r = self.send(Request::new("DELETE", self.item(&t))).await?;
            if !(r.ok() || r.status == 404) {
                return Err(error(&r));
            }
        }
        Ok(())
    }
}
