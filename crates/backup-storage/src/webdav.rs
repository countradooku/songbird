//! `WebDAV` (RFC 4918): Nextcloud, ownCloud, a NAS, or any server the user runs.
//!
//! Layout under the folder URL the user gives: `chunks/<64 hex>`, `manifest`, and
//! `manifest.lock` (an empty file that is only ever `LOCK`ed).
//!
//! The manifest's compare-and-swap: take an exclusive `WebDAV` write lock on `manifest.lock`
//! (atomic on the server; 60 seconds at most, released at once), read the current manifest,
//! compare its generation, write with `If-None-Match: *` or `If-Match: <ETag>`, unlock. Another
//! writer holding the lock is a lost race.
//!
//! **`WebDAV` cannot promise an atomic swap** (D-0122): Apache's `mod_dav` checks `If-Match`
//! and then writes (eight racers all won one generation in the conformance suite), and even its
//! exclusive `LOCK` let two of eight concurrent requests through. So this store says
//! [`BackupStore::atomic_swap`] is `false`: the run reads the manifest back after a swap, and a
//! device that was overtaken sees a fork through the manifests' hash chain instead of losing a
//! backup silently. Only the primary writes backups, so a race needs two primaries, which only
//! an account recovery can briefly create. A server without locks (405 or 501 to `LOCK`) uses the
//! conditional request alone. A weak `ETag` (Apache marks a file changed in the last second
//! weak) never matches strongly, so the adapter reads again until it is strong.
//!
//! Credentials (an app password, never the account password) stay on the device.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use songbird_backup_format::ChunkName;
use zeroize::Zeroizing;

use crate::http::{Http, Request, Response};
use crate::store::{BackupStore, StoreError, check_next, generation_of, status_error};

/// Where and how to reach the folder.
#[derive(Clone)]
pub struct WebDavConfig {
    /// The folder URL, e.g. `https://cloud.example/remote.php/dav/files/ada/Songbird/`.
    pub url: String,
    /// User name.
    pub user: String,
    /// App password.
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for WebDavConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebDavConfig { .. }")
    }
}

/// A backup in a `WebDAV` folder.
pub struct WebDavStore {
    http: Arc<dyn Http>,
    base: String,
    path: String,
    auth: Zeroizing<String>,
}

impl std::fmt::Debug for WebDavStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebDavStore { .. }")
    }
}

/// Every `href` in a multistatus answer, whatever its namespace prefix.
fn hrefs(xml: &str) -> Vec<String> {
    let mut out = vec![];
    let mut rest = xml;
    while let Some(i) = rest.find("href>") {
        let after = rest.get(i + 5..).unwrap_or_default();
        // A closing tag (`</d:href>`) also contains "href>": the text before it is not an href.
        let is_open = rest
            .get(..i)
            .and_then(|b| b.rfind('<'))
            .and_then(|lt| rest.get(lt + 1..=lt + 1))
            != Some("/");
        let Some(j) = after.find("</") else { break };
        if is_open {
            out.push(percent_decode(after.get(..j).unwrap_or_default()));
        }
        rest = after.get(j..).unwrap_or_default();
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%'
            && let (Some(h), Some(l)) = (b.get(i + 1), b.get(i + 2))
            && let Ok(v) = u8::from_str_radix(&format!("{}{}", char::from(*h), char::from(*l)), 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn basic(user: &str, password: &str) -> Zeroizing<String> {
    let raw = Zeroizing::new(format!("{user}:{password}"));
    Zeroizing::new(format!(
        "Basic {}",
        songbird_s3::sigv4::base64(raw.as_bytes())
    ))
}

impl WebDavStore {
    /// A store in the folder `cfg.url` names.
    ///
    /// # Errors
    /// [`StoreError::Protocol`] for a URL that is not `http(s)://host/…`.
    pub fn new(http: Arc<dyn Http>, cfg: &WebDavConfig) -> Result<Self, StoreError> {
        let mut url = cfg.url.clone();
        if !url.ends_with('/') {
            url.push('/');
        }
        let scheme = if url.starts_with("https://") {
            8
        } else if url.starts_with("http://") {
            7
        } else {
            return Err(StoreError::Protocol("url"));
        };
        let slash = url
            .get(scheme..)
            .and_then(|r| r.find('/'))
            .ok_or(StoreError::Protocol("url"))?
            + scheme;
        Ok(Self {
            http,
            base: url.get(..slash).unwrap_or_default().to_owned(),
            path: url.get(slash..).unwrap_or("/").to_owned(),
            auth: basic(&cfg.user, &cfg.password),
        })
    }

    fn req(&self, method: &str, rel: &str) -> Request {
        Request::new(method, format!("{}{}{rel}", self.base, self.path))
            .header("authorization", self.auth.as_str())
    }

    async fn send(&self, r: Request) -> Result<Response, StoreError> {
        self.http.send(r).await
    }

    async fn mkcol(&self, rel: &str) -> Result<(), StoreError> {
        let r = self.send(self.req("MKCOL", rel)).await?;
        // 405: it exists already.
        if r.ok() || r.status == 405 {
            Ok(())
        } else {
            Err(status_error(r.status))
        }
    }

    /// Takes the swap lock: `Ok(Some(token))`, `Ok(None)` when the server has no locks, or a
    /// conflict while another writer holds it.
    async fn lock(&self) -> Result<Option<String>, StoreError> {
        let body = br#"<?xml version="1.0" encoding="utf-8"?><d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype><d:owner>songbird</d:owner></d:lockinfo>"#;
        let r = self
            .send(
                self.req("LOCK", "manifest.lock")
                    .header("timeout", "Second-60")
                    .header("depth", "0")
                    .header("content-type", "application/xml")
                    .body(body.to_vec()),
            )
            .await?;
        match r.status {
            200 | 201 => r
                .header("lock-token")
                .map(|t| Some(t.trim().to_owned()))
                .ok_or(StoreError::Protocol("no lock token")),
            405 | 501 => Ok(None),
            423 => Err(StoreError::Conflict {
                current: self.current().await?.0,
            }),
            s => Err(status_error(s)),
        }
    }

    async fn unlock(&self, token: &str) {
        let _ = self
            .send(
                self.req("UNLOCK", "manifest.lock")
                    .header("lock-token", token),
            )
            .await;
    }

    /// The current manifest's generation and strong `ETag`.
    async fn current(&self) -> Result<(u64, Option<String>), StoreError> {
        for _ in 0..4 {
            let r = self.send(self.req("GET", "manifest")).await?;
            match r.status {
                200 => {
                    let g = generation_of(&r.body)?;
                    match r.header("etag") {
                        Some(e) if e.starts_with("W/") => {
                            tokio::time::sleep(Duration::from_millis(1_100)).await;
                        }
                        e => return Ok((g, e.map(str::to_owned))),
                    }
                }
                404 => return Ok((0, None)),
                s => return Err(status_error(s)),
            }
        }
        Err(StoreError::Protocol("only weak etags"))
    }
}

#[async_trait]
impl BackupStore for WebDavStore {
    fn kind(&self) -> &'static str {
        "webdav"
    }

    fn atomic_swap(&self) -> bool {
        false
    }

    async fn open(&self) -> Result<(), StoreError> {
        self.mkcol("").await?;
        self.mkcol("chunks/").await
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        let r = self
            .send(
                self.req("PUT", &format!("chunks/{}", name.to_hex()))
                    .header("content-type", "application/octet-stream")
                    .body(object),
            )
            .await?;
        if r.ok() {
            Ok(())
        } else {
            Err(status_error(r.status))
        }
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        let r = self
            .send(self.req("GET", &format!("chunks/{}", name.to_hex())))
            .await?;
        if r.ok() {
            Ok(r.body)
        } else {
            Err(status_error(r.status))
        }
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        let body = br#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>"#;
        let r = self
            .send(
                self.req("PROPFIND", "chunks/")
                    .header("depth", "1")
                    .header("content-type", "application/xml")
                    .body(body.to_vec()),
            )
            .await?;
        match r.status {
            207 => {}
            404 => return Ok(vec![]),
            s => return Err(status_error(s)),
        }
        let xml = String::from_utf8_lossy(&r.body);
        let mut out: Vec<ChunkName> = hrefs(&xml)
            .iter()
            .filter_map(|h| {
                h.trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .and_then(ChunkName::from_hex)
            })
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        for n in names {
            let r = self
                .send(self.req("DELETE", &format!("chunks/{}", n.to_hex())))
                .await?;
            if !(r.ok() || r.status == 404) {
                return Err(status_error(r.status));
            }
        }
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let r = self.send(self.req("GET", "manifest")).await?;
        match r.status {
            200 => Ok(Some(r.body)),
            404 => Ok(None),
            s => Err(status_error(s)),
        }
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        check_next(expected, &object)?;
        let token = self.lock().await?;
        let r = self.swap_locked(expected, object).await;
        if let Some(t) = token {
            self.unlock(&t).await;
        }
        r
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        let r = self.send(self.req("DELETE", "")).await?;
        if r.ok() || r.status == 404 {
            Ok(())
        } else {
            Err(status_error(r.status))
        }
    }
}

impl WebDavStore {
    async fn swap_locked(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        let (h, v) = if expected == 0 {
            ("if-none-match", "*".to_owned())
        } else {
            let (current, etag) = self.current().await?;
            if current != expected {
                return Err(StoreError::Conflict { current });
            }
            ("if-match", etag.ok_or(StoreError::Protocol("no etag"))?)
        };
        let r = self
            .send(
                self.req("PUT", "manifest")
                    .header(h, v)
                    .header("content-type", "application/octet-stream")
                    .body(object),
            )
            .await?;
        match r.status {
            200..=299 => Ok(()),
            412 | 423 => Err(StoreError::Conflict {
                current: self.current().await?.0,
            }),
            s => Err(status_error(s)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn hrefs_are_read_whatever_the_prefix() {
        let xml = r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/a/b%20c/</d:href></d:response><D:response><D:href>/a/0f</D:href></D:response><response xmlns="DAV:"><href>/x</href></response></d:multistatus>"#;
        assert_eq!(hrefs(xml), vec!["/a/b c/", "/a/0f", "/x"]);
    }
}
