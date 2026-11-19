//! Any S3-compatible bucket (AWS, Hetzner, Scaleway, Backblaze, MinIO, RustFS…), signed with
//! AWS Signature V4 (`songbird_s3::sigv4`, the server's own implementation), path-style.
//!
//! Layout under the configured prefix: `chunks/<64 hex>` and `manifest`. The manifest's
//! compare-and-swap uses S3 conditional writes: `If-None-Match: *` for the first, `If-Match:
//! <ETag>` after reading the current one; a 412 is a lost race. A provider that ignores those
//! headers fails the conformance suite's race check, and the app says so instead of offering it.
//!
//! The access key stays on the device; `Debug` never shows it.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use songbird_backup_format::ChunkName;
use songbird_s3::sigv4::{self, Scope, Signable};
use zeroize::Zeroizing;

use crate::http::{Http, Request, Response};
use crate::store::{BackupStore, StoreError, check_next, generation_of, status_error};

/// Where and how to reach the bucket.
#[derive(Clone)]
pub struct S3Config {
    /// `https://host[:port]` of the endpoint.
    pub endpoint: String,
    /// The bucket.
    pub bucket: String,
    /// The signing region (`us-east-1` for most non-AWS providers).
    pub region: String,
    /// Access key ID.
    pub access_key: Zeroizing<String>,
    /// Secret access key.
    pub secret_key: Zeroizing<String>,
    /// A prefix inside the bucket (ends with `/`), e.g. `songbird/<vault id>/`.
    pub prefix: String,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3Config { .. }")
    }
}

/// A backup in an S3 bucket.
pub struct S3Store {
    http: Arc<dyn Http>,
    cfg: S3Config,
    host: String,
}

impl std::fmt::Debug for S3Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3Store { .. }")
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The text of every `<tag>…</tag>` in `xml`, in order (S3 answers are flat enough).
fn tags<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = vec![];
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = rest.get(i + open.len()..).unwrap_or_default();
        let Some(j) = after.find(&close) else { break };
        out.push(after.get(..j).unwrap_or_default());
        rest = after.get(j + close.len()..).unwrap_or_default();
    }
    out
}

impl S3Store {
    /// A store in `cfg`'s bucket.
    ///
    /// # Errors
    /// [`StoreError::Protocol`] for an endpoint that is not `http(s)://host[:port]`.
    pub fn new(http: Arc<dyn Http>, mut cfg: S3Config) -> Result<Self, StoreError> {
        let host = cfg
            .endpoint
            .strip_prefix("https://")
            .or_else(|| cfg.endpoint.strip_prefix("http://"))
            .filter(|h| !h.is_empty() && !h.contains('/'))
            .ok_or(StoreError::Protocol("endpoint"))?
            .to_owned();
        if !cfg.prefix.is_empty() && !cfg.prefix.ends_with('/') {
            cfg.prefix.push('/');
        }
        Ok(Self { http, cfg, host })
    }

    fn key(&self, rest: &str) -> String {
        format!("{}{rest}", self.cfg.prefix)
    }

    /// A signed request for `key` (empty: the bucket) with `query` and extra signed headers.
    fn request(
        &self,
        method: &str,
        key: &str,
        query: &[(&str, &str)],
        extra: &[(&str, String)],
        body: Vec<u8>,
    ) -> Request {
        let path = if key.is_empty() {
            format!("/{}", sigv4::uri_encode(&self.cfg.bucket, false))
        } else {
            format!(
                "/{}/{}",
                sigv4::uri_encode(&self.cfg.bucket, false),
                sigv4::uri_encode(key, true)
            )
        };
        let date = sigv4::amz_date(now());
        let payload = sigv4::sha256_hex(&body);
        let mut headers: Vec<(&str, &str)> = vec![
            ("host", &self.host),
            ("x-amz-date", &date),
            ("x-amz-content-sha256", &payload),
        ];
        for (k, v) in extra {
            headers.push((k, v.as_str()));
        }
        let auth = sigv4::authorization(
            &self.cfg.access_key,
            &self.cfg.secret_key,
            Scope {
                region: &self.cfg.region,
                service: "s3",
            },
            &date,
            &Signable {
                method,
                canonical_uri: &path,
                query,
                headers: &headers,
                payload_hash: &payload,
            },
        );
        let q = sigv4::canonical_query(query);
        let url = if q.is_empty() {
            format!("{}{path}", self.cfg.endpoint)
        } else {
            format!("{}{path}?{q}", self.cfg.endpoint)
        };
        let mut r = Request::new(method, url)
            .header("x-amz-date", date.clone())
            .header("x-amz-content-sha256", payload.clone())
            .header("authorization", auth);
        for (k, v) in extra {
            r = r.header(k, v.clone());
        }
        r.body(body)
    }

    async fn send(&self, r: Request) -> Result<Response, StoreError> {
        self.http.send(r).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut out = vec![];
        let mut token: Option<String> = None;
        loop {
            let mut q: Vec<(&str, &str)> =
                vec![("list-type", "2"), ("prefix", prefix), ("max-keys", "1000")];
            if let Some(t) = &token {
                q.push(("continuation-token", t));
            }
            let r = self.send(self.request("GET", "", &q, &[], vec![])).await?;
            if !r.ok() {
                return Err(status_error(r.status));
            }
            let xml = String::from_utf8_lossy(&r.body);
            out.extend(tags(&xml, "Key").into_iter().map(str::to_owned));
            let truncated = tags(&xml, "IsTruncated").first() == Some(&"true");
            token = tags(&xml, "NextContinuationToken")
                .first()
                .map(|t| (*t).to_owned());
            if !truncated || token.is_none() {
                return Ok(out);
            }
        }
    }

    async fn delete_key(&self, key: &str) -> Result<(), StoreError> {
        let r = self
            .send(self.request("DELETE", key, &[], &[], vec![]))
            .await?;
        if r.ok() || r.status == 404 {
            Ok(())
        } else {
            Err(status_error(r.status))
        }
    }

    async fn current(&self) -> Result<(u64, Option<String>), StoreError> {
        let r = self
            .send(self.request("GET", &self.key("manifest"), &[], &[], vec![]))
            .await?;
        match r.status {
            200 => Ok((generation_of(&r.body)?, r.header("etag").map(str::to_owned))),
            404 => Ok((0, None)),
            s => Err(status_error(s)),
        }
    }
}

#[async_trait]
impl BackupStore for S3Store {
    fn kind(&self) -> &'static str {
        "s3"
    }

    async fn open(&self) -> Result<(), StoreError> {
        // The bucket is the user's; check it is reachable with these credentials.
        let r = self
            .send(self.request(
                "GET",
                "",
                &[
                    ("list-type", "2"),
                    ("max-keys", "1"),
                    ("prefix", &self.cfg.prefix),
                ],
                &[],
                vec![],
            ))
            .await?;
        if r.ok() {
            Ok(())
        } else {
            Err(status_error(r.status))
        }
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        let r = self
            .send(self.request(
                "PUT",
                &self.key(&format!("chunks/{}", name.to_hex())),
                &[],
                &[],
                object,
            ))
            .await?;
        if r.ok() {
            Ok(())
        } else {
            Err(status_error(r.status))
        }
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        let r = self
            .send(self.request(
                "GET",
                &self.key(&format!("chunks/{}", name.to_hex())),
                &[],
                &[],
                vec![],
            ))
            .await?;
        if r.ok() {
            Ok(r.body)
        } else {
            Err(status_error(r.status))
        }
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        let p = self.key("chunks/");
        Ok(self
            .list_prefix(&p)
            .await?
            .iter()
            .filter_map(|k| k.strip_prefix(&p).and_then(ChunkName::from_hex))
            .collect())
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        for n in names {
            self.delete_key(&self.key(&format!("chunks/{}", n.to_hex())))
                .await?;
        }
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let r = self
            .send(self.request("GET", &self.key("manifest"), &[], &[], vec![]))
            .await?;
        match r.status {
            200 => Ok(Some(r.body)),
            404 => Ok(None),
            s => Err(status_error(s)),
        }
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        check_next(expected, &object)?;
        let cond = if expected == 0 {
            ("if-none-match", "*".to_owned())
        } else {
            let (current, etag) = self.current().await?;
            if current != expected {
                return Err(StoreError::Conflict { current });
            }
            ("if-match", etag.ok_or(StoreError::Protocol("no etag"))?)
        };
        let r = self
            .send(self.request("PUT", &self.key("manifest"), &[], &[cond], object))
            .await?;
        match r.status {
            200..=299 => Ok(()),
            // Lost the race (412), or a concurrent conditional write in progress (409).
            409 | 412 => Err(StoreError::Conflict {
                current: self.current().await?.0,
            }),
            s => Err(status_error(s)),
        }
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        for k in self.list_prefix(&self.cfg.prefix).await? {
            self.delete_key(&k).await?;
        }
        Ok(())
    }
}
