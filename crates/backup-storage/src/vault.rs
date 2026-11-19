//! The Songbird vault adapter (PROTOCOL §11.8): the vault ID and access secret come from the
//! recovery key, so a new device with only the key can find and read its backup. Writes need an
//! anonymous **day pass** and creation a **creation token** ([`Passes`], D-0130): the app gets
//! them blinded from `api` as its account's primary, and the vault never learns the account.

use std::sync::Arc;

use async_trait::async_trait;
use songbird_backup_format::{BackupKeys, ChunkName};
use songbird_proto::vault as wire;
use zeroize::Zeroizing;

use crate::http::{Http, Request, Response};
use crate::store::{BackupStore, StoreError, check_next, status_error};

/// Anonymous tokens for the vault (D-0130), each a finished token (`songbird_tokens::token::
/// Redemption`, as JSON). The app asks `api` for them as its account's primary, blinded, and
/// hands them here; nothing here sees the account or its keys.
#[async_trait]
pub trait Passes: Send + Sync {
    /// A day pass for UTC day `day` (days since the Unix epoch).
    async fn day_pass(&self, day: u32) -> Result<serde_json::Value, StoreError>;
    /// A vault creation token for the current window.
    async fn creation(&self) -> Result<serde_json::Value, StoreError>;
}

/// Today's UTC day.
#[must_use]
pub fn today() -> u32 {
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    u32::try_from(s / 86_400).unwrap_or(u32::MAX)
}

/// A backup in the Songbird vault.
pub struct VaultStore {
    http: Arc<dyn Http>,
    base: String,
    id_hex: String,
    access_hex: Zeroizing<String>,
    passes: Option<Arc<dyn Passes>>,
    /// The UTC day of the pass this store last presented (0: none).
    pass_day: std::sync::Mutex<u32>,
}

impl std::fmt::Debug for VaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultStore { .. }")
    }
}

fn throttled(r: &Response) -> StoreError {
    let secs = r
        .header("retry-after")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1);
    StoreError::Throttled {
        retry_after_ms: secs.saturating_mul(1000),
    }
}

fn error(r: &Response) -> StoreError {
    match r.status {
        429 => throttled(r),
        409 => {
            let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
            match v.get("error").and_then(serde_json::Value::as_str) {
                Some("full") => StoreError::Full,
                Some("generation") => StoreError::Conflict {
                    current: v
                        .get("generation")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                },
                _ => StoreError::Protocol("conflict"),
            }
        }
        s => status_error(s),
    }
}

impl VaultStore {
    /// The vault `keys` name at `base` (`https://api.example`), read-only without passes.
    #[must_use]
    pub fn new(
        http: Arc<dyn Http>,
        base: impl Into<String>,
        keys: &BackupKeys,
        passes: Option<Arc<dyn Passes>>,
    ) -> Self {
        Self {
            http,
            base: base.into().trim_end_matches('/').to_owned(),
            id_hex: hex::encode(keys.vault_id),
            access_hex: Zeroizing::new(hex::encode(*keys.vault_access)),
            passes,
            pass_day: std::sync::Mutex::new(0),
        }
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        write: bool,
    ) -> Result<Request, StoreError> {
        if write && self.passes.is_none() {
            return Err(StoreError::Unauthorized);
        }
        let mut r = Request::new(method, format!("{}{path}", self.base))
            .header(wire::VAULT_HEADER, self.id_hex.clone())
            .header(wire::ACCESS_HEADER, self.access_hex.as_str());
        if let Some(b) = body {
            r = r.header("content-type", "application/octet-stream").body(b);
        }
        Ok(r)
    }

    async fn send(&self, r: Request) -> Result<Response, StoreError> {
        self.http.send(r).await
    }

    fn token_body(token: &serde_json::Value) -> Vec<u8> {
        serde_json::json!({ "token": token })
            .to_string()
            .into_bytes()
    }

    /// Presents today's day pass unless this store already did.
    async fn ensure_pass(&self) -> Result<(), StoreError> {
        let passes = self.passes.as_ref().ok_or(StoreError::Unauthorized)?;
        let day = today();
        if self.pass_day.lock().is_ok_and(|d| *d == day) {
            return Ok(());
        }
        let body = Self::token_body(&passes.day_pass(day).await?);
        let r = self
            .send(
                self.request("POST", "/v1/vault/day", None, true)?
                    .header("content-type", "application/json")
                    .body(body),
            )
            .await?;
        if !r.ok() {
            return Err(error(&r));
        }
        if let Ok(mut d) = self.pass_day.lock() {
            *d = day;
        }
        Ok(())
    }

    /// A write under today's pass; a pass refused (a day turned) is presented again once.
    async fn write(
        &self,
        build: impl Fn() -> Result<Request, StoreError>,
    ) -> Result<Response, StoreError> {
        self.ensure_pass().await?;
        let r = self.send(build()?).await?;
        let refused = r.status == 403
            && serde_json::from_slice::<serde_json::Value>(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .as_deref()
                == Some("pass");
        if !refused {
            return Ok(r);
        }
        if let Ok(mut d) = self.pass_day.lock() {
            *d = 0;
        }
        self.ensure_pass().await?;
        self.send(build()?).await
    }

    /// The vault's counts: `(generation, bytes, chunks, quota bytes, quota chunks)`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn stats(&self) -> Result<(u64, u64, u64, u64, u64), StoreError> {
        let r = self
            .send(self.request("GET", "/v1/vault", None, false)?)
            .await?;
        if !r.ok() {
            return Err(error(&r));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&r.body).map_err(|_| StoreError::Protocol("stats"))?;
        let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
        Ok((
            n("generation"),
            n("bytes"),
            n("chunks"),
            n("quota_bytes"),
            n("quota_chunks"),
        ))
    }
}

#[async_trait]
impl BackupStore for VaultStore {
    fn kind(&self) -> &'static str {
        "vault"
    }

    async fn open(&self) -> Result<(), StoreError> {
        let passes = self.passes.as_ref().ok_or(StoreError::Unauthorized)?;
        // An existing vault needs no creation token (they are scarce: two per 180 days).
        let r = self
            .send(self.request("GET", "/v1/vault", None, false)?)
            .await?;
        match r.status {
            200 => {}
            404 => {
                let body = Self::token_body(&passes.creation().await?);
                let r = self
                    .send(
                        self.request("POST", "/v1/vault", None, true)?
                            .header("content-type", "application/json")
                            .body(body),
                    )
                    .await?;
                if !r.ok() {
                    return Err(error(&r));
                }
            }
            _ => return Err(error(&r)),
        }
        self.ensure_pass().await
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        let path = format!("/v1/vault/chunks/{}", name.to_hex());
        let r = self
            .write(|| self.request("PUT", &path, Some(object.clone()), true))
            .await?;
        if r.ok() { Ok(()) } else { Err(error(&r)) }
    }

    async fn get(&self, name: &ChunkName) -> Result<Vec<u8>, StoreError> {
        let path = format!("/v1/vault/chunks/{}", name.to_hex());
        let r = self.send(self.request("GET", &path, None, false)?).await?;
        if r.ok() { Ok(r.body) } else { Err(error(&r)) }
    }

    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        let mut out = vec![];
        let mut after: Option<[u8; 32]> = None;
        loop {
            let path = match after {
                Some(a) => format!("/v1/vault/chunks?after={}", hex::encode(a)),
                None => "/v1/vault/chunks".to_owned(),
            };
            let r = self.send(self.request("GET", &path, None, false)?).await?;
            if !r.ok() {
                return Err(error(&r));
            }
            let (names, more) = wire::decode_page(&r.body).ok_or(StoreError::Protocol("list"))?;
            if more && names.is_empty() {
                return Err(StoreError::Protocol("list"));
            }
            after = names.last().copied();
            out.extend(names.into_iter().map(ChunkName));
            if !more {
                return Ok(out);
            }
        }
    }

    async fn delete(&self, names: &[ChunkName]) -> Result<(), StoreError> {
        for part in names.chunks(wire::MAX_NAMES) {
            let raw: Vec<[u8; 32]> = part.iter().map(|n| n.0).collect();
            let body = wire::encode_names(&raw);
            let r = self
                .write(|| self.request("POST", "/v1/vault/chunks/delete", Some(body.clone()), true))
                .await?;
            if !r.ok() {
                return Err(error(&r));
            }
        }
        Ok(())
    }

    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let r = self
            .send(self.request("GET", "/v1/vault/manifest", None, false)?)
            .await?;
        match r.status {
            200 => Ok(Some(r.body)),
            204 => Ok(None),
            _ => Err(error(&r)),
        }
    }

    async fn swap_manifest(&self, expected: u64, object: Vec<u8>) -> Result<(), StoreError> {
        check_next(expected, &object)?;
        let r = self
            .write(|| {
                Ok(self
                    .request("PUT", "/v1/vault/manifest", Some(object.clone()), true)?
                    .header(wire::EXPECTED_HEADER, expected.to_string()))
            })
            .await?;
        if r.ok() { Ok(()) } else { Err(error(&r)) }
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        let r = match self
            .write(|| self.request("DELETE", "/v1/vault", None, true))
            .await
        {
            Err(StoreError::NotFound) => return Ok(()),
            r => r?,
        };
        if r.ok() || r.status == 404 {
            Ok(())
        } else {
            Err(error(&r))
        }
    }
}
