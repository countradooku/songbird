//! The Songbird vault adapter (PROTOCOL §11.8): the vault ID and access secret come from the
//! recovery key, so a new device with only the key can find and read its backup. Writes are
//! also signed by the account's primary device ([`Signer`]).

use std::sync::Arc;

use async_trait::async_trait;
use songbird_backup_format::{BackupKeys, ChunkName};
use songbird_proto::vault as wire;
use zeroize::Zeroizing;

use crate::http::{Http, Request, Response};
use crate::store::{BackupStore, StoreError, check_next, status_error};

/// Signs a request as the account's primary device (`authorization: Songbird …`, PROTOCOL
/// §2.4). The app signs with the device key it keeps; nothing here sees that key.
pub trait Signer: Send + Sync {
    /// The `authorization` header, and the `x-songbird-content-sha256` header for a body.
    fn sign(&self, method: &str, path: &str, body: Option<&[u8]>) -> (String, Option<String>);
}

/// A backup in the Songbird vault.
pub struct VaultStore {
    http: Arc<dyn Http>,
    base: String,
    id_hex: String,
    access_hex: Zeroizing<String>,
    signer: Option<Arc<dyn Signer>>,
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
    /// The vault `keys` name at `base` (`https://api.example`), read-only without a signer.
    #[must_use]
    pub fn new(
        http: Arc<dyn Http>,
        base: impl Into<String>,
        keys: &BackupKeys,
        signer: Option<Arc<dyn Signer>>,
    ) -> Self {
        Self {
            http,
            base: base.into().trim_end_matches('/').to_owned(),
            id_hex: hex::encode(keys.vault_id),
            access_hex: Zeroizing::new(hex::encode(*keys.vault_access)),
            signer,
        }
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        signed: bool,
    ) -> Result<Request, StoreError> {
        let mut r = Request::new(method, format!("{}{path}", self.base))
            .header(wire::VAULT_HEADER, self.id_hex.clone())
            .header(wire::ACCESS_HEADER, self.access_hex.as_str());
        if signed {
            let s = self.signer.as_ref().ok_or(StoreError::Unauthorized)?;
            // The signature covers the path without its query.
            let p = path.split('?').next().unwrap_or(path);
            let (auth, digest) = s.sign(method, p, body.as_deref());
            r = r.header("authorization", auth);
            if let Some(d) = digest {
                r = r.header("x-songbird-content-sha256", d);
            }
        }
        if let Some(b) = body {
            r = r.header("content-type", "application/octet-stream").body(b);
        }
        Ok(r)
    }

    async fn send(&self, r: Request) -> Result<Response, StoreError> {
        self.http.send(r).await
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
        let r = self
            .send(self.request("POST", "/v1/vault", None, true)?)
            .await?;
        if r.ok() { Ok(()) } else { Err(error(&r)) }
    }

    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        let path = format!("/v1/vault/chunks/{}", name.to_hex());
        let r = self
            .send(self.request("PUT", &path, Some(object), true)?)
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
                .send(self.request("POST", "/v1/vault/chunks/delete", Some(body), true)?)
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
            .request("PUT", "/v1/vault/manifest", Some(object), true)?
            .header(wire::EXPECTED_HEADER, expected.to_string());
        let r = self.send(r).await?;
        if r.ok() { Ok(()) } else { Err(error(&r)) }
    }

    async fn destroy(&self) -> Result<(), StoreError> {
        let r = self
            .send(self.request("DELETE", "/v1/vault", None, true)?)
            .await?;
        if r.ok() || r.status == 404 {
            Ok(())
        } else {
            Err(error(&r))
        }
    }
}
