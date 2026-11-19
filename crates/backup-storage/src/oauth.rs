//! OAuth 2.0 for native apps (RFC 8252) with PKCE (RFC 7636), for the Google Drive, OneDrive
//! and Dropbox app folders. Everything here runs on the device: the client IDs are public (no
//! client secret), the tokens are the user's and stay in the app's keychain, and Songbird's
//! servers never see them.
//!
//! The adapters ask a [`TokenSource`] for a bearer token and ask it to refresh once on a 401.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use aws_lc_rs::digest;
use zeroize::Zeroizing;

use crate::http::{Http, Request, encode};
use crate::store::{StoreError, status_error};

/// A provider's endpoints and the app-folder scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The authorization endpoint (opened in the browser).
    pub authorize: String,
    /// The token endpoint.
    pub token: String,
    /// Scopes, space-separated.
    pub scope: String,
    /// Extra authorization parameters (`token_access_type=offline` for Dropbox, …).
    pub extra: Vec<(String, String)>,
}

impl Provider {
    /// Google Drive's hidden app data folder (`drive.appdata`: the app sees only its own files).
    #[must_use]
    pub fn google() -> Self {
        Self {
            authorize: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token: "https://oauth2.googleapis.com/token".into(),
            scope: "https://www.googleapis.com/auth/drive.appdata".into(),
            extra: vec![
                ("access_type".into(), "offline".into()),
                ("prompt".into(), "consent".into()),
            ],
        }
    }

    /// OneDrive's app folder (`Files.ReadWrite.AppFolder`), personal and work accounts.
    #[must_use]
    pub fn microsoft() -> Self {
        Self {
            authorize: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
            token: "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
            scope: "Files.ReadWrite.AppFolder offline_access".into(),
            extra: vec![],
        }
    }

    /// Dropbox, an app registered with the "App folder" access type.
    #[must_use]
    pub fn dropbox() -> Self {
        Self {
            authorize: "https://www.dropbox.com/oauth2/authorize".into(),
            token: "https://api.dropboxapi.com/oauth2/token".into(),
            scope: "files.content.read files.content.write".into(),
            extra: vec![("token_access_type".into(), "offline".into())],
        }
    }
}

/// A PKCE verifier (43 characters of `[A-Za-z0-9-._~]` from 32 random bytes) and its S256
/// challenge.
pub struct Pkce {
    /// Sent with the token request; never leaves the device before that.
    pub verifier: Zeroizing<String>,
    /// `BASE64URL(SHA-256(verifier))`, sent with the authorization request.
    pub challenge: String,
}

impl std::fmt::Debug for Pkce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pkce { .. }")
    }
}

fn b64url(b: &[u8]) -> String {
    songbird_s3::sigv4::base64(b)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

impl Pkce {
    /// A fresh verifier.
    ///
    /// # Errors
    /// [`StoreError::Protocol`] when there is no randomness.
    pub fn new() -> Result<Self, StoreError> {
        let mut r = Zeroizing::new([0u8; 32]);
        getrandom::fill(r.as_mut()).map_err(|_| StoreError::Protocol("randomness"))?;
        let verifier = Zeroizing::new(b64url(r.as_ref()));
        let challenge = b64url(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref());
        Ok(Self {
            verifier,
            challenge,
        })
    }

    /// The challenge for a given verifier (RFC 7636 appendix B's vector is a test).
    #[must_use]
    pub fn challenge_of(verifier: &str) -> String {
        b64url(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref())
    }
}

/// A random `state` value for the authorization request (checked on the redirect).
///
/// # Errors
/// [`StoreError::Protocol`] when there is no randomness.
pub fn state() -> Result<String, StoreError> {
    let mut r = [0u8; 16];
    getrandom::fill(&mut r).map_err(|_| StoreError::Protocol("randomness"))?;
    Ok(b64url(&r))
}

/// The tokens of one signed-in account. `Debug` shows nothing of them.
#[derive(Clone)]
pub struct Tokens {
    /// The bearer token.
    pub access: Zeroizing<String>,
    /// The refresh token, if the provider gave one.
    pub refresh: Option<Zeroizing<String>>,
    /// When the access token expires (Unix seconds).
    pub expires_at: u64,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// A public client of one provider.
#[derive(Debug, Clone)]
pub struct Client {
    /// The provider.
    pub provider: Provider,
    /// The registered client ID (public).
    pub client_id: String,
    /// The redirect URI (a loopback `http://127.0.0.1:<port>/` on desktop, RFC 8252 §7.3).
    pub redirect_uri: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

fn parse_tokens(
    body: &[u8],
    old_refresh: Option<&Zeroizing<String>>,
) -> Result<Tokens, StoreError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| StoreError::Protocol("token"))?;
    let access = v
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .ok_or(StoreError::Protocol("token"))?;
    let refresh = v
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .map(|r| Zeroizing::new(r.to_owned()))
        .or_else(|| old_refresh.cloned());
    let expires = v
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(3_600);
    Ok(Tokens {
        access: Zeroizing::new(access.to_owned()),
        refresh,
        // A minute early, so a token never expires in flight.
        expires_at: now() + expires.saturating_sub(60),
    })
}

impl Client {
    /// The URL to open in the browser.
    #[must_use]
    pub fn authorize_url(&self, pkce: &Pkce, state: &str) -> String {
        let mut q = vec![
            ("response_type".to_owned(), "code".to_owned()),
            ("client_id".to_owned(), self.client_id.clone()),
            ("redirect_uri".to_owned(), self.redirect_uri.clone()),
            ("scope".to_owned(), self.provider.scope.clone()),
            ("state".to_owned(), state.to_owned()),
            ("code_challenge".to_owned(), pkce.challenge.clone()),
            ("code_challenge_method".to_owned(), "S256".to_owned()),
        ];
        q.extend(self.provider.extra.iter().cloned());
        let query: Vec<String> = q
            .iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect();
        format!("{}?{}", self.provider.authorize, query.join("&"))
    }

    /// Exchanges the code from the redirect (after checking its `state`) for tokens.
    ///
    /// # Errors
    /// [`StoreError::Unauthorized`] for a refused code; [`StoreError::Protocol`].
    pub async fn exchange(
        &self,
        http: &dyn Http,
        code: &str,
        pkce: &Pkce,
    ) -> Result<Tokens, StoreError> {
        let body = form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", &self.client_id),
            ("code_verifier", &pkce.verifier),
        ]);
        let r = http
            .send(
                Request::new("POST", self.provider.token.clone())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body),
            )
            .await?;
        match r.status {
            200 => parse_tokens(&r.body, None),
            400 | 401 => Err(StoreError::Unauthorized),
            s => Err(status_error(s)),
        }
    }

    /// A new access token from the refresh token.
    ///
    /// # Errors
    /// [`StoreError::Unauthorized`] when the user revoked access (sign in again).
    pub async fn refresh(&self, http: &dyn Http, tokens: &Tokens) -> Result<Tokens, StoreError> {
        let rt = tokens.refresh.as_ref().ok_or(StoreError::Unauthorized)?;
        let body = form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt),
            ("client_id", &self.client_id),
        ]);
        let r = http
            .send(
                Request::new("POST", self.provider.token.clone())
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body),
            )
            .await?;
        match r.status {
            200 => parse_tokens(&r.body, Some(rt)),
            400 | 401 => Err(StoreError::Unauthorized),
            s => Err(status_error(s)),
        }
    }
}

/// Where adapters get a bearer token.
#[async_trait]
pub trait TokenSource: Send + Sync {
    /// The current access token.
    async fn token(&self) -> Result<Zeroizing<String>, StoreError>;
    /// A new access token (after a 401).
    async fn refresh(&self) -> Result<Zeroizing<String>, StoreError>;
}

/// A fixed token (tests and short-lived tools).
pub struct StaticToken(pub Zeroizing<String>);

impl std::fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticToken(..)")
    }
}

#[async_trait]
impl TokenSource for StaticToken {
    async fn token(&self) -> Result<Zeroizing<String>, StoreError> {
        Ok(self.0.clone())
    }
    async fn refresh(&self) -> Result<Zeroizing<String>, StoreError> {
        Err(StoreError::Unauthorized)
    }
}

/// Tokens that refresh themselves and report every new set (so the app can keep them in its
/// keychain).
pub struct Refreshing {
    client: Client,
    http: Arc<dyn Http>,
    tokens: Mutex<Tokens>,
    saved: Box<dyn Fn(&Tokens) + Send + Sync>,
}

impl std::fmt::Debug for Refreshing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Refreshing { .. }")
    }
}

impl Refreshing {
    /// Tokens of `client`, saved through `saved` whenever they change.
    pub fn new(
        client: Client,
        http: Arc<dyn Http>,
        tokens: Tokens,
        saved: Box<dyn Fn(&Tokens) + Send + Sync>,
    ) -> Self {
        Self {
            client,
            http,
            tokens: Mutex::new(tokens),
            saved,
        }
    }

    fn current(&self) -> Tokens {
        self.tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl TokenSource for Refreshing {
    async fn token(&self) -> Result<Zeroizing<String>, StoreError> {
        let t = self.current();
        if t.expires_at > now() {
            return Ok(t.access);
        }
        self.refresh().await
    }

    async fn refresh(&self) -> Result<Zeroizing<String>, StoreError> {
        let t = self.current();
        let fresh = self.client.refresh(self.http.as_ref(), &t).await?;
        (self.saved)(&fresh);
        let access = fresh.access.clone();
        *self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
        Ok(access)
    }
}

/// Sends a request with a bearer token, refreshing it once on a 401.
///
/// # Errors
/// The transport's errors.
pub async fn send_authorized(
    http: &dyn Http,
    tokens: &dyn TokenSource,
    req: Request,
) -> Result<crate::http::Response, StoreError> {
    let t = tokens.token().await?;
    let r = http
        .send(
            req.clone()
                .header("authorization", format!("Bearer {}", t.as_str())),
        )
        .await?;
    if r.status != 401 {
        return Ok(r);
    }
    let t = tokens.refresh().await?;
    http.send(req.header("authorization", format!("Bearer {}", t.as_str())))
        .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn pkce_matches_rfc_7636_appendix_b() {
        assert_eq!(
            Pkce::challenge_of("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let p = Pkce::new().unwrap();
        assert_eq!(p.verifier.len(), 43);
        assert_eq!(Pkce::challenge_of(&p.verifier), p.challenge);
        assert_eq!(format!("{p:?}"), "Pkce { .. }");
    }

    #[test]
    fn the_authorize_url_carries_pkce_state_and_the_app_folder_scope() {
        let c = Client {
            provider: Provider::google(),
            client_id: "id.apps.googleusercontent.com".into(),
            redirect_uri: "http://127.0.0.1:53682/".into(),
        };
        let p = Pkce::new().unwrap();
        let u = c.authorize_url(&p, "st8");
        assert!(u.starts_with("https://accounts.google.com/o/oauth2/v2/auth?response_type=code&"));
        assert!(
            u.contains("code_challenge_method=S256")
                && u.contains(&p.challenge)
                && u.contains("state=st8")
        );
        assert!(u.contains("drive.appdata") && !u.contains(p.verifier.as_str()));
    }
}
