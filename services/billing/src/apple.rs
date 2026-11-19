//! The App Store (D-0129): `StoreKit` 2 signed transactions, the App Store Server API, and App
//! Store Server Notifications V2. Everything Apple signs is a JWS whose `x5c` chain ends at the
//! pinned Apple root ([`crate::jose::AppleTrust`]).
//!
//! The app never sets `appAccountToken`: Apple holds no Songbird identifier, and a transaction
//! carrying one is refused (D-0126 §14).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls_pki_types::UnixTime;
use serde_json::{Value, json};

use crate::http::{Client, encode};
use crate::jose::{AppleTrust, Es256};
use crate::store::State;
use crate::{Env, Products, ProviderError, day_of_ms};

/// One verified transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The subscription's original transaction ID (names its row, hashed).
    pub original: String,
    /// The product.
    pub product: String,
    /// When the period paid for ends (milliseconds).
    pub expires_ms: u64,
    /// Refunded or revoked.
    pub revoked: bool,
    /// When Apple signed it (milliseconds).
    pub signed_ms: u64,
}

/// One verified renewal info.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Renewal {
    /// Renews automatically.
    pub renews: bool,
    /// The end of a billing grace period, if in one (milliseconds).
    pub grace_ms: Option<u64>,
}

/// A verified notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Its UUID (replays are recognised by it).
    pub uuid: String,
    /// `notificationType`.
    pub kind: String,
    /// The transaction it is about, if any (`TEST` has none).
    pub transaction: Option<Transaction>,
    /// The renewal info, if any.
    pub renewal: Option<Renewal>,
    /// When Apple signed it (milliseconds).
    pub signed_ms: u64,
}

/// The App Store Server API's credentials.
#[derive(Debug)]
pub struct ServerApi {
    /// `https://api.storekit.itunes.apple.com` (or the sandbox's, or an emulator's).
    pub base: String,
    /// App Store Connect's issuer ID.
    pub issuer: String,
    /// The In-App Purchase key's ID.
    pub key_id: String,
    /// The In-App Purchase key.
    pub key: Es256,
}

/// The App Store.
#[derive(Debug)]
pub struct Apple {
    trust: AppleTrust,
    bundle: String,
    env: Env,
    api: Option<ServerApi>,
    http: Client,
}

fn ms(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

impl Apple {
    /// The App Store for `bundle` in `env`.
    #[must_use]
    pub fn new(
        trust: AppleTrust,
        bundle: String,
        env: Env,
        api: Option<ServerApi>,
        http: Client,
    ) -> Self {
        Self {
            trust,
            bundle,
            env,
            api,
            http,
        }
    }

    fn check_env(&self, v: &Value) -> Result<(), ProviderError> {
        let want = match self.env {
            Env::Production => "Production",
            Env::Sandbox => "Sandbox",
        };
        if v.get("bundleId").and_then(Value::as_str) != Some(self.bundle.as_str())
            || v.get("environment").and_then(Value::as_str) != Some(want)
        {
            return Err(ProviderError::Refused);
        }
        Ok(())
    }

    fn verified(&self, jws: &str) -> Result<Value, ProviderError> {
        let payload = self
            .trust
            .verify(jws, UnixTime::now())
            .map_err(|_| ProviderError::Refused)?;
        serde_json::from_slice(&payload).map_err(|_| ProviderError::Refused)
    }

    /// Verifies a signed transaction (`JWSTransaction`).
    ///
    /// # Errors
    /// [`ProviderError::Refused`]: not Apple's, another app or environment, not an
    /// auto-renewable subscription, or carrying an account token.
    pub fn transaction(&self, jws: &str) -> Result<Transaction, ProviderError> {
        let v = self.verified(jws)?;
        self.check_env(&v)?;
        if v.get("type").and_then(Value::as_str) != Some("Auto-Renewable Subscription")
            || v.get("appAccountToken").is_some()
        {
            return Err(ProviderError::Refused);
        }
        Ok(Transaction {
            original: v
                .get("originalTransactionId")
                .and_then(Value::as_str)
                .ok_or(ProviderError::Refused)?
                .to_owned(),
            product: v
                .get("productId")
                .and_then(Value::as_str)
                .ok_or(ProviderError::Refused)?
                .to_owned(),
            expires_ms: ms(&v, "expiresDate").ok_or(ProviderError::Refused)?,
            revoked: v.get("revocationDate").is_some(),
            signed_ms: ms(&v, "signedDate").unwrap_or(0),
        })
    }

    /// Verifies a signed renewal info (`JWSRenewalInfo`).
    ///
    /// # Errors
    /// [`ProviderError::Refused`].
    pub fn renewal(&self, jws: &str) -> Result<Renewal, ProviderError> {
        let v = self.verified(jws)?;
        if v.get("environment").and_then(Value::as_str)
            != Some(match self.env {
                Env::Production => "Production",
                Env::Sandbox => "Sandbox",
            })
        {
            return Err(ProviderError::Refused);
        }
        Ok(Renewal {
            renews: v.get("autoRenewStatus").and_then(Value::as_u64) == Some(1),
            grace_ms: ms(&v, "gracePeriodExpiresDate"),
        })
    }

    /// Verifies an App Store Server Notification V2 (`{"signedPayload": …}`).
    ///
    /// # Errors
    /// [`ProviderError::Refused`].
    pub fn notification(&self, body: &[u8]) -> Result<Notification, ProviderError> {
        let outer: Value = serde_json::from_slice(body).map_err(|_| ProviderError::Refused)?;
        let jws = outer
            .get("signedPayload")
            .and_then(Value::as_str)
            .ok_or(ProviderError::Refused)?;
        let v = self.verified(jws)?;
        if v.get("version").and_then(Value::as_str) != Some("2.0") {
            return Err(ProviderError::Refused);
        }
        let data = v.get("data").ok_or(ProviderError::Refused)?;
        self.check_env(data)?;
        let transaction = data
            .get("signedTransactionInfo")
            .and_then(Value::as_str)
            .map(|t| self.transaction(t))
            .transpose()?;
        let renewal = data
            .get("signedRenewalInfo")
            .and_then(Value::as_str)
            .map(|r| self.renewal(r))
            .transpose()?;
        Ok(Notification {
            uuid: v
                .get("notificationUUID")
                .and_then(Value::as_str)
                .ok_or(ProviderError::Refused)?
                .to_owned(),
            kind: v
                .get("notificationType")
                .and_then(Value::as_str)
                .ok_or(ProviderError::Refused)?
                .to_owned(),
            transaction,
            renewal,
            signed_ms: ms(&v, "signedDate").unwrap_or(0),
        })
    }

    /// The state a transaction and its renewal info describe.
    #[must_use]
    pub fn state(t: &Transaction, r: Option<Renewal>, plan: &'static str) -> State {
        let r = r.unwrap_or_default();
        let end = r.grace_ms.map_or(t.expires_ms, |g| g.max(t.expires_ms));
        State {
            provider: "apple",
            plan,
            paid: day_of_ms(end.saturating_sub(1)),
            revoked: t.revoked,
            renews: r.renews && !t.revoked,
        }
    }

    fn token(&self, api: &ServerApi) -> Result<String, ProviderError> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        api.key
            .sign(
                &json!({ "alg": "ES256", "kid": api.key_id, "typ": "JWT" }),
                &json!({
                    "iss": api.issuer,
                    "iat": iat,
                    "exp": iat + 300,
                    "aud": "appstoreconnect-v1",
                    "bid": self.bundle,
                }),
            )
            .ok_or(ProviderError::Unavailable)
    }

    /// The current state from the App Store Server API (Get All Subscription Statuses), or
    /// `None` when the API is not configured. Returns the state and the time of the answer (an
    /// authoritative answer outranks every notification signed before it).
    ///
    /// # Errors
    /// [`ProviderError::Unavailable`] (Apple unreachable), [`ProviderError::Refused`] (no such
    /// subscription, or an answer that does not verify).
    pub async fn status(
        &self,
        original: &str,
        products: &Products,
    ) -> Result<Option<(State, Option<u64>)>, ProviderError> {
        let Some(api) = &self.api else {
            return Ok(None);
        };
        let bearer = format!("Bearer {}", self.token(api)?);
        let r = self
            .http
            .send(
                "GET",
                &format!("{}/inApps/v1/subscriptions/{}", api.base, encode(original)),
                &[("authorization", bearer.as_str())],
                Vec::new(),
            )
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        match r.status {
            200 => {}
            404 | 400 => return Err(ProviderError::Refused),
            _ => return Err(ProviderError::Unavailable),
        }
        let v: Value = serde_json::from_slice(&r.body).map_err(|_| ProviderError::Unavailable)?;
        let last = v
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|g| g.get("lastTransactions").and_then(Value::as_array))
            .flatten()
            .find(|t| t.get("originalTransactionId").and_then(Value::as_str) == Some(original))
            .ok_or(ProviderError::Refused)?;
        let t = self.transaction(
            last.get("signedTransactionInfo")
                .and_then(Value::as_str)
                .ok_or(ProviderError::Refused)?,
        )?;
        if t.original != original {
            return Err(ProviderError::Refused);
        }
        let r = last
            .get("signedRenewalInfo")
            .and_then(Value::as_str)
            .map(|j| self.renewal(j))
            .transpose()?;
        let plan = products.plan(&t.product).ok_or(ProviderError::Refused)?;
        let mut s = Self::state(&t, r, plan);
        // Status 5: revoked; 2: expired (whatever the dates say).
        match last.get("status").and_then(Value::as_u64) {
            Some(5) => {
                s.revoked = true;
                s.renews = false;
            }
            Some(2) => s.renews = false,
            _ => {}
        }
        Ok(Some((s, None)))
    }
}
