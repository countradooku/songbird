//! Google Play (D-0129): the Play Developer API (`purchases.subscriptionsv2.get`, acknowledge)
//! under a service account, and real-time developer notifications delivered by Pub/Sub push
//! with Google's OIDC token. A notification carries only a purchase token: the state always
//! comes from the API, so a replayed or reordered notification changes nothing.
//!
//! The app never sets `obfuscatedExternalAccountId`: Google holds no Songbird identifier, and a
//! purchase carrying one is refused.

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};

use crate::http::{Client, encode};
use crate::jose::{self, JoseError, Rs256, RsaJwk};
use crate::store::State;
use crate::{Env, Products, ProviderError, now_ms};

/// A service account: its e-mail, key and token endpoint.
#[derive(Debug)]
pub struct ServiceAccount {
    /// `client_email`.
    pub email: String,
    /// `private_key` (PKCS#8).
    pub key: Rs256,
    /// `token_uri`.
    pub token_uri: String,
}

impl ServiceAccount {
    /// From Google's JSON key file.
    ///
    /// # Errors
    /// A missing field or a key that is not RSA PKCS#8.
    pub fn from_json(json: &[u8]) -> Result<Self, &'static str> {
        let v: Value = serde_json::from_slice(json).map_err(|_| "service account: not JSON")?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let pem = s("private_key").ok_or("service account: no private_key")?;
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .concat();
        let der = jose::b64_decode(&b64).ok_or("service account: private_key is not PEM")?;
        Ok(Self {
            email: s("client_email").ok_or("service account: no client_email")?,
            key: Rs256::from_pkcs8(&der)?,
            token_uri: s("token_uri").ok_or("service account: no token_uri")?,
        })
    }
}

/// Who may push notifications: the Pub/Sub subscription's OIDC audience and service account.
#[derive(Debug, Clone)]
pub struct PushAuth {
    /// The `aud` the push subscription was configured with.
    pub audience: String,
    /// The push subscription's service account (`email`).
    pub email: String,
    /// Google's signing keys (`https://www.googleapis.com/oauth2/v3/certs`).
    pub certs_url: String,
}

/// What the API says about a purchase token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Purchase {
    /// The state.
    pub state: State,
    /// The product (subscription) ID, for acknowledgement.
    pub product: String,
    /// Not acknowledged yet (Google refunds unacknowledged purchases after three days).
    pub needs_ack: bool,
}

/// A decoded notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rtdn {
    /// A subscription changed: fetch its state.
    Subscription {
        /// Pub/Sub's message ID.
        id: String,
        /// The purchase token.
        token: String,
    },
    /// A purchase was voided (refund, chargeback).
    Voided {
        /// Pub/Sub's message ID.
        id: String,
        /// The purchase token.
        token: String,
    },
    /// The console's test notification, or something not about subscriptions.
    Other {
        /// Pub/Sub's message ID.
        id: String,
    },
}

/// Google Play.
#[derive(Debug)]
pub struct Google {
    package: String,
    env: Env,
    account: ServiceAccount,
    api: String,
    push: PushAuth,
    http: Client,
    token: Mutex<Option<(String, u64)>>,
    certs: Mutex<(Vec<RsaJwk>, u64)>,
}

/// Parses an RFC 3339 UTC time (`2026-12-17T10:20:30.123Z`) to Unix milliseconds.
#[must_use]
#[allow(
    clippy::many_single_char_names,
    reason = "year, month, day, hour, minute, second: the format's own fields"
)]
pub fn rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b.get(10) != Some(&b'T') || b.last() != Some(&b'Z') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<u32>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || mo == 0
        || mo > 12
        || d == 0
        || d > 31
        || h > 23
        || mi > 59
        || se > 60
    {
        return None;
    }
    let frac = match s.get(19..s.len() - 1)? {
        "" => 0,
        f if f.starts_with('.') && f.len() > 1 && f.len() <= 10 => {
            let digits = f.get(1..)?;
            let mut v: u64 = digits.get(..digits.len().min(3))?.parse().ok()?;
            for _ in digits.len()..3 {
                v *= 10;
            }
            digits.bytes().all(|c| c.is_ascii_digit()).then_some(v)?
        }
        _ => return None,
    };
    let days = u64::try_from(songbird_tokens::token::days_from_civil(i64::from(y), mo, d)).ok()?;
    Some(
        ((days * 86_400 + u64::from(h) * 3_600 + u64::from(mi) * 60 + u64::from(se)) * 1_000)
            + frac,
    )
}

impl Google {
    /// Google Play for `package` in `env`.
    #[must_use]
    pub fn new(
        package: String,
        env: Env,
        account: ServiceAccount,
        api: String,
        push: PushAuth,
        http: Client,
    ) -> Self {
        Self {
            package,
            env,
            account,
            api,
            push,
            http,
            token: Mutex::new(None),
            certs: Mutex::new((Vec::new(), 0)),
        }
    }

    /// An OAuth access token for the Play Developer API (cached until a minute before expiry).
    async fn access_token(&self) -> Result<String, ProviderError> {
        let now = now_ms() / 1_000;
        if let Ok(g) = self.token.lock()
            && let Some((t, exp)) = g.as_ref()
            && *exp > now + 60
        {
            return Ok(t.clone());
        }
        let assertion = self
            .account
            .key
            .sign(
                &json!({ "alg": "RS256", "typ": "JWT" }),
                &json!({
                    "iss": self.account.email,
                    "scope": "https://www.googleapis.com/auth/androidpublisher",
                    "aud": self.account.token_uri,
                    "iat": now,
                    "exp": now + 3_600,
                }),
            )
            .ok_or(ProviderError::Unavailable)?;
        let form = format!(
            "grant_type={}&assertion={}",
            encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            encode(&assertion)
        );
        let r = self
            .http
            .send(
                "POST",
                &self.account.token_uri,
                &[("content-type", "application/x-www-form-urlencoded")],
                form.into_bytes(),
            )
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        if !r.ok() {
            return Err(ProviderError::Unavailable);
        }
        let v: Value = serde_json::from_slice(&r.body).map_err(|_| ProviderError::Unavailable)?;
        let t = v
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or(ProviderError::Unavailable)?
            .to_owned();
        let exp = now + v.get("expires_in").and_then(Value::as_u64).unwrap_or(300);
        if let Ok(mut g) = self.token.lock() {
            *g = Some((t.clone(), exp));
        }
        Ok(t)
    }

    /// `purchases.subscriptionsv2.get`.
    ///
    /// # Errors
    /// [`ProviderError::Refused`] (unknown token, another package, a test purchase in
    /// production, an account identifier set, an unknown product); [`ProviderError::Unavailable`].
    pub async fn purchase(
        &self,
        token: &str,
        products: &Products,
    ) -> Result<Purchase, ProviderError> {
        if token.is_empty() || token.len() > 1_024 {
            return Err(ProviderError::Refused);
        }
        let bearer = format!("Bearer {}", self.access_token().await?);
        let url = format!(
            "{}/androidpublisher/v3/applications/{}/purchases/subscriptionsv2/tokens/{}",
            self.api,
            encode(&self.package),
            encode(token)
        );
        let r = self
            .http
            .send(
                "GET",
                &url,
                &[("authorization", bearer.as_str())],
                Vec::new(),
            )
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        match r.status {
            200 => {}
            400 | 404 | 410 => return Err(ProviderError::Refused),
            _ => return Err(ProviderError::Unavailable),
        }
        let v: Value = serde_json::from_slice(&r.body).map_err(|_| ProviderError::Unavailable)?;
        if v.get("testPurchase").is_some() && self.env == Env::Production {
            return Err(ProviderError::Refused);
        }
        if v.pointer("/externalAccountIdentifiers/obfuscatedExternalAccountId")
            .is_some()
        {
            return Err(ProviderError::Refused);
        }
        let item = v
            .get("lineItems")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .ok_or(ProviderError::Refused)?;
        let product = item
            .get("productId")
            .and_then(Value::as_str)
            .ok_or(ProviderError::Refused)?
            .to_owned();
        let plan = products.plan(&product).ok_or(ProviderError::Refused)?;
        let expiry = item
            .get("expiryTime")
            .and_then(Value::as_str)
            .and_then(rfc3339_ms)
            .ok_or(ProviderError::Refused)?;
        let state = v
            .get("subscriptionState")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let entitled = matches!(
            state,
            "SUBSCRIPTION_STATE_ACTIVE"
                | "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"
                | "SUBSCRIPTION_STATE_CANCELED"
        );
        let today_ms = now_ms();
        let paid_ms = if entitled {
            expiry
        } else {
            expiry.min(today_ms.saturating_sub(86_400_000))
        };
        Ok(Purchase {
            state: State {
                provider: "google",
                plan,
                paid: crate::day_of_ms(paid_ms.saturating_sub(1)),
                revoked: false,
                renews: state == "SUBSCRIPTION_STATE_ACTIVE"
                    && item
                        .pointer("/autoRenewingPlan/autoRenewEnabled")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
            },
            product,
            needs_ack: v.get("acknowledgementState").and_then(Value::as_str)
                == Some("ACKNOWLEDGEMENT_STATE_PENDING"),
        })
    }

    /// Acknowledges a purchase (idempotent at Google).
    ///
    /// # Errors
    /// [`ProviderError::Unavailable`].
    pub async fn acknowledge(&self, product: &str, token: &str) -> Result<(), ProviderError> {
        let bearer = format!("Bearer {}", self.access_token().await?);
        let url = format!(
            "{}/androidpublisher/v3/applications/{}/purchases/subscriptions/{}/tokens/{}:acknowledge",
            self.api,
            encode(&self.package),
            encode(product),
            encode(token)
        );
        let r = self
            .http
            .send(
                "POST",
                &url,
                &[
                    ("authorization", bearer.as_str()),
                    ("content-type", "application/json"),
                ],
                b"{}".to_vec(),
            )
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        if r.ok() {
            Ok(())
        } else {
            Err(ProviderError::Unavailable)
        }
    }

    async fn keys(&self, refresh: bool) -> Result<Vec<RsaJwk>, ProviderError> {
        let now = now_ms() / 1_000;
        // A forced refresh (an unknown key) at most once a minute: forged tokens naming made-up
        // keys cannot turn into a stream of fetches from Google (D-0134).
        if let Ok(g) = self.certs.lock()
            && !g.0.is_empty()
            && (g.1 + 3_600 > now && (!refresh || g.1 + 60 > now))
        {
            return Ok(g.0.clone());
        }
        let r = self
            .http
            .send("GET", &self.push.certs_url, &[], Vec::new())
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        if !r.ok() {
            return Err(ProviderError::Unavailable);
        }
        let keys = jose::rsa_jwks(&r.body);
        if keys.is_empty() {
            return Err(ProviderError::Unavailable);
        }
        if let Ok(mut g) = self.certs.lock() {
            *g = (keys.clone(), now);
        }
        Ok(keys)
    }

    /// Checks a Pub/Sub push's `Authorization: Bearer` OIDC token: Google's signature, issuer,
    /// audience, the push subscription's service account, verified e-mail, not expired.
    ///
    /// # Errors
    /// [`ProviderError::Refused`]; [`ProviderError::Unavailable`] when Google's keys cannot be
    /// fetched.
    pub async fn verify_push(&self, bearer: &str) -> Result<(), ProviderError> {
        let claims = match jose::verify_rs256(bearer, &self.keys(false).await?) {
            Err(JoseError::Signature) => {
                // A key rotated since the last fetch: one refresh.
                jose::verify_rs256(bearer, &self.keys(true).await?)
            }
            r => r,
        }
        .map_err(|_| ProviderError::Refused)?;
        let s = |k: &str| claims.get(k).and_then(Value::as_str);
        let exp = claims.get("exp").and_then(Value::as_u64).unwrap_or(0);
        let ok = matches!(
            s("iss"),
            Some("https://accounts.google.com" | "accounts.google.com")
        ) && s("aud") == Some(self.push.audience.as_str())
            && s("email") == Some(self.push.email.as_str())
            && claims.get("email_verified").and_then(Value::as_bool) == Some(true)
            && exp > now_ms() / 1_000;
        if ok {
            Ok(())
        } else {
            Err(ProviderError::Refused)
        }
    }

    /// Decodes a Pub/Sub push body carrying a real-time developer notification.
    ///
    /// # Errors
    /// [`ProviderError::Refused`] for another package or a malformed body.
    pub fn rtdn(&self, body: &[u8]) -> Result<Rtdn, ProviderError> {
        let v: Value = serde_json::from_slice(body).map_err(|_| ProviderError::Refused)?;
        let id = v
            .pointer("/message/messageId")
            .and_then(Value::as_str)
            .ok_or(ProviderError::Refused)?
            .to_owned();
        let data = v
            .pointer("/message/data")
            .and_then(Value::as_str)
            .and_then(jose::b64_decode)
            .ok_or(ProviderError::Refused)?;
        let n: Value = serde_json::from_slice(&data).map_err(|_| ProviderError::Refused)?;
        if n.get("packageName").and_then(Value::as_str) != Some(self.package.as_str()) {
            return Err(ProviderError::Refused);
        }
        let token = |k: &str| {
            n.pointer(&format!("/{k}/purchaseToken"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        Ok(if let Some(token) = token("subscriptionNotification") {
            Rtdn::Subscription { id, token }
        } else if let Some(token) = token("voidedPurchaseNotification") {
            Rtdn::Voided { id, token }
        } else {
            Rtdn::Other { id }
        })
    }

    /// How long tokens are cached (tests).
    #[must_use]
    pub const fn token_cache() -> Duration {
        Duration::from_secs(60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_times() {
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_ms("1970-01-02T00:00:01.5Z"), Some(86_401_500));
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00.123456789Z"), Some(123));
        assert_eq!(
            rfc3339_ms("2026-12-17T10:20:30.123Z"),
            Some(((20_804 * 86_400 + 10 * 3_600 + 20 * 60 + 30) * 1_000) + 123)
        );
        for bad in [
            "2026-12-17T10:20:30",
            "2026-12-17 10:20:30Z",
            "2026-13-17T10:20:30Z",
            "2026-12-17T10:20:30+01:00",
            "2026-12-17T10:20:30.Z",
            "2026-12-17T10:20:30.1a3Z",
            "",
        ] {
            assert_eq!(rfc3339_ms(bad), None, "{bad}");
        }
    }
}
