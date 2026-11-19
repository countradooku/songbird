//! Mollie, the EU provider for desktop and web (D-0126 §4, D-0129).
//!
//! A checkout: the app makes a random 32-byte **subscriber secret** and keeps it; billing
//! creates a Mollie customer **with no name or e-mail**, then a first payment (`sequenceType =
//! first`) whose metadata names only the subscription row's keyed hash; the browser pays on
//! Mollie's page. Mollie's webhooks carry only a payment ID, which billing fetches back over
//! the API (no webhook signature to trust). A paid first payment starts a Mollie subscription
//! on the mandate; each recurring payment moves the paid-through day; a refund or chargeback
//! revokes. The secret is all the app needs to fetch tokens, see the state or cancel.

use serde_json::{Value, json};

use crate::ProviderError;
use crate::http::{Client, encode};

/// A plan's prices (`"2.99"`) and the currency.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prices {
    /// ISO 4217 (`EUR`).
    pub currency: String,
    /// Plus, a month.
    pub plus_month: String,
    /// Plus, a year.
    pub plus_year: String,
    /// Family, a month.
    pub family_month: String,
    /// Family, a year.
    pub family_year: String,
}

impl Prices {
    /// The price of `plan` for `interval` (`month` or `year`).
    #[must_use]
    pub fn of(&self, plan: &str, interval: &str) -> Option<&str> {
        Some(match (plan, interval) {
            ("plus", "month") => &self.plus_month,
            ("plus", "year") => &self.plus_year,
            ("family", "month") => &self.family_month,
            ("family", "year") => &self.family_year,
            _ => return None,
        })
    }

    /// Every price is `<digits>.<two digits>`.
    #[must_use]
    pub fn valid(&self) -> bool {
        let ok = |p: &str| {
            p.split_once('.').is_some_and(|(a, b)| {
                !a.is_empty()
                    && a.len() <= 4
                    && b.len() == 2
                    && a.bytes().chain(b.bytes()).all(|c| c.is_ascii_digit())
            })
        };
        self.currency.len() == 3
            && self.currency.bytes().all(|c| c.is_ascii_uppercase())
            && [
                &self.plus_month,
                &self.plus_year,
                &self.family_month,
                &self.family_year,
            ]
            .iter()
            .all(|p| ok(p))
    }
}

/// A payment as billing needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    /// `open`, `paid`, `failed`, …
    pub status: String,
    /// `first`, `recurring` or `oneoff`.
    pub sequence: String,
    /// Its customer.
    pub customer: Option<String>,
    /// Its subscription (recurring payments).
    pub subscription: Option<String>,
    /// The subscription row it belongs to (first payments: our metadata).
    pub row: Option<String>,
    /// Refunded or charged back, wholly or in part.
    pub reversed: bool,
}

/// Mollie.
#[derive(Debug)]
pub struct Mollie {
    http: Client,
    api_key: String,
    base: String,
    webhook: String,
    redirect: String,
    /// Prices.
    pub prices: Prices,
}

impl Mollie {
    /// Mollie at `base` (`https://api.mollie.com/v2`).
    #[must_use]
    pub fn new(
        http: Client,
        api_key: String,
        base: String,
        webhook: String,
        redirect: String,
        prices: Prices,
    ) -> Self {
        Self {
            http,
            api_key,
            base,
            webhook,
            redirect,
            prices,
        }
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ProviderError> {
        let bearer = format!("Bearer {}", self.api_key);
        let body = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        let r = self
            .http
            .send(
                method,
                &format!("{}{path}", self.base),
                &[
                    ("authorization", bearer.as_str()),
                    ("content-type", "application/json"),
                ],
                body,
            )
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        match r.status {
            200..=299 => {
                if r.body.is_empty() {
                    Ok(Value::Null)
                } else {
                    serde_json::from_slice(&r.body).map_err(|_| ProviderError::Unavailable)
                }
            }
            404 | 410 | 422 => Err(ProviderError::Refused),
            _ => Err(ProviderError::Unavailable),
        }
    }

    /// Creates a customer with no name and no e-mail; returns its ID.
    ///
    /// # Errors
    /// [`ProviderError`].
    pub async fn customer(&self) -> Result<String, ProviderError> {
        let v = self.call("POST", "/customers", Some(json!({}))).await?;
        v.get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(ProviderError::Unavailable)
    }

    /// The first payment of a subscription; returns the checkout URL for the browser.
    ///
    /// # Errors
    /// [`ProviderError`].
    pub async fn first_payment(
        &self,
        customer: &str,
        plan: &str,
        interval: &str,
        row_hex: &str,
    ) -> Result<String, ProviderError> {
        let value = self
            .prices
            .of(plan, interval)
            .ok_or(ProviderError::Refused)?;
        let v = self
            .call(
                "POST",
                "/payments",
                Some(json!({
                    "amount": { "currency": self.prices.currency, "value": value },
                    "description": format!("Songbird {plan} ({interval})"),
                    "redirectUrl": self.redirect,
                    "webhookUrl": self.webhook,
                    "customerId": customer,
                    "sequenceType": "first",
                    "metadata": { "row": row_hex },
                })),
            )
            .await?;
        v.pointer("/_links/checkout/href")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(ProviderError::Unavailable)
    }

    /// A payment by ID.
    ///
    /// # Errors
    /// [`ProviderError`].
    pub async fn payment(&self, id: &str) -> Result<Payment, ProviderError> {
        if !id.starts_with("tr_")
            || id.len() > 64
            || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err(ProviderError::Refused);
        }
        let v = self
            .call("GET", &format!("/payments/{}", encode(id)), None)
            .await?;
        let s = |p: &str| v.pointer(p).and_then(Value::as_str).map(str::to_owned);
        let nonzero = |p: &str| {
            v.pointer(p)
                .and_then(Value::as_str)
                .is_some_and(|x| x.bytes().any(|c| (b'1'..=b'9').contains(&c)))
        };
        Ok(Payment {
            status: s("/status").ok_or(ProviderError::Unavailable)?,
            sequence: s("/sequenceType").unwrap_or_default(),
            customer: s("/customerId"),
            subscription: s("/subscriptionId"),
            row: s("/metadata/row"),
            reversed: nonzero("/amountRefunded/value") || nonzero("/amountChargedBack/value"),
        })
    }

    /// Starts the subscription on the customer's mandate, its first charge `start` (`YYYY-MM-DD`).
    ///
    /// # Errors
    /// [`ProviderError`].
    pub async fn subscribe(
        &self,
        customer: &str,
        plan: &str,
        interval: &str,
        start: &str,
    ) -> Result<String, ProviderError> {
        let value = self
            .prices
            .of(plan, interval)
            .ok_or(ProviderError::Refused)?;
        let v = self
            .call(
                "POST",
                &format!("/customers/{}/subscriptions", encode(customer)),
                Some(json!({
                    "amount": { "currency": self.prices.currency, "value": value },
                    "interval": if interval == "year" { "12 months" } else { "1 month" },
                    "startDate": start,
                    "description": format!("Songbird {plan} ({interval})"),
                    "webhookUrl": self.webhook,
                })),
            )
            .await?;
        v.get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(ProviderError::Unavailable)
    }

    /// Cancels a subscription (no further charges; what was paid stays paid).
    ///
    /// # Errors
    /// [`ProviderError`].
    pub async fn cancel(&self, customer: &str, subscription: &str) -> Result<(), ProviderError> {
        match self
            .call(
                "DELETE",
                &format!(
                    "/customers/{}/subscriptions/{}",
                    encode(customer),
                    encode(subscription)
                ),
                None,
            )
            .await
        {
            Ok(_) | Err(ProviderError::Refused) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prices_are_checked() {
        let mut p = Prices {
            currency: "EUR".into(),
            plus_month: "2.99".into(),
            plus_year: "29.99".into(),
            family_month: "4.99".into(),
            family_year: "49.99".into(),
        };
        assert!(p.valid());
        assert_eq!(p.of("family", "year"), Some("49.99"));
        assert_eq!(p.of("teams", "year"), None);
        p.plus_month = "2.9".into();
        assert!(!p.valid());
        p.plus_month = "-2.99".into();
        assert!(!p.valid());
        p.plus_month = "2.99".into();
        p.currency = "eur".into();
        assert!(!p.valid());
    }
}
