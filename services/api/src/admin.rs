//! Account creation for operators and tests, over a node link that accepts only `admin.`
//! certificates from the internal CA (D-0036). Registration proper (proof of work, usernames,
//! keys) is Prompt 3's; this is its stand-in, never reachable from the internet.
//!
//! Request: `op u8 (1) | account [16] | n u8 | n × (device [16] | Ed25519 key [32])`.
//! Response: `status u8`: 0 created, 1 exists, 2 malformed (a key of small or mixed order
//! included, as registration refuses them), 3 unavailable.

use std::sync::Arc;

use bytes::Bytes;
use songbird_accounts::{Registry, RegistryError};
use songbird_types::{AccountId, DeviceId};

/// Most devices created with an account.
pub const MAX_DEVICES: usize = 16;

/// Encodes a create-account request.
#[must_use]
pub fn create_request(account: &AccountId, devices: &[(DeviceId, [u8; 32])]) -> Vec<u8> {
    let mut b = Vec::with_capacity(18 + devices.len() * 48);
    b.push(1);
    b.extend_from_slice(account.as_bytes());
    b.push(u8::try_from(devices.len()).unwrap_or(u8::MAX));
    for (d, k) in devices {
        b.extend_from_slice(d.as_bytes());
        b.extend_from_slice(k);
    }
    b
}

/// An account and its devices with their keys.
type NewAccount = (AccountId, Vec<(DeviceId, [u8; 32])>);

fn decode(req: &[u8]) -> Option<NewAccount> {
    let (&op, rest) = req.split_first()?;
    if op != 1 {
        return None;
    }
    let (account, rest) = rest.split_at_checked(16)?;
    let (&count, rest) = rest.split_first()?;
    let count = usize::from(count);
    if count == 0 || count > MAX_DEVICES || rest.len() != count * 48 {
        return None;
    }
    let devices = rest
        .as_chunks::<48>()
        .0
        .iter()
        .map(|c| {
            let (dev, key) = c.split_at(16);
            let key: [u8; 32] = key.try_into().ok()?;
            songbird_keys::ed25519_public_key_ok(&key)
                .then_some((DeviceId::from_slice(dev).ok()?, key))
        })
        .collect::<Option<Vec<_>>>()?;
    Some((AccountId::from_slice(account).ok()?, devices))
}

/// The link handler.
pub fn handler(registry: Arc<Registry>) -> songbird_link::Handler {
    Arc::new(move |req: Bytes| {
        let registry = Arc::clone(&registry);
        Box::pin(async move {
            let status = match decode(&req) {
                None => 2,
                Some((a, ds)) => match registry.create_account(&a, &ds).await {
                    Ok(()) => 0,
                    Err(RegistryError::Exists) => 1,
                    Err(_) => 3,
                },
            };
            Bytes::from(vec![status])
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn honest_key() -> [u8; 32] {
        use aws_lc_rs::signature::KeyPair as _;
        let k = aws_lc_rs::signature::Ed25519KeyPair::generate().unwrap();
        k.public_key().as_ref().try_into().unwrap()
    }

    #[test]
    fn requests_decode_strictly() {
        let a = AccountId::from_bytes([1; 16]);
        let ds = vec![(DeviceId::from_bytes([2; 16]), honest_key())];
        let r = create_request(&a, &ds);
        assert_eq!(decode(&r), Some((a, ds)));
        for cut in 0..r.len() {
            assert_eq!(decode(&r[..cut]), None);
        }
        assert_eq!(decode(&create_request(&a, &[])), None);
        // A small-order key (the identity point) is refused.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = vec![(DeviceId::from_bytes([2; 16]), identity)];
        assert_eq!(decode(&create_request(&a, &weak)), None);
    }
}
