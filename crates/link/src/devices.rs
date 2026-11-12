//! Device requests from `worker` to `delivery` (D-0036), over a link of their own that accepts
//! only `worker.` certificates and only these two requests:
//!
//! - **Forget**: close the devices' sessions on every node and forget their mailboxes.
//! - **Known**: whether the mailbox still holds anything of each device (deletion verification).
//!
//! Request: `op u8 | n u16 | n × device [16]`. Response: `status u8` (0 ok, 1 unavailable), then
//! for Known `n × u8` (1: something left). Bounded by [`MAX_DEVICES`] before anything is
//! allocated.

use songbird_types::DeviceId;

/// Most devices in one request (an account's device limit is far lower).
pub const MAX_DEVICES: usize = 1024;

const OP_FORGET: u8 = 1;
const OP_KNOWN: u8 = 2;

/// A request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRequest {
    /// Close sessions and forget mailboxes.
    Forget(Vec<DeviceId>),
    /// What the mailbox still knows.
    Known(Vec<DeviceId>),
}

impl DeviceRequest {
    /// Encodes the request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (op, ds) = match self {
            Self::Forget(d) => (OP_FORGET, d),
            Self::Known(d) => (OP_KNOWN, d),
        };
        let n = ds.len().min(MAX_DEVICES);
        let mut b = Vec::with_capacity(3 + n * 16);
        b.push(op);
        b.extend_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes());
        for d in ds.iter().take(n) {
            b.extend_from_slice(d.as_bytes());
        }
        b
    }

    /// Decodes a request; `None` for anything malformed.
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        let (&op, rest) = b.split_first()?;
        let (n, rest) = rest.split_at_checked(2)?;
        let n = usize::from(u16::from_be_bytes(n.try_into().ok()?));
        if n > MAX_DEVICES || rest.len() != n * 16 {
            return None;
        }
        let ds: Vec<DeviceId> = rest
            .as_chunks::<16>()
            .0
            .iter()
            .map(|c| DeviceId::from_bytes(*c))
            .collect();
        match op {
            OP_FORGET => Some(Self::Forget(ds)),
            OP_KNOWN => Some(Self::Known(ds)),
            _ => None,
        }
    }
}

/// A response: `Err(())` when delivery could not do it (retry).
pub type DeviceResponse = Result<Vec<bool>, ()>;

/// Encodes a response.
#[must_use]
pub fn encode_response(r: &DeviceResponse) -> Vec<u8> {
    match r {
        Err(()) => vec![1],
        Ok(known) => {
            let mut b = Vec::with_capacity(1 + known.len());
            b.push(0);
            b.extend(known.iter().map(|k| u8::from(*k)));
            b
        }
    }
}

/// Decodes a response to a request for `n` devices (0 for Forget).
#[must_use]
pub fn decode_response(b: &[u8], n: usize) -> Option<DeviceResponse> {
    match b.split_first()? {
        (0, rest) if rest.len() == n => Some(Ok(rest.iter().map(|x| *x == 1).collect())),
        (1, []) => Some(Err(())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_bad_ones_are_refused() {
        let ds: Vec<DeviceId> = (0..3u8).map(|b| DeviceId::from_bytes([b; 16])).collect();
        for r in [
            DeviceRequest::Forget(ds.clone()),
            DeviceRequest::Known(ds.clone()),
            DeviceRequest::Forget(vec![]),
        ] {
            let e = r.encode();
            assert_eq!(DeviceRequest::decode(&e), Some(r));
            for cut in 0..e.len() {
                assert_eq!(DeviceRequest::decode(&e[..cut]), None);
            }
            let mut longer = e.clone();
            longer.push(0);
            assert_eq!(DeviceRequest::decode(&longer), None);
        }
        assert_eq!(DeviceRequest::decode(&[9, 0, 0]), None);
        // A count above the bound is refused before anything is read.
        assert_eq!(DeviceRequest::decode(&[1, 0xff, 0xff]), None);
        let ok: DeviceResponse = Ok(vec![true, false]);
        assert_eq!(decode_response(&encode_response(&ok), 2), Some(ok));
        assert_eq!(
            decode_response(&encode_response(&Err(())), 2),
            Some(Err(()))
        );
        assert_eq!(decode_response(&[0, 1], 2), None);
    }
}
