//! A batch of ephemeral events sent sealed (`PUT /v1/ephemeral/sealed`, PROTOCOL §10.5; Prompt 9,
//! M3, D-0104): presence and last seen to every allowed contact's devices in one request,
//! authorized by the recipients' access keys, carrying no sender.
//!
//! ```text
//! version u8 (1) | n u16 (1..=1024) | (device [16] | len u16 (1..=4096) | payload) * n
//! ```
//!
//! No device appears twice. The answer is always 204 (or a refusal of the whole batch), never
//! which devices were online.

use songbird_types::DeviceId;
use songbird_types::id::ID_LEN;

/// Format version.
pub const VERSION: u8 = 1;
/// Most devices one batch addresses.
pub const MAX_DEVICES: usize = 1024;
/// Largest payload per device (the ephemeral frame's limit, PROTOCOL §1.3).
pub const MAX_PAYLOAD: usize = 4096;
/// Largest batch body.
pub const MAX_BODY: usize = 512 * 1024;

/// Why bytes did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed ephemeral batch")]
pub struct BatchError;

/// One batch: a payload per device.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedBatch {
    /// `(device, payload)`, each device once.
    pub events: Vec<(DeviceId, Vec<u8>)>,
}

impl std::fmt::Debug for SealedBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedBatch")
            .field("events", &self.events.len())
            .finish()
    }
}

impl SealedBatch {
    /// The wire form.
    ///
    /// # Errors
    /// [`BatchError`] for an empty or oversized batch, a payload out of bounds, or a device twice.
    pub fn encode(&self) -> Result<Vec<u8>, BatchError> {
        self.check()?;
        let mut b = Vec::with_capacity(
            3 + self
                .events
                .iter()
                .map(|(_, p)| ID_LEN + 2 + p.len())
                .sum::<usize>(),
        );
        b.push(VERSION);
        b.extend_from_slice(
            &u16::try_from(self.events.len())
                .map_err(|_| BatchError)?
                .to_be_bytes(),
        );
        for (d, p) in &self.events {
            b.extend_from_slice(d.as_bytes());
            b.extend_from_slice(
                &u16::try_from(p.len())
                    .map_err(|_| BatchError)?
                    .to_be_bytes(),
            );
            b.extend_from_slice(p);
        }
        if b.len() > MAX_BODY {
            return Err(BatchError);
        }
        Ok(b)
    }

    fn check(&self) -> Result<(), BatchError> {
        if self.events.is_empty()
            || self.events.len() > MAX_DEVICES
            || self
                .events
                .iter()
                .any(|(_, p)| p.is_empty() || p.len() > MAX_PAYLOAD)
        {
            return Err(BatchError);
        }
        let mut ds: Vec<&DeviceId> = self.events.iter().map(|(d, _)| d).collect();
        ds.sort_unstable_by_key(|d| *d.as_bytes());
        if ds.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(BatchError);
        }
        Ok(())
    }

    /// Decodes the whole input; counts and lengths are checked against the bytes left before
    /// anything proportional to them is allocated.
    ///
    /// # Errors
    /// [`BatchError`].
    pub fn decode(input: &[u8]) -> Result<Self, BatchError> {
        if input.len() > MAX_BODY {
            return Err(BatchError);
        }
        let (&version, rest) = input.split_first().ok_or(BatchError)?;
        let (count, mut rest) = rest.split_first_chunk::<2>().ok_or(BatchError)?;
        let count = usize::from(u16::from_be_bytes(*count));
        if version != VERSION
            || count == 0
            || count > MAX_DEVICES
            || count * (ID_LEN + 3) > rest.len()
        {
            return Err(BatchError);
        }
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            let (device, after) = rest.split_first_chunk::<ID_LEN>().ok_or(BatchError)?;
            let (len, after) = after.split_first_chunk::<2>().ok_or(BatchError)?;
            let len = usize::from(u16::from_be_bytes(*len));
            let (payload, after) = after.split_at_checked(len).ok_or(BatchError)?;
            events.push((DeviceId::from_bytes(*device), payload.to_vec()));
            rest = after;
        }
        if !rest.is_empty() {
            return Err(BatchError);
        }
        let b = Self { events };
        b.check()?;
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;
    use proptest::prelude::*;

    fn d(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    #[test]
    fn batches_round_trip_and_decode_strictly() {
        let b = SealedBatch {
            events: vec![(d(1), vec![1; 100]), (d(2), vec![2; 4096])],
        };
        let w = b.encode().unwrap();
        assert_eq!(SealedBatch::decode(&w), Ok(b.clone()));
        for cut in 0..w.len() {
            assert!(SealedBatch::decode(&w[..cut]).is_err());
        }
        let mut long = w;
        long.push(0);
        assert!(SealedBatch::decode(&long).is_err());
        let twice = SealedBatch {
            events: vec![(d(1), vec![1]), (d(1), vec![2])],
        };
        assert!(twice.encode().is_err());
        let empty_payload = SealedBatch {
            events: vec![(d(1), Vec::new())],
        };
        assert!(empty_payload.encode().is_err());
        assert!(SealedBatch { events: Vec::new() }.encode().is_err());
    }

    proptest! {
        #[test]
        fn the_decoder_never_panics(b in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = SealedBatch::decode(&b);
        }
    }
}
