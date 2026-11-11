//! Identifiers: 16 random bytes from the operating system's CSPRNG, typed per kind.
//!
//! - Typed: an [`AccountId`] cannot be passed where a [`DeviceId`] is expected.
//! - Unguessable: 128 bits from `getrandom`; no timestamps, counters or host data inside.
//! - Redacted: `Debug` prints only the kind (invariant 6: no device IDs in logs). There is no
//!   `Display`. Code that must render an ID for storage or the wire calls
//!   [`Id::to_hex_unredacted`], which is easy to grep for in review.
//! - Binary on the wire: [`Id::as_bytes`] / [`Id::from_slice`]; hex only off the hot path.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use crate::error::IdError;

/// Length of every identifier, in bytes.
pub const ID_LEN: usize = 16;

/// Marker for an identifier kind.
pub trait IdKind: 'static {
    /// Human-readable kind, used in `Debug` output.
    const NAME: &'static str;
}

/// A 16-byte random identifier of kind `K`.
pub struct Id<K: IdKind> {
    bytes: [u8; ID_LEN],
    kind: PhantomData<fn() -> K>,
}

impl<K: IdKind> Id<K> {
    /// A fresh random identifier.
    ///
    /// # Errors
    /// [`IdError::Random`] if the operating system's random source fails.
    pub fn random() -> Result<Self, IdError> {
        let mut bytes = [0u8; ID_LEN];
        getrandom::fill(&mut bytes).map_err(|_| IdError::Random)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Wraps raw bytes (for example read from the database).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self {
            bytes,
            kind: PhantomData,
        }
    }

    /// Parses exactly 16 bytes; anything else is rejected without allocating.
    ///
    /// # Errors
    /// [`IdError::Length`] if `slice` is not 16 bytes long.
    pub fn from_slice(slice: &[u8]) -> Result<Self, IdError> {
        let bytes: [u8; ID_LEN] = slice
            .try_into()
            .map_err(|_| IdError::Length { got: slice.len() })?;
        Ok(Self::from_bytes(bytes))
    }

    /// Parses 32 hex characters.
    ///
    /// # Errors
    /// [`IdError::Length`] or [`IdError::Hex`].
    pub fn parse_hex(s: &str) -> Result<Self, IdError> {
        if s.len() != ID_LEN * 2 {
            return Err(IdError::Length { got: s.len() / 2 });
        }
        let mut bytes = [0u8; ID_LEN];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| IdError::Hex)?;
        Ok(Self::from_bytes(bytes))
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.bytes
    }

    /// Lowercase hex. Named so every use is visible in review: never pass the result to a log or
    /// metric (invariant 6).
    #[must_use]
    pub fn to_hex_unredacted(&self) -> String {
        hex::encode(self.bytes)
    }
}

// Manual impls so `K` needs no bounds of its own.
impl<K: IdKind> Clone for Id<K> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<K: IdKind> Copy for Id<K> {}
impl<K: IdKind> PartialEq for Id<K> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl<K: IdKind> Eq for Id<K> {}
impl<K: IdKind> PartialOrd for Id<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<K: IdKind> Ord for Id<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}
impl<K: IdKind> Hash for Id<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<K: IdKind> fmt::Debug for Id<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(<redacted>)", K::NAME)
    }
}

/// Declares a new identifier kind and its type alias.
#[macro_export]
macro_rules! define_id {
    ($(#[$meta:meta])* $alias:ident, $kind:ident, $name:literal) => {
        #[doc = concat!("Marker for [`", stringify!($alias), "`].")]
        #[derive(Debug)]
        pub enum $kind {}
        impl $crate::id::IdKind for $kind {
            const NAME: &'static str = $name;
        }
        $(#[$meta])*
        pub type $alias = $crate::id::Id<$kind>;
    };
}

define_id!(
    /// An account (one person). Server-visible, but never logged.
    AccountId,
    AccountKind,
    "AccountId"
);
define_id!(
    /// A device belonging to an account. Never logged (invariant 6).
    DeviceId,
    DeviceKind,
    "DeviceId"
);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn random_ids_differ() {
        let a = DeviceId::random().unwrap();
        let b = DeviceId::random().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn debug_is_redacted() {
        let id = DeviceId::from_bytes([0xAB; ID_LEN]);
        let shown = format!("{id:?}");
        assert_eq!(shown, "DeviceId(<redacted>)");
        assert!(!shown.to_lowercase().contains("ab"));
        let nested = format!("{:?}", Some(vec![id]));
        assert!(!nested.contains("abab"));
    }

    #[test]
    fn rejects_wrong_lengths() {
        assert_eq!(
            AccountId::from_slice(&[0; 15]),
            Err(IdError::Length { got: 15 })
        );
        assert_eq!(
            AccountId::from_slice(&[0; 17]),
            Err(IdError::Length { got: 17 })
        );
        assert!(AccountId::parse_hex("zz").is_err());
        assert_eq!(AccountId::parse_hex(&"g".repeat(32)), Err(IdError::Hex));
    }

    proptest! {
        #[test]
        fn bytes_round_trip(bytes in any::<[u8; ID_LEN]>()) {
            let id = DeviceId::from_bytes(bytes);
            prop_assert_eq!(DeviceId::from_slice(id.as_bytes()).unwrap(), id);
            prop_assert_eq!(DeviceId::parse_hex(&id.to_hex_unredacted()).unwrap(), id);
        }

        #[test]
        fn from_slice_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let r = DeviceId::from_slice(&bytes);
            prop_assert_eq!(r.is_ok(), bytes.len() == ID_LEN);
        }

        #[test]
        fn parse_hex_never_panics(s in ".{0,80}") {
            let _ = DeviceId::parse_hex(&s);
        }
    }
}
