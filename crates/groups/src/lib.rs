//! Songbird's MLS delivery service (Prompt 5, D-0065, D-0066): OpenMLS `PublicGroup` validation
//! behind a verify-only aws-lc-rs provider, Songbird's authorization on top, and the
//! allocation-free parsers the send path uses.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod ds;
pub mod roles;
pub mod state;
pub mod tiers;
pub mod wire;

pub use ds::{Applied, Directory, Group, GroupError, Leaf, Limits, Record, Roster};
