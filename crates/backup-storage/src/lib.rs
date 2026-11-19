//! Where Songbird backups live (Prompt 10; D-0119, D-0121; PROTOCOL §11.8).
//!
//! One small interface, [`BackupStore`]: put, get, list and delete chunk objects, and a
//! compare-and-swap of the manifest on its generation. Adapters run **on the device only**:
//! OAuth tokens for third-party clouds and the recovery key never reach Songbird.
//!
//! | Adapter | Module |
//! | --- | --- |
//! | In memory (reference, tests) | [`memory`] |
//! | A local folder, and a single `.songbird-backup` file | [`local`] |
//! | The Songbird vault | [`vault`] |
//!
//! [`run`] makes and restores backups over any of them; [`conformance`] is the suite every
//! adapter passes.
#![forbid(unsafe_code)]

pub mod conformance;
pub mod http;
pub mod local;
pub mod memory;
pub mod run;
pub mod store;
pub mod vault;

pub use store::{BackupStore, StoreError};
