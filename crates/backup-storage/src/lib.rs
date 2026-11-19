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
//! | Any S3-compatible bucket | [`s3`] |
//! | `WebDAV` (Nextcloud, a NAS) | [`webdav`] |
//! | Google Drive's app data folder | [`gdrive`] |
//! | OneDrive's app folder | [`onedrive`] |
//! | Dropbox's app folder | [`dropbox`] |
//! | iCloud Drive (the interface; the native half is the app's) | [`icloud`] |
//!
//! [`oauth`] signs the user in to the three clouds (PKCE, on the device).
//!
//! [`run`] makes and restores backups over any of them; [`conformance`] is the suite every
//! adapter passes.
#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    reason = "product names (OneDrive, MinIO, RustFS, WebDAV) read as prose here"
)]

pub mod conformance;
pub mod dropbox;
pub mod gdrive;
pub mod http;
pub mod icloud;
pub mod local;
pub mod memory;
pub mod oauth;
pub mod onedrive;
pub mod run;
pub mod s3;
pub mod store;
pub mod vault;
pub mod webdav;

pub use store::{BackupStore, StoreError};
