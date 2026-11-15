//! Songbird client wire protocol, version 1 (`docs/PROTOCOL.md` §1–§3).
//!
//! Shared by the server (`services/delivery`) and every client (`crates/client`). It depends on
//! nothing but `songbird-types`, `bytes`, `prost` and `thiserror`, so it builds for mobile targets.
//!
//! - [`frame`]: every WebSocket binary message is one frame: a one-byte type, then fixed-width
//!   big-endian fields. Hot-path frames (`Send`, `Deliver`, `Ack`, `SendResult`, `Ephemeral`) are
//!   hand-encoded; rare control frames (`Hello`, `Auth`, `AuthOk`, `Error`, device-list mismatch)
//!   carry a protobuf body ([`control`]).
//! - [`close`]: WebSocket close codes in three ranges (do not reconnect, reconnect with backoff,
//!   reconnect now) and the retry hint carried in the close reason.
//! - [`auth`]: the domain-separated transcript a device signs to authenticate.
//! - [`system`]: server-signed system frames (notices such as "your device list changed"),
//!   delivered as mailbox envelopes in a reserved format no user envelope may take.
//! - [`devices`]: the signed device list and the link request (Prompt 3).
//! - [`keys`]: the key directory's upload and fetch formats (PQXDH prekeys, Prompt 3).
//! - [`registration`]: the registration request, the transcripts its keys sign, and invite codes
//!   (`POST /v1/registration`, Prompt 3).
//!
//! Every decoder checks lengths against [`Limits`] before allocating anything proportional to
//! its input (invariant 7) and is fuzzed (`fuzz/fuzz_targets/proto_*.rs`).
#![forbid(unsafe_code)]

pub mod auth;
pub mod close;
pub mod control;
pub mod devices;
pub mod frame;
pub mod keys;
pub mod registration;
pub mod system;

pub use close::CloseCode;
pub use frame::{ClientFrame, FrameError, Limits, ServerFrame};

/// WebSocket subprotocol a client must offer.
pub const SUBPROTOCOL: &str = "songbird.v1";
/// Request path of the WebSocket endpoint.
pub const PATH: &str = "/v1/ws";
/// The protocol version this crate speaks.
pub const PROTOCOL_VERSION: u32 = 1;
/// Length of the server's authentication nonce.
pub const NONCE_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a send idempotency key.
pub const IDEMPOTENCY_KEY_LEN: usize = 16;
