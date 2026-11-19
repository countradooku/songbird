//! Anonymous tokens (Prompt 11; D-0126 §2; D-0128).
//!
//! - [`oprf`]: RFC 9497 with `ristretto255-SHA512`, all three modes, checked against the RFC.
//! - [`token`]: Songbird's tokens on the POPRF: what the public metadata says, how a token is
//!   requested, issued, finalized and redeemed, and its nullifier.
#![forbid(unsafe_code)]

pub mod oprf;
pub mod token;
