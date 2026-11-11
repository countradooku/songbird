//! `songbird-proxy`: a censorship-resistant TLS relay for Songbird traffic.
//!
//! Anyone can run it (one container, one TLS certificate) to relay Songbird traffic in countries
//! that block Songbird's servers, in the style of the proxy support in Signal and WhatsApp. A client
//! opens TLS to the proxy's own domain and, inside that session, opens its normal TLS session to the
//! Songbird server. The proxy reads only the inner `ClientHello`'s SNI to pick an allowed upstream,
//! then forwards encrypted bytes. It logs nothing and stores nothing. See `deploy/proxy/README.md`.
#![forbid(unsafe_code)]

pub mod config;
pub mod link;
pub mod relay;
pub mod sni;
