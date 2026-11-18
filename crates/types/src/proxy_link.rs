//! Proxy links: how a proxy address reaches the app.
//!
//! Two forms, both carrying the proxy address in the URL **fragment**, which browsers never send to
//! a web server, so the site hosting the web form never learns which proxy a user opened:
//!
//! - App link: `songbird://proxy#<host>[:<port>]`
//! - Web link: `https://<web-domain>/proxy#<host>[:<port>]` (the web domain is an open owner
//!   decision, see `docs/DECISIONS.md` D-0011; the parser takes the allowed domains as input).
//!
//! The port defaults to 443. Parsing is strict and bounded; see `docs/PROTOCOL.md` §1.1. Shared by
//! the proxy (which prints links) and the client (which dials them, Prompt 9).

use crate::dns::is_valid_host;

/// Longest link accepted.
pub const MAX_LINK_LEN: usize = 300;
/// Default proxy port.
pub const DEFAULT_PORT: u16 = 443;
const APP_PREFIX: &str = "songbird://proxy#";

/// A parsed proxy address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyLink {
    /// Proxy host name (lower case).
    pub host: String,
    /// Proxy TCP port.
    pub port: u16,
}

/// Why a link was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// Longer than [`MAX_LINK_LEN`].
    #[error("link too long")]
    TooLong,
    /// Not one of the two accepted forms, or the web domain is not allowed.
    #[error("not a Songbird proxy link")]
    Scheme,
    /// Bad host name.
    #[error("invalid proxy host")]
    Host,
    /// Bad port.
    #[error("invalid proxy port")]
    Port,
}

impl ProxyLink {
    /// Parses an app or web link. `web_domains` lists the domains accepted in the web form.
    ///
    /// # Errors
    /// Any [`LinkError`].
    pub fn parse(link: &str, web_domains: &[&str]) -> Result<Self, LinkError> {
        if link.len() > MAX_LINK_LEN {
            return Err(LinkError::TooLong);
        }
        let fragment = if let Some(f) = link.strip_prefix(APP_PREFIX) {
            f
        } else if let Some(rest) = link.strip_prefix("https://") {
            let (domain, f) = rest.split_once("/proxy#").ok_or(LinkError::Scheme)?;
            if !web_domains.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
                return Err(LinkError::Scheme);
            }
            f
        } else {
            return Err(LinkError::Scheme);
        };
        let (host, port) = match fragment.rsplit_once(':') {
            Some((h, p)) => {
                if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(LinkError::Port);
                }
                let port: u16 = p.parse().map_err(|_| LinkError::Port)?;
                if port == 0 {
                    return Err(LinkError::Port);
                }
                (h, port)
            }
            None => (fragment, DEFAULT_PORT),
        };
        if !is_valid_host(host.as_bytes()) {
            return Err(LinkError::Host);
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// The app link for this proxy.
    #[must_use]
    pub fn to_app_link(&self) -> String {
        if self.port == DEFAULT_PORT {
            format!("{APP_PREFIX}{}", self.host)
        } else {
            format!("{APP_PREFIX}{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const WEB: &[&str] = &["songbird.example"];

    #[test]
    fn parses_both_forms() {
        let a = ProxyLink::parse("songbird://proxy#Proxy.Example.org", WEB).unwrap();
        assert_eq!(
            a,
            ProxyLink {
                host: "proxy.example.org".into(),
                port: 443
            }
        );
        let b =
            ProxyLink::parse("https://songbird.example/proxy#proxy.example.org:8443", WEB).unwrap();
        assert_eq!(b.port, 8443);
        assert_eq!(b.to_app_link(), "songbird://proxy#proxy.example.org:8443");
        assert_eq!(a.to_app_link(), "songbird://proxy#proxy.example.org");
    }

    #[test]
    fn rejects_bad_links() {
        for bad in [
            "http://songbird.example/proxy#p.example",
            "https://evil.example/proxy#p.example",
            "songbird://proxy#",
            "songbird://proxy#p.example:0",
            "songbird://proxy#p.example:65536",
            "songbird://proxy#p.example:-1",
            "songbird://proxy#p.example:443/x",
            "songbird://proxy#user@p.example",
            "songbird://proxy#[::1]:443",
        ] {
            assert!(ProxyLink::parse(bad, WEB).is_err(), "{bad}");
        }
        assert_eq!(
            ProxyLink::parse(&"a".repeat(400), WEB),
            Err(LinkError::TooLong)
        );
    }

    proptest! {
        #[test]
        fn never_panics(s in ".{0,320}") {
            let _ = ProxyLink::parse(&s, WEB);
        }

        #[test]
        fn round_trips(host in "[a-z0-9]{1,15}(\\.[a-z0-9]{1,15}){1,3}", port in 1u16..) {
            let l = ProxyLink { host, port };
            prop_assert_eq!(ProxyLink::parse(&l.to_app_link(), WEB).unwrap(), l);
        }
    }
}
