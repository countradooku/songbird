//! Bounded, allocation-free extraction of the SNI host name from a TLS `ClientHello`.
//!
//! The relay reads the client's *inner* TLS `ClientHello` (the one addressed to the Songbird
//! server, carried inside the outer TLS session to the proxy) only to learn where to forward the
//! bytes. It never decrypts anything: the inner session is end to end between client and server.
//!
//! Input is untrusted. Every length is checked against the bytes available before use, total
//! input is capped by the caller ([`crate::config::Limits::max_client_hello_bytes`]), and nothing
//! is allocated in proportion to it. Fuzzed in `fuzz/fuzz_targets/client_hello.rs`.

/// TLS record header length.
pub const RECORD_HEADER_LEN: usize = 5;
/// Largest TLS plaintext record payload (RFC 8446 §5.1).
pub const MAX_RECORD_LEN: usize = 16_384;
const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const NAME_TYPE_HOST: u8 = 0;

/// Why a `ClientHello` was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SniError {
    /// The first record is not a TLS handshake record.
    #[error("not a TLS handshake")]
    NotHandshake,
    /// The handshake message is not a `ClientHello`.
    #[error("not a ClientHello")]
    NotClientHello,
    /// A length field points past the data or violates the TLS grammar.
    #[error("malformed ClientHello")]
    Malformed,
    /// The `ClientHello` (or a record) exceeds the configured or protocol bound.
    #[error("ClientHello too large")]
    TooLarge,
    /// No `server_name` extension with a host name.
    #[error("no SNI")]
    NoSni,
    /// The host name is not a valid DNS name.
    #[error("invalid SNI host name")]
    BadHost,
}

/// Result of scanning buffered bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan<'a> {
    /// More bytes are needed; read more and scan again.
    NeedMore,
    /// The SNI host name (validated, may contain upper case; compare case-insensitively).
    Host(&'a str),
}

/// Scans `buf` (raw bytes from the start of the inner TLS stream) for the SNI host name.
///
/// A `ClientHello` may span several handshake records; record payloads are reassembled into
/// `scratch` (sized by the caller to the configured maximum), so no allocation happens here.
///
/// # Errors
/// Any [`SniError`]; the caller closes the connection without a response.
pub fn scan<'s>(buf: &[u8], scratch: &'s mut [u8]) -> Result<Scan<'s>, SniError> {
    let mut filled = 0usize;
    let mut rest = buf;
    loop {
        let Some((header, after)) = rest.split_at_checked(RECORD_HEADER_LEN) else {
            return Ok(Scan::NeedMore);
        };
        let (ctype, len) = match header {
            [t, _, _, hi, lo] => (*t, usize::from(u16::from_be_bytes([*hi, *lo]))),
            _ => return Err(SniError::Malformed),
        };
        if ctype != CONTENT_HANDSHAKE {
            return Err(SniError::NotHandshake);
        }
        if len == 0 || len > MAX_RECORD_LEN {
            return Err(SniError::Malformed);
        }
        let Some((payload, after)) = after.split_at_checked(len) else {
            return Ok(Scan::NeedMore);
        };
        let end = filled.checked_add(len).ok_or(SniError::TooLarge)?;
        scratch
            .get_mut(filled..end)
            .ok_or(SniError::TooLarge)?
            .copy_from_slice(payload);
        filled = end;
        rest = after;

        let msg = scratch.get(..filled).ok_or(SniError::Malformed)?;
        let Some((&msg_type, r)) = msg.split_first() else {
            continue;
        };
        if msg_type != HANDSHAKE_CLIENT_HELLO {
            return Err(SniError::NotClientHello);
        }
        let Some((len3, body)) = r.split_at_checked(3) else {
            continue;
        };
        let body_len = match len3 {
            [a, b, c] => usize::from(*a) << 16 | usize::from(*b) << 8 | usize::from(*c),
            _ => return Err(SniError::Malformed),
        };
        if body_len > scratch.len().saturating_sub(4) {
            return Err(SniError::TooLarge);
        }
        if body.len() < body_len {
            continue; // the ClientHello continues in the next record
        }
        // Hand the scratch borrow over to the result.
        let full: &'s [u8] = scratch;
        let body = full.get(4..4 + body_len).ok_or(SniError::Malformed)?;
        return parse_client_hello(body).map(Scan::Host);
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SniError> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(SniError::Malformed)?;
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, SniError> {
        self.take(1)?.first().copied().ok_or(SniError::Malformed)
    }
    fn u16(&mut self) -> Result<u16, SniError> {
        match self.take(2)? {
            [a, b] => Ok(u16::from_be_bytes([*a, *b])),
            _ => Err(SniError::Malformed),
        }
    }
    fn vec8(&mut self) -> Result<&'a [u8], SniError> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }
    fn vec16(&mut self) -> Result<&'a [u8], SniError> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
}

fn parse_client_hello(body: &[u8]) -> Result<&str, SniError> {
    let mut r = Reader(body);
    r.take(2)?; // legacy_version
    r.take(32)?; // random
    let session_id = r.vec8()?;
    if session_id.len() > 32 {
        return Err(SniError::Malformed);
    }
    let suites = r.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(SniError::Malformed);
    }
    if r.vec8()?.is_empty() {
        return Err(SniError::Malformed); // compression methods
    }
    if r.0.is_empty() {
        return Err(SniError::NoSni); // no extensions at all
    }
    let mut exts = Reader(r.vec16()?);
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let data = exts.vec16()?;
        if ty == EXT_SERVER_NAME {
            return parse_server_name(data);
        }
    }
    Err(SniError::NoSni)
}

fn parse_server_name(data: &[u8]) -> Result<&str, SniError> {
    let mut r = Reader(data);
    let mut list = Reader(r.vec16()?);
    while !list.0.is_empty() {
        let name_type = list.u8()?;
        let name = list.vec16()?;
        if name_type == NAME_TYPE_HOST {
            return validate_host(name);
        }
    }
    Err(SniError::NoSni)
}

/// Accepts a DNS host name (see [`songbird_types::dns::is_valid_host`]).
pub fn validate_host(name: &[u8]) -> Result<&str, SniError> {
    if !songbird_types::dns::is_valid_host(name) {
        return Err(SniError::BadHost);
    }
    std::str::from_utf8(name).map_err(|_| SniError::BadHost)
}

/// Builds a minimal, well-formed `ClientHello` record for tests and fuzz seeds.
#[doc(hidden)]
#[must_use]
pub fn build_client_hello(host: &str, record_split: Option<usize>) -> Vec<u8> {
    let mut sni = Vec::new();
    let name = host.as_bytes();
    let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
    sni.push(NAME_TYPE_HOST);
    sni.extend_from_slice(&name_len.to_be_bytes());
    sni.extend_from_slice(name);
    let mut ext_data = Vec::new();
    ext_data.extend_from_slice(&u16::try_from(sni.len()).unwrap_or(u16::MAX).to_be_bytes());
    ext_data.extend_from_slice(&sni);

    let mut exts = Vec::new();
    // A dummy extension first (supported_versions), then server_name.
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
    exts.extend_from_slice(
        &u16::try_from(ext_data.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    exts.extend_from_slice(&ext_data);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7u8; 32]);
    body.push(0); // session id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[0x01, 0x00]); // null compression
    body.extend_from_slice(&u16::try_from(exts.len()).unwrap_or(u16::MAX).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![HANDSHAKE_CLIENT_HELLO];
    let bl = u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes();
    hs.extend_from_slice(bl.get(1..).unwrap_or_default());
    hs.extend_from_slice(&body);

    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = match record_split {
        Some(at) if at > 0 && at < hs.len() => {
            let (a, b) = hs.split_at(at);
            vec![a, b]
        }
        _ => vec![&hs],
    };
    for c in chunks {
        out.push(CONTENT_HANDSHAKE);
        out.extend_from_slice(&[0x03, 0x01]);
        out.extend_from_slice(&u16::try_from(c.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn run(buf: &[u8]) -> Result<Option<String>, SniError> {
        let mut scratch = vec![0u8; 16 * 1024];
        scan(buf, &mut scratch).map(|s| match s {
            Scan::NeedMore => None,
            Scan::Host(h) => Some(h.to_owned()),
        })
    }

    #[test]
    fn extracts_sni() {
        let hello = build_client_hello("chat.songbird.example", None);
        assert_eq!(
            run(&hello).unwrap().as_deref(),
            Some("chat.songbird.example")
        );
    }

    #[test]
    fn reassembles_across_records() {
        let hello = build_client_hello("chat.songbird.example", Some(20));
        assert_eq!(
            run(&hello).unwrap().as_deref(),
            Some("chat.songbird.example")
        );
    }

    #[test]
    fn needs_more_on_every_prefix() {
        let hello = build_client_hello("chat.songbird.example", Some(30));
        for cut in 0..hello.len() {
            assert_eq!(run(&hello[..cut]).unwrap(), None, "prefix {cut}");
        }
    }

    #[test]
    fn rejects_non_tls_and_bad_hosts() {
        assert_eq!(run(b"GET / HTTP/1.1\r\n\r\n"), Err(SniError::NotHandshake));
        assert_eq!(
            run(&build_client_hello("bad_host.example", None)),
            Err(SniError::BadHost)
        );
        assert_eq!(
            run(&build_client_hello("-x.example", None)),
            Err(SniError::BadHost)
        );
        assert_eq!(
            run(&build_client_hello("a..b", None)),
            Err(SniError::BadHost)
        );
    }

    #[test]
    fn rejects_oversized_hello_without_reading_it() {
        let mut scratch = vec![0u8; 128];
        let hello = build_client_hello("a.".repeat(120).trim_end_matches('.'), None);
        // The record is larger than the configured maximum: rejected before it is copied.
        assert_eq!(scan(&hello, &mut scratch), Err(SniError::TooLarge));
    }

    proptest! {
        #[test]
        fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let mut scratch = vec![0u8; 4096];
            let _ = scan(&bytes, &mut scratch);
        }

        #[test]
        fn round_trips_valid_hosts(host in "[a-z0-9]{1,20}(\\.[a-z0-9]{1,20}){0,4}", split in 0usize..200) {
            let hello = build_client_hello(&host, Some(split));
            prop_assert_eq!(run(&hello).unwrap(), Some(host));
        }

        #[test]
        fn handles_mutations(host in "[a-z]{1,10}\\.[a-z]{2,5}", idx in 0usize..120, val in any::<u8>()) {
            let mut hello = build_client_hello(&host, None);
            if let Some(b) = hello.get_mut(idx) { *b = val; }
            let _ = run(&hello);
        }
    }
}
