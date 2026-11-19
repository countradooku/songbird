//! Billing's decoders of what the network sends (Prompt 11, D-0129): Apple's JWS and its
//! certificates, Google's OIDC tokens and Pub/Sub bodies, base64, RFC 3339 times, DER
//! extension walks. Never panics; nothing the fuzzer makes verifies.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rustls_pki_types::UnixTime;
use songbird_billing::{der, google, jose};

fuzz_target!(|data: &[u8]| {
    let _ = der::has_extension(data, jose::APPLE_LEAF_OID);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jose::b64_decode(s);
        let _ = jose::b64url_decode(s);
        let _ = google::rfc3339_ms(s);
        let trust = jose::AppleTrust::apple(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
        assert!(trust.verify(s, UnixTime::now()).is_err());
        assert!(jose::verify_rs256(s, &jose::rsa_jwks(br#"{"keys":[{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}]}"#)).is_err());
    }
    let _ = jose::rsa_jwks(data);
});
