//! AWS Signature Version 4, header form (`Authorization: AWS4-HMAC-SHA256 …`).
//!
//! Follows the published specification ("Create a signed AWS API request", and for S3
//! "Signature Calculations for the Authorization Header"): the canonical request is
//! `METHOD\nURI\nQUERY\nHEADERS\n\nSIGNED_HEADERS\nPAYLOAD_HASH`, the string to sign is
//! `AWS4-HMAC-SHA256\nDATE\nSCOPE\nhex(SHA256(canonical request))`, and the signing key is the
//! HMAC-SHA256 chain `"AWS4" + secret → date → region → service → "aws4_request"`.
//!
//! S3 differs from other services in one place: the URI path is encoded once (each segment),
//! never twice, and is not normalized. Callers pass the path already encoded with
//! [`uri_encode`] (segments, `/` kept), exactly as it is sent on the wire.

use std::fmt::Write as _;

use aws_lc_rs::{digest, hmac};

/// Payload hash for a body that is not hashed (streamed uploads over TLS).
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Hex SHA-256 of the empty string.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Lowercase hex SHA-256 of `data`.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, data).as_ref())
}

/// `SigV4` `UriEncode`: every byte except the unreserved set `A-Z a-z 0-9 - _ . ~` becomes `%XX`
/// (uppercase hex); `/` is kept when `keep_slash` (object key paths) and encoded otherwise
/// (query names and values).
#[must_use]
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && b == b'/')
        {
            out.push(char::from(b));
        } else {
            // Writing to a String cannot fail.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The canonical query string: names and values encoded with [`uri_encode`], sorted by encoded
/// name then value, joined with `&`. A parameter without a value is `name=`.
#[must_use]
pub fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort_unstable();
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// What is signed.
#[derive(Debug, Clone, Copy)]
pub struct Signable<'a> {
    /// HTTP method, uppercase.
    pub method: &'a str,
    /// Path as sent, already encoded with [`uri_encode`] (`keep_slash = true`).
    pub canonical_uri: &'a str,
    /// Query parameters, not encoded.
    pub query: &'a [(&'a str, &'a str)],
    /// Headers to sign (any case); must include `host` and `x-amz-date`.
    pub headers: &'a [(&'a str, &'a str)],
    /// Hex SHA-256 of the body, or [`UNSIGNED_PAYLOAD`].
    pub payload_hash: &'a str,
}

/// Credential scope: region and service (`s3`).
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    /// Region, e.g. `us-east-1`.
    pub region: &'a str,
    /// Service, e.g. `s3`.
    pub service: &'a str,
}

/// Canonical request and the `SignedHeaders` list.
#[must_use]
pub fn canonical_request(req: &Signable<'_>) -> (String, String) {
    let mut headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|(n, v)| (n.to_ascii_lowercase(), normalize_value(v)))
        .collect();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    // Repeated names are joined with commas, in order (the spec's rule for multi-value headers).
    let mut merged: Vec<(String, String)> = Vec::with_capacity(headers.len());
    for (n, v) in headers {
        match merged.last_mut() {
            Some((last, joined)) if *last == n => {
                joined.push(',');
                joined.push_str(&v);
            }
            _ => merged.push((n, v)),
        }
    }
    let mut canonical_headers = String::new();
    let mut signed = String::new();
    for (i, (n, v)) in merged.iter().enumerate() {
        canonical_headers.push_str(n);
        canonical_headers.push(':');
        canonical_headers.push_str(v);
        canonical_headers.push('\n');
        if i > 0 {
            signed.push(';');
        }
        signed.push_str(n);
    }
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        req.canonical_uri,
        canonical_query(req.query),
        canonical_headers,
        signed,
        req.payload_hash
    );
    (canonical, signed)
}

/// Trims and collapses runs of spaces to one (the spec's `Trimall`).
fn normalize_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut space = false;
    for c in v.trim().chars() {
        if c == ' ' {
            if !space {
                out.push(' ');
            }
            space = true;
        } else {
            out.push(c);
            space = false;
        }
    }
    out
}

/// `date/region/service/aws4_request`, with `date` the first 8 characters of `amz_date`.
fn credential_scope(amz_date: &str, scope: Scope<'_>) -> String {
    format!(
        "{}/{}/{}/aws4_request",
        amz_date.get(..8).unwrap_or(""),
        scope.region,
        scope.service
    )
}

/// The string to sign for a canonical request.
#[must_use]
pub fn string_to_sign(amz_date: &str, scope: Scope<'_>, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{}\n{}",
        credential_scope(amz_date, scope),
        sha256_hex(canonical_request.as_bytes())
    )
}

/// The derived signing key for a day, region and service.
#[must_use]
pub fn signing_key(secret_key: &str, date: &str, scope: Scope<'_>) -> hmac::Key {
    let mut k_secret = zeroize::Zeroizing::new(String::with_capacity(4 + secret_key.len()));
    k_secret.push_str("AWS4");
    k_secret.push_str(secret_key);
    let step = |key: &[u8], data: &str| {
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
    };
    let k_date = step(k_secret.as_bytes(), date);
    let k_region = step(k_date.as_ref(), scope.region);
    let k_service = step(k_region.as_ref(), scope.service);
    let k_signing = step(k_service.as_ref(), "aws4_request");
    hmac::Key::new(hmac::HMAC_SHA256, k_signing.as_ref())
}

/// Hex signature of a string to sign.
#[must_use]
pub fn signature(key: &hmac::Key, string_to_sign: &str) -> String {
    hex::encode(hmac::sign(key, string_to_sign.as_bytes()).as_ref())
}

/// The full `Authorization` header value for `req`, signed at `amz_date`
/// (`YYYYMMDDTHHMMSSZ`, the value of the signed `x-amz-date` header).
#[must_use]
pub fn authorization(
    access_key: &str,
    secret_key: &str,
    scope: Scope<'_>,
    amz_date: &str,
    req: &Signable<'_>,
) -> String {
    let (canonical, signed) = canonical_request(req);
    let sts = string_to_sign(amz_date, scope, &canonical);
    let key = signing_key(secret_key, amz_date.get(..8).unwrap_or(""), scope);
    format!(
        "{ALGORITHM} Credential={access_key}/{}, SignedHeaders={signed}, Signature={}",
        credential_scope(amz_date, scope),
        signature(&key, &sts)
    )
}

/// `YYYYMMDDTHHMMSSZ` for seconds since the Unix epoch (UTC).
#[must_use]
pub fn amz_date(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let rem = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Gregorian date from days since 1970-01-01 (Howard Hinnant's `civil_from_days`, for
/// non-negative day counts).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // AWS SigV4 test suite (aws-sig-v4-test-suite): credentials and date shared by every case.
    const SUITE_AK: &str = "AKIDEXAMPLE";
    const SUITE_SK: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const SUITE_DATE: &str = "20150830T123600Z";
    const SUITE_SCOPE: Scope<'static> = Scope {
        region: "us-east-1",
        service: "service",
    };

    fn suite(query: &[(&str, &str)]) -> String {
        authorization(
            SUITE_AK,
            SUITE_SK,
            SUITE_SCOPE,
            SUITE_DATE,
            &Signable {
                method: "GET",
                canonical_uri: "/",
                query,
                headers: &[
                    ("Host", "example.amazonaws.com"),
                    ("X-Amz-Date", SUITE_DATE),
                ],
                payload_hash: EMPTY_SHA256,
            },
        )
    }

    #[test]
    fn get_vanilla() {
        let req = Signable {
            method: "GET",
            canonical_uri: "/",
            query: &[],
            headers: &[
                ("Host", "example.amazonaws.com"),
                ("X-Amz-Date", SUITE_DATE),
            ],
            payload_hash: EMPTY_SHA256,
        };
        let (canonical, signed) = canonical_request(&req);
        assert_eq!(
            canonical,
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(signed, "host;x-amz-date");
        assert_eq!(
            string_to_sign(SUITE_DATE, SUITE_SCOPE, &canonical),
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );
        assert_eq!(
            suite(&[]),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn get_vanilla_query_order_key_case() {
        // GET /?Param2=value2&Param1=value1
        assert!(
            suite(&[("Param2", "value2"), ("Param1", "value1")]).ends_with(
                "Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
            )
        );
    }

    #[test]
    fn get_vanilla_empty_query_key() {
        // GET /?Param1=value1
        assert!(suite(&[("Param1", "value1")]).ends_with(
            "Signature=a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"
        ));
    }

    // S3 developer guide, "Signature Calculations for the Authorization Header: Transferring
    // Payload in a Single Chunk", examples.
    const S3_AK: &str = "AKIAIOSFODNN7EXAMPLE";
    const S3_SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const S3_DATE: &str = "20130524T000000Z";
    const S3_SCOPE: Scope<'static> = Scope {
        region: "us-east-1",
        service: "s3",
    };
    const S3_HOST: &str = "examplebucket.s3.amazonaws.com";

    #[test]
    fn s3_get_object() {
        let req = Signable {
            method: "GET",
            canonical_uri: "/test.txt",
            query: &[],
            headers: &[
                ("Host", S3_HOST),
                ("Range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", S3_DATE),
            ],
            payload_hash: EMPTY_SHA256,
        };
        let (canonical, _) = canonical_request(&req);
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
        let key = signing_key(S3_SK, "20130524", S3_SCOPE);
        assert_eq!(
            signature(&key, &string_to_sign(S3_DATE, S3_SCOPE, &canonical)),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(
            authorization(S3_AK, S3_SK, S3_SCOPE, S3_DATE, &req),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn s3_put_object() {
        let body = b"Welcome to Amazon S3.";
        let hash = sha256_hex(body);
        assert_eq!(
            hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let uri = format!("/{}", uri_encode("test$file.text", true));
        assert_eq!(uri, "/test%24file.text");
        let auth = authorization(
            S3_AK,
            S3_SK,
            S3_SCOPE,
            S3_DATE,
            &Signable {
                method: "PUT",
                canonical_uri: &uri,
                query: &[],
                headers: &[
                    ("Host", S3_HOST),
                    ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                    ("x-amz-date", S3_DATE),
                    ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                    ("x-amz-content-sha256", &hash),
                ],
                payload_hash: &hash,
            },
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, \
             Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    fn s3_get(query: &[(&str, &str)]) -> String {
        authorization(
            S3_AK,
            S3_SK,
            S3_SCOPE,
            S3_DATE,
            &Signable {
                method: "GET",
                canonical_uri: "/",
                query,
                headers: &[
                    ("Host", S3_HOST),
                    ("x-amz-content-sha256", EMPTY_SHA256),
                    ("x-amz-date", S3_DATE),
                ],
                payload_hash: EMPTY_SHA256,
            },
        )
    }

    #[test]
    fn s3_get_bucket_lifecycle() {
        assert!(s3_get(&[("lifecycle", "")]).ends_with(
            "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        ));
    }

    #[test]
    fn s3_list_objects() {
        // GET /?max-keys=2&prefix=J
        assert!(s3_get(&[("prefix", "J"), ("max-keys", "2")]).ends_with(
            "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        ));
    }

    #[test]
    fn encoding() {
        assert_eq!(uri_encode("a b/c~d_e.f-g", true), "a%20b/c~d_e.f-g");
        assert_eq!(uri_encode("a/b+c=d", false), "a%2Fb%2Bc%3Dd");
        assert_eq!(uri_encode("é", false), "%C3%A9");
        assert_eq!(
            canonical_query(&[("b", "2"), ("a", "x y"), ("a", "1")]),
            "a=1&a=x%20y&b=2"
        );
        assert_eq!(normalize_value("  a   b  c "), "a b c");
    }

    #[test]
    fn dates() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
        assert_eq!(amz_date(1_440_938_160), "20150830T123600Z");
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
        assert_eq!(amz_date(4_107_542_399), "21000228T235959Z");
    }
}
