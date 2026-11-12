//! A tiny bounded scanner for the two XML documents this client reads: S3 error bodies
//! (`<Error><Code>…</Code>…`) and `ListObjectsV2` results. No XML crate: the caller caps the
//! document size before reading, the scanner only looks for fixed, attribute-free element names,
//! never recurses and never allocates more than the input it was given.

use crate::{Error, ErrorCode, ListEntry, ListPage, MAX_KEY_BYTES};

/// The text between the first `<name>` and the following `</name>`, and the rest after it.
fn element<'a>(doc: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = doc.find(&open)? + open.len();
    let after = doc.get(start..)?;
    let len = after.find(&close)?;
    Some((after.get(..len)?, after.get(len + close.len()..)?))
}

/// Replaces the five predefined entities and numeric character references.
fn unescape(s: &str) -> Result<String, Error> {
    if !s.contains('&') {
        return Ok(s.to_owned());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(rest.get(..i).ok_or(Error::Protocol("bad XML"))?);
        let tail = rest.get(i + 1..).ok_or(Error::Protocol("bad XML"))?;
        // Entities are short: look at most 12 bytes ahead (bounded work per `&`).
        let end = tail
            .bytes()
            .take(12)
            .position(|b| b == b';')
            .ok_or(Error::Protocol("bad XML entity"))?;
        let entity = tail.get(..end).ok_or(Error::Protocol("bad XML entity"))?;
        let c = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let n = if let Some(h) = entity.strip_prefix("#x") {
                    u32::from_str_radix(h, 16)
                } else if let Some(d) = entity.strip_prefix('#') {
                    d.parse()
                } else {
                    return Err(Error::Protocol("bad XML entity"));
                };
                n.ok()
                    .and_then(char::from_u32)
                    .ok_or(Error::Protocol("bad XML entity"))?
            }
        };
        out.push(c);
        rest = tail.get(end + 1..).ok_or(Error::Protocol("bad XML"))?;
    }
    out.push_str(rest);
    Ok(out)
}

/// The `<Code>` of an S3 error document, if it is a plausible code (ASCII letters and digits).
pub(crate) fn error_code(body: &[u8]) -> Option<ErrorCode> {
    let doc = std::str::from_utf8(body).ok()?;
    let (code, _) = element(doc, "Code")?;
    ErrorCode::new(code.trim())
}

/// Parses a `ListObjectsV2` result with at most `max_entries` objects.
pub(crate) fn list_objects(body: &[u8], max_entries: usize) -> Result<ListPage, Error> {
    let doc = std::str::from_utf8(body).map_err(|_| Error::Protocol("list result is not UTF-8"))?;
    if !doc.contains("<ListBucketResult") {
        return Err(Error::Protocol("not a ListBucketResult"));
    }
    let is_truncated = match element(doc, "IsTruncated") {
        Some((v, _)) => match v.trim() {
            "true" => true,
            "false" => false,
            _ => return Err(Error::Protocol("bad IsTruncated")),
        },
        None => false,
    };
    let next_continuation_token = match element(doc, "NextContinuationToken") {
        Some((v, _)) => {
            let t = unescape(v.trim())?;
            if t.is_empty() || t.len() > crate::MAX_TOKEN_BYTES {
                return Err(Error::Protocol("bad NextContinuationToken"));
            }
            Some(t)
        }
        None => None,
    };
    if is_truncated && next_continuation_token.is_none() {
        return Err(Error::Protocol(
            "truncated list without a continuation token",
        ));
    }
    let mut objects = Vec::new();
    let mut rest = doc;
    while let Some((contents, after)) = element(rest, "Contents") {
        if objects.len() >= max_entries {
            return Err(Error::Protocol("more objects than requested"));
        }
        let (key, _) = element(contents, "Key").ok_or(Error::Protocol("object without Key"))?;
        let key = unescape(key)?;
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(Error::Protocol("bad Key"));
        }
        let (size, _) = element(contents, "Size").ok_or(Error::Protocol("object without Size"))?;
        let size = size
            .trim()
            .parse::<u64>()
            .map_err(|_| Error::Protocol("bad Size"))?;
        let last_modified = match element(contents, "LastModified") {
            Some((v, _)) if v.len() <= 64 && v.bytes().all(|b| b.is_ascii_graphic()) => {
                v.to_owned()
            }
            Some(_) => return Err(Error::Protocol("bad LastModified")),
            None => String::new(),
        };
        objects.push(ListEntry {
            key,
            size,
            last_modified,
        });
        rest = after;
    }
    Ok(ListPage {
        objects,
        is_truncated,
        next_continuation_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>p/</Prefix>
<KeyCount>2</KeyCount><MaxKeys>2</MaxKeys><IsTruncated>true</IsTruncated>
<Contents><Key>p/a&amp;b&#x20;c&#47;</Key><LastModified>2026-11-12T10:00:00.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>42</Size><StorageClass>STANDARD</StorageClass></Contents>
<Contents><Key>p/z</Key><LastModified>2026-11-12T10:00:01.000Z</LastModified><Size>0</Size></Contents>
<NextContinuationToken>tok/+=</NextContinuationToken></ListBucketResult>"#;

    #[test]
    fn parses_a_page() {
        let p = list_objects(LIST.as_bytes(), 2).unwrap();
        assert!(p.is_truncated);
        assert_eq!(p.next_continuation_token.as_deref(), Some("tok/+="));
        assert_eq!(p.objects.len(), 2);
        assert_eq!(p.objects[0].key, "p/a&b c/");
        assert_eq!(p.objects[0].size, 42);
        assert_eq!(p.objects[0].last_modified, "2026-11-12T10:00:00.000Z");
        assert_eq!((p.objects[1].key.as_str(), p.objects[1].size), ("p/z", 0));
        // Never more than asked for.
        assert!(list_objects(LIST.as_bytes(), 1).is_err());
        // Keys stay out of Debug.
        assert!(!format!("{p:?}").contains("p/z"));
    }

    #[test]
    fn empty_and_malformed() {
        let empty = r"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
        let p = list_objects(empty.as_bytes(), 10).unwrap();
        assert!(p.objects.is_empty() && !p.is_truncated && p.next_continuation_token.is_none());
        for bad in [
            "<html/>",
            "<ListBucketResult><IsTruncated>yes</IsTruncated></ListBucketResult>",
            "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
            "<ListBucketResult><Contents><Size>1</Size></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>k</Key><Size>-1</Size></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>&bogus;</Key><Size>1</Size></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>&#xD800;</Key><Size>1</Size></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>&amp</Key><Size>1</Size></Contents></ListBucketResult>",
        ] {
            assert!(list_objects(bad.as_bytes(), 10).is_err(), "{bad}");
        }
        assert!(list_objects(&[0xff, 0xfe], 10).is_err());
    }

    #[test]
    fn error_codes() {
        let doc = b"<?xml version=\"1.0\"?><Error><Code>BucketAlreadyOwnedByYou</Code><Message>secret/key</Message></Error>";
        assert_eq!(error_code(doc).unwrap().as_str(), "BucketAlreadyOwnedByYou");
        assert!(error_code(b"<Error><Code>a/b</Code></Error>").is_none());
        assert!(error_code(b"<Error></Error>").is_none());
    }

    proptest::proptest! {
        #[test]
        fn never_panics(s in ".{0,512}") {
            let _ = list_objects(s.as_bytes(), 5);
            let _ = error_code(s.as_bytes());
            let _ = unescape(&s);
        }

        #[test]
        fn escaped_keys_round_trip(k in "[^\u{0}-\u{1f}]{1,64}") {
            let esc = k.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
            let doc = format!("<ListBucketResult><Contents><Key>{esc}</Key><Size>7</Size></Contents></ListBucketResult>");
            let p = list_objects(doc.as_bytes(), 1).unwrap();
            proptest::prop_assert_eq!(&p.objects[0].key, &k);
        }
    }
}
