//! A tiny bounded scanner for the two XML documents this client reads: S3 error bodies
//! (`<Error><Code>…</Code>…`), `ListObjectsV2` and `ListObjectVersions` results. No XML crate: the caller caps the
//! document size before reading, the scanner only looks for fixed, attribute-free element names,
//! never recurses and never allocates more than the input it was given.

use crate::{Error, ErrorCode, ListEntry, ListPage, MAX_KEY_BYTES, VersionEntry, VersionPage};

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

fn bool_element(doc: &str, name: &'static str) -> Result<Option<bool>, Error> {
    match element(doc, name) {
        Some((v, _)) => match v.trim() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(Error::Protocol("bad boolean element")),
        },
        None => Ok(None),
    }
}

fn marker(doc: &str, name: &'static str) -> Result<Option<String>, Error> {
    match element(doc, name) {
        Some((v, _)) => {
            let t = unescape(v.trim())?;
            if t.is_empty() {
                Ok(None)
            } else if t.len() > crate::MAX_TOKEN_BYTES.max(MAX_KEY_BYTES) {
                Err(Error::Protocol("bad marker"))
            } else {
                Ok(Some(t))
            }
        }
        None => Ok(None),
    }
}

/// A `ListObjectVersions` result: object versions only (delete markers are skipped, they hold
/// no data).
pub(crate) fn list_versions(body: &[u8], max_entries: usize) -> Result<VersionPage, Error> {
    let doc = std::str::from_utf8(body).map_err(|_| Error::Protocol("list result is not UTF-8"))?;
    if !doc.contains("<ListVersionsResult") {
        return Err(Error::Protocol("not a ListVersionsResult"));
    }
    // Header fields come before the entries: read them from the part before the first entry, so
    // an entry's own elements are never taken for the page's.
    let head_end = [doc.find("<Version>"), doc.find("<DeleteMarker>")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(doc.len());
    let head = doc.get(..head_end).unwrap_or(doc);
    let tail_start = [doc.rfind("</Version>"), doc.rfind("</DeleteMarker>")]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0);
    let tail = doc.get(tail_start..).unwrap_or("");
    let pick = |name: &'static str| -> Result<Option<String>, Error> {
        match marker(head, name)? {
            Some(v) => Ok(Some(v)),
            None => marker(tail, name),
        }
    };
    let is_truncated = match bool_element(head, "IsTruncated")? {
        Some(b) => b,
        None => bool_element(tail, "IsTruncated")?.unwrap_or(false),
    };
    let next_key_marker = pick("NextKeyMarker")?;
    let next_version_id_marker = pick("NextVersionIdMarker")?;
    if is_truncated && next_key_marker.is_none() {
        return Err(Error::Protocol("truncated list without a key marker"));
    }
    let mut versions = Vec::new();
    let mut rest = doc;
    while let Some((v, after)) = element(rest, "Version") {
        if versions.len() >= max_entries {
            return Err(Error::Protocol("more versions than requested"));
        }
        let (key, _) = element(v, "Key").ok_or(Error::Protocol("version without Key"))?;
        let key = unescape(key)?;
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(Error::Protocol("bad Key"));
        }
        let (id, _) =
            element(v, "VersionId").ok_or(Error::Protocol("version without VersionId"))?;
        let version_id = unescape(id.trim())?;
        if version_id.is_empty()
            || version_id.len() > 1024
            || !version_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::Protocol("bad VersionId"));
        }
        let (size, _) = element(v, "Size").ok_or(Error::Protocol("version without Size"))?;
        let size = size
            .trim()
            .parse::<u64>()
            .map_err(|_| Error::Protocol("bad Size"))?;
        let last_modified = match element(v, "LastModified") {
            Some((t, _))
                if !t.is_empty() && t.len() <= 64 && t.bytes().all(|b| b.is_ascii_graphic()) =>
            {
                t.to_owned()
            }
            _ => return Err(Error::Protocol("bad or missing LastModified")),
        };
        let is_latest = bool_element(v, "IsLatest")?.unwrap_or(false);
        versions.push(VersionEntry {
            key,
            version_id,
            last_modified,
            size,
            is_latest,
        });
        rest = after;
    }
    Ok(VersionPage {
        versions,
        is_truncated,
        next_key_marker,
        next_version_id_marker,
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

    const VERSIONS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>registry/</Prefix>
<KeyMarker></KeyMarker><VersionIdMarker></VersionIdMarker><NextKeyMarker>registry/x</NextKeyMarker><NextVersionIdMarker>v9</NextVersionIdMarker>
<MaxKeys>3</MaxKeys><IsTruncated>true</IsTruncated>
<Version><Key>registry/a</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest><LastModified>2026-11-13T10:05:00.000Z</LastModified><Size>9</Size></Version>
<DeleteMarker><Key>registry/b</Key><VersionId>d1</VersionId><IsLatest>true</IsLatest><LastModified>2026-11-13T10:06:00.000Z</LastModified></DeleteMarker>
<Version><Key>registry/a</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest><LastModified>2026-11-13T10:00:00.000Z</LastModified><Size>7</Size></Version>
</ListVersionsResult>"#;

    #[test]
    fn parses_versions_and_skips_delete_markers() {
        let p = list_versions(VERSIONS.as_bytes(), 3).unwrap();
        assert!(p.is_truncated);
        assert_eq!(p.next_key_marker.as_deref(), Some("registry/x"));
        assert_eq!(p.next_version_id_marker.as_deref(), Some("v9"));
        assert_eq!(p.versions.len(), 2);
        assert_eq!(
            (
                p.versions[0].version_id.as_str(),
                p.versions[0].is_latest,
                p.versions[0].size
            ),
            ("v2", true, 9)
        );
        assert_eq!(p.versions[1].last_modified, "2026-11-13T10:00:00.000Z");
        assert!(list_versions(VERSIONS.as_bytes(), 1).is_err());
        assert!(!format!("{p:?}").contains("registry/a"));
        for bad in [
            "<ListBucketResult/>",
            "<ListVersionsResult><IsTruncated>true</IsTruncated></ListVersionsResult>",
            "<ListVersionsResult><Version><Key>k</Key><Size>1</Size><LastModified>t</LastModified></Version></ListVersionsResult>",
            "<ListVersionsResult><Version><Key>k</Key><VersionId>v</VersionId><Size>1</Size></Version></ListVersionsResult>",
        ] {
            assert!(list_versions(bad.as_bytes(), 10).is_err(), "{bad}");
        }
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
            let _ = list_versions(s.as_bytes(), 5);
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
