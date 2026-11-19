//! A strict, minimal DER walk to one question: does this X.509 certificate carry an extension
//! with this OID? (Apple's marker extensions, which rustls-webpki does not expose.) The chain
//! itself is verified by rustls-webpki; this only reads.
//!
//! `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { …, [3] EXPLICIT SEQUENCE OF
//! Extension }, … }`, `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL,
//! extnValue OCTET STRING }`. Lengths in definite form, at most four bytes; anything else is
//! "no".

/// One TLV: its tag, its contents, and what follows it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(n)?;
        if bytes.first() == Some(&0) {
            return None; // not minimal
        }
        let len = bytes
            .iter()
            .fold(0usize, |acc, &x| (acc << 8) | usize::from(x));
        if len < 0x80 {
            return None; // long form for a short length
        }
        (len, rest)
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// Whether the certificate `cert` (DER) has an extension whose OID's content bytes are `oid`.
#[must_use]
pub fn has_extension(cert: &[u8], oid: &[u8]) -> bool {
    extension_oids(cert).is_some_and(|oids| oids.contains(&oid))
}

fn extension_oids(cert: &[u8]) -> Option<Vec<&[u8]>> {
    let (tag, certificate, rest) = tlv(cert)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (tag, mut tbs, _) = tlv(certificate)?;
    if tag != 0x30 {
        return None;
    }
    while !tbs.is_empty() {
        let (tag, contents, rest) = tlv(tbs)?;
        tbs = rest;
        if tag != 0xa3 {
            continue;
        }
        let (tag, mut list, after) = tlv(contents)?;
        if tag != 0x30 || !after.is_empty() {
            return None;
        }
        let mut oids = Vec::new();
        while !list.is_empty() {
            let (tag, ext, rest) = tlv(list)?;
            list = rest;
            if tag != 0x30 {
                return None;
            }
            let (tag, id, _) = tlv(ext)?;
            if tag != 0x06 {
                return None;
            }
            oids.push(id);
        }
        return Some(oids);
    }
    Some(Vec::new())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if body.len() < 0x80 {
            v.push(u8::try_from(body.len()).unwrap());
        } else if body.len() < 0x100 {
            v.push(0x81);
            v.push(u8::try_from(body.len()).unwrap());
        } else {
            v.push(0x82);
            v.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        }
        v.extend_from_slice(body);
        v
    }

    fn cert(exts: &[&[u8]]) -> Vec<u8> {
        let list: Vec<u8> = exts
            .iter()
            .flat_map(|oid| {
                let mut e = wrap(0x06, oid);
                e.extend(wrap(0x04, &[0x05, 0x00]));
                wrap(0x30, &e)
            })
            .collect();
        let mut tbs = wrap(0xa0, &wrap(0x02, &[2]));
        tbs.extend(wrap(0x02, &[1; 200])); // a long serial: long-form lengths around it
        tbs.extend(wrap(0xa3, &wrap(0x30, &list)));
        let mut c = wrap(0x30, &tbs);
        c.extend(wrap(0x30, &[0x06, 0x01, 0x2a]));
        c.extend(wrap(0x03, &[0, 1, 2]));
        wrap(0x30, &c)
    }

    #[test]
    fn finds_exactly_the_extensions_present() {
        let a: &[u8] = &[0x2a, 0x86, 0x48];
        let b: &[u8] = &[0x55, 0x1d, 0x13];
        let c = cert(&[a, b]);
        assert!(has_extension(&c, a));
        assert!(has_extension(&c, b));
        assert!(!has_extension(&c, &[0x2a, 0x86]));
        assert!(!has_extension(&cert(&[]), a));
    }

    #[test]
    fn malformed_der_is_no() {
        let a: &[u8] = &[0x2a, 0x86, 0x48];
        let c = cert(&[a]);
        for cut in 0..c.len() {
            assert!(!has_extension(&c[..cut], a), "truncated at {cut}");
        }
        let mut trailing = c.clone();
        trailing.push(0);
        assert!(!has_extension(&trailing, a));
        // Non-minimal long-form length.
        assert!(tlv(&[0x30, 0x81, 0x05, 1, 2, 3, 4, 5]).is_none());
        assert!(tlv(&[0x30, 0x82, 0x00, 0x90]).is_none());
        assert!(tlv(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none());
    }
}
