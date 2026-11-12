//! Unpadded base64url (RFC 4648 §5), the only base64 that JWTs, VAPID and RFC 8291 use. Small
//! enough to own instead of depending on a crate.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn symbol(v: u32) -> char {
    let i = usize::try_from(v & 63).unwrap_or(0);
    char::from(ALPHABET.get(i).copied().unwrap_or(b'A'))
}

fn value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Encodes `input` as unpadded base64url.
#[must_use]
pub fn encode_url(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(symbol(n >> 18));
        out.push(symbol(n >> 12));
        if chunk.len() > 1 {
            out.push(symbol(n >> 6));
        }
        if chunk.len() > 2 {
            out.push(symbol(n));
        }
    }
    out
}

/// Decodes unpadded base64url. Rejects padding, other alphabets, impossible lengths and
/// non-canonical trailing bits.
#[must_use]
pub fn decode_url(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * u32::try_from(i).ok()?);
        }
        let [_, b0, b1, b2] = n.to_be_bytes();
        match chunk.len() {
            2 => {
                if n & 0xffff != 0 {
                    return None;
                }
                out.push(b0);
            }
            3 => {
                if n & 0xff != 0 {
                    return None;
                }
                out.extend_from_slice(&[b0, b1]);
            }
            _ => out.extend_from_slice(&[b0, b1, b2]),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 §10, without padding.
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_url(plain.as_bytes()), enc);
            assert_eq!(decode_url(enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn url_alphabet_and_round_trip() {
        assert_eq!(encode_url(&[0xfb, 0xff]), "-_8");
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode_url(&encode_url(&all)).unwrap(), all);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode_url("Zg==").is_none());
        assert!(decode_url("Z").is_none());
        assert!(decode_url("Zm+v").is_none());
        assert!(decode_url("Zh").is_none()); // non-canonical trailing bits
        assert!(decode_url("Zm9 v").is_none());
    }
}
