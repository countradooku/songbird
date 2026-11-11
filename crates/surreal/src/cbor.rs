//! The CBOR subset SurrealDB 4 speaks on the `cbor` WebSocket subprotocol (RFC 8949).
//!
//! Encodes and decodes definite-length items only (the server writes definite lengths). The
//! decoder is bounded (invariant 7): every length is checked against the bytes that remain
//! before anything is allocated, nesting is limited to [`MAX_DEPTH`], and indefinite lengths,
//! reserved additional-info values and trailing bytes are rejected. Fuzzed by
//! `fuzz/fuzz_targets/surreal_cbor.rs`.
//!
//! SurrealDB tags used here (`surrealdb-types-4.0.1/src/cbor/convert.rs`): 6 NONE, 7 table,
//! 8 record ID (`[table, key]`), 10 decimal (text), 12 datetime (`[secs, nanos]`),
//! 14 duration, 37 UUID, 49–51 ranges. Tags are kept as [`Value::Tag`]; callers interpret them.

use bytes::{BufMut, Bytes, BytesMut};

/// Deepest nesting accepted when decoding.
pub const MAX_DEPTH: usize = 64;

/// SurrealDB `NONE` (tag 6 over `null`).
pub const TAG_NONE: u64 = 6;
/// SurrealDB table name.
pub const TAG_TABLE: u64 = 7;
/// SurrealDB record ID: `[table, key]`.
pub const TAG_RECORD_ID: u64 = 8;
/// SurrealDB datetime: `[seconds, nanoseconds]`.
pub const TAG_DATETIME: u64 = 12;

/// A CBOR value.
#[derive(Clone, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// An integer in `i64` range (SurrealDB refuses anything wider).
    Int(i64),
    /// A float.
    Float(f64),
    /// A byte string.
    Bytes(Bytes),
    /// A text string.
    Text(String),
    /// An array.
    Array(Vec<Value>),
    /// A map with text keys, in wire order.
    Map(Vec<(String, Value)>),
    /// A tagged value.
    Tag(u64, Box<Value>),
}

impl std::fmt::Debug for Value {
    // Payloads may be ciphertext or identifiers: show shapes, never byte contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(x) => write!(f, "{x}"),
            Self::Bytes(b) => write!(f, "bytes({})", b.len()),
            Self::Text(t) => write!(f, "text({})", t.len()),
            Self::Array(a) => f.debug_list().entries(a).finish(),
            Self::Map(m) => f
                .debug_map()
                .entries(m.iter().map(|(k, v)| (k, v)))
                .finish(),
            Self::Tag(t, v) => write!(f, "tag({t}, {v:?})"),
        }
    }
}

impl Value {
    /// SurrealDB `NONE`.
    #[must_use]
    pub fn none() -> Self {
        Self::Tag(TAG_NONE, Box::new(Self::Null))
    }

    /// Whether this is `NONE` or `null`.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Null) || matches!(self, Self::Tag(TAG_NONE, _))
    }

    /// The integer, if this is one.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The bytes, if this is a byte string.
    #[must_use]
    pub const fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text, if this is a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Consumes an array.
    #[must_use]
    pub fn into_array(self) -> Option<Vec<Self>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// A map entry by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Takes a map entry by key out of a map.
    pub fn take(&mut self, key: &str) -> Option<Self> {
        match self {
            Self::Map(m) => m
                .iter()
                .position(|(k, _)| k == key)
                .map(|i| m.swap_remove(i).1),
            _ => None,
        }
    }

    /// A map from key/value pairs.
    #[must_use]
    pub fn map<K: Into<String>>(entries: impl IntoIterator<Item = (K, Self)>) -> Self {
        Self::Map(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}
impl From<Bytes> for Value {
    fn from(v: Bytes) -> Self {
        Self::Bytes(v)
    }
}
impl From<Vec<Self>> for Value {
    fn from(v: Vec<Self>) -> Self {
        Self::Array(v)
    }
}

/// Why decoding failed. Never echoes input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CborError {
    /// Input ended inside an item.
    #[error("truncated CBOR")]
    Truncated,
    /// Bytes after the top-level item.
    #[error("trailing bytes after CBOR item")]
    Trailing,
    /// Nested deeper than [`MAX_DEPTH`].
    #[error("CBOR nested too deeply")]
    TooDeep,
    /// Indefinite lengths, reserved values, unsupported simple values.
    #[error("unsupported CBOR encoding")]
    Unsupported,
    /// An integer outside `i64`.
    #[error("CBOR integer out of range")]
    IntRange,
    /// A text string that is not UTF-8, or a map key that is not text.
    #[error("invalid CBOR text or map key")]
    Invalid,
}

fn head(out: &mut BytesMut, major: u8, n: u64) {
    let m = major << 5;
    // Shortest form, as RFC 8949 §4.2.1 (deterministic encoding) requires.
    if let Ok(small) = u8::try_from(n) {
        if small < 24 {
            out.put_u8(m | small);
        } else {
            out.put_u8(m | 0x18);
            out.put_u8(small);
        }
    } else if let Ok(v) = u16::try_from(n) {
        out.put_u8(m | 0x19);
        out.put_u16(v);
    } else if let Ok(v) = u32::try_from(n) {
        out.put_u8(m | 0x1a);
        out.put_u32(v);
    } else {
        out.put_u8(m | 0x1b);
        out.put_u64(n);
    }
}

fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Appends the encoding of `v`.
pub fn encode(v: &Value, out: &mut BytesMut) {
    match v {
        Value::Null => out.put_u8(0xf6),
        Value::Bool(false) => out.put_u8(0xf4),
        Value::Bool(true) => out.put_u8(0xf5),
        Value::Int(i) => {
            if let Ok(u) = u64::try_from(*i) {
                head(out, 0, u);
            } else {
                // -1 - n for negative n: never overflows for i64.
                head(out, 1, (-1 - *i).unsigned_abs());
            }
        }
        Value::Float(x) => {
            out.put_u8(0xfb);
            out.put_f64(*x);
        }
        Value::Bytes(b) => {
            head(out, 2, len64(b.len()));
            out.put_slice(b);
        }
        Value::Text(t) => {
            head(out, 3, len64(t.len()));
            out.put_slice(t.as_bytes());
        }
        Value::Array(a) => {
            head(out, 4, len64(a.len()));
            for x in a {
                encode(x, out);
            }
        }
        Value::Map(m) => {
            head(out, 5, len64(m.len()));
            for (k, x) in m {
                head(out, 3, len64(k.len()));
                out.put_slice(k.as_bytes());
                encode(x, out);
            }
        }
        Value::Tag(t, x) => {
            head(out, 6, *t);
            encode(x, out);
        }
    }
}

/// Encodes into a fresh buffer.
#[must_use]
pub fn to_bytes(v: &Value) -> Bytes {
    let mut out = BytesMut::with_capacity(256);
    encode(v, &mut out);
    out.freeze()
}

struct Reader<'a> {
    src: &'a Bytes,
    pos: usize,
}

impl Reader<'_> {
    fn remaining(&self) -> usize {
        self.src.len().saturating_sub(self.pos)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.src.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<std::ops::Range<usize>, CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        if end > self.src.len() {
            return Err(CborError::Truncated);
        }
        let r = self.pos..end;
        self.pos = end;
        Ok(r)
    }

    fn be(&mut self, n: usize) -> Result<u64, CborError> {
        let r = self.take(n)?;
        let s = self.src.get(r).ok_or(CborError::Truncated)?;
        Ok(s.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    /// The argument of an item head (`info` = low five bits).
    fn arg(&mut self, info: u8) -> Result<u64, CborError> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => self.be(1),
            25 => self.be(2),
            26 => self.be(4),
            27 => self.be(8),
            // 28–30 reserved; 31 indefinite length.
            _ => Err(CborError::Unsupported),
        }
    }

    /// A length that must fit in what remains (each element takes at least `min` bytes).
    fn len(&mut self, info: u8, min: usize) -> Result<usize, CborError> {
        let n = usize::try_from(self.arg(info)?).map_err(|_| CborError::Truncated)?;
        if n.saturating_mul(min) > self.remaining() {
            return Err(CborError::Truncated);
        }
        Ok(n)
    }

    #[allow(
        clippy::many_single_char_names,
        reason = "CBOR's own names: major type, info, length"
    )]
    fn value(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let b = self.byte()?;
        let (major, info) = (b >> 5, b & 0x1f);
        match major {
            0 => i64::try_from(self.arg(info)?)
                .map(Value::Int)
                .map_err(|_| CborError::IntRange),
            1 => {
                let n = i64::try_from(self.arg(info)?).map_err(|_| CborError::IntRange)?;
                Ok(Value::Int(-1 - n))
            }
            2 => {
                let n = self.len(info, 1)?;
                let r = self.take(n)?;
                Ok(Value::Bytes(self.src.slice(r)))
            }
            3 => {
                let n = self.len(info, 1)?;
                let r = self.take(n)?;
                let s = self.src.get(r).ok_or(CborError::Truncated)?;
                let t = std::str::from_utf8(s).map_err(|_| CborError::Invalid)?;
                Ok(Value::Text(t.to_owned()))
            }
            4 => {
                let n = self.len(info, 1)?;
                let mut a = Vec::with_capacity(n);
                for _ in 0..n {
                    a.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(a))
            }
            5 => {
                let n = self.len(info, 2)?;
                let mut m = Vec::with_capacity(n);
                for _ in 0..n {
                    let Value::Text(k) = self.value(depth + 1)? else {
                        return Err(CborError::Invalid);
                    };
                    m.push((k, self.value(depth + 1)?));
                }
                Ok(Value::Map(m))
            }
            6 => {
                let t = self.arg(info)?;
                Ok(Value::Tag(t, Box::new(self.value(depth + 1)?)))
            }
            _ => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                // null and undefined
                22 | 23 => Ok(Value::Null),
                25 => {
                    let h = u16::try_from(self.be(2)?).map_err(|_| CborError::Truncated)?;
                    Ok(Value::Float(f16_to_f64(h)))
                }
                26 => {
                    let w = u32::try_from(self.be(4)?).map_err(|_| CborError::Truncated)?;
                    Ok(Value::Float(f64::from(f32::from_bits(w))))
                }
                27 => Ok(Value::Float(f64::from_bits(self.be(8)?))),
                _ => Err(CborError::Unsupported),
            },
        }
    }
}

fn f16_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 == 0 { 1.0 } else { -1.0 };
    let exp = i32::from((h >> 10) & 0x1f);
    let mant = f64::from(h & 0x3ff);
    let v = match exp {
        0 => mant * 2f64.powi(-24),
        31 => {
            if mant == 0.0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        }
        e => (1.0 + mant / 1024.0) * 2f64.powi(e - 15),
    };
    sign * v
}

/// Decodes exactly one item from `src` (byte strings are zero-copy slices of it).
///
/// # Errors
/// [`CborError`].
pub fn decode(src: &Bytes) -> Result<Value, CborError> {
    let mut r = Reader { src, pos: 0 };
    let v = r.value(0)?;
    if r.remaining() != 0 {
        return Err(CborError::Trailing);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rt(v: &Value) -> Value {
        decode(&to_bytes(v)).unwrap()
    }

    #[test]
    fn rfc8949_vectors() {
        // Appendix A examples.
        for (v, hex) in [
            (Value::Int(0), "00"),
            (Value::Int(23), "17"),
            (Value::Int(24), "1818"),
            (Value::Int(1000), "1903e8"),
            (Value::Int(-1), "20"),
            (Value::Int(-1000), "3903e7"),
            (Value::Int(i64::MAX), "1b7fffffffffffffff"),
            (Value::Int(i64::MIN), "3b7fffffffffffffff"),
            (Value::Null, "f6"),
            (Value::Bool(true), "f5"),
            (Value::Text("a".into()), "6161"),
            (
                Value::Bytes(Bytes::from_static(&[1, 2, 3, 4])),
                "4401020304",
            ),
            (Value::Array(vec![Value::Int(1), Value::Int(2)]), "820102"),
            (Value::map([("a", Value::Int(1))]), "a1616101"),
            (Value::none(), "c6f6"),
        ] {
            assert_eq!(hex::encode(to_bytes(&v)), hex, "{v:?}");
            assert_eq!(rt(&v), v);
        }
        // Floats in every width decode.
        for (hex, x) in [
            ("f93c00", 1.0),
            ("fa47c35000", 100_000.0),
            ("fb3ff199999999999a", 1.1),
        ] {
            let b = Bytes::from(hex::decode(hex).unwrap());
            assert_eq!(decode(&b).unwrap(), Value::Float(x));
        }
    }

    #[test]
    fn rejects_bad_input_without_allocating() {
        let bad = |h: &str| decode(&Bytes::from(hex::decode(h).unwrap()));
        // Array claiming 2^32 elements in 6 bytes: refused before allocation.
        assert_eq!(bad("9bffffffff"), Err(CborError::Truncated));
        assert_eq!(bad("9a7fffffff"), Err(CborError::Truncated));
        assert_eq!(bad("5a7fffffff"), Err(CborError::Truncated));
        assert_eq!(bad("9f"), Err(CborError::Unsupported)); // indefinite
        assert_eq!(bad("1bffffffffffffffff"), Err(CborError::IntRange));
        assert_eq!(bad("0000"), Err(CborError::Trailing));
        assert_eq!(bad("a10101"), Err(CborError::Invalid)); // non-text key
        assert_eq!(bad("62c328"), Err(CborError::Invalid)); // bad UTF-8
        let deep = "81".repeat(MAX_DEPTH + 2) + "00";
        assert_eq!(bad(&deep), Err(CborError::TooDeep));
    }

    #[test]
    fn debug_hides_contents() {
        let v = Value::map([("k", Value::Bytes(Bytes::from_static(b"secret")))]);
        assert!(!format!("{v:?}").contains("secret"));
    }

    fn arb() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::Int),
            proptest::collection::vec(any::<u8>(), 0..20).prop_map(|b| Value::Bytes(b.into())),
            ".{0,12}".prop_map(Value::Text),
        ];
        leaf.prop_recursive(4, 32, 6, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                proptest::collection::vec(("[a-z]{0,4}", inner.clone()), 0..5).prop_map(Value::Map),
                (0u64..300, inner).prop_map(|(t, v)| Value::Tag(t, Box::new(v))),
            ]
        })
    }

    proptest! {
        #[test]
        fn round_trip(v in arb()) {
            prop_assert_eq!(rt(&v), v);
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode(&Bytes::from(data));
        }
    }
}
