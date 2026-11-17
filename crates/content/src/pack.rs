//! Packs (Prompt 6, M4, PROTOCOL §7.4, D-0083): one generic format for sticker packs, chat scenes
//! (Yahoo `IMVironments`), sound stickers and emoticon packs.
//!
//! A pack is an encrypted manifest (object 0) and up to [`MAX_ITEMS`] encrypted assets
//! (objects 1 to n), each in the attachment format ([`crate::attachment`]). Every key comes from
//! one 32-byte **pack key**, which travels only in the share link's fragment
//! (`https://<web>/pack#<pack id hex>.<pack key base64url>`), never to the server:
//!
//! ```text
//! object key n = HKDF-SHA256(salt = "", ikm = pack key,
//!                            info = "songbird.v1/pack-object\0" ‖ be16(n), 64 bytes)
//! ```
//!
//! The manifest lists each asset's kind, metadata and key commitment (`digest`), so an asset that
//! does not belong to this pack fails before any chunk is opened. The manifest's own commitment
//! is read from its header ([`crate::attachment::commitment`]): it is authentic because only the
//! pack key opens it. The server sees a pack ID, how many objects there are, their padded sizes and
//! when the pack was last fetched; never the kind, the title or the content.

use aws_lc_rs::hkdf;
use prost::Message as _;
use zeroize::Zeroizing;

use crate::attachment;

/// Most assets in one pack (D-0079).
pub const MAX_ITEMS: usize = 200;
/// Largest encoded manifest (it is object 0 and is padded like any attachment).
pub const MAX_MANIFEST: usize = 64 * 1024;
/// The pack key.
pub const PACK_KEY_LEN: usize = 32;
/// Domain separation of the per-object keys.
pub const CONTEXT: &[u8] = b"songbird.v1/pack-object\0";

/// What a pack is for. The server never sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Kind {
    /// Unknown (refused).
    Unspecified = 0,
    /// Stickers.
    Stickers = 1,
    /// A chat scene: a background, with optional animation and sound, both people see.
    Scene = 2,
    /// Short sounds sent like stickers.
    Sounds = 3,
    /// Inline emoticons, matched by shortcodes.
    Emoticons = 4,
}

/// One asset of a pack.
#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Item {
    /// The asset's object number in the pack (1 to the item count).
    #[prost(uint32, tag = "1")]
    pub object: u32,
    /// Its media type (`image/webp`, `image/png`, `audio/ogg`, `application/x-scene` …).
    #[prost(string, tag = "2")]
    pub content_type: String,
    /// The plaintext size.
    #[prost(uint64, tag = "3")]
    pub size: u64,
    /// The key commitment of the encrypted asset.
    #[prost(bytes = "vec", tag = "4")]
    pub digest: Vec<u8>,
    /// Emoji the item stands for (stickers, sounds).
    #[prost(string, repeated, tag = "5")]
    pub emoji: Vec<String>,
    /// Shortcodes (emoticons: `:)`, `:wave:`).
    #[prost(string, repeated, tag = "6")]
    pub shortcodes: Vec<String>,
    /// Pixels.
    #[prost(uint32, tag = "7")]
    pub width: u32,
    /// Pixels.
    #[prost(uint32, tag = "8")]
    pub height: u32,
    /// Sounds and animations.
    #[prost(uint32, tag = "9")]
    pub duration_ms: u32,
}

/// The manifest (object 0).
#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Manifest {
    /// 1.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// What the pack is.
    #[prost(enumeration = "Kind", tag = "2")]
    pub kind: i32,
    /// Its title.
    #[prost(string, tag = "3")]
    pub title: String,
    /// Who made it, as they wish to be named.
    #[prost(string, tag = "4")]
    pub author: String,
    /// The item shown for the pack (its `object`), 0 for the first.
    #[prost(uint32, tag = "5")]
    pub cover: u32,
    /// The assets, in display order.
    #[prost(message, repeated, tag = "6")]
    pub items: Vec<Item>,
}

impl std::fmt::Debug for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manifest")
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Item { .. }")
    }
}

/// Why a manifest was refused (the field), or a key could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Larger than [`MAX_MANIFEST`].
    #[error("manifest too large")]
    TooLarge,
    /// Not protobuf of the expected shape.
    #[error("malformed manifest")]
    Decode,
    /// A field breaks its bound.
    #[error("invalid field: {0}")]
    Invalid(&'static str),
    /// The crypto library failed.
    #[error("crypto")]
    Crypto,
}

struct Len64;
impl hkdf::KeyType for Len64 {
    fn len(&self) -> usize {
        attachment::KEY_LEN
    }
}

/// The attachment-format key of object `n` (0: the manifest).
///
/// # Errors
/// [`Error::Crypto`].
pub fn object_key(
    pack_key: &[u8; PACK_KEY_LEN],
    n: u16,
) -> Result<Zeroizing<[u8; attachment::KEY_LEN]>, Error> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(pack_key);
    let index = n.to_be_bytes();
    let info = [CONTEXT, &index[..]];
    let mut out = Zeroizing::new([0u8; attachment::KEY_LEN]);
    prk.expand(&info, Len64)
        .and_then(|o| o.fill(&mut out[..]))
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

fn check(ok: bool, field: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(field))
    }
}

fn strings(v: &[String], most: usize, longest: usize, field: &'static str) -> Result<(), Error> {
    check(
        v.len() <= most && v.iter().all(|s| !s.is_empty() && s.len() <= longest),
        field,
    )
}

impl Manifest {
    /// The manifest object's plaintext: its encoding's length (be32), then the encoding. No
    /// pointer carries a manifest's length, so readers open the object at its padded length
    /// and [`Manifest::open`] finds the end, checking the padding after it is zeros.
    ///
    /// # Errors
    /// [`Error::Invalid`], [`Error::TooLarge`].
    pub fn seal(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let b = self.encode_to_vec();
        let n = u32::try_from(b.len())
            .ok()
            .filter(|_| b.len() <= MAX_MANIFEST)
            .ok_or(Error::TooLarge)?;
        let mut out = Vec::with_capacity(4 + b.len());
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&b);
        Ok(out)
    }

    /// Opens a manifest object's plaintext (as [`Manifest::seal`] made it, plus any zero
    /// padding) strictly: the length bounded before decoding, the padding all zeros, then every
    /// field checked.
    ///
    /// # Errors
    /// [`Error::TooLarge`], [`Error::Decode`], [`Error::Invalid`].
    pub fn open(object: &[u8]) -> Result<Self, Error> {
        let (len, rest) = object.split_first_chunk::<4>().ok_or(Error::Decode)?;
        let n = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| Error::TooLarge)?;
        if n > MAX_MANIFEST {
            return Err(Error::TooLarge);
        }
        let (bytes, pad) = rest.split_at_checked(n).ok_or(Error::Decode)?;
        if pad.iter().any(|b| *b != 0) {
            return Err(Error::Decode);
        }
        let m = Self::decode(bytes).map_err(|_| Error::Decode)?;
        m.validate()?;
        Ok(m)
    }

    /// The pack's bounds: version 1, a known kind, at least one and at most [`MAX_ITEMS`] items
    /// numbered 1 to n exactly once, each with a 32-byte digest.
    ///
    /// # Errors
    /// [`Error::Invalid`] naming the field.
    pub fn validate(&self) -> Result<(), Error> {
        check(self.version == 1, "version")?;
        check(
            matches!(
                Kind::try_from(self.kind),
                Ok(Kind::Stickers | Kind::Scene | Kind::Sounds | Kind::Emoticons)
            ),
            "kind",
        )?;
        check(self.title.len() <= 128, "title")?;
        check(self.author.len() <= 128, "author")?;
        let n = self.items.len();
        check((1..=MAX_ITEMS).contains(&n), "items")?;
        check(usize::try_from(self.cover).is_ok_and(|c| c <= n), "cover")?;
        let mut seen = [false; MAX_ITEMS + 1];
        for i in &self.items {
            let slot = usize::try_from(i.object)
                .ok()
                .filter(|o| (1..=n).contains(o))
                .and_then(|o| seen.get_mut(o))
                .ok_or(Error::Invalid("item.object"))?;
            check(!*slot, "item.object")?;
            *slot = true;
            check(
                !i.content_type.is_empty() && i.content_type.len() <= 64,
                "item.content_type",
            )?;
            check(i.digest.len() == attachment::DIGEST_LEN, "item.digest")?;
            check(i.size <= 64 << 20, "item.size")?;
            strings(&i.emoji, 8, 32, "item.emoji")?;
            strings(&i.shortcodes, 8, 32, "item.shortcodes")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
    use super::*;

    fn item(n: u32) -> Item {
        Item {
            object: n,
            content_type: "image/webp".into(),
            size: 12_000,
            digest: vec![u8::try_from(n % 256).unwrap(); 32],
            emoji: vec!["👋".into()],
            ..Item::default()
        }
    }

    fn manifest(n: u32) -> Manifest {
        Manifest {
            version: 1,
            kind: Kind::Stickers.into(),
            title: "Birds".into(),
            author: "a friend".into(),
            cover: 1,
            items: (1..=n).map(item).collect(),
        }
    }

    #[test]
    fn manifests_round_trip_within_bounds() {
        let m = manifest(3);
        assert_eq!(Manifest::open(&m.seal().unwrap()).unwrap(), m);
        let full = manifest(200);
        assert!(full.seal().unwrap().len() <= MAX_MANIFEST);
        assert!(!format!("{full:?}").contains("Birds"));
    }

    #[test]
    fn every_bound_is_enforced() {
        let mut cases: Vec<(Manifest, &str)> = Vec::new();
        let mut m = manifest(2);
        m.version = 2;
        cases.push((m, "version"));
        let mut m = manifest(2);
        m.kind = 0;
        cases.push((m, "kind"));
        let mut m = manifest(2);
        m.kind = 9;
        cases.push((m, "kind"));
        cases.push((manifest(0), "items"));
        cases.push((manifest(201), "items"));
        let mut m = manifest(2);
        m.items[1].object = 1;
        cases.push((m, "item.object"));
        let mut m = manifest(2);
        m.items[1].object = 3;
        cases.push((m, "item.object"));
        let mut m = manifest(2);
        m.items[0].digest = vec![0; 31];
        cases.push((m, "item.digest"));
        let mut m = manifest(2);
        m.cover = 3;
        cases.push((m, "cover"));
        let mut m = manifest(2);
        m.items[0].emoji = vec![String::new()];
        cases.push((m, "item.emoji"));
        let mut m = manifest(2);
        m.items[0].shortcodes = vec!["x".into(); 9];
        cases.push((m, "item.shortcodes"));
        let mut m = manifest(2);
        m.title = "t".repeat(129);
        cases.push((m, "title"));
        for (m, field) in cases {
            assert_eq!(m.validate(), Err(Error::Invalid(field)));
            let b = m.encode_to_vec();
            let mut obj = u32::try_from(b.len()).unwrap().to_be_bytes().to_vec();
            obj.extend_from_slice(&b);
            assert_eq!(Manifest::open(&obj), Err(Error::Invalid(field)));
        }
        assert_eq!(
            Manifest::open(&[0, 0, 0, 4, 0xff, 0xff, 0xff, 0xff]),
            Err(Error::Decode)
        );
        assert_eq!(Manifest::open(&[0, 0, 0, 9, 1]), Err(Error::Decode));
        assert_eq!(Manifest::open(&[0, 1, 0, 1]), Err(Error::TooLarge));
        // Padding after the manifest must be zeros.
        let mut obj = manifest(1).seal().unwrap();
        obj.extend_from_slice(&[0; 40]);
        assert!(Manifest::open(&obj).is_ok());
        obj.push(1);
        assert_eq!(Manifest::open(&obj), Err(Error::Decode));
    }

    #[test]
    fn object_keys_are_distinct_and_pinned() {
        let k = [0x33; 32];
        let a = object_key(&k, 0).unwrap();
        let b = object_key(&k, 1).unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*a, *object_key(&[0x34; 32], 0).unwrap());
        // Pinned (PROTOCOL §13; `tools/attachment-vectors/check.mjs` derives the same).
        assert_eq!(
            hex::encode(&a[..]),
            "b4b86d6d8340ed7c0242fbee69938c04cff4d62f59120a703df1ec02124c3c92a328512b4a91c35aee31481cae363c507eed2d7cf6a4fd4907e1643bda6af388"
        );
        assert_eq!(
            hex::encode(&b[..]),
            "259a6b7cb7cf7d091b07cae12cf177127ebb19396d61a4b6bf3f2993f5f7a23f498f371981a38260ef70a53d15521470114e39017c42b3c995a8fa6a5aa788e7"
        );
    }
}
