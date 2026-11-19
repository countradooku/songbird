//! The Rust types of `proto/backup.proto`, field for field (`prost`). The `.proto` file is the
//! specification.
//!
//! `Debug` prints type names only: keys, names and messages never reach a log.
#![allow(
    missing_docs,
    clippy::doc_markdown,
    reason = "every field is documented in proto/backup.proto, the specification"
)]

use std::fmt;

macro_rules! redacted_debug {
    ($($t:ty),* $(,)?) => {
        $(impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($t), " { .. }"))
            }
        })*
    };
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Manifest {
    #[prost(uint32, tag = "1")]
    pub format_version: u32,
    #[prost(uint32, tag = "2")]
    pub min_reader_version: u32,
    #[prost(uint64, tag = "3")]
    pub created_ms: u64,
    #[prost(string, tag = "4")]
    pub app_version: String,
    #[prost(enumeration = "Platform", tag = "5")]
    pub platform: i32,
    #[prost(bytes = "vec", tag = "6")]
    pub previous: Vec<u8>,
    #[prost(message, repeated, tag = "7")]
    pub streams: Vec<Stream>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Platform {
    Unknown = 0,
    Ios = 1,
    Android = 2,
    Macos = 3,
    Windows = 4,
    Linux = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum StreamKind {
    Unknown = 0,
    Records = 1,
    SmallMedia = 2,
    Media = 3,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Stream {
    #[prost(enumeration = "StreamKind", tag = "1")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub length: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub sha256: Vec<u8>,
    #[prost(message, repeated, tag = "5")]
    pub chunks: Vec<ChunkRef>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct ChunkRef {
    #[prost(bytes = "vec", tag = "1")]
    pub name: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub length: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Record {
    #[prost(oneof = "record::Body", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
    pub body: Option<record::Body>,
}

pub mod record {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    #[prost(skip_debug)]
    #[allow(clippy::large_enum_variant, reason = "decoded once, never moved hot")]
    pub enum Body {
        #[prost(message, tag = "1")]
        Account(super::Account),
        #[prost(message, tag = "2")]
        Profile(super::Profile),
        #[prost(message, tag = "3")]
        Setting(super::Setting),
        #[prost(message, tag = "4")]
        Contact(super::Contact),
        #[prost(message, tag = "5")]
        Group(super::Group),
        #[prost(message, tag = "6")]
        Chat(super::Chat),
        #[prost(message, tag = "7")]
        Message(super::Message),
        #[prost(message, tag = "8")]
        Media(super::Media),
    }

    impl std::fmt::Debug for Body {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::Account(_) => "Account { .. }",
                Self::Profile(_) => "Profile { .. }",
                Self::Setting(_) => "Setting { .. }",
                Self::Contact(_) => "Contact { .. }",
                Self::Group(_) => "Group { .. }",
                Self::Chat(_) => "Chat { .. }",
                Self::Message(_) => "Message { .. }",
                Self::Media(_) => "Media { .. }",
            })
        }
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Account {
    #[prost(bytes = "vec", tag = "1")]
    pub account_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub identity_seed: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub profile_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub storage_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub access_key: Vec<u8>,
    #[prost(string, tag = "6")]
    pub username: String,
    #[prost(bytes = "vec", tag = "7")]
    pub username_key: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub device_list_version: u64,
    #[prost(string, tag = "9")]
    pub server_name: String,
}

impl Drop for Account {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.identity_seed.zeroize();
        self.profile_key.zeroize();
        self.storage_key.zeroize();
        self.access_key.zeroize();
        self.username_key.zeroize();
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Profile {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub about: String,
    #[prost(string, tag = "3")]
    pub status_text: String,
    #[prost(string, tag = "4")]
    pub status_emoji: String,
    #[prost(uint64, tag = "5")]
    pub status_expires_ms: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub avatar: Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub profile_version: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Setting {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Contact {
    #[prost(bytes = "vec", tag = "1")]
    pub contact_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub account_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub name: String,
    #[prost(string, tag = "4")]
    pub notes: String,
    #[prost(string, repeated, tag = "5")]
    pub buddy_groups: Vec<String>,
    #[prost(bytes = "vec", tag = "6")]
    pub identity_key: Vec<u8>,
    #[prost(bool, tag = "7")]
    pub verified: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Group {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(bytes = "vec", tag = "3")]
    pub metadata_key: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub members: Vec<Vec<u8>>,
    #[prost(uint32, tag = "5")]
    pub role: u32,
    #[prost(bool, tag = "6")]
    pub channel: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Chat {
    #[prost(bytes = "vec", tag = "1")]
    pub chat_id: Vec<u8>,
    #[prost(enumeration = "ChatKind", tag = "2")]
    pub kind: i32,
    #[prost(string, tag = "3")]
    pub title: String,
    #[prost(uint64, tag = "4")]
    pub created_ms: u64,
    #[prost(uint64, tag = "5")]
    pub read_up_to_ms: u64,
    #[prost(bool, tag = "6")]
    pub archived: bool,
    #[prost(bool, tag = "7")]
    pub pinned: bool,
    #[prost(uint64, tag = "8")]
    pub muted_until_ms: u64,
    #[prost(uint32, tag = "9")]
    pub timer_s: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ChatKind {
    Unknown = 0,
    Direct = 1,
    Group = 2,
    Channel = 3,
    NoteToSelf = 4,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Message {
    #[prost(bytes = "vec", tag = "1")]
    pub chat_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub message_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub sender: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub sent_ms: u64,
    #[prost(uint64, tag = "5")]
    pub received_ms: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub content: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "7")]
    pub media: Vec<Vec<u8>>,
    #[prost(enumeration = "MessageStatus", tag = "8")]
    pub status: i32,
    #[prost(bool, tag = "9")]
    pub starred: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MessageStatus {
    Unknown = 0,
    Sent = 1,
    Delivered = 2,
    Read = 3,
    Failed = 4,
    Received = 5,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Media {
    #[prost(bytes = "vec", tag = "1")]
    pub r#ref: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub length: u64,
    #[prost(string, tag = "3")]
    pub mime: String,
    #[prost(string, tag = "4")]
    pub file_name: String,
    #[prost(uint32, tag = "5")]
    pub width: u32,
    #[prost(uint32, tag = "6")]
    pub height: u32,
    #[prost(uint32, tag = "7")]
    pub duration_ms: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
#[prost(skip_debug)]
pub struct Blob {
    #[prost(bytes = "vec", tag = "1")]
    pub r#ref: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

redacted_debug!(
    Manifest, Stream, ChunkRef, Record, Account, Profile, Setting, Contact, Group, Chat, Message,
    Media, Blob,
);
