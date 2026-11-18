//! Frames: one WebSocket binary message each.
//!
//! Layout: a one-byte frame type, then fixed-width big-endian fields, then (for frames that carry
//! one) an opaque payload running to the end of the message. The WebSocket message length bounds
//! the frame, so payloads need no length prefix unless there are several (`Send`).
//!
//! | Type | Direction | Frame | Body |
//! | --- | --- | --- | --- |
//! | `0x01` | C→S | `Send` | `req_id u32`, `idempotency_key [16]`, `flags u8`, [MLS: `group [16]`, `epoch u64`], [access: `access_key [16]`], [franked: `commitment [32]`], [expires: `expire_after_s u32`], `count u16`, then per device `count ×` (`device_id [16]`, `len u32`, `envelope [len]`) or shared `count × device_id [16]`, `len u32`, `body [len]` |
//! | `0x02` | C→S | `Ack` | `up_to_seq u64` |
//! | `0x03` | C→S | `Ephemeral` | `to [16]`, `payload` |
//! | `0x04` | C→S | `Attention` | `to [16]`, `payload` (a nudge, Prompt 9, D-0104) |
//! | `0x10` | C→S | `Auth` | protobuf [`control::Auth`] |
//! | `0x81` | S→C | `Deliver` | `seq u64`, `envelope` |
//! | `0x82` | S→C | `SendResult` | `req_id u32`, `status u8`, status body |
//! | `0x83` | S→C | `Ephemeral` | `payload` |
//! | `0x84` | S→C | `Attention` | `payload`: an event that came through the attention class (D-0108) |
//! | `0x90` | S→C | `Hello` | protobuf [`control::Hello`] |
//! | `0x91` | S→C | `AuthOk` | protobuf [`control::AuthOk`] |
//! | `0x92` | S→C | `Error` | protobuf [`control::Error`] |
//!
//! Decoders take the message as [`Bytes`] and return payloads as zero-copy slices of it.
//! They check every length against [`Limits`] before allocating (invariant 7) and reject
//! trailing bytes, so each frame has exactly one encoding.

use std::ops::Range;

use bytes::{BufMut, Bytes, BytesMut};
use prost::Message as _;
use songbird_types::DeviceId;
use songbird_types::id::ID_LEN;

use crate::IDEMPOTENCY_KEY_LEN;
use crate::control;

/// Frame type bytes.
pub mod ty {
    /// Client → server: send envelopes.
    pub const SEND: u8 = 0x01;
    /// Client → server: cumulative acknowledgement.
    pub const ACK: u8 = 0x02;
    /// Client → server: ephemeral event for one device.
    pub const EPHEMERAL: u8 = 0x03;
    /// Client → server: an attention event (a nudge) for one device (Prompt 9).
    pub const ATTENTION: u8 = 0x04;
    /// Client → server: authentication (protobuf).
    pub const AUTH: u8 = 0x10;
    /// Server → client: one stored envelope.
    pub const DELIVER: u8 = 0x81;
    /// Server → client: outcome of a `Send`.
    pub const SEND_RESULT: u8 = 0x82;
    /// Server → client: ephemeral event.
    pub const EPHEMERAL_DELIVER: u8 = 0x83;
    /// Server → client: an attention event, which passed the attention class's budgets and the
    /// recipient's blocks (D-0108). Apps honour a nudge only from this frame.
    pub const ATTENTION_DELIVER: u8 = 0x84;
    /// Server → client: challenge (protobuf).
    pub const HELLO: u8 = 0x90;
    /// Server → client: authenticated (protobuf).
    pub const AUTH_OK: u8 = 0x91;
    /// Server → client: error before close (protobuf).
    pub const ERROR: u8 = 0x92;
}

/// Bytes in a `Deliver` frame before the envelope.
pub const DELIVER_HEADER_LEN: usize = 1 + 8;
/// Bytes in a `Send` frame before the first recipient (no MLS block).
pub const SEND_HEADER_LEN: usize = 1 + 4 + IDEMPOTENCY_KEY_LEN + 1 + 2;
/// Retired `Send` flag (D-0026's MLS commit block, `group [16]`, `epoch u64`): refused since
/// Prompt 5. Commits go to `POST /v1/groups/commit`, which validates them against the group
/// before anything is stored (D-0067). The bit is never reused.
pub const SEND_FLAG_MLS: u8 = 0x01;
/// `Send` flag: one shared body for every recipient device.
pub const SEND_FLAG_SHARED: u8 = 0x02;
/// `Send` flag: the combined access key of the addressed accounts follows (Prompt 4, M4): a send
/// from a contact (per device or a group's shared body). Not with [`SEND_FLAG_REQUEST`].
pub const SEND_FLAG_ACCESS: u8 = 0x04;
/// `Send` flag: this send is a message request (Prompt 4, M4). Not with [`SEND_FLAG_ACCESS`],
/// [`SEND_FLAG_SHARED`] or [`SEND_FLAG_MLS`].
pub const SEND_FLAG_REQUEST: u8 = 0x08;
/// `Send` flag: a franking commitment follows; the server stamps it (Prompt 4, M3).
pub const SEND_FLAG_FRANKED: u8 = 0x10;
/// `Send` flag: the disappearing hint follows, a deadline in seconds from the store (Prompt 4,
/// M3).
pub const SEND_FLAG_EXPIRES: u8 = 0x20;
/// `Send` flag: a group application message (Prompt 5, D-0067): the group ID follows, and the
/// shared body is one MLS `PrivateMessage` that the server fans out to the group's roster, so
/// the frame lists no devices. Needs [`SEND_FLAG_SHARED`]; not with [`SEND_FLAG_MLS`],
/// [`SEND_FLAG_ACCESS`] or [`SEND_FLAG_REQUEST`] (membership is the authorization).
pub const SEND_FLAG_GROUP: u8 = 0x40;
/// `Send` flag: wake nobody (Prompt 8, D-0095). The envelopes are stored and delivered as usual,
/// but a recipient that is offline gets no push for them: receipts, sync messages and other
/// sends the recipient need not see at once. No block follows; any other flag may go with it.
/// The server keeps the bit only while it routes the send: never stored, never logged.
pub const SEND_FLAG_SILENT: u8 = 0x80;
/// Every `Send` flag this version takes; other bits (and the retired [`SEND_FLAG_MLS`]) are
/// refused.
pub const SEND_FLAGS: u8 = SEND_FLAG_SHARED
    | SEND_FLAG_ACCESS
    | SEND_FLAG_REQUEST
    | SEND_FLAG_FRANKED
    | SEND_FLAG_EXPIRES
    | SEND_FLAG_GROUP
    | SEND_FLAG_SILENT;
/// Longest disappearing hint: the 30 days an envelope is kept anyway.
pub const MAX_EXPIRE_AFTER_S: u32 = 30 * 24 * 3600;
/// Length of an access key.
pub const ACCESS_KEY_LEN: usize = 16;
/// Length of a franking commitment.
pub const COMMITMENT_LEN: usize = 32;
/// Bytes per recipient in a `Send` frame, before its envelope.
pub const RECIPIENT_HEADER_LEN: usize = ID_LEN + 4;

/// Size limits, configured on the server and announced out of band to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest single envelope (start: 64 KiB; larger content goes through attachments).
    pub max_envelope_bytes: usize,
    /// Most recipient devices in one `Send`.
    pub max_recipients: usize,
    /// Largest whole `Send` frame.
    pub max_send_bytes: usize,
    /// Largest ephemeral payload.
    pub max_ephemeral_bytes: usize,
    /// Largest protobuf body of a control frame.
    pub max_control_bytes: usize,
}

impl Limits {
    /// Starting values from the master prompt (§5, Limits).
    pub const DEFAULT: Self = Self {
        max_envelope_bytes: 64 * 1024,
        max_recipients: 1024,
        max_send_bytes: 1024 * 1024,
        max_ephemeral_bytes: 4 * 1024,
        max_control_bytes: 4 * 1024,
    };

    /// Largest WebSocket message either side may send under these limits; configure the
    /// WebSocket layer to refuse anything larger before buffering it.
    #[must_use]
    pub fn max_message_bytes(&self) -> usize {
        let deliver = DELIVER_HEADER_LEN.saturating_add(self.max_envelope_bytes);
        let ephemeral = (1 + ID_LEN).saturating_add(self.max_ephemeral_bytes);
        let control = 1usize.saturating_add(self.max_control_bytes);
        self.max_send_bytes.max(deliver).max(ephemeral).max(control)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a frame was rejected. Never echoes input bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Zero-length message.
    #[error("empty frame")]
    Empty,
    /// Unknown or wrong-direction frame type.
    #[error("unknown frame type {0:#04x}")]
    UnknownType(u8),
    /// The message ended inside a field.
    #[error("truncated frame")]
    Truncated,
    /// Bytes left after the last field.
    #[error("trailing bytes after frame")]
    Trailing,
    /// A length is over its limit.
    #[error("{what} too large: {got} > {limit}")]
    TooLarge {
        /// Which length.
        what: &'static str,
        /// Its value.
        got: usize,
        /// The limit.
        limit: usize,
    },
    /// A `Send` with no recipients.
    #[error("no recipients")]
    NoRecipients,
    /// An empty envelope or ephemeral payload.
    #[error("empty payload")]
    EmptyPayload,
    /// A control frame's body is not valid protobuf or has a bad field.
    #[error("invalid control frame: {0}")]
    Control(&'static str),
}

/// One recipient of a `Send`.
#[derive(Clone, PartialEq, Eq)]
pub struct Recipient {
    /// The recipient device.
    pub device: DeviceId,
    /// The ciphertext for that device; opaque to the server.
    pub envelope: Bytes,
}

impl std::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recipient")
            .field("device", &self.device)
            .field("envelope_len", &self.envelope.len())
            .finish()
    }
}

/// What a `Send` carries.
#[derive(Clone, PartialEq, Eq)]
pub enum SendPayload {
    /// One ciphertext per recipient device (pairwise sessions).
    PerDevice(Vec<Recipient>),
    /// One ciphertext for every listed device (an MLS group or channel message), stored once.
    Shared {
        /// Recipient devices.
        devices: Vec<DeviceId>,
        /// The ciphertext.
        body: Bytes,
    },
}

impl SendPayload {
    /// Number of recipient devices.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::PerDevice(r) => r.len(),
            Self::Shared { devices, .. } => devices.len(),
        }
    }

    /// Whether there are no recipients.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The recipient devices, in order.
    pub fn devices(&self) -> impl Iterator<Item = &DeviceId> {
        let (a, b) = match self {
            Self::PerDevice(items) => (Some(items.iter().map(|i| &i.device)), None),
            Self::Shared { devices, .. } => (None, Some(devices.iter())),
        };
        a.into_iter().flatten().chain(b.into_iter().flatten())
    }
}

impl std::fmt::Debug for SendPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PerDevice(r) => f.debug_tuple("PerDevice").field(&r.len()).finish(),
            Self::Shared { devices, body } => f
                .debug_struct("Shared")
                .field("devices", &devices.len())
                .field("len", &body.len())
                .finish(),
        }
    }
}

/// What a `Send` tells the server beyond its recipients (Prompt 4): each set only by its flag.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SendHints {
    /// The XOR of the access keys of every addressed account that is not open: the sender is a
    /// contact (`ACCESS`).
    pub access: Option<[u8; ACCESS_KEY_LEN]>,
    /// The send is a message request (`REQUEST`).
    pub request: bool,
    /// The franking commitment the server stamps (`FRANKED`).
    pub commitment: Option<[u8; COMMITMENT_LEN]>,
    /// Delete undelivered envelopes this many seconds after the store, and never deliver them
    /// later (`EXPIRES`, 1 to [`MAX_EXPIRE_AFTER_S`]).
    pub expire_after_s: Option<u32>,
    /// The group of a group application message (`GROUP`, Prompt 5): the server fans the shared
    /// body out to this group's roster.
    pub group: Option<[u8; 16]>,
    /// Wake no offline recipient (`SILENT`, Prompt 8): stored and delivered as usual, no push.
    pub silent: bool,
}

impl std::fmt::Debug for SendHints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendHints")
            .field("access", &self.access.is_some())
            .field("request", &self.request)
            .field("franked", &self.commitment.is_some())
            .field("expire_after_s", &self.expire_after_s)
            .field("group", &self.group.is_some())
            .field("silent", &self.silent)
            .finish()
    }
}

/// A `Send` frame.
#[derive(Clone, PartialEq, Eq)]
pub struct SendFrame {
    /// Chosen by the client, echoed in the matching `SendResult`.
    pub req_id: u32,
    /// Random per logical message; a retry reuses it so the server stores it once.
    pub idempotency_key: [u8; IDEMPOTENCY_KEY_LEN],
    /// Access key, request, franking commitment, disappearing hint, group.
    pub hints: SendHints,
    /// Recipients and ciphertext, at most [`Limits::max_recipients`] devices.
    pub payload: SendPayload,
}

impl SendFrame {
    /// A plain per-device send.
    #[must_use]
    pub const fn per_device(
        req_id: u32,
        idempotency_key: [u8; IDEMPOTENCY_KEY_LEN],
        recipients: Vec<Recipient>,
    ) -> Self {
        Self {
            req_id,
            idempotency_key,
            hints: SendHints {
                access: None,
                request: false,
                commitment: None,
                expire_after_s: None,
                group: None,
                silent: false,
            },
            payload: SendPayload::PerDevice(recipients),
        }
    }
}

impl std::fmt::Debug for SendFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendFrame")
            .field("req_id", &self.req_id)
            .field("hints", &self.hints)
            .field("payload", &self.payload)
            .finish_non_exhaustive()
    }
}

/// Frames a client sends.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientFrame {
    /// Answer to `Hello`.
    Auth(control::Auth),
    /// Store and deliver envelopes.
    Send(SendFrame),
    /// Everything up to and including `up_to_seq` is stored on the device; delete it.
    Ack {
        /// Highest `seq` acknowledged.
        up_to_seq: u64,
    },
    /// A never-stored event (typing, presence, call signal) for one device.
    Ephemeral {
        /// Recipient device.
        to: DeviceId,
        /// Opaque, client-encrypted payload.
        payload: Bytes,
    },
    /// A never-stored attention event (a nudge, Prompt 9) for one device: routed like
    /// [`ClientFrame::Ephemeral`], within budgets per (sender, recipient) account pair. The
    /// recipient gets an ordinary `Ephemeral` frame.
    Attention {
        /// Recipient device.
        to: DeviceId,
        /// Opaque, client-encrypted payload.
        payload: Bytes,
    },
}

/// Reason codes of a rejected send (`SendResult` status 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Too many sends; retry after the hint.
    RateLimited,
    /// An envelope or the frame is over the limit.
    TooLarge,
    /// More recipients than allowed.
    TooManyRecipients,
    /// A recipient device does not exist.
    UnknownRecipient,
    /// The same device appears twice.
    DuplicateRecipient,
    /// The store is unavailable; retry after the hint.
    Unavailable,
    /// The idempotency key was already used for other recipients; use a fresh key.
    IdempotencyConflict,
    /// An MLS commit from an epoch the group has left: process the winning commit, retry.
    StaleEpoch,
    /// An envelope begins with the prefix reserved for what the server writes
    /// ([`crate::envelope::RESERVED_PREFIX`]: system frames, franking stamps); never a user
    /// message.
    ReservedEnvelope,
    /// A send to another account with neither its access key (or the right one) nor the request
    /// flag (Prompt 4): fetch the profile key again, or send a message request.
    AccessRequired,
    /// A message request that breaks the request rules: not franked, or addressed to more than
    /// one other account (Prompt 4).
    InvalidRequest,
    /// A group message from a device that is not in the group's roster, or to a group that does
    /// not exist (Prompt 5; one answer for both).
    NotMember,
    /// A group message whose body is not an MLS `PrivateMessage` application message of the
    /// frame's group (Prompt 5).
    InvalidGroupMessage,
    /// A group message from a member whose role may not send ("only admins can send", a
    /// channel's subscribers; Prompt 5, D-0070).
    NotAllowed,
    /// A code this version does not know (forward compatibility).
    Other(u16),
}

impl RejectReason {
    /// Wire value.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::RateLimited => 1,
            Self::TooLarge => 2,
            Self::TooManyRecipients => 3,
            Self::UnknownRecipient => 4,
            Self::DuplicateRecipient => 5,
            Self::Unavailable => 6,
            Self::IdempotencyConflict => 7,
            Self::StaleEpoch => 8,
            Self::ReservedEnvelope => 9,
            Self::AccessRequired => 10,
            Self::InvalidRequest => 11,
            Self::NotMember => 12,
            Self::InvalidGroupMessage => 13,
            Self::NotAllowed => 14,
            Self::Other(c) => c,
        }
    }

    /// From a wire value.
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            1 => Self::RateLimited,
            2 => Self::TooLarge,
            3 => Self::TooManyRecipients,
            4 => Self::UnknownRecipient,
            5 => Self::DuplicateRecipient,
            6 => Self::Unavailable,
            7 => Self::IdempotencyConflict,
            8 => Self::StaleEpoch,
            9 => Self::ReservedEnvelope,
            10 => Self::AccessRequired,
            11 => Self::InvalidRequest,
            12 => Self::NotMember,
            13 => Self::InvalidGroupMessage,
            14 => Self::NotAllowed,
            c => Self::Other(c),
        }
    }

    /// Whether retrying the same send later can succeed.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Unavailable)
    }
}

/// Outcome of a send.
#[derive(Debug, Clone, PartialEq)]
pub enum SendStatus {
    /// Stored durably for every recipient (status 0).
    Accepted,
    /// Not stored for anyone (status 1).
    Rejected {
        /// Why.
        reason: RejectReason,
        /// Suggested wait before retrying, in milliseconds (0: none).
        retry_after_ms: u32,
    },
    /// Not stored: the device list is out of date (status 2).
    DeviceMismatch(control::DeviceMismatch),
}

/// Frames the server sends.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerFrame {
    /// Challenge; first frame on every connection.
    Hello(control::Hello),
    /// Authenticated.
    AuthOk(control::AuthOk),
    /// Error, followed by a close.
    Error(control::Error),
    /// One stored envelope.
    Deliver {
        /// Per-device sequence number: strictly increasing, no gaps.
        seq: u64,
        /// Opaque ciphertext.
        envelope: Bytes,
    },
    /// Outcome of the `Send` with this `req_id`.
    SendResult {
        /// From the `Send`.
        req_id: u32,
        /// Outcome.
        status: SendStatus,
    },
    /// An ephemeral event.
    Ephemeral {
        /// Opaque payload; the sender is identified only inside it.
        payload: Bytes,
    },
    /// An attention event (a nudge) that came through the attention class (D-0108).
    Attention {
        /// Opaque payload; the sender is identified only inside it.
        payload: Bytes,
    },
}

/// Bounds-checked reader over a frame. Never panics.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn range(&mut self, n: usize) -> Result<Range<usize>, FrameError> {
        let end = self.pos.checked_add(n).ok_or(FrameError::Truncated)?;
        if end > self.data.len() {
            return Err(FrameError::Truncated);
        }
        let r = self.pos..end;
        self.pos = end;
        Ok(r)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        let r = self.range(N)?;
        self.data
            .get(r)
            .and_then(|s| s.try_into().ok())
            .ok_or(FrameError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, FrameError> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, FrameError> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, FrameError> {
        self.array().map(u64::from_be_bytes)
    }

    fn device(&mut self) -> Result<DeviceId, FrameError> {
        self.array().map(DeviceId::from_bytes)
    }

    /// Everything left, as a range.
    fn rest(&mut self) -> Range<usize> {
        let r = self.pos..self.data.len();
        self.pos = self.data.len();
        r
    }

    fn finish(&self) -> Result<(), FrameError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(FrameError::Trailing)
        }
    }
}

fn check_len(what: &'static str, got: usize, limit: usize) -> Result<(), FrameError> {
    if got > limit {
        Err(FrameError::TooLarge { what, got, limit })
    } else {
        Ok(())
    }
}

/// Splits off the type byte after the whole-message size check.
fn frame_type(msg: &[u8], limits: &Limits) -> Result<u8, FrameError> {
    check_len("frame", msg.len(), limits.max_message_bytes())?;
    msg.first().copied().ok_or(FrameError::Empty)
}

fn control_body<'a>(msg: &'a [u8], limits: &Limits) -> Result<&'a [u8], FrameError> {
    let body = msg.get(1..).ok_or(FrameError::Truncated)?;
    check_len("control body", body.len(), limits.max_control_bytes)?;
    Ok(body)
}

fn decode_control<M: prost::Message + Default>(
    msg: &[u8],
    limits: &Limits,
    what: &'static str,
) -> Result<M, FrameError> {
    let body = control_body(msg, limits)?;
    M::decode(body).map_err(|_| FrameError::Control(what))
}

fn encode_control(out: &mut BytesMut, ty: u8, m: &impl prost::Message) {
    out.reserve(1 + m.encoded_len());
    out.put_u8(ty);
    // `reserve` above guarantees capacity, and `BytesMut` grows anyway; encoding cannot fail.
    let _ = m.encode(out);
}

fn put_len(out: &mut BytesMut, len: usize) {
    // Lengths are bounded by `Limits` (far below 4 GiB) before a frame is encoded.
    out.put_u32(u32::try_from(len).unwrap_or(u32::MAX));
}

impl ClientFrame {
    /// Decodes one client message.
    ///
    /// # Errors
    /// [`FrameError`] for anything malformed or over `limits`.
    pub fn decode(msg: &Bytes, limits: &Limits) -> Result<Self, FrameError> {
        match frame_type(msg, limits)? {
            ty::SEND => decode_send(msg, limits).map(Self::Send),
            ty::ACK => {
                let mut c = Cursor::new(msg, 1);
                let up_to_seq = c.u64()?;
                c.finish()?;
                Ok(Self::Ack { up_to_seq })
            }
            ty::EPHEMERAL => {
                let mut c = Cursor::new(msg, 1);
                let to = c.device()?;
                let r = c.rest();
                if r.is_empty() {
                    return Err(FrameError::EmptyPayload);
                }
                check_len("ephemeral", r.len(), limits.max_ephemeral_bytes)?;
                Ok(Self::Ephemeral {
                    to,
                    payload: msg.slice(r),
                })
            }
            ty::ATTENTION => {
                let mut c = Cursor::new(msg, 1);
                let to = c.device()?;
                let r = c.rest();
                if r.is_empty() {
                    return Err(FrameError::EmptyPayload);
                }
                check_len("ephemeral", r.len(), limits.max_ephemeral_bytes)?;
                Ok(Self::Attention {
                    to,
                    payload: msg.slice(r),
                })
            }
            ty::AUTH => decode_control::<control::Auth>(msg, limits, "auth").map(Self::Auth),
            other => Err(FrameError::UnknownType(other)),
        }
    }

    /// Appends the encoding to `out`.
    pub fn encode(&self, out: &mut BytesMut) {
        match self {
            Self::Auth(a) => encode_control(out, ty::AUTH, a),
            Self::Send(s) => encode_send(s, out),
            Self::Ack { up_to_seq } => {
                out.reserve(9);
                out.put_u8(ty::ACK);
                out.put_u64(*up_to_seq);
            }
            Self::Ephemeral { to, payload } => {
                out.reserve(1 + ID_LEN + payload.len());
                out.put_u8(ty::EPHEMERAL);
                out.put_slice(to.as_bytes());
                out.put_slice(payload);
            }
            Self::Attention { to, payload } => {
                out.reserve(1 + ID_LEN + payload.len());
                out.put_u8(ty::ATTENTION);
                out.put_slice(to.as_bytes());
                out.put_slice(payload);
            }
        }
    }

    /// The encoding as a fresh buffer.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut out = BytesMut::new();
        self.encode(&mut out);
        out.freeze()
    }
}

/// The flag-selected blocks of a `Send`: the MLS commit and the hints, with the flag rules.
fn decode_send_blocks(c: &mut Cursor<'_>, flags: u8) -> Result<SendHints, FrameError> {
    let has = |f: u8| flags & f != 0;
    // Unknown bits and the retired MLS flag are refused by the mask.
    if flags & !SEND_FLAGS != 0
        // A contact or a request, not both; a request is one 1:1 message, never a shared body.
        || (has(SEND_FLAG_ACCESS) && has(SEND_FLAG_REQUEST))
        || (has(SEND_FLAG_REQUEST) && has(SEND_FLAG_SHARED))
        // A group message is one shared body for the roster; membership authorizes it.
        || (has(SEND_FLAG_GROUP) && (!has(SEND_FLAG_SHARED) || has(SEND_FLAG_ACCESS)))
    {
        return Err(FrameError::Control("send.flags"));
    }
    let access = if has(SEND_FLAG_ACCESS) {
        Some(c.array::<ACCESS_KEY_LEN>()?)
    } else {
        None
    };
    let commitment = if has(SEND_FLAG_FRANKED) {
        Some(c.array::<COMMITMENT_LEN>()?)
    } else {
        None
    };
    let expire_after_s = if has(SEND_FLAG_EXPIRES) {
        let s = c.u32()?;
        if s == 0 || s > MAX_EXPIRE_AFTER_S {
            return Err(FrameError::Control("send.expire_after_s"));
        }
        Some(s)
    } else {
        None
    };
    let group = if has(SEND_FLAG_GROUP) {
        Some(c.array::<16>()?)
    } else {
        None
    };
    let hints = SendHints {
        access,
        request: has(SEND_FLAG_REQUEST),
        commitment,
        expire_after_s,
        group,
        silent: has(SEND_FLAG_SILENT),
    };
    Ok(hints)
}

fn decode_send(msg: &Bytes, limits: &Limits) -> Result<SendFrame, FrameError> {
    check_len("send", msg.len(), limits.max_send_bytes)?;
    let mut c = Cursor::new(msg, 1);
    let req_id = c.u32()?;
    let idempotency_key = c.array::<IDEMPOTENCY_KEY_LEN>()?;
    let [flags] = c.array::<1>()?;
    let hints = decode_send_blocks(&mut c, flags)?;
    let count = usize::from(c.u16()?);
    // A group message lists no devices (the server takes the roster); every other send lists
    // at least one.
    if (count == 0) != hints.group.is_some() {
        return Err(if count == 0 {
            FrameError::NoRecipients
        } else {
            FrameError::Control("send.group")
        });
    }
    check_len("recipients", count, limits.max_recipients)?;
    let payload = if flags & SEND_FLAG_SHARED == 0 {
        // Every recipient needs at least its header and one envelope byte: refuse a count the
        // message cannot hold before reserving space for it.
        let min = count
            .checked_mul(RECIPIENT_HEADER_LEN + 1)
            .ok_or(FrameError::Truncated)?;
        if c.remaining() < min {
            return Err(FrameError::Truncated);
        }
        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            let device = c.device()?;
            let len = usize::try_from(c.u32()?).map_err(|_| FrameError::Truncated)?;
            if len == 0 {
                return Err(FrameError::EmptyPayload);
            }
            check_len("envelope", len, limits.max_envelope_bytes)?;
            let r = c.range(len)?;
            recipients.push(Recipient {
                device,
                envelope: msg.slice(r),
            });
        }
        SendPayload::PerDevice(recipients)
    } else {
        let min = count
            .checked_mul(ID_LEN)
            .and_then(|n| n.checked_add(4 + 1))
            .ok_or(FrameError::Truncated)?;
        if c.remaining() < min {
            return Err(FrameError::Truncated);
        }
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            devices.push(c.device()?);
        }
        let len = usize::try_from(c.u32()?).map_err(|_| FrameError::Truncated)?;
        if len == 0 {
            return Err(FrameError::EmptyPayload);
        }
        check_len("envelope", len, limits.max_envelope_bytes)?;
        let r = c.range(len)?;
        SendPayload::Shared {
            devices,
            body: msg.slice(r),
        }
    };
    c.finish()?;
    Ok(SendFrame {
        req_id,
        idempotency_key,
        hints,
        payload,
    })
}

fn encode_send(s: &SendFrame, out: &mut BytesMut) {
    let body: usize = match &s.payload {
        SendPayload::PerDevice(rs) => rs
            .iter()
            .map(|r| RECIPIENT_HEADER_LEN.saturating_add(r.envelope.len()))
            .fold(0, usize::saturating_add),
        SendPayload::Shared { devices, body } => (devices.len() * ID_LEN) + 4 + body.len(),
    };
    out.reserve(
        SEND_HEADER_LEN
            .saturating_add(24 + 16 + 32 + 4 + 16)
            .saturating_add(body),
    );
    out.put_u8(ty::SEND);
    out.put_u32(s.req_id);
    out.put_slice(&s.idempotency_key);
    let mut flags = 0;
    if matches!(s.payload, SendPayload::Shared { .. }) {
        flags |= SEND_FLAG_SHARED;
    }
    let h = &s.hints;
    if h.access.is_some() {
        flags |= SEND_FLAG_ACCESS;
    }
    if h.request {
        flags |= SEND_FLAG_REQUEST;
    }
    if h.commitment.is_some() {
        flags |= SEND_FLAG_FRANKED;
    }
    if h.expire_after_s.is_some() {
        flags |= SEND_FLAG_EXPIRES;
    }
    if h.group.is_some() {
        flags |= SEND_FLAG_GROUP;
    }
    if h.silent {
        flags |= SEND_FLAG_SILENT;
    }
    out.put_u8(flags);
    if let Some(k) = &h.access {
        out.put_slice(k);
    }
    if let Some(c) = &h.commitment {
        out.put_slice(c);
    }
    if let Some(t) = h.expire_after_s {
        out.put_u32(t);
    }
    if let Some(g) = &h.group {
        out.put_slice(g);
    }
    out.put_u16(u16::try_from(s.payload.len()).unwrap_or(u16::MAX));
    match &s.payload {
        SendPayload::PerDevice(rs) => {
            for r in rs {
                out.put_slice(r.device.as_bytes());
                put_len(out, r.envelope.len());
                out.put_slice(&r.envelope);
            }
        }
        SendPayload::Shared { devices, body } => {
            for d in devices {
                out.put_slice(d.as_bytes());
            }
            put_len(out, body.len());
            out.put_slice(body);
        }
    }
}

/// Appends a `Deliver` frame. Hot path: one reserve, two copies, no other allocation.
pub fn encode_deliver(out: &mut BytesMut, seq: u64, envelope: &[u8]) {
    out.reserve(DELIVER_HEADER_LEN + envelope.len());
    out.put_u8(ty::DELIVER);
    out.put_u64(seq);
    out.put_slice(envelope);
}

/// Appends an accepted `SendResult`. Hot path.
pub fn encode_send_accepted(out: &mut BytesMut, req_id: u32) {
    out.reserve(6);
    out.put_u8(ty::SEND_RESULT);
    out.put_u32(req_id);
    out.put_u8(0);
}

impl ServerFrame {
    /// Decodes one server message (client side).
    ///
    /// # Errors
    /// [`FrameError`] for anything malformed or over `limits`.
    pub fn decode(msg: &Bytes, limits: &Limits) -> Result<Self, FrameError> {
        match frame_type(msg, limits)? {
            ty::DELIVER => {
                let mut c = Cursor::new(msg, 1);
                let seq = c.u64()?;
                let r = c.rest();
                if r.is_empty() {
                    return Err(FrameError::EmptyPayload);
                }
                check_len("envelope", r.len(), limits.max_envelope_bytes)?;
                Ok(Self::Deliver {
                    seq,
                    envelope: msg.slice(r),
                })
            }
            ty::SEND_RESULT => {
                let mut c = Cursor::new(msg, 1);
                let req_id = c.u32()?;
                let status = match c.array::<1>()? {
                    [0] => SendStatus::Accepted,
                    [1] => SendStatus::Rejected {
                        reason: RejectReason::from_code(c.u16()?),
                        retry_after_ms: c.u32()?,
                    },
                    [2] => {
                        let r = c.rest();
                        let body = msg.get(r).ok_or(FrameError::Truncated)?;
                        check_len("control body", body.len(), limits.max_control_bytes)?;
                        let m = control::DeviceMismatch::decode(body)
                            .map_err(|_| FrameError::Control("mismatch"))?;
                        m.validate()?;
                        SendStatus::DeviceMismatch(m)
                    }
                    _ => return Err(FrameError::Control("send_result.status")),
                };
                c.finish()?;
                Ok(Self::SendResult { req_id, status })
            }
            t @ (ty::EPHEMERAL_DELIVER | ty::ATTENTION_DELIVER) => {
                let r = 1..msg.len();
                if r.is_empty() {
                    return Err(FrameError::EmptyPayload);
                }
                check_len("ephemeral", r.len(), limits.max_ephemeral_bytes)?;
                let payload = msg.slice(r);
                Ok(if t == ty::ATTENTION_DELIVER {
                    Self::Attention { payload }
                } else {
                    Self::Ephemeral { payload }
                })
            }
            ty::HELLO => {
                let h: control::Hello = decode_control(msg, limits, "hello")?;
                h.validate()?;
                Ok(Self::Hello(h))
            }
            ty::AUTH_OK => decode_control(msg, limits, "auth_ok").map(Self::AuthOk),
            ty::ERROR => decode_control(msg, limits, "error").map(Self::Error),
            other => Err(FrameError::UnknownType(other)),
        }
    }

    /// Appends the encoding to `out`.
    pub fn encode(&self, out: &mut BytesMut) {
        match self {
            Self::Hello(h) => encode_control(out, ty::HELLO, h),
            Self::AuthOk(a) => encode_control(out, ty::AUTH_OK, a),
            Self::Error(e) => encode_control(out, ty::ERROR, e),
            Self::Deliver { seq, envelope } => encode_deliver(out, *seq, envelope),
            Self::SendResult { req_id, status } => match status {
                SendStatus::Accepted => encode_send_accepted(out, *req_id),
                SendStatus::Rejected {
                    reason,
                    retry_after_ms,
                } => {
                    out.reserve(12);
                    out.put_u8(ty::SEND_RESULT);
                    out.put_u32(*req_id);
                    out.put_u8(1);
                    out.put_u16(reason.code());
                    out.put_u32(*retry_after_ms);
                }
                SendStatus::DeviceMismatch(m) => {
                    out.reserve(6 + m.encoded_len());
                    out.put_u8(ty::SEND_RESULT);
                    out.put_u32(*req_id);
                    out.put_u8(2);
                    let _ = m.encode(out);
                }
            },
            Self::Ephemeral { payload } => {
                out.reserve(1 + payload.len());
                out.put_u8(ty::EPHEMERAL_DELIVER);
                out.put_slice(payload);
            }
            Self::Attention { payload } => {
                out.reserve(1 + payload.len());
                out.put_u8(ty::ATTENTION_DELIVER);
                out.put_slice(payload);
            }
        }
    }

    /// The encoding as a fresh buffer.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        let mut out = BytesMut::new();
        self.encode(&mut out);
        out.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; ID_LEN])
    }

    fn arb_device() -> impl Strategy<Value = DeviceId> {
        any::<[u8; ID_LEN]>().prop_map(DeviceId::from_bytes)
    }

    fn arb_payload(max: usize) -> impl Strategy<Value = Bytes> {
        proptest::collection::vec(any::<u8>(), 1..=max).prop_map(Bytes::from)
    }

    fn arb_client() -> impl Strategy<Value = ClientFrame> {
        prop_oneof![
            any::<u64>().prop_map(|up_to_seq| ClientFrame::Ack { up_to_seq }),
            (arb_device(), arb_payload(64))
                .prop_map(|(to, payload)| ClientFrame::Ephemeral { to, payload }),
            (
                any::<u32>(),
                any::<[u8; 16]>(),
                proptest::collection::vec((arb_device(), arb_payload(64)), 1..8),
                // None, a contact's access key, or a request.
                prop_oneof![
                    Just((None, false)),
                    any::<[u8; 16]>().prop_map(|k| (Some(k), false)),
                    Just((None, true)),
                ],
                proptest::option::of(any::<[u8; 32]>()),
                proptest::option::of(1..=MAX_EXPIRE_AFTER_S),
            )
                .prop_map(
                    |(req_id, idempotency_key, rs, (access, request), commitment, expire)| {
                        let mut s = SendFrame::per_device(
                            req_id,
                            idempotency_key,
                            rs.into_iter()
                                .map(|(device, envelope)| Recipient { device, envelope })
                                .collect(),
                        );
                        s.hints = SendHints {
                            access,
                            request,
                            commitment,
                            expire_after_s: expire,
                            group: None,
                            silent: req_id % 7 == 0,
                        };
                        ClientFrame::Send(s)
                    }
                ),
            (
                any::<u32>(),
                any::<[u8; 16]>(),
                proptest::collection::vec(arb_device(), 1..8),
                arb_payload(64)
            )
                .prop_map(|(req_id, idempotency_key, devices, body)| {
                    ClientFrame::Send(SendFrame {
                        hints: SendHints {
                            // A group's body may be franked and disappear too.
                            commitment: (req_id % 3 == 0).then_some([7; 32]),
                            expire_after_s: (req_id % 5 == 0).then_some(60),
                            silent: req_id % 2 == 0,
                            ..SendHints::default()
                        },
                        req_id,
                        idempotency_key,
                        payload: SendPayload::Shared { devices, body },
                    })
                }),
            (
                any::<[u8; 16]>(),
                any::<[u8; 64]>(),
                any::<u64>(),
                "[ -~]{0,64}"
            )
                .prop_map(|(d, s, last_acked_seq, client_version)| {
                    ClientFrame::Auth(control::Auth {
                        device_id: d.to_vec(),
                        signature: s.to_vec(),
                        last_acked_seq,
                        client_version,
                        protocol_version: crate::PROTOCOL_VERSION,
                    })
                }),
        ]
    }

    fn arb_server() -> impl Strategy<Value = ServerFrame> {
        prop_oneof![
            (any::<u64>(), arb_payload(64))
                .prop_map(|(seq, envelope)| ServerFrame::Deliver { seq, envelope }),
            any::<u32>().prop_map(|req_id| ServerFrame::SendResult {
                req_id,
                status: SendStatus::Accepted
            }),
            (any::<u32>(), 1u16..8, any::<u32>()).prop_map(|(req_id, code, retry_after_ms)| {
                ServerFrame::SendResult {
                    req_id,
                    status: SendStatus::Rejected {
                        reason: RejectReason::from_code(code),
                        retry_after_ms,
                    },
                }
            }),
            arb_payload(64).prop_map(|payload| ServerFrame::Ephemeral { payload }),
            arb_payload(64).prop_map(|payload| ServerFrame::Attention { payload }),
            (any::<[u8; 32]>(), any::<u64>(), any::<u64>()).prop_map(|(n, t, g)| {
                ServerFrame::Hello(control::Hello {
                    nonce: n.to_vec(),
                    server_time_ms: t,
                    protocol_versions: vec![1],
                    store_generation: g,
                    server_name: "chat.example".into(),
                })
            }),
            (any::<u64>(), any::<u64>()).prop_map(|(g, s)| ServerFrame::AuthOk(control::AuthOk {
                store_generation: g,
                resume_after_seq: s
            })),
            (any::<u32>(), any::<u32>()).prop_map(|(code, retry_after_ms)| ServerFrame::Error(
                control::Error {
                    code,
                    retry_after_ms
                }
            )),
        ]
    }

    #[test]
    fn group_messages_name_the_group_and_list_no_devices() {
        let frame = |flags: u8, extra: &[u8], devices: u16| {
            let mut b = BytesMut::new();
            b.put_u8(ty::SEND);
            b.put_u32(1);
            b.put_slice(&[3; 16]);
            b.put_u8(flags);
            b.put_slice(extra);
            b.put_u16(devices);
            for _ in 0..devices {
                b.put_slice(&[2; 16]);
            }
            b.put_u32(1);
            b.put_u8(b'x');
            ClientFrame::decode(&b.freeze(), &Limits::DEFAULT)
        };
        let g = SEND_FLAG_GROUP | SEND_FLAG_SHARED;
        let Ok(ClientFrame::Send(s)) = frame(g, &[0x5B; 16], 0) else {
            panic!("a group message")
        };
        assert_eq!(s.hints.group, Some([0x5B; 16]));
        assert!(matches!(&s.payload, SendPayload::Shared { devices, .. } if devices.is_empty()));
        let mut out = BytesMut::new();
        encode_send(&s, &mut out);
        assert_eq!(
            ClientFrame::decode(&out.freeze(), &Limits::DEFAULT),
            Ok(ClientFrame::Send(s))
        );
        // Franked and disappearing group messages: the blocks come before the group.
        let mut extra = vec![9; 32];
        extra.extend_from_slice(&60u32.to_be_bytes());
        extra.extend_from_slice(&[0x5B; 16]);
        assert!(frame(g | SEND_FLAG_FRANKED | SEND_FLAG_EXPIRES, &extra, 0).is_ok());

        let refused = Err(FrameError::Control("send.flags"));
        assert_eq!(
            frame(SEND_FLAG_GROUP, &[0x5B; 16], 0),
            refused,
            "needs a shared body"
        );
        assert_eq!(
            frame(g | SEND_FLAG_ACCESS, &[0; 32], 0),
            refused,
            "membership, not keys"
        );
        assert_eq!(frame(g | SEND_FLAG_REQUEST, &[0x5B; 16], 0), refused);
        assert_eq!(frame(g | SEND_FLAG_MLS, &[0; 40], 0), refused);
        // The roster is the server's: a listed device is refused, and only a group message may
        // list none.
        assert_eq!(
            frame(g, &[0x5B; 16], 1),
            Err(FrameError::Control("send.group"))
        );
        assert_eq!(
            frame(SEND_FLAG_SHARED, &[], 0),
            Err(FrameError::NoRecipients)
        );
    }

    #[test]
    fn send_hint_flags_are_exclusive_and_bounded() {
        let base = |flags: u8, extra: &[u8]| {
            let mut b = BytesMut::new();
            b.put_u8(ty::SEND);
            b.put_u32(1);
            b.put_slice(&[3; 16]);
            b.put_u8(flags);
            b.put_slice(extra);
            b.put_u16(1);
            b.put_slice(&[2; 16]);
            // One device and a one-byte envelope (per device) or body (shared): the same bytes.
            b.put_u32(1);
            b.put_u8(b'x');
            ClientFrame::decode(&b.freeze(), &Limits::DEFAULT)
        };
        let refused = Err(FrameError::Control("send.flags"));
        // Access and request together; either with a shared body; a request that is a commit.
        assert_eq!(
            base(SEND_FLAG_ACCESS | SEND_FLAG_REQUEST, &[0; 16]),
            refused
        );
        assert!(
            base(SEND_FLAG_ACCESS | SEND_FLAG_SHARED, &[0; 16]).is_ok(),
            "a group's key"
        );
        assert_eq!(base(SEND_FLAG_REQUEST | SEND_FLAG_SHARED, &[]), refused);
        assert_eq!(base(SEND_FLAG_REQUEST | SEND_FLAG_MLS, &[0; 24]), refused);
        assert_eq!(base(0x40, &[]), refused);
        // `SILENT` (0x80, D-0095) carries no block and goes with any other flag.
        let silent = base(SEND_FLAG_SILENT, &[]).unwrap();
        let ClientFrame::Send(f) = silent else {
            panic!("not a send")
        };
        assert!(f.hints.silent);
        assert!(base(SEND_FLAG_SILENT | SEND_FLAG_ACCESS, &[0; 16]).is_ok());
        assert!(!matches!(
            base(0, &[]),
            Ok(ClientFrame::Send(SendFrame {
                hints: SendHints { silent: true, .. },
                ..
            }))
        ));
        // The disappearing hint: 1 s to 30 days.
        let exp = |s: u32| base(SEND_FLAG_EXPIRES, &s.to_be_bytes());
        assert_eq!(exp(0), Err(FrameError::Control("send.expire_after_s")));
        assert_eq!(
            exp(MAX_EXPIRE_AFTER_S + 1),
            Err(FrameError::Control("send.expire_after_s"))
        );
        for ok in [1, MAX_EXPIRE_AFTER_S] {
            let Ok(ClientFrame::Send(s)) = exp(ok) else {
                panic!("{ok}")
            };
            assert_eq!(s.hints.expire_after_s, Some(ok));
        }
        // Franked shared bodies are allowed (stamped once); every hint round-trips.
        let Ok(ClientFrame::Send(s)) = base(SEND_FLAG_SHARED | SEND_FLAG_FRANKED, &[9; 32]) else {
            panic!("franked shared")
        };
        assert_eq!(s.hints.commitment, Some([9; 32]));
        assert_eq!(
            ClientFrame::decode(&ClientFrame::Send(s.clone()).to_bytes(), &Limits::DEFAULT),
            Ok(ClientFrame::Send(s))
        );
        // A truncated block.
        assert_eq!(base(SEND_FLAG_ACCESS, &[0; 3]).ok(), None);
    }

    proptest! {
        #[test]
        fn client_round_trip(f in arb_client()) {
            let bytes = f.to_bytes();
            prop_assert_eq!(ClientFrame::decode(&bytes, &Limits::DEFAULT).unwrap(), f);
        }

        #[test]
        fn server_round_trip(f in arb_server()) {
            let bytes = f.to_bytes();
            prop_assert_eq!(ServerFrame::decode(&bytes, &Limits::DEFAULT).unwrap(), f);
        }

        #[test]
        fn decoders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let b = Bytes::from(data);
            let _ = ClientFrame::decode(&b, &Limits::DEFAULT);
            let _ = ServerFrame::decode(&b, &Limits::DEFAULT);
        }

        #[test]
        fn trailing_byte_is_rejected(f in arb_client()) {
            // Frames whose last field runs to the end of the message cannot have trailing bytes.
            prop_assume!(matches!(f, ClientFrame::Send(_) | ClientFrame::Ack { .. }));
            let mut b = BytesMut::new();
            f.encode(&mut b);
            b.put_u8(0);
            prop_assert!(ClientFrame::decode(&b.freeze(), &Limits::DEFAULT).is_err());
        }

        #[test]
        fn truncation_is_rejected(f in arb_client(), cut in 1usize..32) {
            prop_assume!(!matches!(f, ClientFrame::Auth(_) | ClientFrame::Ephemeral { .. }));
            let b = f.to_bytes();
            prop_assume!(cut < b.len());
            prop_assert!(ClientFrame::decode(&b.slice(..b.len() - cut), &Limits::DEFAULT).is_err());
        }
    }

    #[test]
    fn send_count_is_checked_before_allocation() {
        // Claims 1024 recipients but carries none: rejected without reserving 1024 slots.
        for flags in [0, SEND_FLAG_SHARED] {
            let mut b = BytesMut::new();
            b.put_u8(ty::SEND);
            b.put_u32(7);
            b.put_slice(&[0; 16]);
            b.put_u8(flags);
            b.put_u16(1024);
            assert_eq!(
                ClientFrame::decode(&b.freeze(), &Limits::DEFAULT),
                Err(FrameError::Truncated)
            );
        }
        // Refused flags (every bit is assigned since `SILENT`, D-0095: the retired MLS bit is
        // the one left to refuse).
        let mut b = BytesMut::new();
        b.put_u8(ty::SEND);
        b.put_u32(7);
        b.put_slice(&[0; 16]);
        b.put_u8(SEND_FLAG_MLS);
        b.put_u16(1);
        assert_eq!(
            ClientFrame::decode(&b.freeze(), &Limits::DEFAULT),
            Err(FrameError::Control("send.flags"))
        );
    }

    #[test]
    fn limits_are_enforced() {
        let limits = Limits {
            max_envelope_bytes: 4,
            max_recipients: 2,
            max_send_bytes: 1024,
            max_ephemeral_bytes: 3,
            max_control_bytes: 16,
        };
        let big = |n: usize| Bytes::from(vec![1u8; n]);
        let send = |rs: Vec<Recipient>| {
            ClientFrame::Send(SendFrame::per_device(1, [0; 16], rs)).to_bytes()
        };
        let r = |n| Recipient {
            device: dev(1),
            envelope: big(n),
        };
        assert!(ClientFrame::decode(&send(vec![r(4)]), &limits).is_ok());
        assert!(matches!(
            ClientFrame::decode(&send(vec![r(5)]), &limits),
            Err(FrameError::TooLarge {
                what: "envelope",
                ..
            })
        ));
        assert!(matches!(
            ClientFrame::decode(&send(vec![r(1), r(1), r(1)]), &limits),
            Err(FrameError::TooLarge {
                what: "recipients",
                ..
            })
        ));
        assert_eq!(
            ClientFrame::decode(&send(vec![]), &limits),
            Err(FrameError::NoRecipients)
        );
        let eph = ClientFrame::Ephemeral {
            to: dev(2),
            payload: big(4),
        }
        .to_bytes();
        assert!(matches!(
            ClientFrame::decode(&eph, &limits),
            Err(FrameError::TooLarge { .. })
        ));
        let auth = ClientFrame::Auth(control::Auth {
            device_id: vec![0; 16],
            signature: vec![0; 64],
            ..Default::default()
        })
        .to_bytes();
        assert!(matches!(
            ClientFrame::decode(&auth, &limits),
            Err(FrameError::TooLarge { .. })
        ));
        let huge = Bytes::from(vec![ty::ACK; limits.max_message_bytes() + 1]);
        assert!(matches!(
            ClientFrame::decode(&huge, &limits),
            Err(FrameError::TooLarge { what: "frame", .. })
        ));
    }

    #[test]
    fn wrong_direction_types_are_unknown() {
        let deliver = ServerFrame::Deliver {
            seq: 1,
            envelope: Bytes::from_static(b"x"),
        }
        .to_bytes();
        assert_eq!(
            ClientFrame::decode(&deliver, &Limits::DEFAULT),
            Err(FrameError::UnknownType(ty::DELIVER))
        );
        let ack = ClientFrame::Ack { up_to_seq: 1 }.to_bytes();
        assert_eq!(
            ServerFrame::decode(&ack, &Limits::DEFAULT),
            Err(FrameError::UnknownType(ty::ACK))
        );
        assert_eq!(
            ClientFrame::decode(&Bytes::new(), &Limits::DEFAULT),
            Err(FrameError::Empty)
        );
    }

    #[test]
    fn decoded_payloads_share_the_message_buffer() {
        let f = ClientFrame::Ephemeral {
            to: dev(3),
            payload: Bytes::from_static(b"typing"),
        }
        .to_bytes();
        let ClientFrame::Ephemeral { payload, .. } =
            ClientFrame::decode(&f, &Limits::DEFAULT).unwrap()
        else {
            panic!("wrong frame")
        };
        assert_eq!(payload.as_ptr(), f.as_ptr().wrapping_add(1 + ID_LEN));
    }

    #[test]
    fn debug_output_hides_identifiers() {
        let f = ClientFrame::Send(SendFrame::per_device(
            9,
            [0xAB; 16],
            vec![Recipient {
                device: dev(0xCD),
                envelope: Bytes::from_static(b"secret"),
            }],
        ));
        let auth = ClientFrame::Auth(control::Auth {
            device_id: vec![0xEF; 16],
            signature: vec![0x12; 64],
            ..Default::default()
        });
        for shown in [format!("{f:?}"), format!("{auth:?}")] {
            let low = shown.to_lowercase();
            assert!(!low.contains("ab, ") && !low.contains("171"), "{shown}");
            assert!(!low.contains("cd") && !low.contains("205"), "{shown}");
            assert!(!low.contains("239") && !low.contains("secret"), "{shown}");
        }
    }
}
