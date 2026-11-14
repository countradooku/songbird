//! Frames: one WebSocket binary message each.
//!
//! Layout: a one-byte frame type, then fixed-width big-endian fields, then (for frames that carry
//! one) an opaque payload running to the end of the message. The WebSocket message length bounds
//! the frame, so payloads need no length prefix unless there are several (`Send`).
//!
//! | Type | Direction | Frame | Body |
//! | --- | --- | --- | --- |
//! | `0x01` | C→S | `Send` | `req_id u32`, `idempotency_key [16]`, `flags u8`, [MLS: `group [16]`, `epoch u64`], `count u16`, then per device `count ×` (`device_id [16]`, `len u32`, `envelope [len]`) or shared `count × device_id [16]`, `len u32`, `body [len]` |
//! | `0x02` | C→S | `Ack` | `up_to_seq u64` |
//! | `0x03` | C→S | `Ephemeral` | `to [16]`, `payload` |
//! | `0x10` | C→S | `Auth` | protobuf [`control::Auth`] |
//! | `0x81` | S→C | `Deliver` | `seq u64`, `envelope` |
//! | `0x82` | S→C | `SendResult` | `req_id u32`, `status u8`, status body |
//! | `0x83` | S→C | `Ephemeral` | `payload` |
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
    /// Client → server: authentication (protobuf).
    pub const AUTH: u8 = 0x10;
    /// Server → client: one stored envelope.
    pub const DELIVER: u8 = 0x81;
    /// Server → client: outcome of a `Send`.
    pub const SEND_RESULT: u8 = 0x82;
    /// Server → client: ephemeral event.
    pub const EPHEMERAL_DELIVER: u8 = 0x83;
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
/// `Send` flag: an MLS commit block (`group [16]`, `epoch u64`) follows the flags.
pub const SEND_FLAG_MLS: u8 = 0x01;
/// `Send` flag: one shared body for every recipient device.
pub const SEND_FLAG_SHARED: u8 = 0x02;
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

/// The MLS commit a `Send` carries: stored only if the group is at `epoch` (D-0026).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MlsCommitRef {
    /// Group identifier (opaque, chosen by clients).
    pub group: [u8; 16],
    /// Epoch the commit was made from.
    pub epoch: u64,
}

impl std::fmt::Debug for MlsCommitRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsCommitRef")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// A `Send` frame.
#[derive(Clone, PartialEq, Eq)]
pub struct SendFrame {
    /// Chosen by the client, echoed in the matching `SendResult`.
    pub req_id: u32,
    /// Random per logical message; a retry reuses it so the server stores it once.
    pub idempotency_key: [u8; IDEMPOTENCY_KEY_LEN],
    /// Set when this send is an MLS commit.
    pub mls: Option<MlsCommitRef>,
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
            mls: None,
            payload: SendPayload::PerDevice(recipients),
        }
    }
}

impl std::fmt::Debug for SendFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendFrame")
            .field("req_id", &self.req_id)
            .field("mls", &self.mls)
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
    /// An envelope begins with the prefix reserved for server-signed system frames
    /// ([`crate::system::MAGIC`]); system frames are never user messages.
    ReservedEnvelope,
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

fn decode_send(msg: &Bytes, limits: &Limits) -> Result<SendFrame, FrameError> {
    check_len("send", msg.len(), limits.max_send_bytes)?;
    let mut c = Cursor::new(msg, 1);
    let req_id = c.u32()?;
    let idempotency_key = c.array::<IDEMPOTENCY_KEY_LEN>()?;
    let [flags] = c.array::<1>()?;
    if flags & !(SEND_FLAG_MLS | SEND_FLAG_SHARED) != 0 {
        return Err(FrameError::Control("send.flags"));
    }
    let mls = if flags & SEND_FLAG_MLS == 0 {
        None
    } else {
        Some(MlsCommitRef {
            group: c.array()?,
            epoch: c.u64()?,
        })
    };
    let count = usize::from(c.u16()?);
    if count == 0 {
        return Err(FrameError::NoRecipients);
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
        mls,
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
    out.reserve(SEND_HEADER_LEN.saturating_add(24).saturating_add(body));
    out.put_u8(ty::SEND);
    out.put_u32(s.req_id);
    out.put_slice(&s.idempotency_key);
    let mut flags = 0;
    if s.mls.is_some() {
        flags |= SEND_FLAG_MLS;
    }
    if matches!(s.payload, SendPayload::Shared { .. }) {
        flags |= SEND_FLAG_SHARED;
    }
    out.put_u8(flags);
    if let Some(m) = &s.mls {
        out.put_slice(&m.group);
        out.put_u64(m.epoch);
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
            ty::EPHEMERAL_DELIVER => {
                let r = 1..msg.len();
                if r.is_empty() {
                    return Err(FrameError::EmptyPayload);
                }
                check_len("ephemeral", r.len(), limits.max_ephemeral_bytes)?;
                Ok(Self::Ephemeral {
                    payload: msg.slice(r),
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
                proptest::collection::vec((arb_device(), arb_payload(64)), 1..8)
            )
                .prop_map(|(req_id, idempotency_key, rs)| ClientFrame::Send(
                    SendFrame::per_device(
                        req_id,
                        idempotency_key,
                        rs.into_iter()
                            .map(|(device, envelope)| Recipient { device, envelope })
                            .collect(),
                    )
                )),
            (
                any::<u32>(),
                any::<[u8; 16]>(),
                proptest::option::of((any::<[u8; 16]>(), any::<u64>())),
                proptest::collection::vec(arb_device(), 1..8),
                arb_payload(64)
            )
                .prop_map(|(req_id, idempotency_key, mls, devices, body)| {
                    ClientFrame::Send(SendFrame {
                        req_id,
                        idempotency_key,
                        mls: mls.map(|(group, epoch)| MlsCommitRef { group, epoch }),
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
        // Unknown flags are refused.
        let mut b = BytesMut::new();
        b.put_u8(ty::SEND);
        b.put_u32(7);
        b.put_slice(&[0; 16]);
        b.put_u8(0x80);
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
