//! Device-to-device transfer over the local network (PROTOCOL §11.9; D-0119 §10, D-0123).
//!
//! The **new** phone listens and shows a QR code: `songbird-transfer:` and base64url of
//!
//! ```text
//! "SBT" | version u8 (1) | psk [32] | port u16 | n u8 (1..=8) | n × (family u8 (4 | 6) | address [4 | 16])
//! ```
//!
//! The **old** phone scans it and connects over TCP to each address in turn. The channel is
//! Noise `NNpsk0_25519_ChaChaPoly_SHA256` (revision 34) on aws-lc-rs, the prologue
//! `"songbird.v1/transfer\0" || the QR payload`: only a phone that read the code completes the
//! handshake, and both show a 6-digit code from the handshake hash for the user to compare.
//! Transport messages are Noise's (at most 65,535 bytes, `len u16 | ciphertext`), carrying a
//! byte stream of application records:
//!
//! ```text
//! record = kind u8 | len u32 | body
//!   1 HELLO     account [16] | handover token [32] | device [16] | recovery secret [32]
//!   2 CHUNK     name [32] | object
//!   3 MANIFEST  object
//!   4 DONE      (empty)
//!   5 OK        (receiver: everything verified)
//! ```
//!
//! The old phone writes a backup under a **one-time** recovery key (sent in `HELLO`, inside the
//! channel) with the same format and runs as every other store ([`PipeStore`]); the new phone
//! keeps the objects in a folder ([`receive`]), verifies the whole backup, answers `OK`, and
//! recovers the account with the hand-over token. Nothing goes through Songbird's servers except
//! that token's use.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::{digest, hmac};
use songbird_backup_format::ChunkName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::store::{BackupStore, StoreError};

const PROTOCOL: &[u8] = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"songbird.v1/transfer\0";
const QR_PREFIX: &str = "songbird-transfer:";
/// Largest Noise message.
const MAX_MSG: usize = 65_535;
const TAG: usize = 16;
/// Largest application record body (a chunk object and its name).
pub const MAX_RECORD: usize = 9 << 20;

/// What can go wrong in a transfer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    /// The QR code is not a Songbird transfer code.
    #[error("not a transfer code")]
    Code,
    /// No address in the code answered.
    #[error("the other phone could not be reached")]
    Unreachable,
    /// The handshake failed: another code, or someone in between.
    #[error("the phones could not agree on a secure channel")]
    Handshake,
    /// A message failed to decrypt, or arrived out of order.
    #[error("the channel was tampered with")]
    Tampered,
    /// The other side broke the protocol.
    #[error("unexpected message")]
    Protocol,
    /// The socket failed.
    #[error("connection: {0}")]
    Io(#[from] std::io::Error),
}

impl From<TransferError> for StoreError {
    fn from(e: TransferError) -> Self {
        match e {
            TransferError::Io(e) => Self::Io(e),
            _ => Self::Protocol("transfer"),
        }
    }
}

/// The QR payload.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    /// The pre-shared key.
    pub psk: Zeroizing<[u8; 32]>,
    /// The new phone's port.
    pub port: u16,
    /// Its addresses, in the order to try.
    pub addrs: Vec<IpAddr>,
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Code")
            .field("addrs", &self.addrs.len())
            .finish_non_exhaustive()
    }
}

fn b64url(b: &[u8]) -> String {
    songbird_s3::sigv4::base64(b)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn unb64url(s: &str) -> Option<Vec<u8>> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = u32::try_from(A.iter().position(|&x| x == c)?).ok()?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

impl Code {
    /// The bytes the QR encodes (and the prologue binds).
    #[must_use]
    pub fn payload(&self) -> Vec<u8> {
        let mut b = b"SBT\x01".to_vec();
        b.extend_from_slice(self.psk.as_ref());
        b.extend_from_slice(&self.port.to_be_bytes());
        b.push(u8::try_from(self.addrs.len().min(8)).unwrap_or(8));
        for a in self.addrs.iter().take(8) {
            match a {
                IpAddr::V4(v) => {
                    b.push(4);
                    b.extend_from_slice(&v.octets());
                }
                IpAddr::V6(v) => {
                    b.push(6);
                    b.extend_from_slice(&v.octets());
                }
            }
        }
        b
    }

    /// The text of the QR code.
    #[must_use]
    pub fn to_qr(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{QR_PREFIX}{}", b64url(&self.payload())))
    }

    /// Reads a scanned QR code.
    ///
    /// # Errors
    /// [`TransferError::Code`].
    pub fn parse(text: &str) -> Result<Self, TransferError> {
        let raw = Zeroizing::new(
            unb64url(text.strip_prefix(QR_PREFIX).ok_or(TransferError::Code)?)
                .ok_or(TransferError::Code)?,
        );
        let rest = raw.strip_prefix(b"SBT\x01").ok_or(TransferError::Code)?;
        let (psk, rest) = rest.split_first_chunk::<32>().ok_or(TransferError::Code)?;
        let (port, rest) = rest.split_first_chunk::<2>().ok_or(TransferError::Code)?;
        let (&n, mut rest) = rest.split_first().ok_or(TransferError::Code)?;
        if n == 0 || n > 8 {
            return Err(TransferError::Code);
        }
        let mut addrs = vec![];
        for _ in 0..n {
            let (&fam, r) = rest.split_first().ok_or(TransferError::Code)?;
            rest = r;
            match fam {
                4 => {
                    let (a, r) = rest.split_first_chunk::<4>().ok_or(TransferError::Code)?;
                    addrs.push(IpAddr::from(*a));
                    rest = r;
                }
                6 => {
                    let (a, r) = rest.split_first_chunk::<16>().ok_or(TransferError::Code)?;
                    addrs.push(IpAddr::from(*a));
                    rest = r;
                }
                _ => return Err(TransferError::Code),
            }
        }
        if !rest.is_empty() {
            return Err(TransferError::Code);
        }
        Ok(Self {
            psk: Zeroizing::new(*psk),
            port: u16::from_be_bytes(*port),
            addrs,
        })
    }
}

// ------------------------------------------------------------------------------ Noise

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut c = digest::Context::new(&digest::SHA256);
    for p in parts {
        c.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(c.finish().as_ref());
    out
}

fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut c = hmac::Context::with_key(&k);
    for p in parts {
        c.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(c.sign().as_ref());
    out
}

/// Noise's HKDF: `n` outputs (2 or 3).
fn hkdf(ck: &[u8; 32], ikm: &[u8], n: usize) -> Vec<Zeroizing<[u8; 32]>> {
    let temp = Zeroizing::new(mac(ck, &[ikm]));
    let mut out: Vec<Zeroizing<[u8; 32]>> = vec![Zeroizing::new(mac(temp.as_ref(), &[&[1]]))];
    for i in 2..=n {
        let prev = out.last().map(|p| **p).unwrap_or_default();
        let idx = u8::try_from(i).unwrap_or(0);
        out.push(Zeroizing::new(mac(temp.as_ref(), &[&prev, &[idx]])));
    }
    out
}

fn nonce(n: u64) -> Nonce {
    let mut b = [0u8; 12];
    let (_, counter) = b.split_at_mut(4);
    counter.copy_from_slice(&n.to_le_bytes());
    Nonce::assume_unique_for_key(b)
}

struct Cipher {
    key: LessSafeKey,
    n: u64,
}

impl Cipher {
    fn new(k: &[u8; 32]) -> Result<Self, TransferError> {
        Ok(Self {
            key: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, k).map_err(|_| TransferError::Handshake)?,
            ),
            n: 0,
        })
    }

    fn seal(&mut self, ad: &[u8], plain: &[u8]) -> Result<Vec<u8>, TransferError> {
        if self.n == u64::MAX {
            return Err(TransferError::Protocol);
        }
        let mut buf = plain.to_vec();
        self.key
            .seal_in_place_append_tag(nonce(self.n), Aad::from(ad), &mut buf)
            .map_err(|_| TransferError::Protocol)?;
        self.n += 1;
        Ok(buf)
    }

    fn open(&mut self, ad: &[u8], ct: &[u8]) -> Result<Vec<u8>, TransferError> {
        if self.n == u64::MAX {
            return Err(TransferError::Protocol);
        }
        let mut buf = ct.to_vec();
        let len = self
            .key
            .open_in_place(nonce(self.n), Aad::from(ad), &mut buf)
            .map_err(|_| TransferError::Tampered)?
            .len();
        buf.truncate(len);
        self.n += 1;
        Ok(buf)
    }
}

/// The symmetric state of a handshake.
struct Symmetric {
    ck: Zeroizing<[u8; 32]>,
    h: [u8; 32],
    k: Option<Cipher>,
}

impl Symmetric {
    fn new(prologue: &[u8]) -> Self {
        // The name is 36 bytes: h = SHA-256(name).
        let h = hash(&[PROTOCOL]);
        let mut s = Self {
            ck: Zeroizing::new(h),
            h,
            k: None,
        };
        s.mix_hash(prologue);
        s
    }
    fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }
    fn mix_key(&mut self, ikm: &[u8]) -> Result<(), TransferError> {
        let mut o = hkdf(&self.ck, ikm, 2).into_iter();
        let (Some(ck), Some(k)) = (o.next(), o.next()) else {
            return Err(TransferError::Handshake);
        };
        self.ck = ck;
        self.k = Some(Cipher::new(&k)?);
        Ok(())
    }
    fn mix_key_and_hash(&mut self, ikm: &[u8]) -> Result<(), TransferError> {
        let mut o = hkdf(&self.ck, ikm, 3).into_iter();
        let (Some(ck), Some(h), Some(k)) = (o.next(), o.next(), o.next()) else {
            return Err(TransferError::Handshake);
        };
        self.ck = ck;
        self.mix_hash(h.as_ref());
        self.k = Some(Cipher::new(&k)?);
        Ok(())
    }
    fn encrypt_and_hash(&mut self, plain: &[u8]) -> Result<Vec<u8>, TransferError> {
        let h = self.h;
        let ct = self
            .k
            .as_mut()
            .ok_or(TransferError::Handshake)?
            .seal(&h, plain)?;
        self.mix_hash(&ct);
        Ok(ct)
    }
    fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, TransferError> {
        let h = self.h;
        let plain = self
            .k
            .as_mut()
            .ok_or(TransferError::Handshake)?
            .open(&h, ct)
            .map_err(|_| TransferError::Handshake)?;
        self.mix_hash(ct);
        Ok(plain)
    }
    fn split(&self) -> Result<(Cipher, Cipher), TransferError> {
        let mut o = hkdf(&self.ck, &[], 2).into_iter();
        let (Some(a), Some(b)) = (o.next(), o.next()) else {
            return Err(TransferError::Handshake);
        };
        Ok((Cipher::new(&a)?, Cipher::new(&b)?))
    }
}

fn dh(private: &PrivateKey, public: &[u8]) -> Result<Zeroizing<[u8; 32]>, TransferError> {
    agreement::agree(
        private,
        UnparsedPublicKey::new(&X25519, public),
        TransferError::Handshake,
        |s| {
            let mut out = Zeroizing::new([0u8; 32]);
            if s.len() != 32 || s.iter().all(|&b| b == 0) {
                return Err(TransferError::Handshake);
            }
            out.copy_from_slice(s);
            Ok(out)
        },
    )
}

fn ephemeral(seed: Option<[u8; 32]>) -> Result<(PrivateKey, [u8; 32]), TransferError> {
    let k = match seed {
        Some(s) => {
            PrivateKey::from_private_key(&X25519, &s).map_err(|_| TransferError::Handshake)?
        }
        None => PrivateKey::generate(&X25519).map_err(|_| TransferError::Handshake)?,
    };
    let p = k
        .compute_public_key()
        .map_err(|_| TransferError::Handshake)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(p.as_ref());
    Ok((k, out))
}

/// What a finished handshake gives each side.
pub struct Session {
    send: Cipher,
    recv: Cipher,
    /// The 6-digit code both phones show.
    pub code: u32,
    /// The handshake hash (vectors and tests).
    pub hash: [u8; 32],
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session { .. }")
    }
}

fn code_of(h: &[u8; 32]) -> u32 {
    let d = hash(&[b"songbird.v1/transfer-code\0", h]);
    let (first, _) = d.split_first_chunk::<4>().unwrap_or((&[0; 4], &[]));
    u32::from_be_bytes(*first) % 1_000_000
}

/// What finishes the initiator's handshake from the responder's reply.
pub type Finish = Box<dyn FnOnce(&[u8]) -> Result<Session, TransferError> + Send>;

/// The initiator's first message (`psk, e` and an empty payload): 48 bytes.
///
/// # Errors
/// [`TransferError::Handshake`].
pub fn initiator_start(
    code: &Code,
    seed: Option<[u8; 32]>,
) -> Result<(Vec<u8>, Finish), TransferError> {
    let mut s = Symmetric::new(&[PROLOGUE, &code.payload()].concat());
    s.mix_key_and_hash(code.psk.as_ref())?;
    let (e, e_pub) = ephemeral(seed)?;
    s.mix_hash(&e_pub);
    s.mix_key(&e_pub)?;
    let ct = s.encrypt_and_hash(&[])?;
    let msg = [&e_pub[..], &ct].concat();
    let finish: Finish = Box::new(move |reply: &[u8]| {
        let (re, rest) = reply
            .split_first_chunk::<32>()
            .ok_or(TransferError::Handshake)?;
        s.mix_hash(re);
        s.mix_key(re)?;
        s.mix_key(dh(&e, re)?.as_ref())?;
        if !s.decrypt_and_hash(rest)?.is_empty() {
            return Err(TransferError::Handshake);
        }
        let (out, inb) = s.split()?;
        Ok(Session {
            send: out,
            recv: inb,
            code: code_of(&s.h),
            hash: s.h,
        })
    });
    Ok((msg, finish))
}

/// The responder: reads the first message, answers (`e, ee` and an empty payload).
///
/// # Errors
/// [`TransferError::Handshake`] for another code's message.
pub fn respond(
    code: &Code,
    first: &[u8],
    seed: Option<[u8; 32]>,
) -> Result<(Vec<u8>, Session), TransferError> {
    let mut s = Symmetric::new(&[PROLOGUE, &code.payload()].concat());
    s.mix_key_and_hash(code.psk.as_ref())?;
    let (ie, rest) = first
        .split_first_chunk::<32>()
        .ok_or(TransferError::Handshake)?;
    s.mix_hash(ie);
    s.mix_key(ie)?;
    if !s.decrypt_and_hash(rest)?.is_empty() {
        return Err(TransferError::Handshake);
    }
    let (e, e_pub) = ephemeral(seed)?;
    s.mix_hash(&e_pub);
    s.mix_key(&e_pub)?;
    s.mix_key(dh(&e, ie)?.as_ref())?;
    let ct = s.encrypt_and_hash(&[])?;
    let (i_send, i_recv) = s.split()?;
    Ok((
        [&e_pub[..], &ct].concat(),
        Session {
            // The responder sends with the initiator's receiving key.
            send: i_recv,
            recv: i_send,
            code: code_of(&s.h),
            hash: s.h,
        },
    ))
}

// ------------------------------------------------------------------------------ framing

async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, m: &[u8]) -> Result<(), TransferError> {
    let len = u16::try_from(m.len()).map_err(|_| TransferError::Protocol)?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(m).await?;
    Ok(())
}

async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, TransferError> {
    let len = usize::from(r.read_u16().await?);
    let mut m = vec![0u8; len];
    r.read_exact(&mut m).await?;
    Ok(m)
}

/// A secure byte stream over a socket after the handshake.
pub struct Channel<S> {
    io: S,
    session: Session,
    inbox: Zeroizing<Vec<u8>>,
}

impl<S> std::fmt::Debug for Channel<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("code", &self.session.code)
            .finish_non_exhaustive()
    }
}

/// Record kinds.
mod kind {
    pub(super) const HELLO: u8 = 1;
    pub(super) const CHUNK: u8 = 2;
    pub(super) const MANIFEST: u8 = 3;
    pub(super) const DONE: u8 = 4;
    pub(super) const OK: u8 = 5;
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Channel<S> {
    /// The 6-digit code to compare.
    #[must_use]
    pub fn code(&self) -> u32 {
        self.session.code
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), TransferError> {
        for part in data.chunks(MAX_MSG - TAG) {
            let ct = self.session.send.seal(&[], part)?;
            write_msg(&mut self.io, &ct).await?;
        }
        Ok(())
    }

    async fn read_exact(&mut self, n: usize) -> Result<Zeroizing<Vec<u8>>, TransferError> {
        while self.inbox.len() < n {
            let ct = read_msg(&mut self.io).await?;
            let plain = self.session.recv.open(&[], &ct)?;
            self.inbox.extend_from_slice(&plain);
        }
        let rest = self.inbox.split_off(n);
        Ok(std::mem::replace(&mut self.inbox, Zeroizing::new(rest)))
    }

    /// Sends one record.
    async fn send(&mut self, kind: u8, body: &[u8]) -> Result<(), TransferError> {
        let len = u32::try_from(body.len()).map_err(|_| TransferError::Protocol)?;
        if body.len() > MAX_RECORD {
            return Err(TransferError::Protocol);
        }
        let mut head = vec![kind];
        head.extend_from_slice(&len.to_be_bytes());
        head.extend_from_slice(body);
        self.write(&head).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Reads one record.
    async fn recv(&mut self) -> Result<(u8, Zeroizing<Vec<u8>>), TransferError> {
        let head = self.read_exact(5).await?;
        let (&kind, len) = head.split_first().ok_or(TransferError::Protocol)?;
        let len = <[u8; 4]>::try_from(len).map_err(|_| TransferError::Protocol)?;
        let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| TransferError::Protocol)?;
        if len > MAX_RECORD {
            return Err(TransferError::Protocol);
        }
        Ok((kind, self.read_exact(len).await?))
    }
}

/// What the old phone sends first.
#[derive(Clone)]
pub struct Hello {
    /// The account.
    pub account: [u8; 16],
    /// A hand-over token from `POST /v1/account/handover`.
    pub handover: Zeroizing<[u8; 32]>,
    /// The device ID that token reserves.
    pub device: [u8; 16],
    /// The one-time recovery key's secret the backup is written under.
    pub secret: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Hello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hello { .. }")
    }
}

// ------------------------------------------------------------------------------ the two sides

/// The new phone: listens on `addrs` (port 0: any) and returns the code to show.
///
/// # Errors
/// [`TransferError::Io`].
pub async fn listen(addrs: Vec<IpAddr>) -> Result<(tokio::net::TcpListener, Code), TransferError> {
    let bind = addrs.first().copied().ok_or(TransferError::Unreachable)?;
    let l = tokio::net::TcpListener::bind(SocketAddr::new(
        if bind.is_ipv4() {
            IpAddr::from([0, 0, 0, 0])
        } else {
            IpAddr::from([0u16; 8])
        },
        0,
    ))
    .await?;
    let port = l.local_addr()?.port();
    let mut psk = Zeroizing::new([0u8; 32]);
    getrandom::fill(psk.as_mut()).map_err(|_| TransferError::Handshake)?;
    Ok((l, Code { psk, port, addrs }))
}

/// The new phone: accepts the old phone (the first connection whose handshake succeeds; a
/// connection with another code is dropped), returning the channel. The user compares
/// [`Channel::code`] on both screens.
///
/// # Errors
/// [`TransferError::Io`].
pub async fn accept(
    l: &tokio::net::TcpListener,
    code: &Code,
) -> Result<Channel<tokio::net::TcpStream>, TransferError> {
    loop {
        let (mut s, _) = l.accept().await?;
        let _ = s.set_nodelay(true);
        let Ok(first) = read_msg(&mut s).await else {
            continue;
        };
        let Ok((reply, session)) = respond(code, &first, None) else {
            continue;
        };
        write_msg(&mut s, &reply).await?;
        return Ok(Channel {
            io: s,
            session,
            inbox: Zeroizing::new(Vec::new()),
        });
    }
}

/// The old phone: connects to the code's addresses in turn and completes the handshake.
///
/// # Errors
/// [`TransferError::Unreachable`], [`TransferError::Handshake`].
pub async fn connect(code: &Code) -> Result<Channel<tokio::net::TcpStream>, TransferError> {
    for a in &code.addrs {
        match connect_via(code, SocketAddr::new(*a, code.port)).await {
            Err(TransferError::Unreachable) => {}
            r => return r,
        }
    }
    Err(TransferError::Unreachable)
}

/// As [`connect`], to one socket address (the handshake still binds the whole code).
///
/// # Errors
/// [`TransferError::Unreachable`], [`TransferError::Handshake`].
pub async fn connect_via(
    code: &Code,
    addr: SocketAddr,
) -> Result<Channel<tokio::net::TcpStream>, TransferError> {
    let Ok(Ok(mut s)) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    else {
        return Err(TransferError::Unreachable);
    };
    let _ = s.set_nodelay(true);
    let (first, finish) = initiator_start(code, None)?;
    write_msg(&mut s, &first).await?;
    let reply = read_msg(&mut s)
        .await
        .map_err(|_| TransferError::Handshake)?;
    let session = finish(&reply)?;
    Ok(Channel {
        io: s,
        session,
        inbox: Zeroizing::new(Vec::new()),
    })
}

/// The old phone's side as a store the backup run writes into: every chunk and the manifest go
/// down the channel; it holds nothing, so every chunk is new.
pub struct PipeStore<S> {
    ch: Mutex<Channel<S>>,
}

impl<S> std::fmt::Debug for PipeStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PipeStore { .. }")
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> PipeStore<S> {
    /// Sends `HELLO` and wraps the channel.
    ///
    /// # Errors
    /// The channel's.
    pub async fn new(mut ch: Channel<S>, hello: &Hello) -> Result<Self, TransferError> {
        let mut b = Zeroizing::new(Vec::with_capacity(96));
        b.extend_from_slice(&hello.account);
        b.extend_from_slice(hello.handover.as_ref());
        b.extend_from_slice(&hello.device);
        b.extend_from_slice(hello.secret.as_ref());
        ch.send(kind::HELLO, &b).await?;
        Ok(Self { ch: Mutex::new(ch) })
    }

    /// Sends `DONE` and waits for the new phone's `OK` (everything verified).
    ///
    /// # Errors
    /// [`TransferError::Protocol`] when the new phone refused the backup.
    pub async fn finish(&self) -> Result<(), TransferError> {
        let mut ch = self.ch.lock().await;
        ch.send(kind::DONE, &[]).await?;
        match ch.recv().await? {
            (kind::OK, _) => Ok(()),
            _ => Err(TransferError::Protocol),
        }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> BackupStore for PipeStore<S> {
    fn kind(&self) -> &'static str {
        "transfer"
    }
    async fn open(&self) -> Result<(), StoreError> {
        Ok(())
    }
    async fn put(&self, name: &ChunkName, object: Vec<u8>) -> Result<(), StoreError> {
        let mut b = Vec::with_capacity(32 + object.len());
        b.extend_from_slice(&name.0);
        b.extend_from_slice(&object);
        self.ch
            .lock()
            .await
            .send(kind::CHUNK, &b)
            .await
            .map_err(Into::into)
    }
    async fn get(&self, _: &ChunkName) -> Result<Vec<u8>, StoreError> {
        Err(StoreError::NotFound)
    }
    async fn list(&self) -> Result<Vec<ChunkName>, StoreError> {
        Ok(vec![])
    }
    async fn delete(&self, _: &[ChunkName]) -> Result<(), StoreError> {
        Ok(())
    }
    async fn manifest(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(None)
    }
    async fn swap_manifest(&self, _: u64, object: Vec<u8>) -> Result<(), StoreError> {
        self.ch
            .lock()
            .await
            .send(kind::MANIFEST, &object)
            .await
            .map_err(Into::into)
    }
    async fn destroy(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

#[allow(
    clippy::many_single_char_names,
    reason = "record kind and body, read in place"
)]
/// The new phone: receives `HELLO`, every chunk and the manifest into `into` until `DONE`;
/// then `verify` (the caller restores and checks everything) decides whether to answer `OK`.
///
/// # Errors
/// [`TransferError`]; anything `verify` refuses ends the transfer without `OK`.
pub async fn receive<S, F, Fut>(
    mut ch: Channel<S>,
    into: Arc<dyn BackupStore>,
    verify: F,
) -> Result<Hello, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnOnce(Hello) -> Fut,
    Fut: Future<Output = bool>,
{
    let (k, b) = ch.recv().await?;
    if k != kind::HELLO || b.len() != 96 {
        return Err(TransferError::Protocol);
    }
    let mut hello = Hello {
        account: [0; 16],
        handover: Zeroizing::new([0; 32]),
        device: [0; 16],
        secret: Zeroizing::new([0; 32]),
    };
    let (a, rest) = b.split_at(16);
    let (h, rest) = rest.split_at(32);
    let (d, sec) = rest.split_at(16);
    hello.account.copy_from_slice(a);
    hello.handover.copy_from_slice(h);
    hello.device.copy_from_slice(d);
    hello.secret.copy_from_slice(sec);
    into.open().await.map_err(|_| TransferError::Protocol)?;
    loop {
        let (k, b) = ch.recv().await?;
        match k {
            kind::CHUNK => {
                let (name, obj) = b.split_first_chunk::<32>().ok_or(TransferError::Protocol)?;
                into.put(&ChunkName(*name), obj.to_vec())
                    .await
                    .map_err(|_| TransferError::Protocol)?;
            }
            kind::MANIFEST => {
                let g = songbird_backup_format::object::manifest_generation(&b)
                    .map_err(|_| TransferError::Protocol)?;
                into.swap_manifest(g.saturating_sub(1), b.to_vec())
                    .await
                    .map_err(|_| TransferError::Protocol)?;
            }
            kind::DONE => break,
            _ => return Err(TransferError::Protocol),
        }
    }
    if !verify(hello.clone()).await {
        return Err(TransferError::Protocol);
    }
    ch.send(kind::OK, &[]).await?;
    Ok(hello)
}
