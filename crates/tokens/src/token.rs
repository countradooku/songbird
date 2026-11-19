//! Songbird's anonymous tokens on the RFC 9497 POPRF (PROTOCOL §14.4; D-0126 §2; D-0128).
//!
//! A token says "whoever holds this was issued one `kind` token of `level` for `period`" and
//! nothing else. The issuer (billing, for plans) evaluates the PRF on a **blinded** random nonce
//! under public metadata ([`Info`]); the client unblinds; the redeemer (`api`) recomputes the PRF
//! on the nonce and burns its [`nullifier`]. Issuance and redemption share no identifier: even a
//! server holding every record of both cannot join them, because the nonce was blinded when it
//! was issued (RFC 9497 §7.1).
//!
//! One long-lived key pair per key ID ([`Keys`]) serves every kind, level and period: the
//! metadata is bound by the POPRF's tweak, and the DLEQ proof shows the client the evaluation
//! used the public key it pinned, so a server cannot tag one user with a key of their own.
//!
//! Wire shapes are JSON with hex fields ([`IssueRequest`], [`IssueResponse`], [`Redemption`]).

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::oprf::{self, KeyPair, MAX_BATCH, Mode, NE, NH, Suite};

/// Domain separation of [`Info`].
pub const INFO_CONTEXT: &[u8] = b"songbird.v1/token\0";
/// Domain separation of key derivation.
pub const KEY_CONTEXT: &[u8] = b"songbird.v1/token-key\0";
/// Domain separation of nullifiers.
pub const NULLIFIER_CONTEXT: &[u8] = b"songbird.v1/token-nullifier\0";
/// Nonce length (the client's private input).
pub const NONCE_LEN: usize = 32;
/// Most tokens in one issuance.
pub const MAX_ISSUE: usize = MAX_BATCH;

/// What a token is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A month of a plan level (`period`: months since January 1970, UTC).
    Plan,
    /// A day's write session on a backup vault at a level (`period`: UTC day; M4).
    VaultDay,
    /// The creation of one backup vault (`period`: the 180-day window; M4).
    VaultCreate,
}

impl Kind {
    /// The wire number.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Plan => 1,
            Self::VaultDay => 2,
            Self::VaultCreate => 3,
        }
    }

    /// From the wire number.
    #[must_use]
    pub const fn from_u8(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::Plan),
            2 => Some(Self::VaultDay),
            3 => Some(Self::VaultCreate),
            _ => None,
        }
    }
}

/// A token's public metadata: the POPRF's `info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Info {
    /// What it is for.
    pub kind: Kind,
    /// The plan level (1 Plus; 0 is valid only for vault tokens of the default plan).
    pub level: u8,
    /// The period, in the kind's unit.
    pub period: u32,
}

/// [`Info`]'s encoded length.
pub const INFO_LEN: usize = INFO_CONTEXT.len() + 6;

impl Info {
    /// `"songbird.v1/token\0" || kind u8 || level u8 || period u32` (big-endian).
    #[must_use]
    pub fn encode(&self) -> [u8; INFO_LEN] {
        let mut b = [0u8; INFO_LEN];
        let p = self.period.to_be_bytes();
        let fields = [self.kind.as_u8(), self.level, p[0], p[1], p[2], p[3]];
        for (d, s) in b.iter_mut().zip(INFO_CONTEXT.iter().chain(fields.iter())) {
            *d = *s;
        }
        b
    }
}

/// Why a token step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// A field is malformed (hex, length, an unknown kind or key, a bad element).
    #[error("malformed")]
    Malformed,
    /// The issuer's answer does not verify against the pinned key.
    #[error("issuer's proof did not verify")]
    Proof,
    /// The redeemed output is not the PRF of its nonce under its metadata.
    #[error("token invalid")]
    Invalid,
    /// The random source failed.
    #[error("random source failed")]
    Random,
}

impl From<oprf::Error> for TokenError {
    fn from(e: oprf::Error) -> Self {
        match e {
            oprf::Error::Verify => Self::Proof,
            _ => Self::Malformed,
        }
    }
}

fn suite() -> Suite {
    Suite::new(Mode::Poprf)
}

/// The issuer's and redeemer's keys: one POPRF key pair per key ID, derived from one 32-byte
/// secret (`DeriveKeyPair(secret, "songbird.v1/token-key\0" || id)`). The highest ID issues;
/// every listed ID redeems (rotation: add an ID, wait out its tokens, drop the old one).
#[derive(Clone)]
pub struct Keys {
    pairs: Vec<(u8, KeyPair)>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field(
                "ids",
                &self.pairs.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl Keys {
    /// Derives the key pairs of `ids` (at least one, each once) from `secret`.
    ///
    /// # Errors
    /// [`TokenError::Malformed`] for no IDs or a repeated one.
    pub fn derive(secret: &[u8; 32], ids: &[u8]) -> Result<Self, TokenError> {
        let mut sorted = ids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.is_empty() || sorted.len() != ids.len() {
            return Err(TokenError::Malformed);
        }
        let s = suite();
        let pairs = sorted
            .into_iter()
            .map(|id| {
                let mut info = KEY_CONTEXT.to_vec();
                info.push(id);
                s.derive_key_pair(secret, &info).map(|kp| (id, kp))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { pairs })
    }

    /// The ID that issues.
    #[must_use]
    pub fn current(&self) -> u8 {
        self.pairs.last().map_or(0, |(id, _)| *id)
    }

    /// Every ID and its public key (`GET /v1/tokens/keys`; apps pin these).
    #[must_use]
    pub fn public(&self) -> Vec<(u8, [u8; NE])> {
        self.pairs
            .iter()
            .map(|(id, kp)| (*id, kp.public()))
            .collect()
    }

    /// The key pair of key ID `id`.
    #[must_use]
    pub fn pair(&self, id: u8) -> Option<&KeyPair> {
        self.pairs.iter().find(|(i, _)| *i == id).map(|(_, kp)| kp)
    }

    /// Evaluates a request under the current key. The caller has already decided the request
    /// may have `req.blinded.len()` tokens of `req.info()` (billing's caps; `api`'s for vaults).
    ///
    /// # Errors
    /// [`TokenError::Malformed`] for a request under another key, an empty or oversized batch, or
    /// an element that does not decode; [`TokenError::Random`].
    pub fn issue(&self, req: &IssueRequest) -> Result<IssueResponse, TokenError> {
        let info = req.info()?;
        if req.key != self.current() {
            return Err(TokenError::Malformed);
        }
        let kp = self.pair(req.key).ok_or(TokenError::Malformed)?;
        if req.blinded.is_empty() || req.blinded.len() > MAX_ISSUE {
            return Err(TokenError::Malformed);
        }
        let blinded = req
            .blinded
            .iter()
            .map(|b| element_hex(b))
            .collect::<Result<Vec<_>, _>>()?;
        let r = oprf::random_scalar().map_err(|_| TokenError::Random)?;
        let (ev, proof) = kp.blind_evaluate(&suite(), &blinded, &info.encode(), &r)?;
        let proof = proof.ok_or(TokenError::Malformed)?;
        Ok(IssueResponse {
            evaluated: ev
                .iter()
                .map(|e| hex::encode(oprf::element_bytes(e)))
                .collect(),
            proof: hex::encode(proof.to_bytes()),
        })
    }

    /// Checks a redeemed token: a known key, the PRF of its nonce under its metadata
    /// (constant-time comparison). Returns its metadata and nullifier; the caller decides
    /// whether the metadata is acceptable now and burns the nullifier.
    ///
    /// # Errors
    /// [`TokenError::Malformed`], [`TokenError::Invalid`].
    pub fn redeem(&self, r: &Redemption) -> Result<(Info, [u8; 32]), TokenError> {
        let info = r.info()?;
        let kp = self.pair(r.key).ok_or(TokenError::Malformed)?;
        let nonce: [u8; NONCE_LEN] = hex_array(&r.nonce)?;
        let output: [u8; NH] = hex_array(&r.output)?;
        let expected = kp
            .evaluate(&suite(), &nonce, &info.encode())
            .map_err(|_| TokenError::Invalid)?;
        verify_slices_are_equal(&expected, &output).map_err(|_| TokenError::Invalid)?;
        Ok((info, nullifier(r.key, &info, &nonce)))
    }
}

/// A token's nullifier: `SHA-256("songbird.v1/token-nullifier\0" || key || info || nonce)`. The
/// redeemer keeps it until the token could no longer be redeemed.
#[must_use]
pub fn nullifier(key: u8, info: &Info, nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(NULLIFIER_CONTEXT);
    ctx.update(&[key]);
    ctx.update(&info.encode());
    ctx.update(nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

fn hex_array<const N: usize>(s: &str) -> Result<[u8; N], TokenError> {
    // Decoded to a vector, not into a zeroed array: what comes out is exactly the input's bytes
    // (CodeQL reads a zero-initialised buffer as a hard-coded nonce).
    hex::decode(s)
        .ok()
        .and_then(|v| <[u8; N]>::try_from(v).ok())
        .ok_or(TokenError::Malformed)
}

fn element_hex(s: &str) -> Result<RistrettoPoint, TokenError> {
    let b: [u8; NE] = hex_array(s)?;
    oprf::element(&b).map_err(|_| TokenError::Malformed)
}

fn info_of(kind: u8, level: u8, period: u32) -> Result<Info, TokenError> {
    Ok(Info {
        kind: Kind::from_u8(kind).ok_or(TokenError::Malformed)?,
        level,
        period,
    })
}

/// A request for tokens (client to issuer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRequest {
    /// The key ID the client pinned (the issuer's current one).
    pub key: u8,
    /// [`Kind`] as a number.
    pub kind: u8,
    /// The level.
    pub level: u8,
    /// The period.
    pub period: u32,
    /// Blinded elements (hex), 1 to [`MAX_ISSUE`].
    pub blinded: Vec<String>,
}

impl IssueRequest {
    /// Its metadata.
    ///
    /// # Errors
    /// [`TokenError::Malformed`] for an unknown kind.
    pub fn info(&self) -> Result<Info, TokenError> {
        info_of(self.kind, self.level, self.period)
    }
}

/// The issuer's answer: one evaluated element per blinded one, and one batched proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueResponse {
    /// Evaluated elements (hex), in the request's order.
    pub evaluated: Vec<String>,
    /// The DLEQ proof (hex, 64 bytes).
    pub proof: String,
}

/// A token to redeem (client to redeemer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redemption {
    /// The key ID it was issued under.
    pub key: u8,
    /// [`Kind`] as a number.
    pub kind: u8,
    /// The level.
    pub level: u8,
    /// The period.
    pub period: u32,
    /// The nonce (hex, 32 bytes).
    pub nonce: String,
    /// The PRF output (hex, 64 bytes).
    pub output: String,
}

impl Redemption {
    /// Its metadata.
    ///
    /// # Errors
    /// [`TokenError::Malformed`] for an unknown kind.
    pub fn info(&self) -> Result<Info, TokenError> {
        info_of(self.kind, self.level, self.period)
    }
}

/// A client's request in flight: the nonces and blinds it must keep until the answer comes.
pub struct Pending {
    key: u8,
    info: Info,
    nonces: Vec<[u8; NONCE_LEN]>,
    blinds: Vec<Scalar>,
    blinded: Vec<RistrettoPoint>,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("info", &self.info)
            .field("n", &self.nonces.len())
            .finish_non_exhaustive()
    }
}

/// Starts a request for `n` tokens of `info` under key `key`: fresh random nonces, blinded.
///
/// # Errors
/// [`TokenError::Malformed`] for `n` outside 1 to [`MAX_ISSUE`]; [`TokenError::Random`].
pub fn request(key: u8, info: Info, n: usize) -> Result<(Pending, IssueRequest), TokenError> {
    if n == 0 || n > MAX_ISSUE {
        return Err(TokenError::Malformed);
    }
    let mut nonces = Vec::with_capacity(n);
    let mut blinds = Vec::with_capacity(n);
    for _ in 0..n {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| TokenError::Random)?;
        nonces.push(nonce);
        blinds.push(oprf::random_scalar().map_err(|_| TokenError::Random)?);
    }
    request_with(key, info, nonces, blinds)
}

/// [`request`] with the nonces and blinds given (vectors and tests).
///
/// # Errors
/// [`TokenError::Malformed`].
pub fn request_with(
    key: u8,
    info: Info,
    nonces: Vec<[u8; NONCE_LEN]>,
    blinds: Vec<Scalar>,
) -> Result<(Pending, IssueRequest), TokenError> {
    if nonces.is_empty() || nonces.len() > MAX_ISSUE || blinds.len() != nonces.len() {
        return Err(TokenError::Malformed);
    }
    let s = suite();
    let blinded = nonces
        .iter()
        .zip(&blinds)
        .map(|(n, b)| s.blind(n, b))
        .collect::<Result<Vec<_>, _>>()?;
    let req = IssueRequest {
        key,
        kind: info.kind.as_u8(),
        level: info.level,
        period: info.period,
        blinded: blinded
            .iter()
            .map(|b| hex::encode(oprf::element_bytes(b)))
            .collect(),
    };
    Ok((
        Pending {
            key,
            info,
            nonces,
            blinds,
            blinded,
        },
        req,
    ))
}

impl Pending {
    /// Finishes the request with the issuer's answer: checks the batched proof against the
    /// **pinned** public key of the request's key ID, unblinds, and returns the tokens.
    ///
    /// # Errors
    /// [`TokenError::Proof`] when the issuer evaluated under another key or metadata;
    /// [`TokenError::Malformed`].
    pub fn finish(
        self,
        pinned: &[u8; NE],
        resp: &IssueResponse,
    ) -> Result<Vec<Redemption>, TokenError> {
        if resp.evaluated.len() != self.nonces.len() {
            return Err(TokenError::Malformed);
        }
        let pk = oprf::element(pinned).map_err(|_| TokenError::Malformed)?;
        let evaluated = resp
            .evaluated
            .iter()
            .map(|e| element_hex(e))
            .collect::<Result<Vec<_>, _>>()?;
        let proof = oprf::Proof::from_bytes(&hex_array(&resp.proof)?)?;
        let inputs: Vec<&[u8]> = self.nonces.iter().map(<[u8; 32]>::as_slice).collect();
        let outputs = suite().finalize(
            &inputs,
            &self.blinds,
            &self.blinded,
            &evaluated,
            Some(&pk),
            &self.info.encode(),
            Some(&proof),
        )?;
        Ok(self
            .nonces
            .iter()
            .zip(outputs)
            .map(|(n, o)| Redemption {
                key: self.key,
                kind: self.info.kind.as_u8(),
                level: self.info.level,
                period: self.info.period,
                nonce: hex::encode(n),
                output: hex::encode(o),
            })
            .collect())
    }
}

// ----- periods -----

/// Days since the Unix epoch of a civil date (proleptic Gregorian; H. Hinnant's algorithm).
#[must_use]
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date (year, month 1–12, day 1–31) of a day since the epoch.
#[must_use]
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The month (months since January 1970) holding UTC day `day`.
#[must_use]
pub fn month_of(day: u32) -> u32 {
    let (y, m, _) = civil_from_days(i64::from(day));
    u32::try_from((y - 1970) * 12 + i64::from(m) - 1).unwrap_or(0)
}

/// The first UTC day of month `month`.
#[must_use]
pub fn first_day(month: u32) -> u32 {
    let y = 1970 + i64::from(month / 12);
    u32::try_from(days_from_civil(y, month % 12 + 1, 1)).unwrap_or(u32::MAX)
}

/// The last UTC day of month `month`.
#[must_use]
pub fn last_day(month: u32) -> u32 {
    first_day(month.saturating_add(1)).saturating_sub(1)
}

#[cfg(test)]
mod tests;
