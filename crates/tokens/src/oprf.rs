//! RFC 9497 (oblivious pseudorandom functions) with the ciphersuite `ristretto255-SHA512`,
//! written from the RFC on `curve25519-dalek` (ristretto255, RFC 9496) and aws-lc-rs (SHA-512),
//! and checked byte for byte against the RFC's Appendix A.1 (`tests/rfc9497.rs`).
//!
//! Three modes share one core: OPRF (§3.3.1), VOPRF (§3.3.2) and POPRF (§3.3.3). Songbird's
//! tokens use the **POPRF**: the server's evaluation is bound to public metadata (`info`: the
//! token kind, level and period), proven with a DLEQ proof against one long-lived public key the
//! apps pin. The server learns the metadata, never the client's input.
//!
//! Randomness (blinds, proof scalars) is passed in by the caller so the vectors can be checked;
//! [`random_scalar`] is the production source (§4.7.2, 64 bytes reduced).

#![allow(
    clippy::many_single_char_names,
    reason = "the names are RFC 9497's (k, A, B, C, D, M, Z), so the code reads against it"
)]

use aws_lc_rs::digest;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity as _;

/// The ciphersuite identifier.
pub const SUITE: &[u8] = b"ristretto255-SHA512";
/// Serialized element length (`Ne`).
pub const NE: usize = 32;
/// Serialized scalar length (`Ns`).
pub const NS: usize = 32;
/// Output length (`Nh`, SHA-512).
pub const NH: usize = 64;
/// Most elements in one batched evaluation (bounds the server's work per request).
pub const MAX_BATCH: usize = 16;

/// The protocol variant (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `modeOPRF`.
    Oprf = 0,
    /// `modeVOPRF`.
    Voprf = 1,
    /// `modePOPRF`.
    Poprf = 2,
}

/// Why a step failed (no secret ever appears in one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// An element or scalar is not canonical, or an element is the identity.
    #[error("deserialization failed")]
    Deserialize,
    /// An input or `info` maps to the identity (or a tweaked key does).
    #[error("invalid input")]
    InvalidInput,
    /// The tweaked private key is zero (`info` maps to the private key: rotate it).
    #[error("inverse of zero")]
    Inverse,
    /// The DLEQ proof does not verify.
    #[error("proof did not verify")]
    Verify,
    /// Empty or oversized batch, lists of different lengths, an input too long.
    #[error("bad lengths")]
    Length,
    /// Key derivation failed 256 times (never in practice).
    #[error("key derivation failed")]
    DeriveKeyPair,
}

/// `CreateContextString(mode, "ristretto255-SHA512")`.
#[must_use]
pub fn context_string(mode: Mode) -> Vec<u8> {
    let mut c = Vec::with_capacity(9 + SUITE.len());
    c.extend_from_slice(b"OPRFV1-");
    c.push(match mode {
        Mode::Oprf => 0,
        Mode::Voprf => 1,
        Mode::Poprf => 2,
    });
    c.push(b'-');
    c.extend_from_slice(SUITE);
    c
}

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut ctx = digest::Context::new(&digest::SHA512);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// `I2OSP(len, 2)`, refusing what does not fit.
fn len2(n: usize) -> Result<[u8; 2], Error> {
    u16::try_from(n)
        .map(u16::to_be_bytes)
        .map_err(|_| Error::Length)
}

/// RFC 9380 §5.3.1 `expand_message_xmd` with SHA-512 (b = 64, s = 128 bytes), for an output of
/// exactly 64 bytes (all this suite needs: `ell` = 1). `msg` and `dst` are given in parts.
fn expand_xmd_64(msg: &[&[u8]], dst: &[&[u8]]) -> Result<[u8; 64], Error> {
    let dst_len: usize = dst.iter().map(|d| d.len()).sum();
    let dst_len = u8::try_from(dst_len).map_err(|_| Error::Length)?;
    let z_pad = [0u8; 128];
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(&z_pad);
    for m in msg {
        ctx.update(m);
    }
    ctx.update(&64u16.to_be_bytes());
    ctx.update(&[0]);
    for d in dst {
        ctx.update(d);
    }
    ctx.update(&[dst_len]);
    let b0 = ctx.finish();
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(b0.as_ref());
    ctx.update(&[1]);
    for d in dst {
        ctx.update(d);
    }
    ctx.update(&[dst_len]);
    let mut out = [0u8; 64];
    out.copy_from_slice(ctx.finish().as_ref());
    Ok(out)
}

/// The suite's operations under one context string.
#[derive(Debug, Clone)]
pub struct Suite {
    mode: Mode,
    context: Vec<u8>,
}

impl Suite {
    /// The suite in `mode`.
    #[must_use]
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            context: context_string(mode),
        }
    }

    /// Its mode.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// `HashToGroup` (`hash_to_ristretto255`, DST `"HashToGroup-" || contextString`).
    ///
    /// # Errors
    /// [`Error::Length`] for an input over 65,535 bytes.
    pub fn hash_to_group(&self, input: &[u8]) -> Result<RistrettoPoint, Error> {
        let u = expand_xmd_64(&[input], &[b"HashToGroup-", &self.context])?;
        Ok(RistrettoPoint::from_uniform_bytes(&u))
    }

    /// `HashToScalar` with DST `"HashToScalar-" || contextString`.
    ///
    /// # Errors
    /// [`Error::Length`].
    pub fn hash_to_scalar(&self, msg: &[&[u8]]) -> Result<Scalar, Error> {
        let u = expand_xmd_64(msg, &[b"HashToScalar-", &self.context])?;
        Ok(Scalar::from_bytes_mod_order_wide(&u))
    }

    /// `DeriveKeyPair(seed, info)` (§3.2.1).
    ///
    /// # Errors
    /// [`Error::Length`] for `info` over 65,535 bytes; [`Error::DeriveKeyPair`] never in practice.
    pub fn derive_key_pair(&self, seed: &[u8; 32], info: &[u8]) -> Result<KeyPair, Error> {
        let l = len2(info.len())?;
        for counter in 0..=255u8 {
            let u = expand_xmd_64(
                &[seed, &l, info, &[counter]],
                &[b"DeriveKeyPair", &self.context],
            )?;
            let sk = Scalar::from_bytes_mod_order_wide(&u);
            if sk != Scalar::ZERO {
                return Ok(KeyPair {
                    sk,
                    pk: RistrettoPoint::mul_base(&sk),
                });
            }
        }
        Err(Error::DeriveKeyPair)
    }

    /// `m = HashToScalar("Info" || I2OSP(len(info), 2) || info)` (POPRF).
    fn info_scalar(&self, info: &[u8]) -> Result<Scalar, Error> {
        self.hash_to_scalar(&[b"Info", &len2(info.len())?, info])
    }

    // ----- DLEQ proofs (§2.2) -----

    fn seed(&self, b: &RistrettoPoint) -> Result<[u8; 64], Error> {
        let bm = b.compress();
        let dst_len = len2(5 + self.context.len())?;
        Ok(sha512(&[
            &len2(NE)?,
            bm.as_bytes(),
            &dst_len,
            b"Seed-",
            &self.context,
        ]))
    }

    fn composite_scalar(
        &self,
        seed: &[u8; 64],
        i: usize,
        c: &RistrettoPoint,
        d: &RistrettoPoint,
    ) -> Result<Scalar, Error> {
        let ne = len2(NE)?;
        self.hash_to_scalar(&[
            &len2(seed.len())?,
            seed,
            &len2(i)?,
            &ne,
            c.compress().as_bytes(),
            &ne,
            d.compress().as_bytes(),
            b"Composite",
        ])
    }

    /// `ComputeComposites` (verifier) or `ComputeCompositesFast` (prover, with `k`).
    fn composites(
        &self,
        k: Option<&Scalar>,
        b: &RistrettoPoint,
        c: &[RistrettoPoint],
        d: &[RistrettoPoint],
    ) -> Result<(RistrettoPoint, RistrettoPoint), Error> {
        if c.is_empty() || c.len() != d.len() || c.len() > MAX_BATCH {
            return Err(Error::Length);
        }
        let seed = self.seed(b)?;
        let mut m = RistrettoPoint::identity();
        let mut z = RistrettoPoint::identity();
        for (i, (ci, di)) in c.iter().zip(d).enumerate() {
            let s = self.composite_scalar(&seed, i, ci, di)?;
            m += s * ci;
            if k.is_none() {
                z += s * di;
            }
        }
        if let Some(k) = k {
            z = k * m;
        }
        Ok((m, z))
    }

    fn challenge(
        &self,
        b: &RistrettoPoint,
        m: &RistrettoPoint,
        z: &RistrettoPoint,
        t2: &RistrettoPoint,
        t3: &RistrettoPoint,
    ) -> Result<Scalar, Error> {
        let ne = len2(NE)?;
        self.hash_to_scalar(&[
            &ne,
            b.compress().as_bytes(),
            &ne,
            m.compress().as_bytes(),
            &ne,
            z.compress().as_bytes(),
            &ne,
            t2.compress().as_bytes(),
            &ne,
            t3.compress().as_bytes(),
            b"Challenge",
        ])
    }

    /// `GenerateProof(k, A, B, C, D)` with the random scalar `r` given.
    ///
    /// # Errors
    /// [`Error::Length`].
    pub fn generate_proof(
        &self,
        k: &Scalar,
        a: &RistrettoPoint,
        b: &RistrettoPoint,
        c: &[RistrettoPoint],
        d: &[RistrettoPoint],
        r: &Scalar,
    ) -> Result<Proof, Error> {
        let (m, z) = self.composites(Some(k), b, c, d)?;
        let t2 = r * a;
        let t3 = r * m;
        let ch = self.challenge(b, &m, &z, &t2, &t3)?;
        Ok(Proof {
            c: ch,
            s: r - ch * k,
        })
    }

    /// `VerifyProof(A, B, C, D, proof)`.
    ///
    /// # Errors
    /// [`Error::Verify`] if it does not verify; [`Error::Length`].
    pub fn verify_proof(
        &self,
        a: &RistrettoPoint,
        b: &RistrettoPoint,
        c: &[RistrettoPoint],
        d: &[RistrettoPoint],
        proof: &Proof,
    ) -> Result<(), Error> {
        let (m, z) = self.composites(None, b, c, d)?;
        let t2 = proof.s * a + proof.c * b;
        let t3 = proof.s * m + proof.c * z;
        let expected = self.challenge(b, &m, &z, &t2, &t3)?;
        if expected == proof.c {
            Ok(())
        } else {
            Err(Error::Verify)
        }
    }

    // ----- the client -----

    /// `Blind(input)` (OPRF, VOPRF) with the blind given.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if the input maps to the identity.
    pub fn blind(&self, input: &[u8], blind: &Scalar) -> Result<RistrettoPoint, Error> {
        let p = self.hash_to_group(input)?;
        if p == RistrettoPoint::identity() || *blind == Scalar::ZERO {
            return Err(Error::InvalidInput);
        }
        Ok(blind * p)
    }

    /// The POPRF tweaked key `G·m + pkS` for `info` (computed by `Blind`).
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if it is the identity.
    pub fn tweaked_key(&self, pk: &RistrettoPoint, info: &[u8]) -> Result<RistrettoPoint, Error> {
        let t = RistrettoPoint::mul_base(&self.info_scalar(info)?) + pk;
        if t == RistrettoPoint::identity() {
            return Err(Error::InvalidInput);
        }
        Ok(t)
    }

    /// `Finalize` for a batch: checks the proof (VOPRF against `pkS`, POPRF against the tweaked
    /// key for `info`), then unblinds and hashes each output. OPRF has no proof.
    ///
    /// # Errors
    /// [`Error::Verify`], [`Error::Length`].
    #[allow(clippy::too_many_arguments, reason = "the RFC's Finalize, batched")]
    pub fn finalize(
        &self,
        inputs: &[&[u8]],
        blinds: &[Scalar],
        blinded: &[RistrettoPoint],
        evaluated: &[RistrettoPoint],
        pk: Option<&RistrettoPoint>,
        info: &[u8],
        proof: Option<&Proof>,
    ) -> Result<Vec<[u8; NH]>, Error> {
        let n = inputs.len();
        if n == 0 || blinds.len() != n || blinded.len() != n || evaluated.len() != n {
            return Err(Error::Length);
        }
        match self.mode {
            Mode::Oprf => {}
            Mode::Voprf => {
                let (pk, proof) = pk.zip(proof).ok_or(Error::Verify)?;
                self.verify_proof(&G, pk, blinded, evaluated, proof)?;
            }
            Mode::Poprf => {
                let (pk, proof) = pk.zip(proof).ok_or(Error::Verify)?;
                let t = self.tweaked_key(pk, info)?;
                self.verify_proof(&G, &t, evaluated, blinded, proof)?;
            }
        }
        inputs
            .iter()
            .zip(blinds)
            .zip(evaluated)
            .map(|((input, b), e)| {
                if *b == Scalar::ZERO {
                    return Err(Error::InvalidInput);
                }
                let n = b.invert() * e;
                self.output(input, info, &n)
            })
            .collect()
    }

    /// The `"Finalize"` hash over an unblinded (or directly evaluated) element.
    fn output(&self, input: &[u8], info: &[u8], n: &RistrettoPoint) -> Result<[u8; NH], Error> {
        let ne = len2(NE)?;
        let li = len2(input.len())?;
        let e = n.compress();
        Ok(match self.mode {
            Mode::Poprf => sha512(&[
                &li,
                input,
                &len2(info.len())?,
                info,
                &ne,
                e.as_bytes(),
                b"Finalize",
            ]),
            Mode::Oprf | Mode::Voprf => sha512(&[&li, input, &ne, e.as_bytes(), b"Finalize"]),
        })
    }
}

/// A server key pair.
#[derive(Clone)]
pub struct KeyPair {
    sk: Scalar,
    pk: RistrettoPoint,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("pk", &hex::encode(self.pk.compress().as_bytes()))
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// The public key, serialized (`pkSm`).
    #[must_use]
    pub fn public(&self) -> [u8; NE] {
        self.pk.compress().to_bytes()
    }

    /// The public key.
    #[must_use]
    pub const fn public_point(&self) -> &RistrettoPoint {
        &self.pk
    }

    /// The private key, serialized (`skSm`; tests only compare it with the RFC).
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; NS] {
        self.sk.to_bytes()
    }

    /// `BlindEvaluate` for a batch with one proof, the proof's random scalar given.
    ///
    /// # Errors
    /// [`Error::Inverse`] (POPRF: `info` maps to the private key); [`Error::Length`].
    pub fn blind_evaluate(
        &self,
        suite: &Suite,
        blinded: &[RistrettoPoint],
        info: &[u8],
        r: &Scalar,
    ) -> Result<(Vec<RistrettoPoint>, Option<Proof>), Error> {
        if blinded.is_empty() || blinded.len() > MAX_BATCH {
            return Err(Error::Length);
        }
        match suite.mode {
            Mode::Oprf => Ok((blinded.iter().map(|b| self.sk * b).collect(), None)),
            Mode::Voprf => {
                let ev: Vec<RistrettoPoint> = blinded.iter().map(|b| self.sk * b).collect();
                let p = suite.generate_proof(&self.sk, &G, &self.pk, blinded, &ev, r)?;
                Ok((ev, Some(p)))
            }
            Mode::Poprf => {
                let t = self.sk + suite.info_scalar(info)?;
                if t == Scalar::ZERO {
                    return Err(Error::Inverse);
                }
                let ti = t.invert();
                let ev: Vec<RistrettoPoint> = blinded.iter().map(|b| ti * b).collect();
                let tk = RistrettoPoint::mul_base(&t);
                let p = suite.generate_proof(&t, &G, &tk, &ev, blinded, r)?;
                Ok((ev, Some(p)))
            }
        }
    }

    /// `Evaluate(skS, input[, info])`: the output without the protocol (the server checking a
    /// redeemed token).
    ///
    /// # Errors
    /// [`Error::InvalidInput`], [`Error::Inverse`], [`Error::Length`].
    pub fn evaluate(&self, suite: &Suite, input: &[u8], info: &[u8]) -> Result<[u8; NH], Error> {
        let p = suite.hash_to_group(input)?;
        if p == RistrettoPoint::identity() {
            return Err(Error::InvalidInput);
        }
        let e = match suite.mode {
            Mode::Oprf | Mode::Voprf => self.sk * p,
            Mode::Poprf => {
                let t = self.sk + suite.info_scalar(info)?;
                if t == Scalar::ZERO {
                    return Err(Error::Inverse);
                }
                t.invert() * p
            }
        };
        suite.output(input, info, &e)
    }
}

/// A DLEQ proof: two scalars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    /// The challenge.
    pub c: Scalar,
    /// The response.
    pub s: Scalar,
}

impl Proof {
    /// `c || s`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 2 * NS] {
        let mut out = [0u8; 2 * NS];
        out[..NS].copy_from_slice(self.c.as_bytes());
        out[NS..].copy_from_slice(self.s.as_bytes());
        out
    }

    /// From `c || s`, each canonical.
    ///
    /// # Errors
    /// [`Error::Deserialize`].
    pub fn from_bytes(b: &[u8; 2 * NS]) -> Result<Self, Error> {
        let (c, s) = b.split_at(NS);
        Ok(Self {
            c: scalar(c)?,
            s: scalar(s)?,
        })
    }
}

/// `DeserializeElement`: canonical, and never the identity.
///
/// # Errors
/// [`Error::Deserialize`].
pub fn element(b: &[u8]) -> Result<RistrettoPoint, Error> {
    let c = CompressedRistretto::from_slice(b).map_err(|_| Error::Deserialize)?;
    let p = c.decompress().ok_or(Error::Deserialize)?;
    if p == RistrettoPoint::identity() {
        return Err(Error::Deserialize);
    }
    Ok(p)
}

/// `SerializeElement`.
#[must_use]
pub fn element_bytes(p: &RistrettoPoint) -> [u8; NE] {
    p.compress().to_bytes()
}

/// `DeserializeScalar`: canonical (below the group order).
///
/// # Errors
/// [`Error::Deserialize`].
pub fn scalar(b: &[u8]) -> Result<Scalar, Error> {
    let a: [u8; NS] = b.try_into().map_err(|_| Error::Deserialize)?;
    Option::from(Scalar::from_canonical_bytes(a)).ok_or(Error::Deserialize)
}

/// `RandomScalar` (§4.7.2): 64 random bytes reduced modulo the order, never zero.
///
/// # Errors
/// The system's random source failed.
pub fn random_scalar() -> Result<Scalar, getrandom::Error> {
    loop {
        let mut b = [0u8; 64];
        getrandom::fill(&mut b)?;
        let s = Scalar::from_bytes_mod_order_wide(&b);
        if s != Scalar::ZERO {
            return Ok(s);
        }
    }
}
