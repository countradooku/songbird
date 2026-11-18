//! The bytes the backend expects, built with the backend's own crates
//! (`songbird-proto`, `-pow`, `-keys`) so the app and the server can never
//! disagree. Plain Rust with no NSH, tested without an engine.

use aws_lc_rs::{
    digest,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use songbird_proto::registration::{self, DEVICE_CONTEXT, IDENTITY_CONTEXT, RegisterRequest};

/// The api's request-signing domain (`services/api/src/auth.rs:34`).
const API_DOMAIN: &[u8] = b"songbird-api-v1\0";

/// Lowercase hex, as the api checks it.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

/// Bytes from hex (either case); `None` on anything else.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `N` random bytes from the system's source. Without one nothing is safe
/// to sign, so this stops rather than return predictable bytes.
pub fn random<const N: usize>() -> [u8; N] {
    match aws_lc_rs::rand::generate::<[u8; N]>(&SystemRandom::new()) {
        Ok(bytes) => bytes.expose(),
        Err(_) => std::process::abort(),
    }
}

/// An Ed25519 key from its 32-byte seed.
pub fn ed25519(seed: &[u8; 32]) -> Option<Ed25519KeyPair> {
    Ed25519KeyPair::from_seed_unchecked(seed).ok()
}

/// A key's 32-byte public half.
pub fn public(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap_or([0; 32])
}

pub fn sha256(body: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, body)
        .as_ref()
        .try_into()
        .unwrap_or([0; 32])
}

/// The transcript a signed api request covers (`services/api/src/auth.rs:87`).
pub fn api_transcript(
    server_name: &str,
    method: &str,
    path: &str,
    ts_ms: u64,
    nonce: &[u8; 16],
    device: &[u8; 16],
    body_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(API_DOMAIN.len() + server_name.len() + path.len() + 96);
    t.extend_from_slice(API_DOMAIN);
    t.extend_from_slice(server_name.as_bytes());
    t.push(0);
    t.extend_from_slice(method.as_bytes());
    t.push(0);
    t.extend_from_slice(path.as_bytes());
    t.push(0);
    t.extend_from_slice(&ts_ms.to_be_bytes());
    t.extend_from_slice(nonce);
    t.extend_from_slice(device);
    t.extend_from_slice(body_sha256);
    t
}

/// The `authorization` header and, for a body, the
/// `x-songbird-content-sha256` header of a request.
pub fn sign_request(
    key: &Ed25519KeyPair,
    device: &[u8; 16],
    server_name: &str,
    method: &str,
    path: &str,
    ts_ms: u64,
    body: Option<&[u8]>,
) -> (String, Option<String>) {
    let nonce: [u8; 16] = random();
    let hash = body.map(sha256);
    let t = api_transcript(
        server_name,
        method,
        path,
        ts_ms,
        &nonce,
        device,
        &hash.unwrap_or([0; 32]),
    );
    let sig = key.sign(&t);
    let header = format!(
        "Songbird {}.{}.{}.{}",
        hex(device),
        ts_ms,
        hex(&nonce),
        hex(sig.as_ref())
    );
    (header, hash.map(|h| hex(&h)))
}

/// Why a registration request could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    Challenge,
    Invite,
    ServerName,
    Keys,
}

/// The registration request for `challenge` (with its PoW `solutions`),
/// signed by both new keys (`crates/proto/src/registration.rs`).
pub fn registration(
    server_name: &str,
    challenge: &[u8],
    solutions: Vec<u32>,
    invite: Option<&str>,
    identity_seed: &[u8; 32],
    device_seed: &[u8; 32],
) -> Result<Vec<u8>, BuildError> {
    let challenge: [u8; songbird_pow::CHALLENGE_LEN] =
        challenge.try_into().map_err(|_| BuildError::Challenge)?;
    let invite = match invite.map(str::trim).filter(|s| !s.is_empty()) {
        Some(text) => Some(registration::invite::parse(text).ok_or(BuildError::Invite)?),
        None => None,
    };
    let identity = ed25519(identity_seed).ok_or(BuildError::Keys)?;
    let device = ed25519(device_seed).ok_or(BuildError::Keys)?;
    let (identity_key, auth_key) = (public(&identity), public(&device));
    let signed = |context| {
        registration::transcript(context, server_name, &challenge, &identity_key, &auth_key)
            .map_err(|_| BuildError::ServerName)
    };
    let identity_sig: [u8; 64] = identity
        .sign(&signed(IDENTITY_CONTEXT)?)
        .as_ref()
        .try_into()
        .map_err(|_| BuildError::Keys)?;
    let auth_sig: [u8; 64] = device
        .sign(&signed(DEVICE_CONTEXT)?)
        .as_ref()
        .try_into()
        .map_err(|_| BuildError::Keys)?;
    Ok(RegisterRequest {
        challenge,
        solutions,
        invite,
        identity_key,
        auth_key,
        identity_sig,
        auth_sig,
    }
    .encode())
}

/// Whether `text` is a well-formed invite code (24 Crockford symbols).
/// The server is the only judge of whether it is valid.
pub fn invite_well_formed(text: &str) -> bool {
    registration::invite::parse(text).is_some()
}

/// `hash ‖ proof` for claiming `username` (`PUT /v1/username`).
pub fn username_claim(username: &str) -> Option<Vec<u8>> {
    let name = songbird_keys::username::Username::parse(username).ok()?;
    let mut body = name.hash().to_vec();
    body.extend_from_slice(&name.proof(&random::<32>()));
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(unhex("00AB10"), Some(vec![0, 0xab, 0x10]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn transcript_matches_the_api_layout() {
        let t = api_transcript(
            "api.localhost",
            "GET",
            "/v1/devices",
            7,
            &random(),
            &random(),
            &[0; 32],
        );
        assert!(t.starts_with(b"songbird-api-v1\0api.localhost\0GET\0/v1/devices\0"));
        assert_eq!(t.len(), 16 + 13 + 1 + 3 + 1 + 11 + 1 + 8 + 16 + 16 + 32);
        assert_eq!(&t[t.len() - 72..t.len() - 64], &7u64.to_be_bytes());
    }

    #[test]
    fn signatures_verify_with_the_public_key() {
        let key = ed25519(&random()).unwrap();
        let device: [u8; 16] = random();
        let (auth, digest) = sign_request(
            &key,
            &device,
            "api.localhost",
            "PUT",
            "/v1/x",
            1,
            Some(b"{}"),
        );
        assert!(auth.starts_with(&format!("Songbird {}.", hex(&device))));
        assert_eq!(digest.unwrap().len(), 64);
        let parts: Vec<&str> = auth.trim_start_matches("Songbird ").split('.').collect();
        assert_eq!(parts.len(), 4);
        let nonce: [u8; 16] = unhex(parts[2]).unwrap().try_into().unwrap();
        let t = api_transcript(
            "api.localhost",
            "PUT",
            "/v1/x",
            1,
            &nonce,
            &device,
            &sha256(b"{}"),
        );
        let sig = unhex(parts[3]).unwrap();
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, public(&key))
            .verify(&t, &sig)
            .unwrap();
    }

    #[test]
    fn invites_follow_the_server_format() {
        assert!(!invite_well_formed("ABCD1234"));
        assert!(!invite_well_formed(""));
    }

    #[test]
    fn usernames_follow_the_server_rules() {
        assert_eq!(username_claim("radu").map(|b| b.len()), Some(32 + 64));
        assert!(username_claim("1radu").is_none());
        assert!(username_claim("ra..du").is_none());
    }
}
