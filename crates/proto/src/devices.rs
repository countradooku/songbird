//! Devices (`docs/PROTOCOL.md` §4.6; Prompt 3, M4; D-0052): the signed, versioned device list
//! and the link request a new device sends after QR provisioning.
//!
//! # Device list
//!
//! ```text
//! version u8 (1) | account [16] | list_version u64 | issued_ms u64 | n u8 (1..=16)
//!   | n × (device [16] | auth_key [32] | identity_key [33] | flags u8 (1 primary))
//!   | signature [64]
//! ```
//!
//! The account identity key (Ed25519, M1) signs `"songbird.v1/device-list\0"` followed by every
//! byte before the signature. Exactly one entry is the primary (the device holding the account
//! identity key). `list_version` only grows: clients keep the highest they have seen and refuse
//! anything older, so a server cannot roll a list back; the server refuses one that does not grow.
//! Integers are big-endian.
//!
//! # Link request (`POST /v1/devices/link`)
//!
//! ```text
//! version u8 (1) | token [32] | device [16] | auth_key [32] | identity_key [33]
//!   | auth_sig [64] | identity_sig [64] | confirm [32]
//! ```
//!
//! Both keys sign [`link_transcript`] (Ed25519 for the authentication key, XEdDSA for the device
//! identity key), each under its own context, binding the single-use token, the server-chosen
//! device ID and both keys. `confirm` is `songbird_keys::provisioning::confirm_tag` under the
//! confirmation key of the [`Provision`] message over the identity-context transcript: the
//! server stores it for the primary, which checks it before it signs a list naming the device.
//! The server sees the token, so the token alone cannot keep it from linking keys of its own;
//! the confirmation key, which it never sees, does.
//!
//! # Provisioning message (sealed to the new device; the server never sees it in the clear)
//!
//! ```text
//! version u8 (1) | account [16] | account_identity [32] | token [32] | device [16]
//!   | confirm_key [32] | u8 len | server_name
//! ```
//!
//! Version 2 (Prompt 9, D-0102) adds the account's storage key, so the new device can read and
//! write the encrypted record store (settings, contacts):
//!
//! ```text
//! version u8 (2) | ...version 1's fields... | storage_key [32]
//! ```

use songbird_types::id::ID_LEN;
use songbird_types::{AccountId, DeviceId};

use crate::control::MAX_SERVER_NAME_LEN;

/// Format version.
pub const VERSION: u8 = 1;
/// Most devices a list may name (the configured limit is lower).
pub const MAX_LIST_DEVICES: usize = 16;
/// An X25519 device identity key, `0x05 || u`.
pub const IDENTITY_LEN: usize = 33;
/// Domain separation of the list signature.
pub const LIST_CONTEXT: &[u8] = b"songbird.v1/device-list\0";
/// Context of the link request's authentication-key signature.
pub const LINK_AUTH_CONTEXT: &[u8] = b"songbird.v1/link-device-auth\0";
/// Context of the link request's identity-key signature.
pub const LINK_IDENTITY_CONTEXT: &[u8] = b"songbird.v1/link-device-identity\0";
/// Link token length.
pub const TOKEN_LEN: usize = 32;
/// Link request length without a second factor (the factor kind byte included).
pub const LINK_LEN: usize = 1 + TOKEN_LEN + ID_LEN + 32 + IDENTITY_LEN + 64 + 64 + 32 + 1;
/// Longest link request (with a passkey assertion).
pub const MAX_LINK_LEN: usize = LINK_LEN + 2 + 1023 + 2 * (2 + 4096) + 1 + 255;
/// Shortest PIN.
pub const MIN_PIN: usize = 6;
/// Longest PIN.
pub const MAX_PIN: usize = 12;
/// Context of a passkey assertion's challenge for linking.
pub const LINK_PASSKEY_CONTEXT: &[u8] = b"songbird.v1/link-passkey\0";
/// Longest provisioning message (ciphertext the new device decrypts; opaque to the server).
pub const MAX_PROVISIONING_LEN: usize = 4096;
/// Longest device list.
pub const MAX_LIST_LEN: usize =
    1 + ID_LEN + 8 + 8 + 1 + MAX_LIST_DEVICES * (ID_LEN + 32 + IDENTITY_LEN + 1) + 64;

const FLAG_PRIMARY: u8 = 1;

/// One device of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListedDevice {
    /// The device.
    pub device: DeviceId,
    /// Its authentication key (Ed25519).
    pub auth_key: [u8; 32],
    /// Its identity key (`0x05 || u`).
    pub identity_key: [u8; IDENTITY_LEN],
    /// Whether it holds the account identity key.
    pub primary: bool,
}

/// A signed device list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceList {
    /// The account.
    pub account: AccountId,
    /// Strictly increasing.
    pub list_version: u64,
    /// When the primary signed it (Unix milliseconds, informational).
    pub issued_ms: u64,
    /// The devices, primary included.
    pub devices: Vec<ListedDevice>,
    /// Ed25519 signature by the account identity key over [`DeviceList::signed_bytes`].
    pub signature: [u8; 64],
}

/// Why bytes did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DevicesError {
    /// Wrong version or length, flags, counts, not exactly one primary, a device twice.
    #[error("malformed device message")]
    Malformed,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DevicesError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(DevicesError::Malformed)?;
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DevicesError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DevicesError::Malformed)
    }
    fn u8(&mut self) -> Result<u8, DevicesError> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, DevicesError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn id16(&mut self) -> Result<[u8; ID_LEN], DevicesError> {
        self.array()
    }
}

impl DeviceList {
    /// The bytes before the signature (what the account identity key signs, after
    /// [`LIST_CONTEXT`]).
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MAX_LIST_LEN);
        b.push(VERSION);
        b.extend_from_slice(self.account.as_bytes());
        b.extend_from_slice(&self.list_version.to_be_bytes());
        b.extend_from_slice(&self.issued_ms.to_be_bytes());
        b.push(u8::try_from(self.devices.len()).unwrap_or(u8::MAX));
        for d in &self.devices {
            b.extend_from_slice(d.device.as_bytes());
            b.extend_from_slice(&d.auth_key);
            b.extend_from_slice(&d.identity_key);
            b.push(if d.primary { FLAG_PRIMARY } else { 0 });
        }
        b
    }

    /// What the signature covers: [`LIST_CONTEXT`] then [`DeviceList::body`].
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut b = LIST_CONTEXT.to_vec();
        b.extend_from_slice(&self.body());
        b
    }

    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// The primary entry.
    #[must_use]
    pub fn primary(&self) -> Option<&ListedDevice> {
        self.devices.iter().find(|d| d.primary)
    }

    /// Decodes a list: the whole input; 1 to 16 devices, each once, exactly one primary.
    ///
    /// # Errors
    /// [`DevicesError::Malformed`].
    pub fn decode(input: &[u8]) -> Result<Self, DevicesError> {
        if input.len() > MAX_LIST_LEN {
            return Err(DevicesError::Malformed);
        }
        let mut r = Reader(input);
        if r.u8()? != VERSION {
            return Err(DevicesError::Malformed);
        }
        let account = AccountId::from_bytes(r.id16()?);
        let list_version = r.u64()?;
        let issued_ms = r.u64()?;
        let n = usize::from(r.u8()?);
        if n == 0 || n > MAX_LIST_DEVICES {
            return Err(DevicesError::Malformed);
        }
        let mut devices: Vec<ListedDevice> = Vec::with_capacity(n);
        for _ in 0..n {
            let device = DeviceId::from_bytes(r.id16()?);
            let auth_key = r.array()?;
            let identity_key = r.array()?;
            let primary = match r.u8()? {
                0 => false,
                FLAG_PRIMARY => true,
                _ => return Err(DevicesError::Malformed),
            };
            if devices.iter().any(|d| d.device == device) {
                return Err(DevicesError::Malformed);
            }
            devices.push(ListedDevice {
                device,
                auth_key,
                identity_key,
                primary,
            });
        }
        let signature = r.array()?;
        if !r.0.is_empty() || devices.iter().filter(|d| d.primary).count() != 1 {
            return Err(DevicesError::Malformed);
        }
        Ok(Self {
            account,
            list_version,
            issued_ms,
            devices,
            signature,
        })
    }
}

/// A link request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRequest {
    /// The single-use token the primary obtained and sent through the provisioning channel.
    pub token: [u8; TOKEN_LEN],
    /// The device ID the server reserved with the token.
    pub device: DeviceId,
    /// The new device's authentication key (Ed25519).
    pub auth_key: [u8; 32],
    /// The new device's identity key (`0x05 || u`).
    pub identity_key: [u8; IDENTITY_LEN],
    /// Ed25519 by `auth_key` over the transcript with [`LINK_AUTH_CONTEXT`].
    pub auth_sig: [u8; 64],
    /// XEdDSA by `identity_key` over the transcript with [`LINK_IDENTITY_CONTEXT`].
    pub identity_sig: [u8; 64],
    /// The confirmation tag for the primary (opaque to the server).
    pub confirm: [u8; 32],
    /// The second factor, when the account has one (Prompt 3, M4b, D-0053).
    pub factor: Factor,
}

/// A link request's second factor.
#[derive(Clone, PartialEq, Eq, Default)]
pub enum Factor {
    /// None given.
    #[default]
    None,
    /// The account's two-step PIN: 6 to 12 ASCII digits.
    Pin(String),
    /// A passkey assertion whose challenge is
    /// `SHA-256(LINK_PASSKEY_CONTEXT || identity-context transcript)`
    /// (`songbird_keys::webauthn::link_challenge`).
    Passkey {
        /// Credential ID (1 to 1023 bytes).
        credential_id: Vec<u8>,
        /// Authenticator data (at most 4096 bytes).
        authenticator_data: Vec<u8>,
        /// `clientDataJSON` (at most 4096 bytes).
        client_data_json: Vec<u8>,
        /// Signature (at most 255 bytes).
        signature: Vec<u8>,
    },
}

impl std::fmt::Debug for Factor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "Factor::None",
            Self::Pin(_) => "Factor::Pin(..)",
            Self::Passkey { .. } => "Factor::Passkey(..)",
        })
    }
}

/// Whether a PIN has the allowed shape.
#[must_use]
pub fn pin_ok(pin: &str) -> bool {
    (MIN_PIN..=MAX_PIN).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit())
}

impl LinkRequest {
    /// The wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(LINK_LEN);
        b.push(VERSION);
        b.extend_from_slice(&self.token);
        b.extend_from_slice(self.device.as_bytes());
        b.extend_from_slice(&self.auth_key);
        b.extend_from_slice(&self.identity_key);
        b.extend_from_slice(&self.auth_sig);
        b.extend_from_slice(&self.identity_sig);
        b.extend_from_slice(&self.confirm);
        match &self.factor {
            Factor::None => b.push(0),
            Factor::Pin(p) => {
                b.push(1);
                b.push(u8::try_from(p.len()).unwrap_or(u8::MAX));
                b.extend_from_slice(p.as_bytes());
            }
            Factor::Passkey {
                credential_id,
                authenticator_data,
                client_data_json,
                signature,
            } => {
                b.push(2);
                for part in [credential_id, authenticator_data, client_data_json] {
                    b.extend_from_slice(
                        &u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes(),
                    );
                    b.extend_from_slice(part);
                }
                b.push(u8::try_from(signature.len()).unwrap_or(u8::MAX));
                b.extend_from_slice(signature);
            }
        }
        b
    }

    /// Decodes a whole request (at least [`LINK_LEN`], at most [`MAX_LINK_LEN`] bytes).
    ///
    /// # Errors
    /// [`DevicesError::Malformed`].
    pub fn decode(input: &[u8]) -> Result<Self, DevicesError> {
        if input.len() < LINK_LEN || input.len() > MAX_LINK_LEN {
            return Err(DevicesError::Malformed);
        }
        let mut r = Reader(input);
        if r.u8()? != VERSION {
            return Err(DevicesError::Malformed);
        }
        let token = r.array()?;
        let device = DeviceId::from_bytes(r.id16()?);
        let auth_key = r.array()?;
        let identity_key = r.array()?;
        let auth_sig = r.array()?;
        let identity_sig = r.array()?;
        let confirm = r.array()?;
        let factor = match r.u8()? {
            0 => Factor::None,
            1 => {
                let n = usize::from(r.u8()?);
                let pin = std::str::from_utf8(r.take(n)?).map_err(|_| DevicesError::Malformed)?;
                if !pin_ok(pin) {
                    return Err(DevicesError::Malformed);
                }
                Factor::Pin(pin.to_owned())
            }
            2 => {
                let mut part = |max: usize| -> Result<Vec<u8>, DevicesError> {
                    let n = usize::from(u16::from_be_bytes(r.array()?));
                    if n == 0 || n > max {
                        return Err(DevicesError::Malformed);
                    }
                    Ok(r.take(n)?.to_vec())
                };
                let credential_id = part(1023)?;
                let authenticator_data = part(4096)?;
                let client_data_json = part(4096)?;
                let n = usize::from(r.u8()?);
                if n == 0 {
                    return Err(DevicesError::Malformed);
                }
                Factor::Passkey {
                    credential_id,
                    authenticator_data,
                    client_data_json,
                    signature: r.take(n)?.to_vec(),
                }
            }
            _ => return Err(DevicesError::Malformed),
        };
        if !r.0.is_empty() {
            return Err(DevicesError::Malformed);
        }
        Ok(Self {
            token,
            device,
            auth_key,
            identity_key,
            auth_sig,
            identity_sig,
            confirm,
            factor,
        })
    }
}

/// What the primary seals to the new device's provisioning key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provision {
    /// The account.
    pub account: AccountId,
    /// The account identity key (Ed25519), so the new device can check device lists.
    pub account_identity: [u8; 32],
    /// The link token.
    pub token: [u8; TOKEN_LEN],
    /// The device ID the token reserves.
    pub device: DeviceId,
    /// The key of the confirmation tag.
    pub confirm_key: [u8; 32],
    /// The server the account lives on.
    pub server_name: String,
    /// The account's storage key (version 2; Prompt 9).
    pub storage_key: Option<[u8; 32]>,
}

/// The provisioning message's version with the storage key.
pub const PROVISION_V2: u8 = 2;

impl Provision {
    /// The plaintext.
    ///
    /// # Errors
    /// [`DevicesError::Malformed`] for an empty or overlong server name.
    pub fn encode(&self) -> Result<Vec<u8>, DevicesError> {
        let len = u8::try_from(self.server_name.len()).map_err(|_| DevicesError::Malformed)?;
        if self.server_name.is_empty() {
            return Err(DevicesError::Malformed);
        }
        let mut b =
            Vec::with_capacity(1 + 16 + 32 + 32 + 16 + 32 + 1 + self.server_name.len() + 32);
        b.push(if self.storage_key.is_some() {
            PROVISION_V2
        } else {
            VERSION
        });
        b.extend_from_slice(self.account.as_bytes());
        b.extend_from_slice(&self.account_identity);
        b.extend_from_slice(&self.token);
        b.extend_from_slice(self.device.as_bytes());
        b.extend_from_slice(&self.confirm_key);
        b.push(len);
        b.extend_from_slice(self.server_name.as_bytes());
        if let Some(k) = &self.storage_key {
            b.extend_from_slice(k);
        }
        Ok(b)
    }

    /// Decodes the whole plaintext.
    ///
    /// # Errors
    /// [`DevicesError::Malformed`].
    pub fn decode(input: &[u8]) -> Result<Self, DevicesError> {
        let mut r = Reader(input);
        let version = r.u8()?;
        if version != VERSION && version != PROVISION_V2 {
            return Err(DevicesError::Malformed);
        }
        let account = AccountId::from_bytes(r.id16()?);
        let account_identity = r.array()?;
        let token = r.array()?;
        let device = DeviceId::from_bytes(r.id16()?);
        let confirm_key = r.array()?;
        let n = usize::from(r.u8()?);
        let name = r.take(n)?;
        let storage_key = if version == PROVISION_V2 {
            Some(r.array()?)
        } else {
            None
        };
        if n == 0 || !r.0.is_empty() {
            return Err(DevicesError::Malformed);
        }
        let server_name = std::str::from_utf8(name)
            .map_err(|_| DevicesError::Malformed)?
            .to_owned();
        Ok(Self {
            account,
            account_identity,
            token,
            device,
            confirm_key,
            server_name,
            storage_key,
        })
    }
}

/// The bytes each new key signs: `context || u8 len(server_name) || server_name || token [32]
/// || device [16] || auth_key [32] || identity_key [33]`.
///
/// # Errors
/// [`DevicesError::Malformed`] for an empty or overlong server name.
pub fn link_transcript(
    context: &[u8],
    server_name: &str,
    token: &[u8; TOKEN_LEN],
    device: &DeviceId,
    auth_key: &[u8; 32],
    identity_key: &[u8; IDENTITY_LEN],
) -> Result<Vec<u8>, DevicesError> {
    let len = u8::try_from(server_name.len()).map_err(|_| DevicesError::Malformed)?;
    if server_name.is_empty() || server_name.len() > MAX_SERVER_NAME_LEN {
        return Err(DevicesError::Malformed);
    }
    let mut t = Vec::with_capacity(context.len() + 1 + server_name.len() + 113);
    t.extend_from_slice(context);
    t.push(len);
    t.extend_from_slice(server_name.as_bytes());
    t.extend_from_slice(token);
    t.extend_from_slice(device.as_bytes());
    t.extend_from_slice(auth_key);
    t.extend_from_slice(identity_key);
    Ok(t)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

    use proptest::prelude::*;

    use super::*;

    fn entry(b: u8, primary: bool) -> ListedDevice {
        ListedDevice {
            device: DeviceId::from_bytes([b; 16]),
            auth_key: [b; 32],
            identity_key: [5; IDENTITY_LEN],
            primary,
        }
    }

    fn list() -> DeviceList {
        DeviceList {
            account: AccountId::from_bytes([9; 16]),
            list_version: 7,
            issued_ms: 1_000,
            devices: vec![entry(1, true), entry(2, false)],
            signature: [3; 64],
        }
    }

    #[test]
    fn lists_round_trip_and_decode_strictly() {
        let l = list();
        let b = l.encode();
        assert_eq!(DeviceList::decode(&b), Ok(l.clone()));
        assert_eq!(&l.signed_bytes()[..LIST_CONTEXT.len()], LIST_CONTEXT);
        for cut in 0..b.len() {
            assert!(DeviceList::decode(&b[..cut]).is_err());
        }
        let mut long = b.clone();
        long.push(0);
        assert!(DeviceList::decode(&long).is_err());
        // No primary, two primaries, a device twice, an unknown flag, no devices.
        let mut none = l.clone();
        none.devices[0].primary = false;
        assert!(DeviceList::decode(&none.encode()).is_err());
        let mut two = l.clone();
        two.devices[1].primary = true;
        assert!(DeviceList::decode(&two.encode()).is_err());
        let mut dup = l.clone();
        dup.devices[1].device = dup.devices[0].device;
        assert!(DeviceList::decode(&dup.encode()).is_err());
        let mut flag = b.clone();
        flag[1 + 16 + 8 + 8 + 1 + 16 + 32 + 33] = 2;
        assert!(DeviceList::decode(&flag).is_err());
        let mut empty = l;
        empty.devices.clear();
        assert!(DeviceList::decode(&empty.encode()).is_err());
    }

    #[test]
    fn link_requests_round_trip_and_transcripts_differ_by_context() {
        let r = LinkRequest {
            token: [1; 32],
            device: DeviceId::from_bytes([2; 16]),
            auth_key: [3; 32],
            identity_key: [4; IDENTITY_LEN],
            auth_sig: [5; 64],
            identity_sig: [6; 64],
            confirm: [7; 32],
            factor: Factor::None,
        };
        let b = r.encode();
        assert_eq!(b.len(), LINK_LEN);
        assert_eq!(LinkRequest::decode(&b), Ok(r.clone()));
        assert!(LinkRequest::decode(&b[..LINK_LEN - 1]).is_err());
        let t = |c| {
            link_transcript(
                c,
                "chat.example",
                &r.token,
                &r.device,
                &r.auth_key,
                &r.identity_key,
            )
            .unwrap()
        };
        assert_ne!(t(LINK_AUTH_CONTEXT), t(LINK_IDENTITY_CONTEXT));
        // With each kind of second factor.
        for factor in [
            Factor::Pin("123456".to_owned()),
            Factor::Passkey {
                credential_id: vec![1; 32],
                authenticator_data: vec![2; 37],
                client_data_json: b"{}".to_vec(),
                signature: vec![3; 70],
            },
        ] {
            let with = LinkRequest {
                factor,
                ..r.clone()
            };
            let b = with.encode();
            assert_eq!(LinkRequest::decode(&b), Ok(with));
            for cut in LINK_LEN..b.len() {
                assert!(LinkRequest::decode(&b[..cut]).is_err());
            }
            let mut long = b.clone();
            long.push(0);
            assert!(LinkRequest::decode(&long).is_err());
        }
        // PINs: digits only, 6 to 12.
        for bad in ["12345", "1234567890123", "12345a"] {
            let mut b = r.encode();
            b.pop();
            b.push(1);
            b.push(u8::try_from(bad.len()).unwrap());
            b.extend_from_slice(bad.as_bytes());
            assert!(LinkRequest::decode(&b).is_err(), "{bad}");
        }
    }

    #[test]
    fn provision_messages_round_trip_and_decode_strictly() {
        let p = Provision {
            account: AccountId::from_bytes([1; 16]),
            account_identity: [2; 32],
            token: [3; 32],
            device: DeviceId::from_bytes([4; 16]),
            confirm_key: [5; 32],
            server_name: "chat.example".to_owned(),
            storage_key: None,
        };
        let b = p.encode().unwrap();
        assert_eq!(Provision::decode(&b), Ok(p.clone()));
        // Version 2 carries the storage key; cut short it does not decode.
        let v2 = Provision {
            storage_key: Some([6; 32]),
            ..p.clone()
        };
        let b2 = v2.encode().unwrap();
        assert_eq!(b2.first(), Some(&PROVISION_V2));
        assert_eq!(Provision::decode(&b2), Ok(v2));
        assert!(Provision::decode(&b2[..b2.len() - 1]).is_err());
        for cut in 0..b.len() {
            assert!(Provision::decode(&b[..cut]).is_err());
        }
        let mut long = b;
        long.push(0);
        assert!(Provision::decode(&long).is_err());
        let mut empty = p;
        empty.server_name.clear();
        assert!(empty.encode().is_err());
    }

    proptest! {
        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = DeviceList::decode(&b);
            let _ = LinkRequest::decode(&b);
            let _ = Provision::decode(&b);
        }
    }
}
