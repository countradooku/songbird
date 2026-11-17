//! Room IDs, participant identities and record names (PROTOCOL §8.1, §8.6).
//!
//! - A **room** is a random 16-byte call ID; LiveKit names it in lowercase hex.
//! - A device's **participant identity** in a room is
//!   `hex(HMAC-SHA256(k_identity, room ‖ device)[..16])`: stable in one room (a reconnecting device
//!   keeps its keys), unlinkable across rooms, and recomputable by the server when it must remove a
//!   device, so no table maps identities to devices.
//! - **Records** in `valkey-hot` are named by keyed hashes (`k_record`), never by a room, group or
//!   account ID.

use aws_lc_rs::hmac;
use songbird_types::DeviceId;

/// Domain separation of the two keys derived from the call secret.
const IDENTITY_CONTEXT: &[u8] = b"songbird.v1/call-identity";
const RECORD_CONTEXT: &[u8] = b"songbird.v1/call-records";

/// A call's room: 16 random bytes. `Debug` prints nothing of it (invariant 6).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoomId([u8; 16]);

impl std::fmt::Debug for RoomId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomId(..)")
    }
}

impl RoomId {
    /// A fresh room from the system's random source.
    ///
    /// `None` if the random source failed.
    #[must_use]
    pub fn random() -> Option<Self> {
        let mut b = [0u8; 16];
        aws_lc_rs::rand::fill(&mut b).ok()?;
        Some(Self(b))
    }

    /// From its bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    /// Its bytes (the call ID apps see).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// LiveKit's name for it: 32 lowercase hex characters.
    #[must_use]
    pub fn name(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses LiveKit's name for it (webhooks).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        if name.len() != 32 || name.bytes().any(|c| c.is_ascii_uppercase()) {
            return None;
        }
        let mut b = [0u8; 16];
        hex::decode_to_slice(name, &mut b).ok()?;
        Some(Self(b))
    }
}

/// The keys derived from `[calls] secret`.
pub struct CallKeys {
    identity: hmac::Key,
    record: hmac::Key,
}

impl std::fmt::Debug for CallKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallKeys { .. }")
    }
}

/// A record name's keyed tag: 16 bytes of HMAC.
pub type Tag = [u8; 16];

impl CallKeys {
    /// Derives both keys from the 32-byte call secret.
    #[must_use]
    pub fn new(secret: &[u8; 32]) -> Self {
        let root = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let derive =
            |ctx: &[u8]| hmac::Key::new(hmac::HMAC_SHA256, hmac::sign(&root, ctx).as_ref());
        Self {
            identity: derive(IDENTITY_CONTEXT),
            record: derive(RECORD_CONTEXT),
        }
    }

    /// The participant identity of `device` in `room`.
    #[must_use]
    pub fn identity(&self, room: &RoomId, device: &DeviceId) -> String {
        let mut ctx = hmac::Context::with_key(&self.identity);
        ctx.update(room.as_bytes());
        ctx.update(device.as_bytes());
        hex::encode(ctx.sign().as_ref().get(..16).unwrap_or_default())
    }

    fn tag(&self, kind: &[u8], subject: &[u8]) -> Tag {
        let mut ctx = hmac::Context::with_key(&self.record);
        ctx.update(&[u8::try_from(kind.len()).unwrap_or(u8::MAX)]);
        ctx.update(kind);
        ctx.update(subject);
        let mut out = [0u8; 16];
        out.copy_from_slice(ctx.sign().as_ref().get(..16).unwrap_or(&[0; 16]));
        out
    }

    /// The tag of a group, as a call record holds it.
    #[must_use]
    pub fn group_tag(&self, group: &[u8; 16]) -> Tag {
        self.tag(b"group", group)
    }

    /// The record of a call (`cl:r:<tag>`).
    #[must_use]
    pub fn call_record(&self, room: &RoomId) -> String {
        format!("cl:r:{}", hex::encode(self.tag(b"room", room.as_bytes())))
    }

    /// The pointer from a group to its live call (`cl:g:<tag>`).
    #[must_use]
    pub fn group_record(&self, group: &[u8; 16]) -> String {
        format!("cl:g:{}", hex::encode(self.group_tag(group)))
    }

    /// The tag of a call link, from the hash the registry names it by: names its call record and
    /// lobby.
    #[must_use]
    pub fn link_tag(&self, link_hash: &[u8; 32]) -> Tag {
        self.tag(b"link", link_hash)
    }

    /// The keyed tag of a device, as a lobby entry holds it.
    #[must_use]
    pub fn device_tag(&self, device: &DeviceId) -> Tag {
        self.tag(b"device", device.as_bytes())
    }

    /// The set of identities removed from a room (`cl:x:<tag>`).
    #[must_use]
    pub fn deny_record(&self, room: &RoomId) -> String {
        format!("cl:x:{}", hex::encode(self.tag(b"deny", room.as_bytes())))
    }

    /// The record marking a webhook event handled (`cl:w:<tag>`).
    #[must_use]
    pub fn webhook_record(&self, event: &str) -> String {
        format!(
            "cl:w:{}",
            hex::encode(self.tag(b"webhook", event.as_bytes()))
        )
    }

    /// A budget's record (`cl:b:<kind>:<tag>`): `kind` names the budget, `subject` what it
    /// counts (an account or a device), never stored in the name.
    #[must_use]
    pub fn budget_record(&self, kind: &str, subject: &[u8]) -> String {
        format!(
            "cl:b:{kind}:{}",
            hex::encode(self.tag(kind.as_bytes(), subject))
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]
    use super::*;

    #[test]
    fn identities_are_stable_in_a_room_and_unlinkable_across_rooms() {
        let k = CallKeys::new(&[1; 32]);
        let d = DeviceId::from_bytes([2; 16]);
        let r1 = RoomId::from_bytes([3; 16]);
        let r2 = RoomId::from_bytes([4; 16]);
        assert_eq!(k.identity(&r1, &d), k.identity(&r1, &d));
        assert_ne!(k.identity(&r1, &d), k.identity(&r2, &d));
        assert_ne!(
            k.identity(&r1, &d),
            k.identity(&r1, &DeviceId::from_bytes([5; 16]))
        );
        assert_ne!(
            k.identity(&r1, &d),
            CallKeys::new(&[9; 32]).identity(&r1, &d)
        );
        let id = k.identity(&r1, &d);
        assert_eq!(id.len(), 32);
        assert!(!id.contains(&hex::encode(d.as_bytes())));
    }

    #[test]
    fn record_names_reveal_no_id() {
        let k = CallKeys::new(&[1; 32]);
        let room = RoomId::from_bytes([0xAB; 16]);
        let group = [0xCD; 16];
        for name in [
            k.call_record(&room),
            k.group_record(&group),
            k.budget_record("c", &group),
        ] {
            assert!(!name.contains("abab") && !name.contains("cdcd"), "{name}");
        }
        assert_ne!(k.budget_record("c", &group), k.budget_record("w", &group));
    }

    #[test]
    fn room_names_round_trip_and_debug_hides_them() {
        let r = RoomId::random().unwrap();
        assert_eq!(RoomId::parse(&r.name()), Some(r));
        assert_eq!(RoomId::parse(&r.name().to_uppercase()), None);
        assert_eq!(RoomId::parse("abc"), None);
        assert_eq!(format!("{r:?}"), "RoomId(..)");
    }
}
