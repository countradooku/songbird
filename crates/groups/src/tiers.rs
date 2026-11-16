//! Group tiers and the receipt rule (Prompt 5, M4; D-0065 §5, D-0072).
//!
//! Receipts are encrypted, so this rule is the apps': every app applies the same function.
//!
//! | Tier | Members (people) | Delivered receipts | Read receipts | Batching window |
//! | --- | --- | --- | --- | --- |
//! | Small group | up to 32 | every device | yes (if enabled) | 1 s |
//! | Large group | 33 and more | the primary device only | yes (if enabled) | 10 s |
//! | Channel | any | none | none | — |
//!
//! "Primaries only" means a large group's "delivered" waits for each member's phone; it saves
//! about a quarter of the envelopes in Prompt 4's busy case (47 % to 34 %).

use std::time::Duration;

use crate::roles::Policy;

/// The largest small group, in people.
pub const SMALL_GROUP: usize = 32;

/// A group's tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Up to [`SMALL_GROUP`] people.
    Small,
    /// More.
    Large,
    /// A private channel: admins post, subscribers read.
    Channel,
}

impl Tier {
    /// The tier of a group with this policy and this many people (accounts, not devices).
    #[must_use]
    pub const fn of(policy: &Policy, people: usize) -> Self {
        if policy.is_channel() {
            Self::Channel
        } else if people <= SMALL_GROUP {
            Self::Small
        } else {
            Self::Large
        }
    }
}

/// What a device sends for messages it receives in a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipts {
    /// Send delivered receipts.
    pub delivered: bool,
    /// Send read (and played) receipts, if the person's read-receipt setting is on.
    pub read: bool,
    /// How long receipts are gathered before one is sent.
    pub window: Duration,
}

/// The receipt rule for a device in a group of this tier; `primary` is whether the device is
/// its account's primary (the signed device list says which).
#[must_use]
pub const fn receipts(tier: Tier, primary: bool) -> Receipts {
    match tier {
        Tier::Small => Receipts {
            delivered: true,
            read: true,
            window: Duration::from_secs(1),
        },
        Tier::Large => Receipts {
            delivered: primary,
            read: true,
            window: Duration::from_secs(10),
        },
        Tier::Channel => Receipts {
            delivered: false,
            read: false,
            window: Duration::ZERO,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_follow_size_and_policy() {
        assert_eq!(Tier::of(&Policy::GROUP, 1), Tier::Small);
        assert_eq!(Tier::of(&Policy::GROUP, 32), Tier::Small);
        assert_eq!(Tier::of(&Policy::GROUP, 33), Tier::Large);
        assert_eq!(Tier::of(&Policy::GROUP, 1_024), Tier::Large);
        // A channel is a channel at any size.
        assert_eq!(Tier::of(&Policy::CHANNEL, 2), Tier::Channel);
    }

    #[test]
    fn receipts_by_tier() {
        for primary in [true, false] {
            let small = receipts(Tier::Small, primary);
            assert!(small.delivered && small.read);
            assert_eq!(small.window, Duration::from_secs(1));
            let channel = receipts(Tier::Channel, primary);
            assert!(
                !channel.delivered && !channel.read,
                "no receipts in channels"
            );
        }
        // Large groups: delivered receipts from primaries only, read receipts from any device.
        assert!(receipts(Tier::Large, true).delivered);
        assert!(!receipts(Tier::Large, false).delivered);
        assert!(receipts(Tier::Large, false).read);
        assert_eq!(receipts(Tier::Large, true).window, Duration::from_secs(10));
    }
}
