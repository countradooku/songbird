//! Chat-wide state many people write: pins, the disappearing timer, the restricted-chat policy.
//! Each is decided by the greatest [`Stamp`], so every device agrees whatever the arrival order.

use std::collections::BTreeMap;

use super::{MsgKey, Stamp};
use crate::schema::{ChatPolicy, Pin, TimerChange};

/// At most this many messages are pinned in a chat; the newest pins win.
pub const MAX_PINNED: usize = 3;

/// A chat's shared state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chat {
    /// target → the greatest pin operation (its stamp; the duration, or `None` for unpin).
    pins: BTreeMap<MsgKey, (Stamp, Option<u32>)>,
    timer: Option<(Stamp, u32)>,
    policy: Option<(Stamp, bool, bool)>,
}

impl Chat {
    /// A (validated) pin or unpin.
    pub fn pin(&mut self, stamp: Stamp, p: &Pin) {
        let Some(target) = p.target.as_ref().and_then(MsgKey::from_ref) else {
            return;
        };
        let new = (stamp, (!p.unpin).then_some(p.duration_s));
        self.pins
            .entry(target)
            .and_modify(|cur| {
                if new > *cur {
                    *cur = new;
                }
            })
            .or_insert(new);
    }

    /// The pinned messages at `now_ms`, newest pin first, at most [`MAX_PINNED`].
    #[must_use]
    pub fn pinned(&self, now_ms: u64) -> Vec<MsgKey> {
        let mut live: Vec<(Stamp, MsgKey)> = self
            .pins
            .iter()
            .filter_map(|(k, (s, d))| {
                let until = s.at_ms.saturating_add(u64::from((*d)?) * 1000);
                (until > now_ms).then_some((*s, *k))
            })
            .collect();
        live.sort_unstable_by(|a, b| b.cmp(a));
        live.into_iter().take(MAX_PINNED).map(|(_, k)| k).collect()
    }

    /// A (validated) disappearing-timer change.
    pub fn timer_change(&mut self, stamp: Stamp, t: &TimerChange) {
        if self.timer.is_none_or(|cur| (stamp, t.expire_timer_s) > cur) {
            self.timer = Some((stamp, t.expire_timer_s));
        }
    }

    /// The chat's disappearing timer in seconds (0 off).
    #[must_use]
    pub fn timer(&self) -> u32 {
        self.timer.map_or(0, |(_, t)| t)
    }

    /// A restricted-chat policy change.
    pub fn policy_change(&mut self, stamp: Stamp, p: &ChatPolicy) {
        let new = (stamp, p.restrict_export, p.restrict_auto_save);
        if self.policy.is_none_or(|cur| new > cur) {
            self.policy = Some(new);
        }
    }

    /// (export refused, automatic media saving refused).
    #[must_use]
    pub fn policy(&self) -> (bool, bool) {
        self.policy.map_or((false, false), |(_, e, s)| (e, s))
    }
}
