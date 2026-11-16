//! The contact gate's cluster-wide part (Prompt 4, M4; `docs/PROTOCOL.md` §5.10–5.11; D-0062):
//! message requests and broadcast lists.
//!
//! The send path classifies every send from the directory snapshot alone (no store round trip on
//! the hot path, [`crate::Lane`]). Two lanes then need state shared by every node, and come here:
//!
//! - **Requests** (a stranger's first messages): throttled per sender, per (sender, recipient) pair
//!   and per recipient account, then dropped silently if the recipient blocked the sender or
//!   refuses requests. The budgets are spent *before* the block check, so a blocked sender sees
//!   exactly what an unblocked one sees (its sends accepted, or the same rate limits): a block
//!   cannot be detected from the answers.
//! - **Broadcast lists** (one send to several contacts): a budget of recipient accounts per
//!   sender.
//!
//! Every record is keyed: Valkey sees HMACs of accounts and pairs, never an ID; SurrealDB's block
//! rows are named by keyed hashes of the (blocker, blocked) pair ([`GateKeys`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub use songbird_accounts::blocks::GateKeys;
use songbird_types::AccountId;

/// What the gate decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Store it.
    Allow,
    /// Accept it and store nothing for the recipient (blocked, or requests refused). The sender
    /// is told it was accepted.
    Drop,
    /// Over a budget: refuse, retry after this many milliseconds.
    Limited(u32),
    /// The gate's stores are unreachable: refuse as unavailable (fail closed).
    Unavailable,
}

/// A boxed future (the gate is held as a trait object, off the hot path's static types).
pub type GateFuture<'a> = Pin<Box<dyn Future<Output = Admit> + Send + 'a>>;

/// The cluster-wide checks of the request and broadcast lanes.
pub trait Gate: Send + Sync + 'static {
    /// A message request from `sender` to `recipient`. `refused` is the recipient's request
    /// policy from the directory snapshot (requests off): budgets are spent all the same.
    fn request<'a>(
        &'a self,
        sender: &'a AccountId,
        recipient: &'a AccountId,
        refused: bool,
    ) -> GateFuture<'a>;

    /// A broadcast from `sender` to `accounts` other accounts.
    fn broadcast<'a>(&'a self, sender: &'a AccountId, accounts: u32) -> GateFuture<'a>;
}

/// The budgets (`[…send.requests]`). Defaults: a stranger may start 20 requests an hour (burst
/// 10) and send one recipient 10 messages an hour before an answer (burst 5); an account takes 100
/// requests an hour (burst 30); broadcasts reach 1,024 accounts an hour (burst 256), at most 256
/// accounts a send.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RequestLimits {
    /// Requests per hour per sender account.
    pub per_sender_hour: u32,
    /// Burst of the above.
    pub per_sender_burst: u32,
    /// Requests per hour per (sender, recipient).
    pub per_pair_hour: u32,
    /// Burst of the above.
    pub per_pair_burst: u32,
    /// Requests per hour per recipient account.
    pub per_recipient_hour: u32,
    /// Burst of the above.
    pub per_recipient_burst: u32,
    /// Broadcast recipient accounts per hour per sender.
    pub broadcast_accounts_hour: u32,
    /// Burst of the above.
    pub broadcast_burst: u32,
    /// Most accounts one broadcast may address.
    pub max_broadcast_accounts: u32,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            per_sender_hour: 20,
            per_sender_burst: 10,
            per_pair_hour: 10,
            per_pair_burst: 5,
            per_recipient_hour: 100,
            per_recipient_burst: 30,
            broadcast_accounts_hour: 1_024,
            broadcast_burst: 256,
            max_broadcast_accounts: 256,
        }
    }
}

impl songbird_types::config::Validate for RequestLimits {
    fn validate(&self, v: &mut songbird_types::config::Validator) {
        for (name, n) in [
            ("per_sender_hour", self.per_sender_hour),
            ("per_sender_burst", self.per_sender_burst),
            ("per_pair_hour", self.per_pair_hour),
            ("per_pair_burst", self.per_pair_burst),
            ("per_recipient_hour", self.per_recipient_hour),
            ("per_recipient_burst", self.per_recipient_burst),
            ("broadcast_accounts_hour", self.broadcast_accounts_hour),
            ("broadcast_burst", self.broadcast_burst),
        ] {
            v.check((1..=1_000_000).contains(&n), name, "must be in 1..=1000000");
        }
        v.check(
            (2..=1_024).contains(&self.max_broadcast_accounts),
            "max_broadcast_accounts",
            "must be in 2..=1024",
        );
    }
}

/// Cost-weighted GCRA on Valkey's clock: `ARGV[1]` the emission interval, `ARGV[2]` the burst
/// tolerance (microseconds), `ARGV[3]` the cost. 0 when allowed (and recorded), else the wait in
/// microseconds.
pub const GCRA_COST: &str = "local t = redis.call('TIME') \
     local now = tonumber(t[1]) * 1000000 + tonumber(t[2]) \
     local tat = tonumber(redis.call('GET', KEYS[1]) or now) \
     if tat < now then tat = now end \
     local new = tat + tonumber(ARGV[1]) * tonumber(ARGV[3]) \
     local wait = new - tonumber(ARGV[2]) - now \
     if wait > 0 then return wait end \
     redis.call('SET', KEYS[1], new, 'PX', math.ceil((new - now) / 1000) + 1) \
     return 0";

fn wait_ms(us: u64) -> u32 {
    u32::try_from(us.div_ceil(1000)).unwrap_or(u32::MAX).max(1)
}

/// The deployed gate: block rows in the registry (SurrealDB), budgets in `valkey-hot`.
pub struct RegistryGate {
    registry: Arc<songbird_accounts::Registry>,
    hot: songbird_valkey::ValkeyConn,
    keys: GateKeys,
    limits: RequestLimits,
}

impl std::fmt::Debug for RegistryGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryGate")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl RegistryGate {
    /// The gate over a registry and `valkey-hot`.
    #[must_use]
    pub const fn new(
        registry: Arc<songbird_accounts::Registry>,
        hot: songbird_valkey::ValkeyConn,
        keys: GateKeys,
        limits: RequestLimits,
    ) -> Self {
        Self {
            registry,
            hot,
            keys,
            limits,
        }
    }

    /// Spends `cost` of a budget; `Ok(0)` when allowed, else the wait in microseconds.
    async fn spend(&self, record: &str, per_hour: u32, burst: u32, cost: u32) -> Result<u64, ()> {
        let interval_us = 3_600_000_000 / u64::from(per_hour.max(1));
        let tolerance_us = interval_us.saturating_mul(u64::from(burst.max(1)));
        self.hot
            .query::<i64>(
                redis::cmd("EVAL")
                    .arg(GCRA_COST)
                    .arg(1)
                    .arg(record)
                    .arg(interval_us)
                    .arg(tolerance_us)
                    .arg(cost.max(1)),
            )
            .await
            .map(|w| u64::try_from(w).unwrap_or(0))
            .map_err(|_| ())
    }
}

impl Gate for RegistryGate {
    fn request<'a>(
        &'a self,
        sender: &'a AccountId,
        recipient: &'a AccountId,
        refused: bool,
    ) -> GateFuture<'a> {
        Box::pin(async move {
            let l = &self.limits;
            let (s, r) = (
                sender.as_bytes().as_slice(),
                recipient.as_bytes().as_slice(),
            );
            for (kind, subject, per_hour, burst) in [
                ("s", vec![s], l.per_sender_hour, l.per_sender_burst),
                ("p", vec![s, r], l.per_pair_hour, l.per_pair_burst),
                ("r", vec![r], l.per_recipient_hour, l.per_recipient_burst),
            ] {
                match self
                    .spend(&self.keys.record(kind, &subject), per_hour, burst, 1)
                    .await
                {
                    Ok(0) => {}
                    Ok(wait) => return Admit::Limited(wait_ms(wait)),
                    Err(()) => return Admit::Unavailable,
                }
            }
            if refused {
                return Admit::Drop;
            }
            match self
                .registry
                .is_blocked(&self.keys.pair(recipient, sender))
                .await
            {
                Ok(true) => Admit::Drop,
                Ok(false) => Admit::Allow,
                Err(_) => Admit::Unavailable,
            }
        })
    }

    fn broadcast<'a>(&'a self, sender: &'a AccountId, accounts: u32) -> GateFuture<'a> {
        Box::pin(async move {
            let l = &self.limits;
            match self
                .spend(
                    &self.keys.record("b", &[sender.as_bytes()]),
                    l.broadcast_accounts_hour,
                    l.broadcast_burst,
                    accounts,
                )
                .await
            {
                Ok(0) => Admit::Allow,
                Ok(wait) => Admit::Limited(wait_ms(wait)),
                Err(()) => Admit::Unavailable,
            }
        })
    }
}

/// An in-process gate with the same rules (tests and development): blocks and budgets in memory,
/// budgets as plain counters per process.
#[derive(Debug, Default)]
pub struct MemoryGate {
    state: std::sync::Mutex<MemoryState>,
    limits: RequestLimits,
}

#[derive(Debug, Default)]
struct MemoryState {
    blocks: std::collections::HashSet<(AccountId, AccountId)>,
    spent: std::collections::HashMap<(char, AccountId, AccountId), u32>,
}

impl MemoryGate {
    /// A gate with these budgets (counted, never refilled: tests).
    #[must_use]
    pub fn new(limits: RequestLimits) -> Self {
        Self {
            state: std::sync::Mutex::default(),
            limits,
        }
    }

    /// `blocker` blocks `target`.
    pub fn block(&self, blocker: AccountId, target: AccountId) {
        self.lock().blocks.insert((blocker, target));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Gate for MemoryGate {
    fn request<'a>(
        &'a self,
        sender: &'a AccountId,
        recipient: &'a AccountId,
        refused: bool,
    ) -> GateFuture<'a> {
        let l = self.limits;
        let mut st = self.lock();
        let zero = AccountId::from_bytes([0; 16]);
        let mut over = false;
        for (k, a, b, max) in [
            ('s', *sender, zero, l.per_sender_burst),
            ('p', *sender, *recipient, l.per_pair_burst),
            ('r', zero, *recipient, l.per_recipient_burst),
        ] {
            let n = st.spent.entry((k, a, b)).or_default();
            if *n >= max {
                over = true;
                break;
            }
            *n += 1;
        }
        let out = if over {
            Admit::Limited(1_000)
        } else if refused || st.blocks.contains(&(*recipient, *sender)) {
            Admit::Drop
        } else {
            Admit::Allow
        };
        Box::pin(std::future::ready(out))
    }

    fn broadcast<'a>(&'a self, sender: &'a AccountId, accounts: u32) -> GateFuture<'a> {
        let max = self.limits.broadcast_burst;
        let mut st = self.lock();
        let n = st.spent.entry(('b', *sender, *sender)).or_default();
        let out = if n.saturating_add(accounts) > max {
            Admit::Limited(1_000)
        } else {
            *n += accounts;
            Admit::Allow
        };
        Box::pin(std::future::ready(out))
    }
}
