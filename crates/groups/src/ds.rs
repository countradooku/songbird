//! The MLS delivery service's core (Prompt 5, M1): pure, no I/O.
//!
//! OpenMLS's `PublicGroup` checks every handshake as RFC 9420 requires (signatures, tree and
//! path, proposals, transcript). Songbird adds, before anything is merged:
//!
//! - **the sender binding**: a member commit is signed by the leaf whose credential is the
//!   authenticated device; an external commit's new leaf is that device;
//! - **credentials** are basic, and their identity is a 16-byte device ID the directory knows;
//!   no update may change a leaf's identity;
//! - **proposals**: add, remove, update, self-remove and (in an external commit) external init
//!   only; pre-shared keys, re-init, group-context changes and custom proposals are refused
//!   until a milestone defines them (roles, M2);
//! - **external commits** rejoin a lost device only: the joining device's account already has a
//!   device in the group, and the commit may remove only that account's own leaves;
//! - **size**: at most `Limits::max_members` leaves;
//! - **Welcomes**: exactly one encrypted secret per added KeyPackage, none for anyone else;
//! - **the `GroupInfo`** uploaded with the commit is the new epoch's, signed by the committer.
//!
//! A [`Group`] is consumed by [`Group::apply_commit`] and returned only on success, so state
//! that failed half-way can never be used: the caller reloads its stored record.

use std::collections::BTreeSet;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use songbird_types::{AccountId, DeviceId};

use crate::crypto::{GROUP_CIPHERSUITES, VerifyOnlyCrypto};
use crate::roles::{self, Change, Denied, ROLES_EXTENSION, Role, Roles};
use crate::state::{GroupState, StateError, StateParts};
use crate::wire::{self, Bundle, GROUP_ID_LEN, WireError};

const CRYPTO: VerifyOnlyCrypto = VerifyOnlyCrypto;

/// The registry's roster format with roles (D-0070).
pub const ROSTER_V2: u8 = 2;
/// Largest proposal message accepted (a `SelfRemove` is a few hundred bytes).
pub const MAX_PROPOSAL: usize = 4096;

/// What the delivery service needs to know about devices.
pub trait Directory {
    /// The account a device belongs to, if the device exists and is listed.
    fn account_of(&self, device: &DeviceId) -> Option<AccountId>;
}

/// Limits on groups (`[api.groups]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most leaves (devices) in a group; Prompt 5 starts at 1,024.
    pub max_members: usize,
    /// Largest commit bundle accepted, checked before parsing.
    pub max_bundle: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_members: 1_024,
            max_bundle: 4 << 20,
        }
    }
}

/// Why a handshake was refused. Nothing was merged.
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("malformed: {0}")]
    Wire(#[from] WireError),
    #[error("malformed MLS message")]
    Malformed,
    #[error("not a handshake this endpoint takes")]
    Kind,
    #[error("another group")]
    OtherGroup,
    #[error("stale epoch; the group is at {current}")]
    StaleEpoch { current: u64 },
    #[error("unsupported ciphersuite")]
    Ciphersuite,
    #[error("the sender is not the authenticated device")]
    Sender,
    #[error("a credential is not a known device")]
    Credential,
    #[error("a proposal Songbird does not allow")]
    Proposal,
    #[error("an external commit that is not a rejoin")]
    External,
    #[error("the device is already a member")]
    Duplicate,
    #[error("the group would exceed {max} members")]
    TooLarge { max: usize },
    #[error("the Welcome does not match the added devices")]
    Welcome,
    #[error("the GroupInfo is not the new epoch's, signed by the committer")]
    GroupInfo,
    #[error("rejected by MLS validation")]
    Invalid,
    #[error("the roles extension is missing or malformed")]
    Roles,
    #[error("not allowed by the group's roles: {0}")]
    Forbidden(Denied),
    #[error("the change-log entry is not signed by the committer")]
    LogSignature,
    #[error("state: {0}")]
    State(#[from] StateError),
}

/// The roles extension of a group context (D-0070).
pub fn roles_of(ctx: &GroupContext) -> Result<Roles, GroupError> {
    roles_in(ctx.extensions())
}

/// The roles extension among a group context's extensions (clients read them with
/// `MlsGroup::extensions`).
pub fn roles_in(exts: &Extensions<GroupContext>) -> Result<Roles, GroupError> {
    let ext = exts.unknown(ROLES_EXTENSION).ok_or(GroupError::Roles)?;
    Roles::decode(&ext.0).map_err(|_| GroupError::Roles)
}

/// A change-log entry (D-0070) is the committer's: signed by its leaf key, bound to this group
/// and epoch. The server cannot read it and cannot forge one.
fn verify_log(
    group: &[u8; GROUP_ID_LEN],
    from_epoch: u64,
    log: &[u8],
    key: &SignaturePublicKey,
) -> Result<(), GroupError> {
    let entry = wire::LogEntry::parse(log)?;
    let content = wire::log_signed_content(group, from_epoch, entry.ciphertext);
    CRYPTO
        .verify_signature(
            SignatureScheme::ED25519,
            &content,
            key.as_slice(),
            entry.signature,
        )
        .map_err(|_| GroupError::LogSignature)
}

/// Only the roles extension (and `required_capabilities`) may be in a group's context.
fn extensions_allowed(ctx: &GroupContext) -> bool {
    ctx.extensions().iter().all(|e| match e {
        Extension::Unknown(t, _) => *t == ROLES_EXTENSION,
        Extension::RequiredCapabilities(_) => true,
        _ => false,
    })
}

/// One leaf of the roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leaf {
    pub device: DeviceId,
    pub index: u32,
}

/// The roster the server authorizes and fans out with: one entry per leaf, sorted by device.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Roster {
    leaves: Vec<Leaf>,
}

impl Roster {
    fn of(public: &PublicGroup) -> Result<Self, GroupError> {
        let mut leaves = public
            .members()
            .map(|m| {
                Ok(Leaf {
                    device: device_of(&m.credential)?,
                    index: m.index.u32(),
                })
            })
            .collect::<Result<Vec<_>, GroupError>>()?;
        leaves.sort_unstable();
        // Two leaves for one device would make the device's sends ambiguous.
        if leaves
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.device == b.device))
        {
            return Err(GroupError::Duplicate);
        }
        Ok(Self { leaves })
    }

    /// The device's leaf, if it is a member.
    #[must_use]
    pub fn leaf(&self, device: &DeviceId) -> Option<u32> {
        self.leaves
            .binary_search_by(|l| l.device.cmp(device))
            .ok()
            .and_then(|i| self.leaves.get(i))
            .map(|l| l.index)
    }

    /// Every member device, sorted.
    pub fn devices(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.leaves.iter().map(|l| l.device)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

/// What a commit changed, for the caller to persist and fan out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The epoch the commit was made from; the group is now at `from_epoch + 1`.
    pub from_epoch: u64,
    /// Devices added (each gets the Welcome).
    pub added: Vec<DeviceId>,
    /// Devices no longer in the group (each still gets the commit, to learn it).
    pub removed: Vec<DeviceId>,
    /// SHA-256 of the commit message, to recognise a retried commit.
    pub commit_hash: [u8; 32],
    /// The committer's change-log entry (`wire::LogEntry` bytes), its signature verified.
    pub log: Option<Vec<u8>>,
}

/// The stored form of a group: what the registry keeps under the group ID, compared and set
/// by epoch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    pub group: [u8; GROUP_ID_LEN],
    pub epoch: u64,
    pub state: StateParts,
    /// The current epoch's `GroupInfo` (`MLSMessage`), for devices that join by external
    /// commit.
    pub group_info: Vec<u8>,
}

impl Record {
    /// Postcard bytes of the record.
    pub fn encode(&self) -> Result<Vec<u8>, GroupError> {
        postcard::to_stdvec(self).map_err(|_| GroupError::State(StateError::Encoding))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        postcard::from_bytes(bytes).map_err(|_| GroupError::State(StateError::Encoding))
    }
}

/// A group as the delivery service tracks it.
#[derive(Debug)]
pub struct Group {
    id: [u8; GROUP_ID_LEN],
    public: PublicGroup,
    state: GroupState,
    roster: Roster,
    info: Vec<u8>,
}

fn device_of(credential: &Credential) -> Result<DeviceId, GroupError> {
    if credential.credential_type() != CredentialType::Basic {
        return Err(GroupError::Credential);
    }
    let basic =
        BasicCredential::try_from(credential.clone()).map_err(|_| GroupError::Credential)?;
    DeviceId::from_slice(basic.identity()).map_err(|_| GroupError::Credential)
}

fn mls_message(bytes: &[u8]) -> Result<MlsMessageBodyIn, GroupError> {
    let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| GroupError::Malformed)?;
    Ok(msg.extract())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Checks a `GroupInfo` is for `context` and signed by `leaf`'s key.
fn check_group_info(
    bytes: &[u8],
    context: &GroupContext,
    leaf: u32,
    signature_key: &SignaturePublicKey,
) -> Result<(), GroupError> {
    if wire::wire_format(bytes)? != wire::WIRE_GROUP_INFO {
        return Err(GroupError::GroupInfo);
    }
    if wire::group_info_signer(bytes)? != leaf {
        return Err(GroupError::GroupInfo);
    }
    let MlsMessageBodyIn::GroupInfo(gi) = mls_message(bytes)? else {
        return Err(GroupError::GroupInfo);
    };
    if gi.group_context() != context {
        return Err(GroupError::GroupInfo);
    }
    let key = OpenMlsSignaturePublicKey::from_signature_key(
        signature_key.clone(),
        context.ciphersuite().signature_algorithm(),
    );
    gi.verify_no_out(&CRYPTO, &key)
        .map_err(|_| GroupError::GroupInfo)?;
    Ok(())
}

impl Group {
    /// Starts tracking a group its creator just made: epoch 0, the creator as the only leaf, a
    /// Songbird ciphersuite, the requested ID.
    pub fn create(
        id: [u8; GROUP_ID_LEN],
        creator: &DeviceId,
        group_info: &[u8],
        ratchet_tree: &[u8],
        dir: &impl Directory,
    ) -> Result<Self, GroupError> {
        let Some(creator_account) = dir.account_of(creator) else {
            return Err(GroupError::Credential);
        };
        let MlsMessageBodyIn::GroupInfo(gi) = mls_message(group_info)? else {
            return Err(GroupError::Kind);
        };
        let ctx = gi.group_context();
        if ctx.group_id().as_slice() != id {
            return Err(GroupError::OtherGroup);
        }
        if !GROUP_CIPHERSUITES.contains(&ctx.ciphersuite()) {
            return Err(GroupError::Ciphersuite);
        }
        if ctx.epoch().as_u64() != 0 || !extensions_allowed(ctx) {
            return Err(GroupError::Kind);
        }
        // The creator's account is the only owner, and the only entry.
        let roles = roles_of(ctx)?;
        if roles.explicit.len() != 1 || roles.explicit.get(&creator_account) != Some(&Role::Owner) {
            return Err(GroupError::Roles);
        }
        if wire::group_info_signer(group_info)? != 0 {
            return Err(GroupError::GroupInfo);
        }
        let tree = RatchetTreeIn::tls_deserialize_exact(ratchet_tree)
            .map_err(|_| GroupError::Malformed)?;
        let state = GroupState::empty();
        let (public, _) =
            PublicGroup::from_external(&CRYPTO, &state, tree, gi, ProposalStore::new())
                .map_err(|_| GroupError::Invalid)?;
        let roster = Roster::of(&public)?;
        if roster.len() != 1 || roster.leaf(creator) != Some(0) {
            return Err(GroupError::Sender);
        }
        Ok(Self {
            id,
            public,
            state,
            roster,
            info: group_info.to_vec(),
        })
    }

    /// Loads a stored record.
    pub fn load(record: Record) -> Result<Self, GroupError> {
        let state = GroupState::from_parts(record.state)?;
        let gid = GroupId::from_slice(&record.group);
        let public = PublicGroup::load(&state, &gid)?.ok_or(StateError::Encoding)?;
        if public.group_context().epoch().as_u64() != record.epoch {
            return Err(GroupError::State(StateError::Encoding));
        }
        let roster = Roster::of(&public)?;
        Ok(Self {
            id: record.group,
            public,
            state,
            roster,
            info: record.group_info,
        })
    }

    /// The record to store.
    #[must_use]
    pub fn record(&self) -> Record {
        Record {
            group: self.id,
            epoch: self.epoch(),
            state: self.state.parts(),
            group_info: self.info.clone(),
        }
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.public.group_context().epoch().as_u64()
    }

    #[must_use]
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// The current `GroupInfo` (`MLSMessage`).
    #[must_use]
    pub fn group_info(&self) -> &[u8] {
        &self.info
    }

    /// The current ratchet tree (TLS), for a device joining by Welcome or external commit.
    pub fn ratchet_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.public
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|_| GroupError::Malformed)
    }

    /// The accounts a commit adds and removes devices for (D-0070). Devices the directory no
    /// longer lists are dead: anyone may remove them, so they are left out of `lost`.
    fn change(
        &self,
        staged: &StagedCommit,
        removed_leaves: &BTreeSet<u32>,
        added: &[DeviceId],
        dir: &impl Directory,
    ) -> Result<Change, GroupError> {
        // Leaves removed by their own proposal (leaving): the leaver authorized it.
        let self_removed: BTreeSet<u32> = staged
            .queued_proposals()
            .filter_map(|q| match (q.proposal(), q.sender()) {
                (Proposal::SelfRemove, Sender::Member(idx)) => Some(idx.u32()),
                _ => None,
            })
            .collect();
        let mut c = Change::default();
        let mut removed_devices = BTreeSet::new();
        for idx in removed_leaves {
            let leaf = self
                .public
                .leaf(LeafNodeIndex::new(*idx))
                .ok_or(GroupError::Proposal)?;
            let device = device_of(leaf.credential())?;
            removed_devices.insert(device);
            if let Some(a) = dir.account_of(&device) {
                if self_removed.contains(idx) {
                    c.left.insert(a);
                } else {
                    c.lost.insert(a);
                }
            }
        }
        for d in self.roster.devices() {
            if let Some(a) = dir.account_of(&d) {
                c.before.insert(a);
                if !removed_devices.contains(&d) {
                    c.after.insert(a);
                }
            }
        }
        for d in added {
            if let Some(a) = dir.account_of(d) {
                c.gained.insert(a);
                c.after.insert(a);
            }
        }
        Ok(c)
    }

    /// The group's roles (its context's roles extension).
    pub fn roles(&self) -> Result<Roles, GroupError> {
        roles_of(self.public.group_context())
    }

    /// The roster as the registry keeps it for the send path and `api` (D-0070):
    /// `version u8 (2) | policy [7] | n × (device [16] | role u8)`, devices ascending. A device
    /// the directory no longer lists has the role `ReadOnly` (it cannot connect anyway).
    pub fn roster_bytes(&self, dir: &impl Directory) -> Result<Vec<u8>, GroupError> {
        let roles = self.roles()?;
        let mut out = Vec::with_capacity(8 + self.roster.len() * 17);
        out.push(ROSTER_V2);
        out.extend_from_slice(&roles.policy.to_bytes());
        for d in self.roster.devices() {
            let role = dir
                .account_of(&d)
                .map_or(Role::ReadOnly, |a| roles.role(&a));
            out.extend_from_slice(d.as_bytes());
            out.push(role.as_u8());
        }
        Ok(out)
    }

    /// Proposal kinds, identities of new and updated leaves, and the external-commit rule.
    /// Returns the leaves the commit removes.
    fn check_leaves(
        &self,
        staged: &StagedCommit,
        sender: &DeviceId,
        sender_account: AccountId,
        external: bool,
        dir: &impl Directory,
    ) -> Result<BTreeSet<u32>, GroupError> {
        for q in staged.queued_proposals() {
            match q.proposal() {
                Proposal::Add(_)
                | Proposal::Remove(_)
                | Proposal::Update(_)
                | Proposal::SelfRemove => {}
                Proposal::ExternalInit(_) if external => {}
                // Roles and policy changes (M2), authorized by `roles::authorize`.
                Proposal::GroupContextExtensions(_) if !external => {}
                _ => return Err(GroupError::Proposal),
            }
        }

        // The committer's (or joiner's) new leaf keeps the authenticated device's identity.
        if let Some(leaf) = staged.update_path_leaf_node() {
            if device_of(leaf.credential())? != *sender {
                return Err(GroupError::Sender);
            }
        } else if external {
            return Err(GroupError::External);
        }
        // Updates never change a leaf's identity.
        for up in staged.update_proposals() {
            let Sender::Member(idx) = up.sender() else {
                return Err(GroupError::Proposal);
            };
            let old = self.public.leaf(*idx).ok_or(GroupError::Proposal)?;
            if device_of(up.update_proposal().leaf_node().credential())?
                != device_of(old.credential())?
            {
                return Err(GroupError::Credential);
            }
        }

        // Removed leaves: the commit's Remove proposals, and the self-removals it commits (a
        // leaver's SelfRemove, by reference: queued by `apply_proposal`).
        let mut removed: BTreeSet<u32> = staged
            .remove_proposals()
            .map(|r| r.remove_proposal().removed().u32())
            .collect();
        for q in staged.queued_proposals() {
            if let (Proposal::SelfRemove, Sender::Member(idx)) = (q.proposal(), q.sender()) {
                removed.insert(idx.u32());
            }
        }
        if external {
            // A rejoin: the account already has a device here. The only leaf it may remove is
            // the joining device's own old one (a resync, RFC 9420 §12.4.3.2); another lost
            // device of the account is removed by a member's commit.
            let account_present = self
                .roster
                .devices()
                .any(|d| d != *sender && dir.account_of(&d) == Some(sender_account))
                || self.roster.leaf(sender).is_some();
            if !account_present {
                return Err(GroupError::External);
            }
            for idx in &removed {
                let leaf = self
                    .public
                    .leaf(LeafNodeIndex::new(*idx))
                    .ok_or(GroupError::External)?;
                if device_of(leaf.credential())? != *sender {
                    return Err(GroupError::External);
                }
            }
            if self
                .roster
                .leaf(sender)
                .is_some_and(|i| !removed.contains(&i))
            {
                return Err(GroupError::Duplicate);
            }
        }
        Ok(removed)
    }

    /// Added devices: known, not already present (unless their old leaf goes), and the Welcome
    /// holds exactly one secret per added KeyPackage. Returns the added devices.
    fn check_adds(
        &self,
        staged: &StagedCommit,
        welcome: Option<&[u8]>,
        removed: &BTreeSet<u32>,
        dir: &impl Directory,
    ) -> Result<Vec<DeviceId>, GroupError> {
        let mut added = Vec::new();
        let mut added_refs = BTreeSet::new();
        for a in staged.add_proposals() {
            let kp = a.add_proposal().key_package();
            let device = device_of(kp.leaf_node().credential())?;
            if dir.account_of(&device).is_none() {
                return Err(GroupError::Credential);
            }
            if self
                .roster
                .leaf(&device)
                .is_some_and(|i| !removed.contains(&i))
                || added.contains(&device)
            {
                return Err(GroupError::Duplicate);
            }
            let r = kp.hash_ref(&CRYPTO).map_err(|_| GroupError::Invalid)?;
            added_refs.insert(r.as_slice().to_vec());
            added.push(device);
        }
        match (welcome, added.is_empty()) {
            (None, true) => {}
            (Some(w), false) => {
                if wire::wire_format(w)? != wire::WIRE_WELCOME {
                    return Err(GroupError::Welcome);
                }
                let MlsMessageBodyIn::Welcome(welcome) = mls_message(w)? else {
                    return Err(GroupError::Welcome);
                };
                if welcome.ciphersuite() != self.public.ciphersuite() {
                    return Err(GroupError::Welcome);
                }
                let refs: BTreeSet<Vec<u8>> = welcome
                    .secrets()
                    .iter()
                    .map(|s| s.new_member().as_slice().to_vec())
                    .collect();
                if refs.len() != welcome.secrets().len() || refs != added_refs {
                    return Err(GroupError::Welcome);
                }
            }
            _ => return Err(GroupError::Welcome),
        }
        Ok(added)
    }

    /// Queues a member's proposal to leave (D-0070): an MLS `SelfRemove` in a `PublicMessage`,
    /// at the current epoch, signed by the leaf of `sender`. The next commit includes it by
    /// reference; its committer needs no role to do so. Every other proposal is refused: the
    /// rest of a group's changes travel inline in commits.
    ///
    /// Returns the message's SHA-256 (to recognise a retry). On error the group is dropped, as
    /// for a commit.
    pub fn apply_proposal(
        mut self,
        sender: &DeviceId,
        msg: &[u8],
    ) -> Result<(Self, [u8; 32]), GroupError> {
        if msg.len() > MAX_PROPOSAL {
            return Err(GroupError::Wire(WireError::TooLarge));
        }
        if wire::wire_format(msg)? != wire::WIRE_PUBLIC {
            return Err(GroupError::Kind);
        }
        let MlsMessageBodyIn::PublicMessage(pm) = mls_message(msg)? else {
            return Err(GroupError::Kind);
        };
        if pm.content_type() != ContentType::Proposal {
            return Err(GroupError::Kind);
        }
        if pm.group_id().as_slice() != self.id {
            return Err(GroupError::OtherGroup);
        }
        let current = self.epoch();
        if pm.epoch().as_u64() != current {
            return Err(GroupError::StaleEpoch { current });
        }
        let Sender::Member(leaf) = *pm.sender() else {
            return Err(GroupError::Sender);
        };
        if self.roster.leaf(sender) != Some(leaf.u32()) {
            return Err(GroupError::Sender);
        }
        let processed = self
            .public
            .process_message(&CRYPTO, pm)
            .map_err(|_| GroupError::Invalid)?;
        let ProcessedMessageContent::ProposalMessage(q) = processed.into_content() else {
            return Err(GroupError::Kind);
        };
        if !matches!(q.proposal(), Proposal::SelfRemove) {
            return Err(GroupError::Proposal);
        }
        self.public
            .add_proposal(&self.state, *q)
            .map_err(GroupError::State)?;
        Ok((self, sha256(msg)))
    }

    /// Validates, authorizes and merges a commit bundle sent by `sender`. On success the group
    /// is at the next epoch; on error it is dropped, and the caller reloads its record.
    pub fn apply_commit(
        mut self,
        sender: &DeviceId,
        bundle: &[u8],
        dir: &impl Directory,
        limits: &Limits,
    ) -> Result<(Self, Applied), GroupError> {
        let b = Bundle::parse(bundle, limits.max_bundle)?;
        if wire::wire_format(b.commit)? != wire::WIRE_PUBLIC {
            return Err(GroupError::Kind);
        }
        let MlsMessageBodyIn::PublicMessage(pm) = mls_message(b.commit)? else {
            return Err(GroupError::Kind);
        };
        if pm.content_type() != ContentType::Commit {
            return Err(GroupError::Kind);
        }
        if pm.group_id().as_slice() != self.id {
            return Err(GroupError::OtherGroup);
        }
        let from_epoch = self.epoch();
        if pm.epoch().as_u64() != from_epoch {
            return Err(GroupError::StaleEpoch {
                current: from_epoch,
            });
        }
        let sender_account = dir.account_of(sender).ok_or(GroupError::Sender)?;
        let external = match pm.sender() {
            Sender::Member(leaf) => {
                if self.roster.leaf(sender) != Some(leaf.u32()) {
                    return Err(GroupError::Sender);
                }
                false
            }
            Sender::NewMemberCommit => true,
            _ => return Err(GroupError::Sender),
        };

        let processed = self
            .public
            .process_message(&CRYPTO, pm)
            .map_err(|_| GroupError::Invalid)?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(GroupError::Kind);
        };

        let removed_leaves = self.check_leaves(&staged, sender, sender_account, external, dir)?;
        let added = self.check_adds(&staged, b.welcome, &removed_leaves, dir)?;

        let new_size = self.roster.len() + added.len() + usize::from(external)
            - removed_leaves.len().min(self.roster.len());
        if new_size > limits.max_members {
            return Err(GroupError::TooLarge {
                max: limits.max_members,
            });
        }

        // Roles (D-0070): the commit's new roles extension must be valid and the change allowed
        // for the committer's role. External commits cannot change extensions, and only rejoin.
        let new_context = staged.group_context().clone();
        if !extensions_allowed(&new_context) {
            return Err(GroupError::Proposal);
        }
        let new_roles = roles_of(&new_context)?;
        if !external {
            let old_roles = roles_of(self.public.group_context())?;
            let change = self.change(&staged, &removed_leaves, &added, dir)?;
            roles::authorize(&sender_account, &old_roles, &new_roles, &change)
                .map_err(GroupError::Forbidden)?;
        }

        let old = self.roster.clone();
        self.public
            .merge_commit(&self.state, *staged)
            .map_err(|_| GroupError::Invalid)?;
        self.roster = Roster::of(&self.public)?;

        // The uploaded GroupInfo describes the new epoch and is signed by the committer's
        // (or joiner's) leaf as it is now.
        let committer = self.roster.leaf(sender).ok_or(GroupError::Sender)?;
        let committer_leaf = self
            .public
            .leaf(LeafNodeIndex::new(committer))
            .ok_or(GroupError::Sender)?;
        if &new_context != self.public.group_context() {
            return Err(GroupError::Invalid);
        }
        check_group_info(
            b.group_info,
            &new_context,
            committer,
            committer_leaf.signature_key(),
        )?;
        if self.roster.len() > limits.max_members {
            return Err(GroupError::TooLarge {
                max: limits.max_members,
            });
        }
        self.info = b.group_info.to_vec();

        if let Some(log) = b.log {
            verify_log(&self.id, from_epoch, log, committer_leaf.signature_key())?;
        }

        let removed = old
            .devices()
            .filter(|d| self.roster.leaf(d).is_none())
            .collect();
        let applied = Applied {
            from_epoch,
            added,
            removed,
            commit_hash: sha256(b.commit),
            log: b.log.map(<[u8]>::to_vec),
        };
        Ok((self, applied))
    }
}
