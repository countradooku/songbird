//! Prompt 5's client harness (D-0066): simulated devices running OpenMLS on its own
//! `RustCrypto` provider, as an app would, against Songbird's delivery-service core. Test-only:
//! no service depends on this crate.
#![forbid(unsafe_code)]
#![allow(
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test harness: failing loudly is the point"
)]

use std::cell::Cell;
use std::collections::BTreeMap;

/// The package type, for callers without their own `openmls`.
pub use openmls::prelude::KeyPackage;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use songbird_groups::crypto::GROUP_CIPHERSUITE;
use songbird_groups::ds::ds_external_senders;
use songbird_groups::roles::{self, Policy, ROLES_EXTENSION, Roles};
use songbird_groups::wire::{Bundle, LogEntry, log_signed_content};
use songbird_groups::{Directory, Group, Limits};
use songbird_types::{AccountId, DeviceId};

thread_local! {
    static SUITE: Cell<Ciphersuite> = const { Cell::new(GROUP_CIPHERSUITE) };
}

/// The ciphersuite this thread's devices use for new groups and KeyPackages: Songbird's
/// ([`GROUP_CIPHERSUITE`], X-Wing) unless a benchmark compares another.
#[must_use]
pub fn suite() -> Ciphersuite {
    SUITE.with(Cell::get)
}

/// Sets [`suite`] for this thread (benchmarks only; the delivery service refuses other suites).
pub fn set_suite(suite: Ciphersuite) {
    SUITE.with(|c| c.set(suite));
}

/// A test directory: device → account.
#[derive(Debug, Default, Clone)]
pub struct Dir(pub BTreeMap<DeviceId, AccountId>);

impl Directory for Dir {
    fn account_of(&self, device: &DeviceId) -> Option<AccountId> {
        self.0.get(device).copied()
    }
}

/// One simulated device.
pub struct Device {
    pub id: DeviceId,
    pub account: AccountId,
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub cred: CredentialWithKey,
    pub group: Option<MlsGroup>,
    /// The delivery service's external-sender key new groups name (D-0075), if any.
    pub ds_key: Option<[u8; 32]>,
    raw_key: (Vec<u8>, Vec<u8>),
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The group ID every harness test uses.
pub const GID: [u8; 16] = [0x5B; 16];

#[must_use]
pub fn id_from(n: u16, tag: u8) -> [u8; 16] {
    let mut b = [tag; 16];
    b[..2].copy_from_slice(&n.to_be_bytes());
    b
}

impl Device {
    /// A device of `account`, registered in `dir`.
    #[must_use]
    pub fn new(n: u16, account: AccountId, dir: &mut Dir) -> Self {
        let id = DeviceId::from_bytes(id_from(n, 0xD0));
        dir.0.insert(id, account);
        Self::unregistered(id, account)
    }

    /// The same device after losing its group state but keeping its keys (restored from the
    /// platform keystore): same ID, same signature key.
    #[must_use]
    pub fn restored(other: &Self) -> Self {
        let mut d = Self::with_key(
            other.id,
            other.account,
            OpenMlsRustCrypto::default(),
            other.raw_key.clone(),
        );
        d.ds_key = other.ds_key;
        d
    }

    /// A device the directory does not know.
    #[must_use]
    pub fn unregistered(id: DeviceId, account: AccountId) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let scheme = GROUP_CIPHERSUITE.signature_algorithm();
        let raw_key = provider.crypto().signature_key_gen(scheme).unwrap();
        Self::with_key(id, account, provider, raw_key)
    }

    fn with_key(
        id: DeviceId,
        account: AccountId,
        provider: OpenMlsRustCrypto,
        raw_key: (Vec<u8>, Vec<u8>),
    ) -> Self {
        let scheme = GROUP_CIPHERSUITE.signature_algorithm();
        let signer = SignatureKeyPair::from_raw(scheme, raw_key.0.clone(), raw_key.1.clone());
        signer.store(provider.storage()).unwrap();
        let cred = CredentialWithKey {
            credential: BasicCredential::new(id.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Self {
            id,
            account,
            provider,
            signer,
            cred,
            group: None,
            ds_key: None,
            raw_key,
        }
    }

    /// A new KeyPackage and its wire bytes (what an app uploads to the key directory).
    #[must_use]
    pub fn key_package_with_bytes(&self) -> (KeyPackage, Vec<u8>) {
        let kp = self.key_package();
        let bytes = kp.tls_serialize_detached().unwrap();
        (kp, bytes)
    }

    #[must_use]
    pub fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(caps())
            .build(suite(), &self.provider, &self.signer, self.cred.clone())
            .unwrap()
            .key_package()
            .clone()
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.group.as_ref().map_or(0, |g| g.epoch().as_u64())
    }

    /// Creates a group with this device's account as owner; returns `(GroupInfo, ratchet tree)`
    /// for the server.
    pub fn create(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.create_with(Policy::GROUP)
    }

    /// Creates a group (or, with [`Policy::CHANNEL`], a channel) with this policy.
    pub fn create_with(&mut self, policy: Policy) -> (Vec<u8>, Vec<u8>) {
        self.create_in(GID, policy)
    }

    /// Creates group `id` with this policy (a device holds one group at a time here; a second
    /// group needs [`Device::restored`]).
    pub fn create_in(&mut self, id: [u8; 16], policy: Policy) -> (Vec<u8>, Vec<u8>) {
        let roles = Roles::new(self.account, policy);
        let cfg = MlsGroupCreateConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .ciphersuite(suite())
            .max_past_epochs(1)
            .capabilities(caps())
            .with_group_context_extensions(context_extensions(
                &roles,
                self.ds_key.as_ref().map(ds_external_senders),
            ))
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &cfg,
            GroupId::from_slice(&id),
            self.cred.clone(),
        )
        .unwrap();
        self.group = Some(group);
        (self.group_info(), self.tree())
    }

    /// The group's roles, as this client sees them.
    #[must_use]
    pub fn roles(&self) -> Roles {
        songbird_groups::ds::roles_in(self.group.as_ref().unwrap().extensions()).unwrap()
    }

    /// A commit that sets the group's roles and policy (pending).
    pub fn set_roles(&mut self, roles: &Roles) -> Vec<u8> {
        self.commit_with(Vec::new(), &[], false, Some(roles))
    }

    #[must_use]
    pub fn group_info(&self) -> Vec<u8> {
        let g = self.group.as_ref().unwrap();
        g.export_group_info(self.provider.crypto(), &self.signer, false)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }

    #[must_use]
    pub fn tree(&self) -> Vec<u8> {
        self.group
            .as_ref()
            .unwrap()
            .export_ratchet_tree()
            .tls_serialize_detached()
            .unwrap()
    }

    /// Builds a commit (pending until the server answers) with the new epoch's `GroupInfo`,
    /// and returns its bundle.
    pub fn commit(&mut self, adds: Vec<KeyPackage>, removes: &[u32], update: bool) -> Vec<u8> {
        self.commit_with(adds, removes, update, None)
    }

    /// A commit with adds, removals, a key update and, if given, new roles.
    pub fn commit_with(
        &mut self,
        adds: Vec<KeyPackage>,
        removes: &[u32],
        update: bool,
        roles: Option<&Roles>,
    ) -> Vec<u8> {
        // A context change carries the group's external senders over unchanged (D-0075).
        let external = self
            .group
            .as_ref()
            .unwrap()
            .extensions()
            .external_senders()
            .cloned();
        let exts = roles.map(|r| context_extensions(r, external));
        self.commit_ext(adds, removes, update, exts)
    }

    /// A commit with adds, removals, a key update and, if given, these context extensions
    /// exactly (tests of what the server refuses).
    pub fn commit_ext(
        &mut self,
        adds: Vec<KeyPackage>,
        removes: &[u32],
        update: bool,
        exts: Option<Extensions<GroupContext>>,
    ) -> Vec<u8> {
        let (p, s) = (&self.provider, &self.signer);
        let g = self.group.as_mut().unwrap();
        let mut builder = g
            .commit_builder()
            .propose_adds(adds)
            .propose_removals(removes.iter().map(|l| LeafNodeIndex::new(*l)))
            .force_self_update(update);
        if let Some(e) = exts {
            builder = builder.propose_group_context_extensions(e).unwrap();
        }
        let bundle = builder
            .load_psks(p.storage())
            .unwrap()
            .create_group_info(true)
            .build(p.rand(), p.crypto(), s, |_| true)
            .unwrap()
            .stage_commit(p)
            .unwrap();
        let (commit, welcome, info) = bundle.into_messages();
        let commit = commit.tls_serialize_detached().unwrap();
        let welcome = welcome.map(|w| w.tls_serialize_detached().unwrap());
        let info = info.unwrap().tls_serialize_detached().unwrap();
        Bundle {
            commit: &commit,
            welcome: welcome.as_deref(),
            group_info: &info,
            log: None,
        }
        .encode()
    }

    pub fn add(&mut self, kps: &[KeyPackage]) -> Vec<u8> {
        self.commit(kps.to_vec(), &[], false)
    }

    pub fn remove(&mut self, leaves: &[u32]) -> Vec<u8> {
        self.commit(Vec::new(), leaves, false)
    }

    pub fn update(&mut self) -> Vec<u8> {
        self.commit(Vec::new(), &[], true)
    }

    /// The server accepted the pending commit.
    pub fn merge(&mut self) {
        let p = &self.provider;
        self.group
            .as_mut()
            .unwrap()
            .merge_pending_commit(p)
            .unwrap();
    }

    /// The server refused it.
    pub fn discard(&mut self) {
        let p = &self.provider;
        self.group
            .as_mut()
            .unwrap()
            .clear_pending_commit(p.storage())
            .unwrap();
    }

    /// Joins from a Welcome and the ratchet tree the server serves.
    pub fn join(&mut self, welcome: &[u8], tree: &[u8]) {
        let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(welcome)
            .unwrap()
            .extract()
        else {
            panic!("not a Welcome")
        };
        let tree = RatchetTreeIn::tls_deserialize_exact(tree).unwrap();
        let g =
            StagedWelcome::new_from_welcome(&self.provider, config().join_config(), w, Some(tree))
                .unwrap()
                .into_group(&self.provider)
                .unwrap();
        self.group = Some(g);
    }

    /// Processes another member's commit as an app does: OpenMLS validates it, then the roles
    /// rule (`songbird_groups::roles::authorize`) decides, with this client's own view of the
    /// group and `dir`. A refused commit is not merged and the client stays at its epoch.
    pub fn receive_checked(&mut self, bundle: &[u8], dir: &Dir) -> Result<(), String> {
        self.judge(bundle, dir, true)
    }

    /// As [`Device::receive_checked`], but leaves the group as it is either way (to judge
    /// several alternative commits from one epoch).
    pub fn verify_commit(&mut self, bundle: &[u8], dir: &Dir) -> Result<(), String> {
        self.judge(bundle, dir, false)
    }

    fn judge(&mut self, bundle: &[u8], dir: &Dir, merge: bool) -> Result<(), String> {
        let b = Bundle::parse(bundle, usize::MAX).map_err(|e| e.to_string())?;
        let msg = MlsMessageIn::tls_deserialize_exact(b.commit).map_err(|e| e.to_string())?;
        let p = &self.provider;
        let g = self.group.as_mut().unwrap();
        let old_roles = songbird_groups::ds::roles_in(g.extensions()).map_err(|e| e.to_string())?;
        let processed = g
            .process_message(
                p,
                msg.try_into_protocol_message().map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        let Sender::Member(idx) = *processed.sender() else {
            return Err("not a member's commit".into());
        };
        let actor = g
            .member(idx)
            .and_then(|c| DeviceId::from_slice(c.serialized_content()).ok())
            .and_then(|d| dir.account_of(&d))
            .ok_or("unknown committer")?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("expected a commit".into());
        };
        let new_roles =
            songbird_groups::ds::roles_of(staged.group_context()).map_err(|e| e.to_string())?;
        let account = |c: &Credential| {
            DeviceId::from_slice(c.serialized_content())
                .ok()
                .and_then(|d| dir.account_of(&d))
        };
        let mut change = roles::Change::default();
        let removed: Vec<LeafNodeIndex> = staged
            .remove_proposals()
            .map(|r| r.remove_proposal().removed())
            .collect();
        let self_removed: Vec<LeafNodeIndex> = staged
            .queued_proposals()
            .filter_map(|q| match (q.proposal(), q.sender()) {
                (Proposal::SelfRemove, Sender::Member(i)) => Some(*i),
                _ => None,
            })
            .collect();
        // The delivery service may propose removals only (D-0075); `external` collects the
        // still-listed devices it would remove, which `authorize` refuses.
        let mut server_removed = Vec::new();
        for q in staged.queued_proposals() {
            match (q.sender(), q.proposal()) {
                (Sender::External(_), Proposal::Remove(r)) => server_removed.push(r.removed()),
                (Sender::External(_) | Sender::NewMemberProposal, _) => {
                    return Err("an outsider's proposal other than a server removal".into());
                }
                _ => {}
            }
        }
        for m in g.members() {
            if let Some(a) = account(&m.credential) {
                change.before.insert(a);
                if server_removed.contains(&m.index) {
                    change.external.insert(a);
                } else if self_removed.contains(&m.index) {
                    change.left.insert(a);
                } else if removed.contains(&m.index) {
                    change.lost.insert(a);
                } else {
                    change.after.insert(a);
                }
            }
        }
        for a in staged.add_proposals() {
            if let Some(acc) = account(a.add_proposal().key_package().leaf_node().credential()) {
                change.gained.insert(acc);
                change.after.insert(acc);
            }
        }
        if let Err(e) = roles::authorize(&actor, &old_roles, &new_roles, &change) {
            return Err(format!("refused by the roles rule: {e}"));
        }
        if merge {
            g.merge_staged_commit(p, *staged)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// A commit carrying a change-log entry (D-0070): `ciphertext` (already encrypted by the
    /// app) signed with this device's leaf key for the epoch the commit is made from.
    pub fn commit_logged(
        &mut self,
        adds: Vec<KeyPackage>,
        removes: &[u32],
        roles: Option<&Roles>,
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let from_epoch = self.epoch();
        let signature = self.sign_log(from_epoch, ciphertext);
        let bundle = self.commit_with(adds, removes, false, roles);
        with_log(&bundle, &LogEntry::encode(ciphertext, &signature))
    }

    /// This device's signature on a change-log entry for `from_epoch`.
    #[must_use]
    pub fn sign_log(&self, from_epoch: u64, ciphertext: &[u8]) -> [u8; 64] {
        use openmls_traits::signatures::Signer as _;
        let content = log_signed_content(&GID, from_epoch, ciphertext);
        self.signer.sign(&content).unwrap().try_into().unwrap()
    }

    /// Proposes to leave (an MLS `SelfRemove`, `PublicMessage`); another member's next commit
    /// includes it.
    pub fn leave(&mut self) -> Vec<u8> {
        let (p, s) = (&self.provider, &self.signer);
        self.group
            .as_mut()
            .unwrap()
            .leave_group_via_self_remove(p, s)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }

    /// Proposes one's own removal as a plain `Remove` (OpenMLS `leave_group`), which Songbird
    /// does not take standalone (tests).
    pub fn leave_by_remove(&mut self) -> Vec<u8> {
        let (p, s) = (&self.provider, &self.signer);
        self.group
            .as_mut()
            .unwrap()
            .leave_group(p, s)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }

    /// Stores another member's proposal (fanned out by the server) for the next commit.
    pub fn receive_proposal(&mut self, msg: &[u8]) {
        let msg = MlsMessageIn::tls_deserialize_exact(msg).unwrap();
        let p = &self.provider;
        let g = self.group.as_mut().unwrap();
        let processed = g
            .process_message(p, msg.try_into_protocol_message().unwrap())
            .unwrap();
        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(q) => {
                g.store_pending_proposal(p.storage(), *q).unwrap();
            }
            _ => panic!("expected a proposal"),
        }
    }

    /// A proposal from the delivery service (D-0075), checked as apps check it before storing
    /// it for their next commit: a `Remove` from the group's external sender, of a device that
    /// is no longer in its account's signed device list (`dir`, this client's view). Anything
    /// else is dropped (not stored) and reported.
    pub fn receive_server_proposal(&mut self, msg: &[u8], dir: &Dir) -> Result<(), String> {
        let msg = MlsMessageIn::tls_deserialize_exact(msg).map_err(|e| e.to_string())?;
        let p = &self.provider;
        let g = self.group.as_mut().unwrap();
        let processed = g
            .process_message(
                p,
                msg.try_into_protocol_message().map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        if !matches!(processed.sender(), Sender::External(_)) {
            return Err("not the delivery service's".into());
        }
        let ProcessedMessageContent::ProposalMessage(q) = processed.into_content() else {
            return Err("not a proposal".into());
        };
        let Proposal::Remove(r) = q.proposal() else {
            return Err("the delivery service may only propose removals".into());
        };
        let listed = g
            .member(r.removed())
            .and_then(|c| DeviceId::from_slice(c.serialized_content()).ok())
            .and_then(|d| dir.account_of(&d))
            .is_some();
        if listed {
            return Err("a server removal of a device that is still listed".into());
        }
        g.store_pending_proposal(p.storage(), *q)
            .map_err(|e| e.to_string())
    }

    /// Processes an external commit (a join) as apps do (D-0076): from an account already in
    /// the group it is a rejoin; from a new account it must carry a proof under a link key the
    /// group's roles extension publishes (`songbird_groups::links::verify`). Refused joins are
    /// not merged.
    pub fn receive_join_checked(&mut self, bundle: &[u8], dir: &Dir) -> Result<(), String> {
        let b = Bundle::parse(bundle, usize::MAX).map_err(|e| e.to_string())?;
        let msg = MlsMessageIn::tls_deserialize_exact(b.commit).map_err(|e| e.to_string())?;
        let p = &self.provider;
        let g = self.group.as_mut().unwrap();
        let roles = songbird_groups::ds::roles_in(g.extensions()).map_err(|e| e.to_string())?;
        let from_epoch = g.epoch().as_u64();
        let processed = g
            .process_message(
                p,
                msg.try_into_protocol_message().map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        if !matches!(processed.sender(), Sender::NewMemberCommit) {
            return Err("not a join".into());
        }
        let aad = processed.aad().to_vec();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("expected a commit".into());
        };
        let leaf = staged.update_path_leaf_node().ok_or("no joiner's leaf")?;
        let device = DeviceId::from_slice(leaf.credential().serialized_content())
            .map_err(|e| e.to_string())?;
        let account = dir.account_of(&device).ok_or("an unknown joiner")?;
        let present = g.members().any(|m| {
            DeviceId::from_slice(m.credential.serialized_content())
                .ok()
                .and_then(|d| dir.account_of(&d))
                == Some(account)
        });
        if !present {
            let group: [u8; 16] = g.group_id().as_slice().try_into().unwrap();
            songbird_groups::links::verify(
                &roles,
                &group,
                from_epoch,
                &aad,
                &device,
                leaf.signature_key().as_slice(),
                None,
            )
            .map_err(|e| format!("a join from a new account without a valid link proof: {e}"))?;
        }
        g.merge_staged_commit(p, *staged).map_err(|e| e.to_string())
    }

    /// A commit publishing `link`'s proof key in the group's roles extension (pending), as the
    /// link's creator commits it before sharing the link (D-0076).
    pub fn publish_link(&mut self, link: &LinkSecret) -> Vec<u8> {
        let mut roles = self.roles();
        roles.links.insert(link.handle, link.public_key());
        self.set_roles(&roles)
    }

    /// Processes another member's commit (from the bundle the server fanned out).
    pub fn receive(&mut self, bundle: &[u8]) {
        let b = Bundle::parse(bundle, usize::MAX).unwrap();
        let msg = MlsMessageIn::tls_deserialize_exact(b.commit).unwrap();
        let p = &self.provider;
        let g = self.group.as_mut().unwrap();
        let processed = g
            .process_message(p, msg.try_into_protocol_message().unwrap())
            .unwrap();
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                g.merge_staged_commit(p, *staged).unwrap();
            }
            _ => panic!("expected a commit"),
        }
    }

    /// An application message (`PrivateMessage`).
    pub fn message(&mut self, text: &[u8]) -> Vec<u8> {
        let (p, s) = (&self.provider, &self.signer);
        self.group
            .as_mut()
            .unwrap()
            .create_message(p, s, text)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }

    /// Reads an application message.
    pub fn read(&mut self, msg: &[u8]) -> Vec<u8> {
        let msg = MlsMessageIn::tls_deserialize_exact(msg).unwrap();
        let p = &self.provider;
        let processed = self
            .group
            .as_mut()
            .unwrap()
            .process_message(p, msg.try_into_protocol_message().unwrap())
            .unwrap();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => m.into_bytes(),
            _ => panic!("expected an application message"),
        }
    }

    /// The devices this client sees in the group, sorted.
    #[must_use]
    pub fn roster(&self) -> Vec<DeviceId> {
        let mut v: Vec<DeviceId> = self
            .group
            .as_ref()
            .unwrap()
            .members()
            .map(|m| DeviceId::from_slice(m.credential.serialized_content()).unwrap())
            .collect();
        v.sort_unstable();
        v
    }

    /// This device's leaf index.
    #[must_use]
    pub fn leaf(&self) -> u32 {
        self.group.as_ref().unwrap().own_leaf_index().u32()
    }

    /// Joins by external commit from the server's `GroupInfo` and tree. OpenMLS removes this
    /// device's old leaf itself when its signature key is still in the tree (a resync).
    pub fn rejoin(&mut self, group_info: &[u8], tree: &[u8]) -> Vec<u8> {
        self.rejoin_with_aad(group_info, tree, |_, _| Vec::new())
    }

    /// Joins by invite link (D-0076): an external commit carrying `link`'s proof for this
    /// group, the `GroupInfo`'s epoch, this device and its leaf key.
    pub fn join_by_link(&mut self, group_info: &[u8], tree: &[u8], link: &LinkSecret) -> Vec<u8> {
        let (id, key) = (self.id, self.signer.public().to_vec());
        self.rejoin_with_aad(group_info, tree, |group, epoch| {
            link.prove(group, epoch, &id, &key)
        })
    }

    /// An external commit whose authenticated data is `aad(group, epoch)` (tests of what the
    /// server and members refuse).
    pub fn rejoin_with_aad(
        &mut self,
        group_info: &[u8],
        tree: &[u8],
        aad: impl FnOnce(&[u8; 16], u64) -> Vec<u8>,
    ) -> Vec<u8> {
        let MlsMessageBodyIn::GroupInfo(gi) = MlsMessageIn::tls_deserialize_exact(group_info)
            .unwrap()
            .extract()
        else {
            panic!("not a GroupInfo")
        };
        let aad = aad(
            gi.group_id().as_slice().try_into().unwrap(),
            gi.epoch().as_u64(),
        );
        let tree = RatchetTreeIn::tls_deserialize_exact(tree).unwrap();
        let (group, bundle) = MlsGroup::external_commit_builder()
            .with_aad(aad)
            .with_ratchet_tree(tree)
            .with_config(config().join_config().clone())
            .build_group(&self.provider, gi, self.cred.clone())
            .unwrap()
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(caps())
                    .build(),
            )
            .load_psks(self.provider.storage())
            .unwrap()
            .create_group_info(true)
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &self.signer,
                |_| true,
            )
            .unwrap()
            .finalize(&self.provider)
            .unwrap();
        let (commit, _, info) = bundle.into_messages();
        let commit = commit.tls_serialize_detached().unwrap();
        let info = info.unwrap().tls_serialize_detached().unwrap();
        self.group = Some(group);
        Bundle {
            commit: &commit,
            welcome: None,
            group_info: &info,
            log: None,
        }
        .encode()
    }
}

#[must_use]
pub fn config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(suite())
        .max_past_epochs(1)
        .capabilities(caps())
        .build()
}

/// What every Songbird leaf supports: the group ciphersuite, basic credentials and the roles
/// extension (OpenMLS refuses a group-context extension some member does not support).
#[must_use]
pub fn caps() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[suite()]),
        Some(&[ExtensionType::Unknown(ROLES_EXTENSION)]),
        Some(&[ProposalType::SelfRemove]),
        Some(&[CredentialType::Basic]),
    )
}

/// A Songbird group's context extensions: `required_capabilities` naming the roles extension
/// (OpenMLS accepts a change to a custom extension only if it is required) and the roles.
#[must_use]
pub fn roles_extensions(roles: &Roles) -> Extensions<GroupContext> {
    context_extensions(roles, None)
}

/// [`roles_extensions`] plus, if given, the delivery service's `external_senders` (D-0075).
#[must_use]
pub fn context_extensions(
    roles: &Roles,
    external: Option<ExternalSendersExtension>,
) -> Extensions<GroupContext> {
    let mut v = vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(ROLES_EXTENSION)],
            &[ProposalType::SelfRemove],
            &[CredentialType::Basic],
        )),
        Extension::Unknown(ROLES_EXTENSION, UnknownExtension(roles.encode())),
    ];
    if let Some(e) = external {
        v.push(Extension::ExternalSenders(e));
    }
    Extensions::from_vec(v).unwrap()
}

/// A copy of `bundle` carrying the change-log entry `log`.
#[must_use]
pub fn with_log(bundle: &[u8], log: &[u8]) -> Vec<u8> {
    let b = Bundle::parse(bundle, usize::MAX).unwrap();
    Bundle {
        log: Some(log),
        ..b
    }
    .encode()
}

/// Splits a bundle into its Welcome.
#[must_use]
pub fn welcome_of(bundle: &[u8]) -> Vec<u8> {
    Bundle::parse(bundle, usize::MAX)
        .unwrap()
        .welcome
        .unwrap()
        .to_vec()
}

/// Server helper: start tracking a device's new group.
pub fn server_create(creator: &mut Device, dir: &Dir) -> Group {
    server_create_with(creator, dir, &Limits::default())
}

/// Server helper: start tracking a device's new group under `limits` (the delivery service's
/// external-sender key among them, D-0075: set `creator.ds_key` to the same key).
pub fn server_create_with(creator: &mut Device, dir: &Dir, limits: &Limits) -> Group {
    let (gi, tree) = creator.create();
    Group::create(GID, &creator.id, &gi, &tree, dir, limits).unwrap()
}

/// An invite link as apps hold it (PROTOCOL §6.8): a random handle and a 32-byte secret, from
/// which HKDF-SHA-256 (salt `songbird.v1/group-link`) derives `auth` (for the server), `info`
/// (the group's info key) and `proof` (the seed of the link's Ed25519 key, D-0076).
#[derive(Debug, Clone)]
pub struct LinkSecret {
    pub handle: [u8; 16],
    pub secret: [u8; 32],
}

impl LinkSecret {
    /// A fresh link.
    #[must_use]
    pub fn random() -> Self {
        let mut handle = [0u8; 16];
        let mut secret = [0u8; 32];
        aws_lc_rs::rand::fill(&mut handle).unwrap();
        aws_lc_rs::rand::fill(&mut secret).unwrap();
        Self { handle, secret }
    }

    fn derive(&self, info: &[u8]) -> [u8; 32] {
        use aws_lc_rs::hkdf;
        let mut out = [0u8; 32];
        hkdf::Salt::new(hkdf::HKDF_SHA256, b"songbird.v1/group-link")
            .extract(&self.secret)
            .expand(&[info], hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut out)
            .unwrap();
        out
    }

    /// What the server is shown (it keeps `SHA-256(auth)`).
    #[must_use]
    pub fn auth(&self) -> [u8; 32] {
        self.derive(b"auth")
    }

    fn key(&self) -> aws_lc_rs::signature::Ed25519KeyPair {
        aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(&self.derive(b"proof")).unwrap()
    }

    /// The link's proof key, which members publish in the roles extension.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        use aws_lc_rs::signature::KeyPair as _;
        self.key().public_key().as_ref().try_into().unwrap()
    }

    /// A joiner's proof (the external commit's authenticated data).
    #[must_use]
    pub fn prove(
        &self,
        group: &[u8; 16],
        epoch: u64,
        device: &DeviceId,
        leaf_key: &[u8],
    ) -> Vec<u8> {
        let content =
            songbird_groups::links::proof_content(group, epoch, &self.handle, device, leaf_key);
        let sig: [u8; 64] = self.key().sign(&content).as_ref().try_into().unwrap();
        songbird_groups::links::LinkProof::encode(&self.handle, &sig)
    }
}

/// The delivery service's signer as an OpenMLS client signer, for building proposals a
/// malicious server could send (tests of the members' rule). The private half is the seed.
#[must_use]
pub fn ds_client_signer(seed: &[u8; 32]) -> SignatureKeyPair {
    let public = songbird_groups::external::DsSigner::from_seed(seed)
        .unwrap()
        .public_key();
    SignatureKeyPair::from_raw(
        GROUP_CIPHERSUITE.signature_algorithm(),
        seed.to_vec(),
        public.to_vec(),
    )
}
