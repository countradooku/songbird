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

use std::collections::BTreeMap;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use songbird_groups::crypto::GROUP_CIPHERSUITE;
use songbird_groups::wire::Bundle;
use songbird_groups::{Directory, Group};
use songbird_types::{AccountId, DeviceId};

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
        Self::with_key(
            other.id,
            other.account,
            OpenMlsRustCrypto::default(),
            other.raw_key.clone(),
        )
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
            raw_key,
        }
    }

    #[must_use]
    pub fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .build(
                GROUP_CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.cred.clone(),
            )
            .unwrap()
            .key_package()
            .clone()
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.group.as_ref().map_or(0, |g| g.epoch().as_u64())
    }

    /// Creates the group; returns `(GroupInfo, ratchet tree)` for the server.
    pub fn create(&mut self) -> (Vec<u8>, Vec<u8>) {
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config(),
            GroupId::from_slice(&GID),
            self.cred.clone(),
        )
        .unwrap();
        self.group = Some(group);
        (self.group_info(), self.tree())
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
        let (p, s) = (&self.provider, &self.signer);
        let g = self.group.as_mut().unwrap();
        let bundle = g
            .commit_builder()
            .propose_adds(adds)
            .propose_removals(removes.iter().map(|l| LeafNodeIndex::new(*l)))
            .force_self_update(update)
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
        let MlsMessageBodyIn::GroupInfo(gi) = MlsMessageIn::tls_deserialize_exact(group_info)
            .unwrap()
            .extract()
        else {
            panic!("not a GroupInfo")
        };
        let tree = RatchetTreeIn::tls_deserialize_exact(tree).unwrap();
        let (group, bundle) = MlsGroup::external_commit_builder()
            .with_ratchet_tree(tree)
            .with_config(config().join_config().clone())
            .build_group(&self.provider, gi, self.cred.clone())
            .unwrap()
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
        }
        .encode()
    }
}

#[must_use]
pub fn config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(GROUP_CIPHERSUITE)
        .max_past_epochs(1)
        .build()
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
    let (gi, tree) = creator.create();
    Group::create(GID, &creator.id, &gi, &tree, dir).unwrap()
}
