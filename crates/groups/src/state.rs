//! One group's public MLS state as the delivery service stores it.
//!
//! OpenMLS keeps a `PublicGroup` through its `PublicStorageProvider` trait, as serde values.
//! [`GroupState`] holds them, already serialized, for exactly one group, so a group's state is one
//! value the registry can compare-and-set by epoch. It is tagged with the OpenMLS storage version
//! ([`STORAGE_VERSION`]); a newer OpenMLS with another version refuses old state instead of
//! misreading it, and fixtures of stored state are re-loaded by the tests on every upgrade.
//!
//! Why not the RFC 9420 wire forms (`GroupInfo` and the ratchet tree)? OpenMLS rebuilds a
//! `PublicGroup` from them only through `from_external`, which checks the lifetimes of leaves
//! that were never updated; a member idle for longer than its KeyPackage's lifetime (at most
//! 100 days, D-0051) would make the group impossible to load (D-0066).

use std::cell::RefCell;

use openmls_traits::public_storage::PublicStorageProvider;
use openmls_traits::storage::{CURRENT_VERSION, traits};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The OpenMLS storage version this state is written in.
pub const STORAGE_VERSION: u16 = CURRENT_VERSION;

/// Most proposals by reference a group may queue in one epoch.
pub const MAX_QUEUED_PROPOSALS: usize = 64;

/// Errors of the state store.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state encoding")]
    Encoding,
    #[error("state belongs to another group")]
    OtherGroup,
    #[error("too many queued proposals")]
    TooManyProposals,
}

/// The serialized parts of one group's public state.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateParts {
    pub version: u16,
    pub group_id: Vec<u8>,
    pub tree: Option<Vec<u8>>,
    pub context: Option<Vec<u8>>,
    pub confirmation_tag: Option<Vec<u8>>,
    pub interim_transcript_hash: Option<Vec<u8>>,
    /// `(proposal reference, queued proposal)`, in arrival order.
    pub proposals: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A store holding exactly one group's state; OpenMLS reads and writes it through
/// `PublicStorageProvider`.
#[derive(Debug)]
pub struct GroupState {
    parts: RefCell<StateParts>,
}

fn enc<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, StateError> {
    postcard::to_stdvec(value).map_err(|_| StateError::Encoding)
}

fn dec<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StateError> {
    postcard::from_bytes(bytes).map_err(|_| StateError::Encoding)
}

impl GroupState {
    /// An empty store for the group with this (serialized) ID.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            parts: RefCell::new(StateParts {
                version: STORAGE_VERSION,
                ..StateParts::default()
            }),
        }
    }

    /// A store loaded from its parts; refuses another storage version.
    pub fn from_parts(parts: StateParts) -> Result<Self, StateError> {
        if parts.version != STORAGE_VERSION {
            return Err(StateError::Encoding);
        }
        Ok(Self {
            parts: RefCell::new(parts),
        })
    }

    /// The parts, for writing back to the registry.
    #[must_use]
    pub fn parts(&self) -> StateParts {
        self.parts.borrow().clone()
    }

    /// The parts, consumed.
    #[must_use]
    pub fn into_parts(self) -> StateParts {
        self.parts.into_inner()
    }

    fn check_group<G: Serialize + ?Sized>(&self, group_id: &G) -> Result<(), StateError> {
        let id = enc(group_id)?;
        let mut parts = self.parts.borrow_mut();
        if parts.group_id.is_empty() {
            parts.group_id = id;
            Ok(())
        } else if parts.group_id == id {
            Ok(())
        } else {
            Err(StateError::OtherGroup)
        }
    }

    fn write<G: Serialize + ?Sized, V: Serialize + ?Sized>(
        &self,
        group_id: &G,
        value: &V,
        slot: impl FnOnce(&mut StateParts) -> &mut Option<Vec<u8>>,
    ) -> Result<(), StateError> {
        self.check_group(group_id)?;
        let bytes = enc(value)?;
        *slot(&mut self.parts.borrow_mut()) = Some(bytes);
        Ok(())
    }

    fn read<G: Serialize + ?Sized, V: DeserializeOwned>(
        &self,
        group_id: &G,
        slot: impl FnOnce(&StateParts) -> Option<&Vec<u8>>,
    ) -> Result<Option<V>, StateError> {
        self.check_group(group_id)?;
        let parts = self.parts.borrow();
        slot(&parts).map(|b| dec(b)).transpose()
    }

    fn clear<G: Serialize + ?Sized>(
        &self,
        group_id: &G,
        slot: impl FnOnce(&mut StateParts) -> &mut Option<Vec<u8>>,
    ) -> Result<(), StateError> {
        self.check_group(group_id)?;
        *slot(&mut self.parts.borrow_mut()) = None;
        Ok(())
    }
}

const V: u16 = CURRENT_VERSION;

impl PublicStorageProvider<V> for GroupState {
    type PublicError = StateError;

    fn write_tree<G: traits::GroupId<V>, T: traits::TreeSync<V>>(
        &self,
        group_id: &G,
        tree: &T,
    ) -> Result<(), StateError> {
        self.write(group_id, tree, |p| &mut p.tree)
    }

    fn write_interim_transcript_hash<G: traits::GroupId<V>, H: traits::InterimTranscriptHash<V>>(
        &self,
        group_id: &G,
        hash: &H,
    ) -> Result<(), StateError> {
        self.write(group_id, hash, |p| &mut p.interim_transcript_hash)
    }

    fn write_context<G: traits::GroupId<V>, C: traits::GroupContext<V>>(
        &self,
        group_id: &G,
        context: &C,
    ) -> Result<(), StateError> {
        self.write(group_id, context, |p| &mut p.context)
    }

    fn write_confirmation_tag<G: traits::GroupId<V>, C: traits::ConfirmationTag<V>>(
        &self,
        group_id: &G,
        tag: &C,
    ) -> Result<(), StateError> {
        self.write(group_id, tag, |p| &mut p.confirmation_tag)
    }

    fn queue_proposal<
        G: traits::GroupId<V>,
        R: traits::ProposalRef<V>,
        Q: traits::QueuedProposal<V>,
    >(
        &self,
        group_id: &G,
        proposal_ref: &R,
        proposal: &Q,
    ) -> Result<(), StateError> {
        self.check_group(group_id)?;
        let r = enc(proposal_ref)?;
        let q = enc(proposal)?;
        let mut parts = self.parts.borrow_mut();
        if let Some(slot) = parts.proposals.iter_mut().find(|(k, _)| *k == r) {
            slot.1 = q;
            return Ok(());
        }
        if parts.proposals.len() >= MAX_QUEUED_PROPOSALS {
            return Err(StateError::TooManyProposals);
        }
        parts.proposals.push((r, q));
        Ok(())
    }

    fn queued_proposals<
        G: traits::GroupId<V>,
        R: traits::ProposalRef<V>,
        Q: traits::QueuedProposal<V>,
    >(
        &self,
        group_id: &G,
    ) -> Result<Vec<(R, Q)>, StateError> {
        self.check_group(group_id)?;
        self.parts
            .borrow()
            .proposals
            .iter()
            .map(|(r, q)| Ok((dec(r)?, dec(q)?)))
            .collect()
    }

    fn tree<G: traits::GroupId<V>, T: traits::TreeSync<V>>(
        &self,
        group_id: &G,
    ) -> Result<Option<T>, StateError> {
        self.read(group_id, |p| p.tree.as_ref())
    }

    fn group_context<G: traits::GroupId<V>, C: traits::GroupContext<V>>(
        &self,
        group_id: &G,
    ) -> Result<Option<C>, StateError> {
        self.read(group_id, |p| p.context.as_ref())
    }

    fn interim_transcript_hash<G: traits::GroupId<V>, H: traits::InterimTranscriptHash<V>>(
        &self,
        group_id: &G,
    ) -> Result<Option<H>, StateError> {
        self.read(group_id, |p| p.interim_transcript_hash.as_ref())
    }

    fn confirmation_tag<G: traits::GroupId<V>, C: traits::ConfirmationTag<V>>(
        &self,
        group_id: &G,
    ) -> Result<Option<C>, StateError> {
        self.read(group_id, |p| p.confirmation_tag.as_ref())
    }

    fn delete_tree<G: traits::GroupId<V>>(&self, group_id: &G) -> Result<(), StateError> {
        self.clear(group_id, |p| &mut p.tree)
    }

    fn delete_confirmation_tag<G: traits::GroupId<V>>(
        &self,
        group_id: &G,
    ) -> Result<(), StateError> {
        self.clear(group_id, |p| &mut p.confirmation_tag)
    }

    fn delete_context<G: traits::GroupId<V>>(&self, group_id: &G) -> Result<(), StateError> {
        self.clear(group_id, |p| &mut p.context)
    }

    fn delete_interim_transcript_hash<G: traits::GroupId<V>>(
        &self,
        group_id: &G,
    ) -> Result<(), StateError> {
        self.clear(group_id, |p| &mut p.interim_transcript_hash)
    }

    fn remove_proposal<G: traits::GroupId<V>, R: traits::ProposalRef<V>>(
        &self,
        group_id: &G,
        proposal_ref: &R,
    ) -> Result<(), StateError> {
        self.check_group(group_id)?;
        let r = enc(proposal_ref)?;
        self.parts.borrow_mut().proposals.retain(|(k, _)| *k != r);
        Ok(())
    }

    fn clear_proposal_queue<G: traits::GroupId<V>, R: traits::ProposalRef<V>>(
        &self,
        group_id: &G,
    ) -> Result<(), StateError> {
        self.check_group(group_id)?;
        self.parts.borrow_mut().proposals.clear();
        Ok(())
    }
}
