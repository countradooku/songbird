//! Proofs on the wire: akd's own protobuf encodings (`akd::proto`), so any akd client library
//! can read them.

use akd::proto::specs::types as pb;
use akd::{AppendOnlyProof, HistoryProof, LookupProof};
use protobuf::Message as _;

/// A proof did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed proof")]
pub struct ProofError;

/// Largest proof accepted for decoding.
pub const MAX_PROOF: usize = 4 << 20;

fn parse<M: protobuf::Message>(b: &[u8]) -> Result<M, ProofError> {
    if b.len() > MAX_PROOF {
        return Err(ProofError);
    }
    M::parse_from_bytes(b).map_err(|_| ProofError)
}

/// A lookup proof's bytes.
///
/// # Errors
/// [`ProofError`] (protobuf refused to encode).
pub fn encode_lookup(p: &LookupProof) -> Result<Vec<u8>, ProofError> {
    pb::LookupProof::from(p)
        .write_to_bytes()
        .map_err(|_| ProofError)
}

/// A lookup proof from its bytes.
///
/// # Errors
/// [`ProofError`].
pub fn decode_lookup(b: &[u8]) -> Result<LookupProof, ProofError> {
    LookupProof::try_from(&parse::<pb::LookupProof>(b)?).map_err(|_| ProofError)
}

/// A history proof's bytes.
///
/// # Errors
/// [`ProofError`].
pub fn encode_history(p: &HistoryProof) -> Result<Vec<u8>, ProofError> {
    pb::HistoryProof::from(p)
        .write_to_bytes()
        .map_err(|_| ProofError)
}

/// A history proof from its bytes.
///
/// # Errors
/// [`ProofError`].
pub fn decode_history(b: &[u8]) -> Result<HistoryProof, ProofError> {
    HistoryProof::try_from(&parse::<pb::HistoryProof>(b)?).map_err(|_| ProofError)
}

/// An append-only (audit) proof's bytes.
///
/// # Errors
/// [`ProofError`].
pub fn encode_audit(p: &AppendOnlyProof) -> Result<Vec<u8>, ProofError> {
    pb::AppendOnlyProof::from(p)
        .write_to_bytes()
        .map_err(|_| ProofError)
}

/// An append-only proof from its bytes.
///
/// # Errors
/// [`ProofError`].
pub fn decode_audit(b: &[u8]) -> Result<AppendOnlyProof, ProofError> {
    AppendOnlyProof::try_from(&parse::<pb::AppendOnlyProof>(b)?).map_err(|_| ProofError)
}
