use thiserror::Error;

#[derive(Debug, Error)]
pub enum KdfError {
    #[error("IKM must not be empty")]
    EmptyIKM,
    #[error("requested output length {requested} exceeds max {max}")]
    OutputLen { requested: usize, max: usize },
    #[error("expand failure: {0}")]
    ExpandFailure(String),
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    #[error("Nullifier already used")]
    ReplayedNullifier,
}