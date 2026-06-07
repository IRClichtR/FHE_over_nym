use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("codec error: {0}")]
    Codec(#[from] postcard::Error),
    #[error("envelope kind mismatch: expected {expected}, found {found}")]
    KindMismatch {
        expected: &'static str,
        found: &'static str,
    },
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("initialization error: {0}")]
    InitializationError(String),
    #[error("mixnet error: {0}")]
    Mixnet(#[from] nym_sdk::Error),
    #[error("envelope error: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("mixnet channel closed")]
    Disconnected,
    #[error("received message carried no anonymous sender tag (was it sent without a SURB?)")]
    MissingSenderTag,
}
