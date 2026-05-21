use thiserror::Error;

#[derive(Debug, Error)]
pub enum HKDFError {
    #[error("IKM must not be empty")]
    EmptyIKM,
    #[error("requested output length {requested} excedes max {max}")]
    OutputLen { requested: usize, max: usize },
    #[error("expand failure: {0}")]
    ExpandFailure(String),
}