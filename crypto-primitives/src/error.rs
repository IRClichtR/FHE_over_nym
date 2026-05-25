use thiserror::Error;

/// Errors from nonce generation (`nonce.rs`).
/// Message is intentionally generic — no RNG internals are exposed.
#[derive(Debug, Error)]
pub enum NonceError {
    #[error("nonce generation failed")]
    GenerationFailed,
}

/// Errors from HKDF key derivation (`kdf.rs`).
/// A single opaque variant: callers cannot influence the KDF internals,
/// so distinguishing sub-causes would only help an attacker profile the system.
#[derive(Debug, Error)]
pub enum KdfError {
    #[error("key derivation failed")]
    DerivationFailed,
}

/// Errors from tag computation (`tag.rs`).
/// The HMAC key is always 32 bytes (= TagKey), so this variant is
/// unreachable in practice but must be handled for correctness.
#[derive(Debug, Error)]
pub enum TagError {
    #[error("tag computation failed")]
    ComputationFailed,
}

/// Map HMAC key-length errors to TagError without leaking the invalid length.
impl From<hmac::digest::InvalidLength> for TagError {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        TagError::ComputationFailed
    }
}

/// Errors from proof generation and verification (`proof.rs`).
///
/// `Invalid` and `Replayed` are intentionally distinct: callers must handle
/// replay differently from a malformed proof (e.g. drop vs. blacklist sender).
/// Internal computation failures collapse to `ComputationFailed` — no detail.
#[derive(Debug, Error)]
pub enum ProofError {
    /// Proof failed structural or content validation.
    /// The specific check that failed is not revealed.
    #[error("invalid proof")]
    Invalid,
    /// The nullifier has already been spent; this is a replay attempt.
    #[error("nullifier already spent")]
    Replayed,
    /// HMAC key initialisation failed (unreachable with 32-byte keys).
    #[error("proof computation failed")]
    ComputationFailed,
}

/// Map HMAC key-length errors to ProofError without leaking the invalid length.
impl From<hmac::digest::InvalidLength> for ProofError {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        ProofError::ComputationFailed
    }
}
