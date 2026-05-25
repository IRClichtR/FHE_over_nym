use getrandom::{rand_core::TryRng, SysRng};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum NonceGenerationError {
    #[error("nonce generation failed: {0}")]
    RngFailure(String),
}

pub struct Nonce(pub(crate) [u8; 32]);

impl Drop for Nonce {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct NonceGenerator {
    rng: SysRng,
}

impl NonceGenerator {
    pub fn new() -> Self {
        Self { rng: SysRng }
    }

    pub fn generate(&mut self) -> Result<Nonce, NonceGenerationError> {
        let mut bytes = [0u8; 32];
        self.rng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| NonceGenerationError::RngFailure(e.to_string()))?;
        Ok(Nonce(bytes))
    }
}
