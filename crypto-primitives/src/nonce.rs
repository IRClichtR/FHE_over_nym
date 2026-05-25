use crate::error::NonceError;
use getrandom::{rand_core::TryRng, SysRng};
use zeroize::Zeroize;

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

    pub fn generate(&mut self) -> Result<Nonce, NonceError> {
        let mut bytes = [0u8; 32];
        // RNG error detail is intentionally discarded — callers get a generic failure.
        self.rng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| NonceError::GenerationFailed)?;
        Ok(Nonce(bytes))
    }
}
