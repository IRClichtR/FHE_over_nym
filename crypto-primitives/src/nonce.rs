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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        println!("Testing nonce generation...");
        let mut generator = NonceGenerator::new();
        let nonce1 = generator.generate().expect("Failed to generate nonce");
        let nonce2 = generator.generate().expect("Failed to generate nonce");
        assert_ne!(nonce1.0, nonce2.0, "Generated nonces should be unique");
    }
}