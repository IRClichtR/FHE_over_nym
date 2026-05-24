
use zeroize::Zeroizing;
pub type ZeroizingVec<T> = Zeroizing<Vec<T>>;

use getrandom::{rand_core::TryRng, SysRng};
use error::HKDFError;
pub mod error;

pub struct Salt(pub(crate) [u8; 32]);

impl Drop for Salt {
    fn drop(&mut self) {
        // Zero out the salt when it goes out of scope
        self.0.iter_mut().for_each(|byte| *byte = 0);
    }
}

pub struct SaltGenerator {
    rng: SysRng,
}

impl SaltGenerator {
    pub fn new() -> SaltGenerator {
        Self {rng: SysRng}
    }

    /// Generates a new salt of 32 bytes.
    /// The salt is automatically zeroed out when it goes out of scope.
    /// ensures that the salt is not accidentally reused or leaked.
    pub fn generate_salt(&mut self) -> Result<Salt, HKDFError> {
        let mut salt = [0u8; 32];
        // Fill the salt with pseudorandom bytes
        self.rng.try_fill_bytes(&mut salt)
            .map_err(|e| HKDFError::SaltGenerationError(e.to_string()))?;
        
        Ok(Salt(salt))
    }
}

pub struct HKDFParameters {
    pub ikm: ZeroizingVec<u8>,
    pub salt: Salt,
}

impl HKDFParameters {    
    pub fn new(ikm: impl Into<Vec<u8>>, salt: Salt) -> Result<Self, HKDFError> {
        Ok(Self {
            ikm: ZeroizingVec::new(ikm.into()),
            salt,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

}
