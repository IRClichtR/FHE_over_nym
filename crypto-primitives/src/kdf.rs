use zeroize::Zeroizing;
pub type ZeroizingVec<T> = Zeroizing<Vec<T>>;

use getrandom::{rand_core::TryRng, SysRng};
use crate::error::HKDFError;

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
    pub info: Vec<u8>,
}

impl HKDFParameters {    
    pub fn new(ikm: impl Into<Vec<u8>>, salt: Salt) -> Result<Self, HKDFError> {
        Ok(Self {
            ikm: ZeroizingVec::new(ikm.into()),
            salt,
            info: Vec::new(), // TODO: set info some versioned value to prevent cross-protocol key reuse
        })
    }
}

pub fn derive_sender_keys(params: HKDFParameters) -> SenderKeys {
    // internally:
    //   tag_key     = HKDF-SHA256(
    //                   ikm  = shared_secret || stealth_input,
    //                   salt = nonce,
    //                   info = b"fhe-relay-tag-v1"
    //                 )
    //   binding_key = HKDF-SHA256(
    //                   ikm  = shared_secret || stealth_input,
    //                   salt = nonce,
    //                   info = b"fhe-relay-binding-v1"
    //                 )
    unimplemented!()
}

pub fn derive_recipient_keys(params: HKDFParameters) -> RecipientKeys {
    // internally: identical HKDF call for tag_key only
    //             binding_key not derived — B never needs it
    unimplemented!()
}