use tfhe::prelude::*;
use tfhe::{ClientKey as FheSecretKey, ConfigBuilder, FheUint8, PublicKey as FhePublicKey, ServerKey as FheServerKey};

/// Byte-level FHE ciphertext: each plaintext byte is independently encrypted as a `FheUint8`.
/// The vector length equals the plaintext length, so byte positions are preserved across
/// homomorphic operations.
pub type FheCiphertext = Vec<FheUint8>;

/// Encrypts `plaintext` byte-by-byte under `fhe_pk`.
///
/// The public key allows anyone (e.g. the sender) to encrypt without holding the secret key.
/// The resulting `FheCiphertext` can be evaluated homomorphically by the relayer and decrypted
/// only by the holder of the corresponding `FheSecretKey`.
pub fn encrypt(plaintext: &[u8], fhe_pk: &FhePublicKey) -> FheCiphertext {
    // TODO: optimize replace by Compact change of responsabilities Client A encrypt compact then relayer expands to FheUint8 for evaluation, then compacts again before sending to B for decryption
    plaintext
        .iter()
        .map(|&byte| FheUint8::encrypt(byte, fhe_pk))
        .collect()
}

/// Decrypts `ciphertext` byte-by-byte using `fhe_sk`, returning the original plaintext.
///
/// Only the recipient holding the secret key can call this; the relayer never sees plaintext.
pub fn decrypt(ciphertext: &FheCiphertext, fhe_sk: &FheSecretKey) -> Vec<u8> {
    ciphertext.iter().map(|ct| ct.decrypt(fhe_sk)).collect()
}

/// Bundles the three TFHE keys produced at setup time.
///
/// Key distribution across protocol roles:
/// - `public_key`  → sender  (encrypts the payload)
/// - `secret_key`  → recipient (decrypts the result)
/// - `server_key`  → relayer  (evaluates the circuit homomorphically, never decrypts)
///
/// In practice these keys are exchanged out-of-band before any message is sent.
pub struct FHEKeys {
    pub public_key: FhePublicKey,
    pub secret_key: FheSecretKey,
    pub server_key: FheServerKey,
}

impl FHEKeys {
    /// Generates a fresh TFHE key set using the default parameter set.
    ///
    /// `tfhe::generate_keys` returns a `(ClientKey, ServerKey)` pair; the `PublicKey`
    /// is then derived from the `ClientKey` so that the sender can encrypt without it.
    pub fn new() -> Self {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        let public_key = FhePublicKey::new(&client_key);
        FHEKeys { public_key, secret_key: client_key, server_key }
    }
}

/// Applies a homomorphic computation to `ciphertext` on the relay side.
///
/// `server_key` is set as the active thread-local key before the circuit runs;
/// TFHE integer operations implicitly use whichever key was last set on the thread.
/// Minimal example: homomorphically adds 1 to each byte in the ciphertext, returning a new ciphertext.
pub fn evaluate(ciphertext: &FheCiphertext, server_key: &FheServerKey) -> FheCiphertext {
    tfhe::set_server_key(server_key.clone());
    ciphertext
        .iter()
        .map(|ct| ct + 1u8)
        .collect()
}
