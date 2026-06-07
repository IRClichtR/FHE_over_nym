use tfhe::prelude::*;
use tfhe::{
    ClientKey as FheSecretKey, CompactCiphertextList, CompactPublicKey as FhePublicKey,
    ConfigBuilder, FheUint8, ServerKey as FheServerKey,
};

/// Byte-level FHE ciphertext: each plaintext byte independently encrypted as a `FheUint8`.
pub type FheCiphertext = Vec<FheUint8>;

/// Encrypts `plaintext` under `fhe_pk` into a compact batch ciphertext.
///
/// Called by the sender (A) — requires only the public key.
/// The resulting `CompactCiphertextList` must be expanded server-side via `expand`.
pub fn encrypt_compact(plaintext: &[u8], fhe_pk: &FhePublicKey) -> CompactCiphertextList {
    let mut builder = CompactCiphertextList::builder(fhe_pk);
    for &byte in plaintext {
        builder.push(byte);
    }
    builder.build()
}

/// Expands a compact ciphertext into an evaluable `FheCiphertext`.
///
/// Called by the server/relayer — requires `server_key` for the key-switching step.
/// `len` must match the number of bytes originally encrypted.
pub fn expand(
    compact: &CompactCiphertextList,
    server_key: &FheServerKey,
    len: usize,
) -> FheCiphertext {
    tfhe::set_server_key(server_key.clone());
    let expander = compact.expand().unwrap();
    (0..len).map(|i| expander.get::<FheUint8>(i).unwrap().unwrap()).collect()
}

/// Decrypts `ciphertext` byte-by-byte; only the holder of `fhe_sk` can call this.
pub fn decrypt(ciphertext: &FheCiphertext, fhe_sk: &FheSecretKey) -> Vec<u8> {
    ciphertext.iter().map(|ct| ct.decrypt(fhe_sk)).collect()
}

/// Bundles the three TFHE keys produced at setup time.
///
/// Key distribution across protocol roles:
/// - `public_key`  → sender  (compact batch encryption)
/// - `secret_key`  → recipient (decryption)
/// - `server_key`  → relayer  (expand + homomorphic evaluation)
pub struct FHEKeys {
    pub public_key: FhePublicKey,
    pub secret_key: FheSecretKey,
    pub server_key: FheServerKey,
}

impl FHEKeys {
    pub fn new() -> Self {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        let public_key = FhePublicKey::new(&client_key);
        FHEKeys { public_key, secret_key: client_key, server_key }
    }
}

/// Applies a homomorphic computation server-side.
/// Minimal example: adds 1 to every byte in the ciphertext.
pub fn evaluate(ciphertext: &FheCiphertext, server_key: &FheServerKey) -> FheCiphertext {
    tfhe::set_server_key(server_key.clone());
    ciphertext.iter().map(|ct| ct + 1u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_expand_decrypt() {
        let keys = FHEKeys::new();
        let plaintext = b"Hello, FHE!";
        let compact = encrypt_compact(plaintext, &keys.public_key);
        let ciphertext = expand(&compact, &keys.server_key, plaintext.len());
        let decrypted = decrypt(&ciphertext, &keys.secret_key);
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_evaluate() {
        let keys = FHEKeys::new();
        let plaintext = b"Hello, FHE!";
        let compact = encrypt_compact(plaintext, &keys.public_key);
        let ciphertext = expand(&compact, &keys.server_key, plaintext.len());
        let evaluated_ciphertext = evaluate(&ciphertext, &keys.server_key);
        let decrypted = decrypt(&evaluated_ciphertext, &keys.secret_key);
        let expected: Vec<u8> = plaintext.iter().map(|&b| b + 1).collect();
        assert_eq!(expected, decrypted);
    }
}
