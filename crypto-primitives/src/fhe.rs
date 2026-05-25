use tfhe::prelude::*;
use tfhe::{ClientKey as FheSecretKey, ConfigBuilder, FheUint8, PublicKey as FhePublicKey, ServerKey as FheServerKey};

// Byte-level FHE ciphertext: each plaintext byte becomes one FheUint8 ciphertext.
pub type FheCiphertext = Vec<FheUint8>;

pub fn encrypt(plaintext: &[u8], fhe_pk: &FhePublicKey) -> FheCiphertext {
    plaintext
        .iter()
        .map(|&byte| FheUint8::encrypt(byte, fhe_pk))
        .collect()
}

pub fn decrypt(ciphertext: &FheCiphertext, fhe_sk: &FheSecretKey) -> Vec<u8> {
    ciphertext.iter().map(|ct| ct.decrypt(fhe_sk)).collect()
}

pub struct FHEKeys {
    pub public_key: FhePublicKey,   // Used for encryption by the sender
    pub secret_key: FheSecretKey,   // Used for decryption by the recipient
    pub server_key: FheServerKey,   // Used for homomorphic evaluation by the relayer
}

impl FHEKeys {
    pub fn new() -> Self {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = tfhe::generate_keys(config);
        let public_key = FhePublicKey::new(&client_key);
        FHEKeys { public_key, secret_key: client_key, server_key }
    }
}

// Applies a homomorphic computation on the relay side using the server key.
pub fn evaluate(ciphertext: &FheCiphertext, server_key: &FheServerKey) -> FheCiphertext {
    tfhe::set_server_key(server_key.clone());
    // Identity placeholder — replace with actual homomorphic circuit when defined.
    ciphertext.clone()
}