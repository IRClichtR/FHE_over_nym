// use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use tfhe::{ClientKey as FheSecretKey, PublicKey as FhePublicKey};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(PartialEq, Eq)]
pub struct Tag(pub [u8; 32]); // HMAC output onchain identifier
pub struct Nullifier(pub [u8; 32]); // HMAC(binding_key, tag), replay protection
pub struct TagKey(pub [u8; 32]); // derived, used for HMAC only
pub struct BindingKey(pub [u8; 32]); // derived, used only for proof nullifier
pub struct StealthInput(pub [u8; 32]); // X25519 output /!\ never store the shared secret, only use it for identification and zero it out immediately after use



// --- Keypairs Types ---
// -------------------------------

pub struct EphemeralKeyPair {
    pub secret: StaticSecret, // used once for encryption, then discarded
    pub public: PublicKey, // travels in envelope as ek
}

pub struct StaticKeyPair {
    pub sk_b: StaticSecret, // Stays with b, used for multiple encryptions, never travels
    pub pk_b: PublicKey, // given by other protocole to a
}

// --- Bundle Types ---
// -------------------------------

#[derive(Debug)]
pub struct SenderBundle {
    pub pk_b: PublicKey,
    pub fhe_pk: FhePublicKey, // The public key is shared by b in an out of scope phase
    pub shared_secret: [u8; 32], // The shared_secret for identification only
}

pub struct RecipientBundle {
    pub sk_b: StaticSecret,
    pub fhe_sk: FheSecretKey, // The secret key is shared by b in an out of scope phase
    pub shared_secret: [u8; 32], 
}

pub struct RelayerBundle {
    pub fhe_server_key: tfhe::ServerKey, // out of scope registration with relayer
}

// --- Derived Keys ---
// -------------------------------

pub struct SenderKeys {
    pub(crate) tag_key: TagKey,
    pub(crate) binding_key: BindingKey,
}

pub struct RecipientKeys {
    pub(crate) tag_key: TagKey,
}

// --- Proof types ---
// -------------------------------

pub struct BindingProof(Vec<u8>);
pub struct NullifierProof(HashSet<Nullifier>); // contains the nullifier and the proof that it was correctly derived from the tag and binding key

// Results

pub struct FheEvalResult(Vec<u8>); // The result of the FHE evaluation, encrypted under fhe_pk, travels in envelope as ct
