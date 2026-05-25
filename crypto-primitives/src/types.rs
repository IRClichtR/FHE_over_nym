// use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use tfhe::{ClientKey as FheSecretKey, CompactPublicKey as FhePublicKey};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(PartialEq, Eq)]
#[derive(Debug)]
pub struct Tag(pub [u8; 32]); // HMAC output onchain identifier
#[derive(PartialEq, Eq, Hash)]
pub struct Nullifier(pub [u8; 32]); // HMAC(binding_key, tag), replay protection
#[derive(Debug, PartialEq, Eq)]
pub struct TagKey(pub [u8; 32]); // derived, used for HMAC only
#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct SenderKeys {
    pub(crate) tag_key: TagKey,
    pub(crate) binding_key: BindingKey,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RecipientKeys {
    pub(crate) tag_key: TagKey,
}

// --- Proof types ---
// -------------------------------

pub struct BindingProof(pub(crate) Vec<u8>);
/// Set of spent nullifiers maintained by the relay for replay protection.
pub struct NullifierProof(pub(crate) HashSet<Nullifier>);

impl NullifierProof {
    /// Creates an empty spent-nullifier set.
    pub fn new() -> Self {
        NullifierProof(HashSet::new())
    }

    /// Marks a nullifier as spent. Returns false if it was already present (replay).
    pub fn insert(&mut self, nullifier: Nullifier) -> bool {
        self.0.insert(nullifier)
    }

    /// Returns true if the nullifier has already been spent.
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.0.contains(nullifier)
    }
}

// Results

pub struct FheEvalResult(Vec<u8>); // The result of the FHE evaluation, encrypted under fhe_pk, travels in envelope as ct
