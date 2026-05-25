use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::error::ProofError;
use crate::nonce::Nonce;
use crate::types::{BindingKey, BindingProof, Nullifier, NullifierProof, StealthInput, Tag};

/// Derives the nullifier: HMAC-SHA256(key=binding_key, msg=tag).
///
/// The nullifier is the on-chain identifier that marks a tag as spent.
/// It reveals nothing about the binding key or the underlying ECDH material,
/// but is deterministic: the same (binding_key, tag) pair always yields the same nullifier.
fn generate_nullifier(binding_key: &BindingKey, tag: &Tag) -> Result<Nullifier, ProofError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&binding_key.0)?;
    mac.update(&tag.0);
    Ok(Nullifier(mac.finalize().into_bytes().into()))
}

/// Generates the binding proof that the sender attaches to their message.
///
/// The proof is a 64-byte blob:
///   `[0..32]`  nullifier  = HMAC(binding_key, tag)
///   `[32..64]` commitment = HMAC(binding_key, nonce || shared_secret || stealth_input)
///
/// The nullifier uniquely identifies the spend on-chain. The commitment binds the proof
/// to the exact session key material (nonce, ECDH output, stealth input) so it cannot
/// be replayed across different sessions even if the same tag were reused.
pub fn generate_proof(
    tag: &Tag,
    shared_secret: &[u8; 32],
    stealth_input: &StealthInput,
    nonce: Nonce,             // consumed so it is zeroized after use
    binding_key: &BindingKey,
) -> Result<BindingProof, ProofError> {
    let nullifier = generate_nullifier(binding_key, tag)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(&binding_key.0)?;
    mac.update(&nonce.0);
    mac.update(shared_secret);
    mac.update(&stealth_input.0);
    let commitment: [u8; 32] = mac.finalize().into_bytes().into();
    // nonce is dropped (zeroized) here

    let mut proof_bytes = Vec::with_capacity(64);
    proof_bytes.extend_from_slice(&nullifier.0);
    proof_bytes.extend_from_slice(&commitment);
    Ok(BindingProof(proof_bytes))
}

/// Verifies a binding proof and checks the nullifier has not been spent.
///
/// Two checks are performed in order:
/// 1. **Structure**: the proof must be exactly 64 bytes and its embedded nullifier
///    (first 32 bytes) must match the provided `nullifier`.
/// 2. **Replay protection**: the nullifier must not appear in `seen` (the relay's
///    spent-nullifier set). If it does, the message is a replay and is rejected.
///
/// Note: the commitment (bytes 32–64) is not re-derivable here because the relay
/// does not hold the binding key. Full cryptographic binding verification requires
/// a zero-knowledge proof layer on top of this primitive.
pub fn verify_proof(
    proof: &BindingProof,
    nullifier: &Nullifier,
    seen: &NullifierProof,
) -> Result<(), ProofError> {
    if proof.0.len() != 64 || proof.0[..32] != nullifier.0 {
        return Err(ProofError::Invalid);
    }

    if seen.0.contains(nullifier) {
        return Err(ProofError::Replayed);
    }

    Ok(())
}
