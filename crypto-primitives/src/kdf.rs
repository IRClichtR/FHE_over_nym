use crate::error::KdfError;
use crate::nonce::Nonce;
use crate::types::{BindingKey, RecipientKeys, SenderKeys, StealthInput, TagKey};
use hkdf::Hkdf;
use sha2::Sha256;

const INFO_TAG: &[u8] = b"fhe-relay-tag-v1";
const INFO_BINDING: &[u8] = b"fhe-relay-binding-v1";

/// ikm = shared_secret || stealth_input  (stack-allocated [u8; 64])
/// tag_key     = HKDF-SHA256(ikm, salt=nonce, info=INFO_TAG)
/// binding_key = HKDF-SHA256(ikm, salt=nonce, info=INFO_BINDING)
pub fn derive_sender_keys(
    shared_secret: &[u8; 32],
    stealth_input: &StealthInput,
    nonce: &Nonce,
) -> Result<SenderKeys, KdfError> {
    let ikm = compute_ikm(shared_secret, stealth_input);
    let prk = extract(&ikm, &nonce.0);
    Ok(SenderKeys {
        tag_key: TagKey(expand(&prk, INFO_TAG)),
        binding_key: BindingKey(expand(&prk, INFO_BINDING)),
    })
}

/// ikm = shared_secret || stealth_input  (stack-allocated [u8; 64])
/// tag_key = HKDF-SHA256(ikm, salt=nonce, info=INFO_TAG)
/// binding_key is not derived — recipient never needs it
pub fn derive_recipient_keys(
    shared_secret: &[u8; 32],
    stealth_input: &StealthInput,
    nonce: &Nonce,
) -> Result<RecipientKeys, KdfError> {
    let ikm = compute_ikm(shared_secret, stealth_input);
    let prk = extract(&ikm, &nonce.0);
    Ok(RecipientKeys {
        tag_key: TagKey(expand(&prk, INFO_TAG)),
    })
}

fn compute_ikm(shared_secret: &[u8; 32], stealth_input: &StealthInput) -> [u8; 64] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(shared_secret);
    ikm[32..].copy_from_slice(&stealth_input.0);
    ikm
}

// nonce used as salt in HKDF, so it is not included in the ikm and can be
// passed directly to the extract function
fn extract(ikm: &[u8; 64], nonce: &[u8; 32]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(nonce.as_ref()), ikm);
    let mut prk_bytes = [0u8; 32];
    prk_bytes.copy_from_slice(&prk);
    prk_bytes
}

// Output is always 32 bytes (within HKDF-SHA256 max of 8160), and PRK is always
// 32 bytes (= SHA-256 output), so both from_prk and expand are infallible here.
fn expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    // Both operations are infallible: PRK is always 32 bytes (= SHA-256 output)
    // and OKM is always 32 bytes (well within the 8160-byte HKDF-SHA256 limit).
    let hkdf = Hkdf::<Sha256>::from_prk(prk).expect("key derivation failed");
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm).expect("key derivation failed");
    okm
}
