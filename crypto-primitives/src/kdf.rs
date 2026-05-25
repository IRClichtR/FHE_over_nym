use crate::error::KdfError;
use crate::nonce::Nonce;
use crate::types::{RecipientKeys, SenderKeys, StealthInput};

const INFO_TAG: &[u8] = b"fhe-relay-tag-v1";
const INFO_BINDING: &[u8] = b"fhe-relay-binding-v1";

pub fn derive_sender_keys(
    shared_secret: &[u8; 32],
    stealth_input: &StealthInput,
    nonce: &Nonce,
) -> Result<SenderKeys, KdfError> {
    // ikm = shared_secret || stealth_input  (stack-allocated [u8; 64])
    // tag_key     = HKDF-SHA256(ikm, salt=nonce, info=INFO_TAG)
    // binding_key = HKDF-SHA256(ikm, salt=nonce, info=INFO_BINDING)
    unimplemented!()
}

pub fn derive_recipient_keys(
    shared_secret: &[u8; 32],
    stealth_input: &StealthInput,
    nonce: &Nonce,
) -> Result<RecipientKeys, KdfError> {
    // ikm = shared_secret || stealth_input  (stack-allocated [u8; 64])
    // tag_key = HKDF-SHA256(ikm, salt=nonce, info=INFO_TAG)
    // binding_key is not derived — recipient never needs it
    unimplemented!()
}
