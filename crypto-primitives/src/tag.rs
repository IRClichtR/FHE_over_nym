use crate::error::TagError;
use crate::types::{Tag, TagKey};
use crate::nonce::Nonce;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Generates a tag: HMAC-SHA256(key=tag_key, msg=nonce).
///
/// The tag is the on-chain identifier for the message.
/// The nonce is consumed and zeroized after the HMAC update.
pub fn generate_tag(tag_key: TagKey, nonce: Nonce) -> Result<Tag, TagError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&tag_key.0)?;
    mac.update(&nonce.0);
    Ok(Tag(mac.finalize().into_bytes().into()))
}

/// Returns true if the candidate tag matches the one derived from tag_key and nonce.
pub fn recognize_tag(tag_key: TagKey, nonce: Nonce, candidate: &Tag) -> Result<bool, TagError> {
    let generated = generate_tag(tag_key, nonce)?;
    Ok(generated == *candidate)
}
