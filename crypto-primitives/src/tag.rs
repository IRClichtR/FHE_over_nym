use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::nonce::Nonce;
use crate::types::{StealthInput, Tag, TagKey};

/// Generates a tag using HMAC with the provided tag key and nonce.
pub fn generate_tag(tag_key: TagKey, nonce: Nonce) -> Tag {
    let mut mac = Hmac::<Sha256>::new_from_slice(&tag_key.0).expect("HMAC can take key of any size");
    mac.update(&nonce.0);
    Tag(mac.finalize().into_bytes().into())
}

pub fn recognize_tag(tag_key: TagKey, nonce: Nonce, candidate: &Tag) -> bool {
    let generated = generate_tag(tag_key, nonce);
    generated == *candidate
}