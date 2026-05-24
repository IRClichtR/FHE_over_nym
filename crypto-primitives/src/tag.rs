use crate::types::{Nonce, Tag, TagKey};

pub fn generate_tag(tag_key: TagKey, nonce: Nonce) -> Tag {
    // Generate a tag by computing an HMAC using the tag key and nonce as input
    unimplemented!()
}

pub fn recognize_tag(tag_key: TagKey, nonce: Nonce,candidate: &Tag) -> bool {
    // recompute HMAC with the tag key and nonce, and compare it to the candidate tag
    unimplemented!()
}