use serde::{Deserialize, Serialize};

use crate::error::EnvelopeError;

// Tagged union: serializing this (and only this) puts the variant discriminant on
// the wire. postcard tags by position — treat this list as append-only.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Envelope {
    Client(ClientEnvelope),
    Relayer(RelayerEnvelope),
    Dispatch(DispatchEnvelope),
    Verified(VerifiedNotification),
    Received(ReceivedNotification),
    Delivery(DeliveryEnvelope),
}

impl Envelope {
    // Human-readable kind label, used in mismatch errors and tracing telemetry.
    pub fn kind(&self) -> &'static str {
        match self {
            Envelope::Client(_)   => "Client",
            Envelope::Relayer(_)  => "Relayer",
            Envelope::Dispatch(_) => "Dispatch",
            Envelope::Verified(_) => "Verified",
            Envelope::Received(_) => "Received",
            Envelope::Delivery(_) => "Delivery",
        }
    }
}

// Ties a concrete envelope struct to its place in the tagged union.
// into_envelope wraps it for sending; from_envelope pulls it back out on receive,
// returning KindMismatch if the wire carried a different variant.
pub trait WireEnvelope: Sized {
    const KIND: &'static str;
    fn into_envelope(self) -> Envelope;
    fn from_envelope(env: Envelope) -> Result<Self, EnvelopeError>;
}

macro_rules! impl_wire_envelope {
    ($ty:ty, $variant:ident, $name:literal) => {
        impl WireEnvelope for $ty {
            const KIND: &'static str = $name;
            fn into_envelope(self) -> Envelope {
                Envelope::$variant(self)
            }
            fn from_envelope(env: Envelope) -> Result<Self, EnvelopeError> {
                match env {
                    Envelope::$variant(inner) => Ok(inner),
                    other => Err(EnvelopeError::KindMismatch {
                        expected: $name,
                        found: other.kind(),
                    }),
                }
            }
        }
    };
}

impl_wire_envelope!(ClientEnvelope,       Client,   "Client");
impl_wire_envelope!(RelayerEnvelope,      Relayer,  "Relayer");
impl_wire_envelope!(DispatchEnvelope,     Dispatch, "Dispatch");
impl_wire_envelope!(VerifiedNotification, Verified, "Verified");
impl_wire_envelope!(ReceivedNotification, Received, "Received");
impl_wire_envelope!(DeliveryEnvelope,     Delivery, "Delivery");

// Codec that always goes through the tagged union.
// encode wraps a concrete type into Envelope then serializes;
// decode returns the tagged union so callers can route on kind() before extracting.
#[derive(Clone, Default)]
pub struct EnvelopeCodec;

impl EnvelopeCodec {
    pub fn new() -> Self {
        EnvelopeCodec
    }

    // Wrap a concrete envelope into the tagged union and serialize it.
    pub fn encode<E: WireEnvelope>(&self, env: E) -> Result<Vec<u8>, EnvelopeError> {
        Ok(postcard::to_allocvec(&env.into_envelope())?)
    }

    // Serialize an already-built Envelope (used by the surb transport layer
    // which works with the tagged union directly).
    pub fn encode_envelope(&self, env: &Envelope) -> Result<Vec<u8>, EnvelopeError> {
        Ok(postcard::to_allocvec(env)?)
    }

    // Decode bytes into the tagged union; the receive loop then matches on kind()
    // to route, or calls WireEnvelope::from_envelope to extract a typed value.
    pub fn decode(&self, bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

// ── Envelope structs ─────────────────────────────────────────────────────────

// A → mailbox
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientEnvelope {
    pub nonce:          [u8; 32], // per-message random nonce
    pub ek:             [u8; 32], // ephemeral encryption key (KEM encapsulation)
    pub tag:            [u8; 32], // message correlation tag
    pub fhe_ciphertext: Vec<u8>,  // FHE-encrypted payload
    pub binding_proof:  Vec<u8>,  // ZK proof binding this message to the sender's key
    pub nullifier:      [u8; 32], // credential nullifier, prevents replay
    pub fhe_pk:         Vec<u8>,  // sender's FHE public key (needed to compute the FHE result)
}

// mailbox → relayer
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayerEnvelope {
    pub tag:            [u8; 32], // correlation tag forwarded from the client message
    pub binding_proof:  Vec<u8>,  // forwarded binding proof for the relayer to verify
    pub nullifier:      [u8; 32], // forwarded nullifier for deduplication
    pub fhe_pk:         Vec<u8>,  // forwarded FHE public key
    pub fhe_ciphertext: Vec<u8>,  // forwarded FHE ciphertext
}

// mailbox → dispatcher (triggered after Verified)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchEnvelope {
    pub nonce:          [u8; 32], // original per-message nonce (needed for decryption)
    pub ek:             [u8; 32], // original ephemeral key
    pub tag:            [u8; 32], // correlation tag
    pub fhe_ciphertext: Vec<u8>,  // FHE ciphertext to be dispatched
}

// relayer → mailbox (notification)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifiedNotification {
    pub tag: [u8; 32], // tag of the message the relayer has verified
}

// dispatcher → mailbox (notification)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceivedNotification {
    pub tag: [u8; 32], // tag of the message the dispatcher has delivered
}

// dispatcher → B
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeliveryEnvelope {
    pub nonce:          [u8; 32], // per-message nonce for final decryption by B
    pub ek:             [u8; 32], // ephemeral key for final decryption by B
    pub tag:            [u8; 32], // correlation tag
    pub fhe_ciphertext: Vec<u8>,  // FHE-encrypted payload addressed to B
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_verified() -> VerifiedNotification {
        VerifiedNotification { tag: [0xAB; 32] }
    }

    #[test]
    fn round_trips_through_the_tagged_union() {
        let codec = EnvelopeCodec::new();
        let original = sample_verified();
        let bytes = codec.encode(original.clone()).unwrap();
        let env = codec.decode(&bytes).unwrap();
        assert_eq!(env.kind(), "Verified");
        let back = VerifiedNotification::from_envelope(env).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn verified_and_received_are_distinguishable() {
        // These two structs are byte-identical as bare values. Untagged they would
        // cross-decode silently; going through Envelope, asking for the wrong one
        // is a clean KindMismatch error.
        let codec = EnvelopeCodec::new();
        let bytes = codec.encode(sample_verified()).unwrap();
        let env = codec.decode(&bytes).unwrap();

        assert!(VerifiedNotification::from_envelope(env.clone()).is_ok());

        let err = ReceivedNotification::from_envelope(env).unwrap_err();
        match err {
            EnvelopeError::KindMismatch { expected, found } => {
                assert_eq!(expected, "Received");
                assert_eq!(found, "Verified");
            }
            other => panic!("expected KindMismatch, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_and_delivery_are_distinguishable() {
        // DispatchEnvelope and DeliveryEnvelope have the same field layout.
        let codec = EnvelopeCodec::new();
        let d = DispatchEnvelope {
            nonce: [1; 32],
            ek: [2; 32],
            tag: [3; 32],
            fhe_ciphertext: vec![9, 9, 9],
        };
        let bytes = codec.encode(d.clone()).unwrap();
        let env = codec.decode(&bytes).unwrap();
        assert_eq!(env.kind(), "Dispatch");
        assert!(DeliveryEnvelope::from_envelope(env.clone()).is_err());
        assert_eq!(DispatchEnvelope::from_envelope(env).unwrap(), d);
    }
}
