use serde::{Serialize, Deserialize, de::DeserializeOwned};

pub struct EnvelopeCodec;

impl EnvelopeCodec {
    pub fn new() -> Self {
        EnvelopeCodec
    }

    pub fn serialize_envelope<T: Serialize>(&self, envelope: &T) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(envelope)
    }

    pub fn deserialize_envelope<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Envelope {
    Client(ClientEnvelope),
    Relayer(RelayerEnvelope),
    Dispatch(DispatchEnvelope),
    VerifiedNotification(VerifiedNotification),
    ReceivedNotification(ReceivedNotification),
    Delivery(DeliveryEnvelope),
}

// A → mailbox
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientEnvelope {
    pub nonce:          [u8; 32],
    pub ek:             [u8; 32],
    pub tag:            [u8; 32],
    pub fhe_ciphertext: Vec<u8>,
    pub binding_proof:  Vec<u8>,
    pub nullifier:      [u8; 32],
    pub fhe_pk:         Vec<u8>,
}

// mailbox → relayer
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayerEnvelope {
    pub tag:            [u8; 32],
    pub binding_proof:  Vec<u8>,
    pub nullifier:      [u8; 32],
    pub fhe_pk:         Vec<u8>,
    pub fhe_ciphertext: Vec<u8>,
}

// mailbox → dispatcher (triggered after Verified)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchEnvelope {
    pub nonce:          [u8; 32],
    pub ek:             [u8; 32],
    pub tag:            [u8; 32],
    pub fhe_ciphertext: Vec<u8>,
}

// relayer → mailbox (notification)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifiedNotification {
    pub tag: [u8; 32],
}

// dispatcher → mailbox (notification)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceivedNotification {
    pub tag: [u8; 32],
}

// dispatcher → B
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeliveryEnvelope {
    pub nonce:          [u8; 32],
    pub ek:             [u8; 32],
    pub tag:            [u8; 32],
    pub fhe_ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_envelope_serialization() {
        let original = ClientEnvelope {
            nonce: [0u8; 32],
            ek: [1u8; 32],
            tag: [2u8; 32],
            fhe_ciphertext: vec![3, 4, 5],
            binding_proof: vec![6, 7, 8],
            nullifier: [9u8; 32],
            fhe_pk: vec![10, 11, 12],
        };
        let codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original).unwrap();
        let deserialized: ClientEnvelope = codec.deserialize_envelope(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_relayer_envelope_serialization() {
        let original = RelayerEnvelope {
            tag: [2u8; 32],
            binding_proof: vec![6, 7, 8],
            nullifier: [9u8; 32],
            fhe_pk: vec![10, 11, 12],
            fhe_ciphertext: vec![3, 4, 5],
        };
        let codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original).unwrap();
        let deserialized: RelayerEnvelope = codec.deserialize_envelope(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_dispatch_envelope_serialization() {
        let original = DispatchEnvelope {
            nonce: [0u8; 32],
            ek: [1u8; 32],
            tag: [2u8; 32],
            fhe_ciphertext: vec![3, 4, 5],
        };
        let codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original).unwrap();
        let deserialized: DispatchEnvelope = codec.deserialize_envelope(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_verified_notification_serialization() {
        let original = VerifiedNotification { tag: [2u8; 32] };
        let codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original).unwrap();
        let deserialized: VerifiedNotification = codec.deserialize_envelope(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_received_notification_serialization() {
        let original = ReceivedNotification { tag: [2u8; 32] };
        let codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original).unwrap();
        let deserialized: ReceivedNotification = codec.deserialize_envelope(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_delivery_envelope_serialization() {
        let original = DeliveryEnvelope {
            nonce: [0u8; 32],
            ek: [1u8; 32],
            tag: [2u8; 32],
            fhe_ciphertext: vec![3, 4, 5],
        };
        let codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original).unwrap();
        let deserialized: DeliveryEnvelope = codec.deserialize_envelope(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_envelope_enum_serialization() {
        let original = Envelope::Client(ClientEnvelope {
            nonce: [0u8; 32],
            ek: [1u8; 32],
            tag: [2u8; 32],
            fhe_ciphertext: vec![3, 4, 5],
            binding_proof: vec![6, 7, 8],
            nullifier: [9u8; 32],
            fhe_pk: vec![10, 11, 12],
        });
        let codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original).unwrap();
        let deserialized: Envelope = codec.deserialize_envelope(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
