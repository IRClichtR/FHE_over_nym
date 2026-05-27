use serde::{Serialize, Deserialize, de::DeserializeOwned};
use postcard::{to_io, from_bytes};

pub struct EnvelopeCodec {
    scratch_buf: Vec<u8>,
}

impl EnvelopeCodec {
    pub fn new() -> Self {
        EnvelopeCodec { scratch_buf: Vec::new() }
    }

    pub fn serialize_envelope<T: Serialize>(&mut self, envelope: &T) -> Vec<u8> {
        self.scratch_buf.clear();
        to_io(envelope, &mut self.scratch_buf).expect("Serialization failed");
        self.scratch_buf.clone()
    }

    pub fn deserialize_envelope<T: DeserializeOwned>(&self, bytes: &[u8]) -> T {
        from_bytes(bytes).expect("Deserialization failed")
    }
}

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
    nonce:          [u8; 32],
    ek:             [u8; 32],
    tag:            [u8; 32],
    fhe_ciphertext: Vec<u8>,
    binding_proof:  Vec<u8>,
    nullifier:      [u8; 32],
    fhe_pk:         Vec<u8>,
}

// mailbox → relayer
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayerEnvelope {
    tag:            [u8; 32],
    binding_proof:  Vec<u8>,
    nullifier:      [u8; 32],
    fhe_pk:         Vec<u8>,
    fhe_ciphertext: Vec<u8>,
}

// mailbox → dispatcher (triggered after Verified)

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchEnvelope {
    nonce:          [u8; 32],
    ek:             [u8; 32],
    tag:            [u8; 32],
    fhe_ciphertext: Vec<u8>,
}

// relayer → mailbox (notification)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifiedNotification {
    tag:            [u8; 32],
}

// dispatcher → mailbox (notification)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceivedNotification {
    tag:            [u8; 32],
}

// dispatcher → B
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeliveryEnvelope {
    nonce:          [u8; 32],
    ek:             [u8; 32],
    tag:            [u8; 32],
    fhe_ciphertext: Vec<u8>,
}

#[cfg(test)]
// test serialization && deserialization of envelopes
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

        let mut codec = EnvelopeCodec::new();

        // round-trip serialization
        let serialized = codec.serialize_envelope(&original);
        let deserialized: ClientEnvelope = codec.deserialize_envelope(&serialized);        

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

        let mut codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original);
        let deserialized: RelayerEnvelope = codec.deserialize_envelope(&serialized);
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

        let mut codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original);
        let deserialized: DispatchEnvelope = codec.deserialize_envelope(&serialized);
        assert_eq!(original, deserialized);
    }

        #[test]
    fn test_verified_notification_serialization() {
        let original = VerifiedNotification {
            tag: [2u8; 32],
        };

        let mut codec = EnvelopeCodec::new();
        let serialized = codec.serialize_envelope(&original);
        let deserialized: VerifiedNotification = codec.deserialize_envelope(&serialized);
        assert_eq!(original, deserialized);
    }

        #[test]
        fn test_received_notification_serialization() {
            let original = ReceivedNotification {
                tag: [2u8; 32],
            };
    
            let mut codec = EnvelopeCodec::new();
            let serialized = codec.serialize_envelope(&original);
            let deserialized: ReceivedNotification = codec.deserialize_envelope(&serialized);
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

            let mut codec = EnvelopeCodec::new();
            let serialized = codec.serialize_envelope(&original);
            let deserialized: DeliveryEnvelope = codec.deserialize_envelope(&serialized);
            assert_eq!(original, deserialized);
        }
    }