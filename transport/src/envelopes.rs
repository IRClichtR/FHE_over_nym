// TODO: use custom types
// Implement serialization and deserialization trait on types

// A → mailbox
struct ClientEnvelope {
    nonce:          [u8; 32],
    ek:             [u8; 32],
    tag:            [u8; 32],
    fhe_ciphertext: Vec<u8>,
    binding_proof:  Vec<u8>,
    nullifier:      [u8; 32],
    fhe_pk:         Vec<u8>,
}

// mailbox → relayer
struct RelayerEnvelope {
    tag:            [u8; 32],
    binding_proof:  Vec<u8>,
    nullifier:      [u8; 32],
    fhe_pk:         Vec<u8>,
    fhe_ciphertext: Vec<u8>,
}

// mailbox → dispatcher (triggered after Verified)
struct DispatchEnvelope {
    nonce:          [u8; 32],
    ek:             [u8; 32],
    tag:            [u8; 32],
    fhe_ciphertext: Vec<u8>,
}

// relayer → mailbox (notification)
struct VerifiedNotification {
    tag:            [u8; 32],
}

// dispatcher → mailbox (notification)
struct ReceivedNotification {
    tag:            [u8; 32],
}

// dispatcher → B
struct DeliveryEnvelope {
    nonce:          [u8; 32],
    ek:             [u8; 32],
    tag:            [u8; 32],
    fhe_ciphertext: Vec<u8>,
}

#[cfg(test)]
// test serialization && deserialization of envelopes