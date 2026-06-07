use nym_sdk::mixnet::{AnonymousSenderTag, IncludedSurbs, MixnetClient, MixnetClientBuilder, MixnetMessageSender, Recipient, StoragePaths};
use crate::envelopes::*;
use crate::error::TransportError;


// Question left open registration and authentication should be added as a separate channel. This service is not in the scope of the POC


/// The Surb transport layer is meant to be used for the communication between
/// the sender and the mailbox and between the receiver and the dispatcher. It
/// is based on the SURB (Single Use Reply Block) model, which allows for
/// secure and anonymous communication between parties in a mix network.
/// The sender creates a message and wraps it in a SURB that contains the
/// serialized envelope.
/// client: Mixnet client that will be used to send and receive messages
/// service_address: The NymAddress of the recipient of the message
pub struct SurbSender {
    client: MixnetClient,
    service_address: Recipient, // either mailbox or dispatcher address
}

impl SurbSender {
    pub async fn new(target_addr: Recipient) -> Result<Self, TransportError> {
        let config_dir = std::env::var("CONFIG_DIR").unwrap_or_else(|_| "./config".to_string());
        let storage_paths = StoragePaths::new_from_dir(&config_dir)?;
        let client: MixnetClient = MixnetClientBuilder::new_with_default_storage(storage_paths)
            .await
            .map_err(|e| TransportError::InitializationError(format!("Failed to create MixnetClient: {}", e)))?
            .build()
            .map_err(|e| TransportError::InitializationError(format!("Failed to initialize MixnetClient: {}", e)))?
            .connect_to_mixnet()
            .await?;

        Ok(SurbSender {
            client,
            service_address: target_addr,
        })
    }

    // this function should be launched in a separate task and should listen for incoming messages on the mixnet and process them accordingly. For the POC, we can just print the received messages.
    pub async fn send(&mut self, envelope: Envelope) -> Result<Envelope, TransportError> {
        let codec = EnvelopeCodec::new();
        let serialized_envelope = codec.serialize_envelope(&envelope)?;
        // Include one SURB so the receiver can reply without learning our address
        self.client
            .send_message(self.service_address, serialized_envelope, IncludedSurbs::Amount(1))
            .await?;

        // Listen for reply
        loop {
            match self.client.wait_for_messages().await {
                None => return Err(TransportError::Disconnected),
                Some(msgs) if msgs.is_empty() => continue,
                Some(msgs) => {
                    let bytes = msgs.into_iter().next().unwrap().message;
                    let reply = codec.deserialize_envelope(&bytes)?;
                    println!("Received reply: {:?}", reply);
                    return Ok(reply);
                }
            }
        }
    }
}

pub struct SurbReceiver {
    client: MixnetClient,
}

impl SurbReceiver {
    pub async fn new() -> Result<Self, TransportError> {
        let config_dir = std::env::var("CONFIG_DIR").unwrap_or_else(|_| "./config".to_string());
        let storage_paths = StoragePaths::new_from_dir(&config_dir)?;
        let client: MixnetClient = MixnetClientBuilder::new_with_default_storage(storage_paths)
            .await
            .map_err(|e| TransportError::InitializationError(format!("Failed to create MixnetClient: {}", e)))?
            .build()
            .map_err(|e| TransportError::InitializationError(format!("Failed to initialize MixnetClient: {}", e)))?
            .connect_to_mixnet()
            .await?;

        Ok(SurbReceiver { client })
    }

    pub fn address(&self) -> &Recipient {
        self.client.nym_address()
    }

    /// Wait for an incoming SURB-tagged message. Returns the deserialized envelope
    /// and the anonymous sender tag needed to reply.
    pub async fn receive(&mut self) -> Result<(Envelope, AnonymousSenderTag), TransportError> {
        let codec = EnvelopeCodec::new();
        loop {
            match self.client.wait_for_messages().await {
                None => return Err(TransportError::Disconnected),
                Some(msgs) if msgs.is_empty() => continue,
                Some(msgs) => {
                    let msg = msgs.into_iter().next().unwrap();
                    let tag = msg.sender_tag.ok_or(TransportError::MissingSenderTag)?;
                    let envelope = codec.deserialize_envelope(&msg.message)?;
                    return Ok((envelope, tag));
                }
            }
        }
    }

    // Function used by the receiver to reply to the sender through the mixnet. The receiver will use the anonymous sender tag received in the message to send the reply back to the sender. The reply will be wrapped in a SURB and sent through the mixnet.
    pub async fn reply_to_anon(&self, anon: AnonymousSenderTag, msg: Envelope) -> Result<(), TransportError> {
        let codec = EnvelopeCodec::new();
        let serialized_envelope = codec.serialize_envelope(&msg)?;
        self.client.send_reply(anon, serialized_envelope).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two distinct Nym clients exercise the full SURB round-trip.
    // The receiver runs in a separate tokio task to mirror real deployment,
    // where sender and receiver are independent processes.
    // Skipped in CI; run with: cargo test -- --include-ignored
    #[tokio::test]
    #[ignore = "requires live Nym mixnet"]
    async fn surb_roundtrip() {
        let mut receiver = SurbReceiver::new().await.unwrap();
        let receiver_addr = *receiver.address();

        let sent = Envelope::Client(ClientEnvelope {
            nonce: [1u8; 32],
            ek: [2u8; 32],
            tag: [3u8; 32],
            fhe_ciphertext: vec![4, 5, 6],
            binding_proof: vec![7, 8, 9],
            nullifier: [10u8; 32],
            fhe_pk: vec![11, 12, 13],
        });
        let ack = Envelope::VerifiedNotification(VerifiedNotification { tag: [0xAAu8; 32] });
        let ack_clone = ack.clone();

        // Receiver runs concurrently: waits for message, then replies via SURB tag
        // (it never learns the sender's Nym address)
        let receiver_task = tokio::spawn(async move {
            let (received, tag) = receiver.receive().await.unwrap();
            receiver.reply_to_anon(tag, ack_clone).await.unwrap();
            received
        });

        // Sender sends anonymously (with SURB) and blocks until the reply arrives
        let mut sender = SurbSender::new(receiver_addr).await.unwrap();
        let reply = sender.send(sent.clone()).await.unwrap();

        let received = receiver_task.await.unwrap();
        assert_eq!(sent, received);
        assert_eq!(ack, reply);
    }
}
