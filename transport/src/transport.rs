use std::collections::HashMap;
use nym_sdk::mixnet::{self, MixnetClientBuilder, StoragePaths};
use crate::envelopes::*;

// Question left open registration and authentication should be added as a separate channel. This service is not in the scope of the POC

// 2. manage communications between the three services: mailbox, relayer, dispatcher. For this layer we use smolmix since we need persistent connection and constant information exchange.


/// The Surb transport layer is meant to be used for the communication between 
/// the sender and the mailbox and between the receiver and the dispatcher. It
/// is based on the SURB (Single Use Reply Block) model, which allows for 
/// secure and anonymous communication between parties in a mix network. 
/// The sender creates a message and wraps it in a SURB that contains the 
/// serialized envelope.
/// client: Mixnet client that will be used to send and receive messages
/// surb_receiver: The NymAddress of the recipient of the message
pub struct SurbTransport {
    client: MixnetClient, // bears send and receive capacity
    surb_receiver: NymAddress,
}

impl SurbTransport {
    pub async fn new(receiver: NymAddress) -> Result<Self, TransportError> {
        let config_dir: PathBuf = TempDir::new()?
            .path()
            .to_path_buf();
        let storage_path = StoragePaths::new_from_dir(&config_dir)?;
        let client = MixnetClientBuilder::new_with_default_storage(storage_path)
            .await?
            .build()?;

        Ok(SurbTransport {
            client,
            surb_receiver: receiver,
        })
    }
}
