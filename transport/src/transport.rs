pub struct NymTransport {
    local_address: (),
    net: (),
}

pub struct Channel {
    peer: (),
    inner: (),
}

impl NymTransport {
    pub fn bind(local_address: ()) -> Self {
        Self {
            local_address,
            net: (),
        }
    }

    pub fn connect(&self, peer: ()) -> Channel {
        Channel {
            peer,
            inner: (),
        }
    }
}

impl Channel {
    pub fn send(&self, data: Vec<u8>) {
        // Send data to peer
    }

    pub fn receive(&self) -> Vec<u8> {
        // Receive data from peer
        Vec::new()
    }
}

pub struct MailboxTransport {
    transport: NymTransport,
    relayer_channel: Channel,
    dispatcher_channel: Channel,
}

pub struct RelayerTransport {
    transport: NymTransport,
    mailbox_channel: Channel,
    dispatcher_channel: Channel,
}

pub struct DispatcherTransport {
    transport: NymTransport,
    mailbox_channel: Channel,
    relayer_channel: Channel,
}

pub struct ClientTransport {
    transport: NymTransport,
    mailbox_channel: Option<Channel>,
    dispatcher_channel: Option<Channel>,
}

// Question left open registration and authentication should be added as a separate channel. This service is not in the scope of the POC