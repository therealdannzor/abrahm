pub mod client_handle;
pub mod common;
pub mod message;
pub mod server_handle;
pub mod udp_utils;

// Public key as plain text, the token assigned when connecting to the server, and its address
pub struct PeerInfo(String, mio::Token, std::net::SocketAddr);

// FromServerEvent is the event type emitted from the server when a new peer connects succesfully
pub enum FromServerEvent {
    HostSocket(std::net::SocketAddr),
    NewClient(PeerInfo),
}

#[derive(Clone)]
pub struct OrdPayload(Vec<u8>, u32);

// PayloadEvent includes all invents concerning payload messages from peers
pub enum PayloadEvent {
    // Token: identifies the peer
    // Vec<u8>: payload data
    // u32: nonce
    Message(mio::Token, OrdPayload),

    // Get returns messages that have been sent by a certain peer, stored in the mailbox
    Get {
        peer: mio::Token,
        response: tokio::sync::oneshot::Sender<Vec<OrdPayload>>,
    },
}

// DialEvent is when the server attempts to reach out to a peer
pub enum DialEvent {
    Message {
        send_to: mio::Token,
        payload: Vec<u8>,
        response: tokio::sync::oneshot::Sender<usize>,
    },
}

// Messages sent between the backend loops
pub enum InternalMessage {
    FromServerEvent(FromServerEvent),
    DialEvent(DialEvent),
}
