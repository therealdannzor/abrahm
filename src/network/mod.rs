pub mod api;
pub mod client_handle;
pub mod common;
pub mod discovery;
pub mod message;
pub mod server_handle;
pub mod udp_utils;

pub struct UpgradedPeerData(
    themis::keys::EcdsaPublicKey, // public key and ID of recipient for messages
    String,                       // port to use
    mio::Token,                   // how the sender should ID itself
);

#[derive(Debug)]
// Public key as plain text, the token assigned when connecting to the server,
// the new port to use from now on (when only using the token as ID), and the
// token id's own server port to repond to.
pub struct PeerInfo(String, mio::Token, std::net::SocketAddr, String);

#[derive(Debug)]
// FromServerEvent is the event type emitted from the server when a new peer connects succesfully
pub enum FromServerEvent {
    HostSocket(
        std::net::SocketAddr,
        std::sync::Arc<tokio::sync::Mutex<mio::net::UdpSocket>>,
    ),
    GetHostPort(tokio::sync::oneshot::Sender<String>),
    NewClient(PeerInfo),
}

#[derive(Clone)]
pub struct OrdPayload(Vec<u8>, u32);

// PayloadEvent includes all invents concerning payload messages from peers
pub enum PayloadEvent {
    // StoreMessage is the format in which other peers send messages to the host
    // Token: identifies the peer
    // Vec<u8>: payload data
    // u32: nonce
    StoreMessage(mio::Token, OrdPayload),

    // Get returns messages that have been sent by a certain peer, stored in the mailbox
    // Token: peer identifier
    // Sender: response channel
    Get(mio::Token, tokio::sync::oneshot::Sender<Vec<OrdPayload>>),
}

#[derive(Debug)]
// DialEvent is when the server attempts to reach out to a peer
pub enum DialEvent {
    // DispatchMessage is the format in which the host "dials" up another peer
    // Token: identifies the peer
    // Vec<u8>: data to send
    // Sender: response channel (0 if something went wrong)
    DispatchMessage(mio::Token, Vec<u8>, tokio::sync::oneshot::Sender<usize>),
}

#[derive(Debug)]
// Messages sent between the backend loops
pub enum InternalMessage {
    FromServerEvent(FromServerEvent),
    DialEvent(DialEvent),
}
