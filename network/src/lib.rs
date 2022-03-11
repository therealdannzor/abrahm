pub mod api;
pub mod client_handle;
pub mod common;
pub mod connection_hub;
pub mod discovery;
pub mod message;
pub mod peer;
pub mod server_handle;
pub mod utils;

#[derive(PartialEq, Clone, Debug)]
pub struct UpgradedPeerData(
    themis::keys::EcdsaPublicKey, // ID of message recipient
    String,                       // port to use to reach recipient
    u32,                          // local ID of message sender for recipient
);
impl UpgradedPeerData {
    pub fn key_type(&self) -> themis::keys::EcdsaPublicKey {
        self.0.clone()
    }
    pub fn server_port(&self) -> String {
        self.1.clone()
    }
    pub fn id(&self) -> u32 {
        self.2.clone()
    }
}

#[derive(Clone)]
pub struct PeerStreamHandle(UpgradedPeerData, tokio::sync::mpsc::Sender<HandshakeAPI>);
impl PeerStreamHandle {
    pub fn id(&self) -> themis::keys::EcdsaPublicKey {
        self.0.key_type()
    }
    pub fn port(&self) -> String {
        self.0.server_port()
    }
    pub fn short_id(&self) -> u32 {
        self.0.id()
    }
}

#[derive(Debug)]
// Public key as plain text, the new short ID for this peer, and the peer's server port
pub struct PeerInfo(String, usize, String);

#[derive(Debug)]
// FromServerEvent is the event type emitted from the server when a new peer connects succesfully
pub enum FromServerEvent {
    HostSocket(String),
    GetHostPort(tokio::sync::oneshot::Sender<String>),
    NewClient(PeerInfo),
}

#[derive(Clone)]
pub struct OrdPayload(Vec<u8>, u32);

pub struct PeerShortId(usize);

// PayloadEvent includes all invents concerning payload messages from peers
pub enum PayloadEvent {
    // StoreMessage is the format in which other peers send messages to the host
    // Token: identifies the peer
    // Vec<u8>: payload data
    // u32: nonce
    StoreMessage(PeerShortId, OrdPayload),

    // Get returns messages that have been sent by a certain peer, stored in the mailbox
    // Token: peer identifier
    // Sender: response channel
    Get(PeerShortId, tokio::sync::oneshot::Sender<Vec<OrdPayload>>),
}

// Handshake status API
pub enum HandshakeAPI {
    NewState(i32),
    GetState(tokio::sync::oneshot::Sender<i32>),
    IsAuth(tokio::sync::oneshot::Sender<bool>),
}

pub fn handshake_get_state() -> (tokio::sync::oneshot::Receiver<i32>, HandshakeAPI) {
    let (send, recv) = tokio::sync::oneshot::channel();
    let message = HandshakeAPI::GetState(send);
    (recv, message)
}
