pub mod client_handle;
pub mod common;
pub mod core;
pub mod event_loop;
pub mod message;

// FromServer is the message type sent from the server to clients
pub struct FromServerToClient(Vec<u8>);

// ToServer is the message type sent from clients to the server
pub enum ToServerFromClient {
    Message(themis::keys::EcdsaPublicKey, Vec<u8>),
    NewClient(crate::network::client_handle::ClientHandle),
}
