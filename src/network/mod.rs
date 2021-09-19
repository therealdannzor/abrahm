pub mod client_handle;
pub mod common;
pub mod core;
pub mod event_loop;
pub mod message;
pub mod tcp_utils;

// FromServerEvent is the event type emitted from the server
pub struct FromServerEvent(Vec<u8>);

// ToServerEvent is the event type the server reacts to (e.g., external messages)
pub enum ToServerEvent {
    Message(themis::keys::EcdsaPublicKey, Vec<u8>),
    NewClient(crate::network::client_handle::ClientHandle),
    FatalError(std::io::Error),
}
