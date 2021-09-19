pub mod client_handle;
pub mod common;
pub mod core;
pub mod message;
pub mod server_handle;
pub mod tcp_utils;

#[derive(Clone)]
// FromServerEvent is the event type emitted from the server
pub enum FromServerEvent {
    Message(mio::Token, Vec<u8>),
}

// ToServerEvent is the event type the server reacts to (e.g., external messages)
pub enum ToServerEvent {
    NewClient(crate::network::client_handle::ClientHandle),
    FatalError(std::io::Error),
}
