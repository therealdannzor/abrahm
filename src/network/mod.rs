pub mod client_handle;
pub mod common;
pub mod core;
pub mod message;
pub mod server_handle;
pub mod udp_utils;

// FromServerEvent is the event type emitted from the server
pub enum FromServerEvent {
    NewClient(mio::Token, std::net::SocketAddr),
}
