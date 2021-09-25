use mio::net::UdpSocket;
use mio::Token;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub fn open_socket() -> (UdpSocket, SocketAddr) {
    let socket = "127.0.0.1:0".parse().unwrap();

    let srv = match UdpSocket::bind(socket) {
        Ok(s) => s,
        Err(e) => panic!("could not bind socket, error: {:?}", e),
    };

    let port = srv.local_addr().unwrap().port();

    let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    (srv, sock_addr)
}

// Updates the token to make sure we have unique ones for each stream.
pub fn next_token(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}
