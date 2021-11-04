use mio::net::UdpSocket;
use mio::{Interest, Poll, Token};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;

pub fn net_open() -> (Poll, Arc<Mutex<UdpSocket>>, SocketAddr) {
    let addr = "127.0.0.1:0".parse().unwrap();
    let mut socket = match UdpSocket::bind(addr) {
        Ok(s) => s,
        Err(e) => panic!("could not bind socket, error: {:?}", e),
    };

    const SOCKET_TOK: Token = Token(1024); // token which represents the server
    const INTERESTS: Interest = Interest::READABLE.add(Interest::WRITABLE);

    let poller = Poll::new().unwrap();
    let _ = poller
        .registry()
        .register(&mut socket, SOCKET_TOK, INTERESTS);

    let port = socket.local_addr().unwrap().port();
    let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    (poller, Arc::new(Mutex::new(socket)), sock_addr)
}

// Updates the token to make sure we have unique ones for each stream.
pub fn next_token(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}
