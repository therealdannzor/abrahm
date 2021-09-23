use mio::net::UdpSocket;
use mio::Token;

pub fn open_socket() -> UdpSocket {
    let socket = "127.0.0.1:1024".parse().unwrap();

    let srv = match UdpSocket::bind(socket) {
        Ok(s) => s,
        Err(e) => panic!("could not bind socket, error: {:?}", e),
    };

    srv
}

// Updates the token to make sure we have unique ones for each stream.
pub fn next_token(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}
