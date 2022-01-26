use tokio::net::{TcpListener, UdpSocket};

pub async fn get_udp_and_addr() -> (UdpSocket, String) {
    let socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(e) => panic!("could not bind socket, error: {:?}", e),
    };

    let port = socket.local_addr().unwrap().port().to_string();

    (socket, port)
}

pub async fn any_udp_socket() -> UdpSocket {
    let socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(e) => panic!("error when opening a new socket: {}", e),
    };
    socket
}

pub async fn get_tcp_and_addr() -> (TcpListener, String) {
    let socket = match TcpListener::bind("127.0.0.1:0").await {
        Ok(s) => s,
        Err(e) => panic!("error when opening a new socket: {}", e),
    };

    let port = socket.local_addr().unwrap().port().to_string();
    (socket, port)
}
