#![allow(unused)]

use super::{DialEvent, FromServerEvent, InternalMessage};
use mio::net::UdpSocket;
use mio::Token;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender};

struct ToPeer {
    server: UdpSocket,
    dest: UdpSocket,
}

// peer_loop contains the operations that concern all the peers connected to the server.
async fn peer_loop(mut rx: Receiver<InternalMessage>, mut internal_tx: Sender<InternalMessage>) {
    let mut id_conns: HashMap<Token, SocketAddr> = HashMap::new();
    let mut stream_conns: HashMap<SocketAddr, UdpSocket> = HashMap::new();

    while let Some(msg) = rx.recv().await {
        match msg {
            InternalMessage::FromServerEvent(FromServerEvent::HostSocket(addr)) => {
                let sock = UdpSocket::bind(addr).unwrap();
                stream_conns.insert(addr, sock);
            }
            InternalMessage::FromServerEvent(FromServerEvent::NewClient(msg)) => {
                let op = id_conns.insert(msg.1, msg.2);
                if op.is_some() {
                    log::warn!(
                        "updated socket address for token {:?}, old={:?}, new={:?}",
                        msg.1,
                        op.unwrap(),
                        msg.2
                    );
                }
            }
            InternalMessage::DialEvent(DialEvent::Message {
                send_to,
                payload,
                response,
            }) => {
                let recipient = id_conns.get(&send_to);
                if recipient.is_none() {
                    log::warn!("trying to send message to unknown peer: {:?}", recipient);
                    continue;
                }
                let recipient = recipient.unwrap();
                let host_sock_addr = id_conns.get(&Token(1024)).unwrap();
                let host_sock = stream_conns.get(host_sock_addr).unwrap();
                host_sock.connect(*recipient);
                let attempt_send = host_sock.send(&payload);
                if attempt_send.is_err() {
                    response.send(0);
                } else {
                    let bytes_sent = attempt_send.unwrap();
                    response.send(bytes_sent);
                }
            }
        }
    }
}
