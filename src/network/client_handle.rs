#![allow(unused)]

use super::{DialEvent, FromServerEvent, InternalMessage};
use mio::net::UdpSocket;
use mio::Token;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

pub struct MessagePeerHandle {
    tx: UnboundedSender<InternalMessage>,
}

impl MessagePeerHandle {
    fn new(tx: UnboundedSender<InternalMessage>) -> Self {
        Self { tx }
    }

    pub fn send(&self, message: DialEvent) {
        self.tx.send(InternalMessage::DialEvent(message));
    }
}

pub async fn spawn_to_peer_loop_listener() -> (MessagePeerHandle, JoinHandle<()>) {
    // channel-pair used by the server backend to send payloads to connected peers. This channel
    // goes into the peer loop below since the server loop handles incoming connections, as opposed
    // to the peer loop which deals with outbound messages.
    let (from_backend_tx, from_backend_rx): (
        UnboundedSender<InternalMessage>,
        UnboundedReceiver<InternalMessage>,
    ) = mpsc::unbounded_channel();

    let handle = MessagePeerHandle::new(from_backend_tx);

    let join = tokio::spawn(async move {
        peer_loop(from_backend_rx);
    });

    (handle, join)
}

// peer_loop contains the operations that concern all the peers connected to the server.
async fn peer_loop(mut rx: UnboundedReceiver<InternalMessage>) {
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
