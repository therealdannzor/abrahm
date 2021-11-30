use super::common::{create_p2p_message, extract_server_port_field};
use super::{
    DialEvent, FromServerEvent, InternalMessage, OrdPayload, PayloadEvent, UpgradedPeerData,
};
use mio::net::UdpSocket;
use mio::Token;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::Notify;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot, Mutex,
};

pub struct MessagePeerHandle(
    // transmit channel to send messages to other peers
    Sender<InternalMessage>,
    // transmit channel to request messages received from other peers
    Sender<PayloadEvent>,
    // receive upgraded peer data
    Receiver<UpgradedPeerData>,
);

impl MessagePeerHandle {
    pub fn new(
        tx_outbound: Sender<InternalMessage>,
        tx_inbound: Sender<PayloadEvent>,
        rx_upgrade: Receiver<UpgradedPeerData>,
    ) -> Self {
        Self {
            0: tx_outbound,
            1: tx_inbound,
            2: rx_upgrade,
        }
    }

    // send_payload sends a message to a recipient, identified by a Token (inner value usize).
    // It returns a receive channel part which will include how many bytes were written.
    // If the message was fully transmitted, this should be the same length as the payload.
    pub async fn send_payload(&self, payload: Vec<u8>, send_to: Token) -> oneshot::Receiver<usize> {
        let (send, recv): (oneshot::Sender<usize>, oneshot::Receiver<usize>) = oneshot::channel();
        let dial_message = DialEvent::DispatchMessage(send_to, payload, send);
        let _ = self.0.send(InternalMessage::DialEvent(dial_message)).await;
        recv
    }

    pub async fn send_get(&self, target: Token) -> oneshot::Receiver<Vec<OrdPayload>> {
        let (send, recv): (
            oneshot::Sender<Vec<OrdPayload>>,
            oneshot::Receiver<Vec<OrdPayload>>,
        ) = oneshot::channel();
        let get_message = PayloadEvent::Get(target, send);
        let _ = self.1.send(get_message).await;
        recv
    }

    pub async fn get_host_port(&self) -> String {
        let (send, recv): (oneshot::Sender<String>, oneshot::Receiver<String>) = oneshot::channel();
        let sender = self.0.clone();
        let _ = sender
            .send(InternalMessage::FromServerEvent(
                FromServerEvent::GetHostPort(send),
            ))
            .await;

        let res = match recv.await {
            Ok(v) => v,
            Err(_) => {
                panic!("the sender dropped");
            }
        };

        res
    }

    pub async fn recv_all_upgraded_peers(&mut self, lim: usize) -> Vec<UpgradedPeerData> {
        let mut ug_peers: Vec<UpgradedPeerData> = Vec::new();
        while let Some(msg) = self.2.recv().await {
            if !ug_peers.contains(&msg) {
                ug_peers.push(msg);
            } else if ug_peers.len() == lim {
                break;
            }
        }
        ug_peers
    }
}

pub async fn spawn_peer_listeners(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    rx: Receiver<InternalMessage>,
    rx2: Receiver<PayloadEvent>,
    notify: Arc<Notify>,
) {
    let join_peer = tokio::spawn(async move {
        peer_loop(pk, sk, rx, notify).await;
    });
    let join_upgraded = tokio::spawn(async move {
        peer_upgraded_loop(rx2).await;
    });
    let _ = join_peer.await;
    let _ = join_upgraded.await;
}

// peer_upgraded_loop supports the reception and storage of p2p messages after full completed handshake
async fn peer_upgraded_loop(mut rx: Receiver<PayloadEvent>) {
    let token_to_ord_payload: HashMap<Token, Vec<OrdPayload>> = HashMap::new();
    let token_to_ord_payload = Arc::new(Mutex::new(token_to_ord_payload));
    loop {
        while let Some(msg) = rx.recv().await {
            match msg {
                PayloadEvent::StoreMessage(token, ord_payload) => {
                    let arc = token_to_ord_payload.clone();
                    let mut inner = arc.lock().await;
                    if inner.get(&token).is_none() {
                        inner.insert(token, Vec::new());
                    }
                    inner.get(&token).unwrap().clone().push(ord_payload);
                }
                PayloadEvent::Get(token, sender) => {
                    let arc = token_to_ord_payload.clone();
                    let mut inner = arc.lock().await;
                    let payload = match inner.get(&token) {
                        Some(p) => sender.send(p.to_vec()),
                        None => sender.send(vec![OrdPayload(vec![0], 0)]),
                    };
                }
            }
        }
    }
}

// peer_loop supports the internal operations of the peers it is connected to
async fn peer_loop(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    mut rx: Receiver<InternalMessage>,
    notify: Arc<Notify>,
) {
    let hex_key_to_token: HashMap<String, Token> = HashMap::new();
    let hex_key_to_token = Arc::new(Mutex::new(hex_key_to_token));
    let token_to_sock: HashMap<Token, SocketAddr> = HashMap::new();
    let token_to_sock = Arc::new(Mutex::new(token_to_sock));
    let server_token = Token(1024);
    let mut server_udp: Option<Arc<Mutex<UdpSocket>>> = None;
    loop {
        while let Some(msg) = rx.recv().await {
            let secret_key = sk.clone();
            let public_key = pk.clone();
            match msg {
                InternalMessage::FromServerEvent(FromServerEvent::HostSocket(addr, sock)) => {
                    let arc = token_to_sock.clone();
                    let mut idc = arc.lock().await;
                    idc.insert(server_token, addr);
                    // signals readiness to request for host port
                    notify.notify_one();

                    server_udp = Some(sock);
                    drop(idc);
                }
                InternalMessage::FromServerEvent(FromServerEvent::GetHostPort(sender)) => {
                    let arc = token_to_sock.clone();
                    let idc = arc.lock().await;

                    let _ = match idc.get(&server_token) {
                        Some(port) => {
                            let _ = sender.send(port.port().to_string());
                        }
                        None => {
                            panic!("server backend not initialized, abort (unexpected error)");
                        }
                    };
                    drop(idc);
                }
                InternalMessage::FromServerEvent(FromServerEvent::NewClient(msg)) => {
                    log::debug!(
                        "client handle registered a new client event, id: {}",
                        msg.1 .0
                    );
                    let addr = "127.0.0.1:0".parse().unwrap();
                    let socket = match UdpSocket::bind(addr) {
                        Ok(sok) => sok,
                        Err(e) => {
                            panic!("udp socket error respond to new client event: {}", e);
                        }
                    };

                    // Create a message that tells the peer, who recently connected, that
                    // we have accepted your connection, given you a new short id (Token),
                    // and that you will be able to send messages without having to write
                    // your public key. Instead, use a token id instead, and speak on a
                    // dedicated port. This port is only designated for communication from
                    // you to me (unidirectional).
                    let mut payload = "ACK=".to_string();
                    // This is what I know you as when you want to speak with me. This way,
                    // you don't have to send me your whole public key as a hex string
                    // every time you want to ping me. Remember, every time you speak with
                    // me from now on, I *only* recognize you by this short id.
                    let peer_id: String = msg.1.clone().0.to_string();
                    // This is the port that is exclusively for you from now on. So if you
                    // use your short id and send messages to me on this socket, I will be
                    // able to verify the authenticity of your messages and know it is you.
                    let port = msg.2.port().to_string();

                    payload.push_str(&peer_id);
                    payload.push_str(&port);

                    // create p2p message that includes the public key as hex string as a
                    // final confirmation of who the recipient is speaking to and who now
                    // have given the recipient a short code, i.e. upgraded the connection
                    // between the two
                    let full_msg = create_p2p_message(public_key, secret_key, &payload);

                    let mut resp_address = "127.0.0.1:".to_string();
                    let response_port = msg.3.parse::<u16>().unwrap(); // already sanitized
                    let respond_to_socket =
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), response_port);

                    if let Err(e) = socket.send_to(&full_msg, respond_to_socket) {
                        log::error!("failed to send ack response to peer: {}", e);
                    };
                    log::info!(
                        "client handle responded to new client with short id: {}",
                        msg.1 .0
                    );

                    let arc = token_to_sock.clone();
                    let mut idc = arc.lock().await;
                    let op = idc.insert(msg.1, msg.2);
                    if op.is_some() {
                        log::warn!(
                            "client handle updated socket address for token {:?}, old={:?}, new={:?}",
                            msg.1,
                            op.unwrap(),
                            msg.2
                        );
                    }
                    let arc = hex_key_to_token.clone();
                    let mut idc = arc.lock().await;
                    idc.insert(msg.0, msg.1);
                }
                InternalMessage::DialEvent(DialEvent::DispatchMessage(
                    send_to,
                    payload,
                    response,
                )) => {
                    log::debug!("peer loop: new dial event");
                    let arc = token_to_sock.clone();
                    let idc = arc.lock().await;
                    let recipient_sock_addr = match idc.get(&send_to) {
                        Some(v) => v,
                        None => {
                            log::warn!(
                                "trying to send message to unknown peer token: {:?}",
                                send_to.clone()
                            );
                            continue;
                        }
                    };
                    if server_udp.clone().is_none() {
                        log::warn!("server UDP server has not started yet");
                        continue;
                    }
                    let arc = server_udp.clone().unwrap();
                    let srv = arc.lock().await;
                    match srv.send_to(&payload, *recipient_sock_addr) {
                        Ok(n) => {
                            if n != payload.len() {
                                log::error!(
                                    "failed to send full payload, sent: {}, full: {}",
                                    n,
                                    payload.len()
                                );
                                let _ = response.send(0);
                            } else {
                                // all good
                                log::debug!("sent {} bytes to {}", n, recipient_sock_addr);
                                let _ = response.send(n);
                            }
                        }
                        Err(e) => {
                            log::error!("error when trying to send payload: {:?}", e);
                            let _ = response.send(0);
                        }
                    }
                }
            }
        }
        log::error!("peer loop exited, this should not happen");
    }
}
