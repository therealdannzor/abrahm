use super::{DialEvent, FromServerEvent, InternalMessage, OrdPayload, PayloadEvent};
use mio::net::UdpSocket;
use mio::Token;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};
use tokio::task::JoinHandle;

pub struct MessagePeerHandle(
    // transmit channel to send messages to other peers
    Sender<InternalMessage>,
    // transmit channel to request messages received from other peers
    Sender<PayloadEvent>,
);

impl MessagePeerHandle {
    fn new(tx_outbound: Sender<InternalMessage>, tx_inbound: Sender<PayloadEvent>) -> Self {
        Self {
            0: tx_outbound,
            1: tx_inbound,
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
        match self
            .0
            .send(InternalMessage::FromServerEvent(
                FromServerEvent::GetHostPort(send),
            ))
            .await
        {
            Ok(_) => (),
            Err(_) => {
                panic!("the receiver has already been closed");
            }
        };
        let res = match recv.await {
            Ok(v) => v,
            Err(_) => {
                panic!("the sender dropped");
            }
        };
        res
    }
}

pub async fn spawn_peer_listeners(
    tx_out: Sender<InternalMessage>,
    rx_out: Receiver<InternalMessage>,
    tx_in: Sender<PayloadEvent>,
    rx_in: Receiver<PayloadEvent>,
) -> (MessagePeerHandle, JoinHandle<()>, JoinHandle<()>) {
    // sends and retrieves messages of peers
    let message_peer_handle = MessagePeerHandle::new(tx_out, tx_in);

    let join_peer_loop = tokio::spawn(async move {
        peer_loop(rx_out).await;
    });

    let join_inbox_loop = tokio::spawn(async move {
        spawn_message_inbox_loop(rx_in).await;
    });

    (message_peer_handle, join_peer_loop, join_inbox_loop)
}

async fn spawn_message_inbox_loop(mut rx: Receiver<PayloadEvent>) {
    let mailbox_data: Arc<Mutex<HashMap<Token, Vec<OrdPayload>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    while let Some(msg) = rx.recv().await {
        match msg {
            PayloadEvent::StoreMessage(tok, ord_pay) => {
                let mut mailbox = mailbox_data.lock().unwrap();
                let mut empty_vec: Vec<OrdPayload> = Vec::new();
                let val = mailbox.get_mut(&tok).unwrap_or(&mut empty_vec);
                val.push(ord_pay);
                drop(mailbox);
            }
            PayloadEvent::Get(peer, response) => {
                let mut mailbox = mailbox_data.lock().unwrap();
                let messages = mailbox.get(&peer).unwrap();
                let _ = response.send(messages.to_vec());
                let v = mailbox.get_mut(&peer).unwrap();
                v.clear();
                drop(mailbox);
            }
        }
    }
}

// peer_loop contains the operations that concern all the peers connected to the server.
async fn peer_loop(mut rx: Receiver<InternalMessage>) {
    let id_conns: HashMap<Token, SocketAddr> = HashMap::new();
    let id_conns = Mutex::new(id_conns);
    let id_conns = Arc::new(id_conns);
    let mut stream_conns: HashMap<SocketAddr, UdpSocket> = HashMap::new();
    let server_token = Token(1024);

    while let Some(msg) = rx.recv().await {
        match msg {
            InternalMessage::FromServerEvent(FromServerEvent::HostSocket(addr)) => {
                let arc = id_conns.clone();
                let mut idc = arc.lock().unwrap();
                let sock = UdpSocket::bind(addr.clone()).unwrap();
                idc.insert(server_token, addr.clone());
                stream_conns.insert(addr, sock);
                drop(idc);
            }
            InternalMessage::FromServerEvent(FromServerEvent::GetHostPort(sender)) => {
                let arc = id_conns.clone();
                let idc = arc.lock().unwrap();
                let _ = match idc.get(&server_token) {
                    Some(port) => {
                        let _ = sender.send(port.port().to_string());
                    }
                    None => {
                        panic!("server backend not initialized, abort");
                    }
                };
                drop(idc);
            }
            InternalMessage::FromServerEvent(FromServerEvent::NewClient(msg)) => {
                let arc = id_conns.clone();
                let mut idc = arc.lock().unwrap();
                let op = idc.insert(msg.1, msg.2);
                if op.is_some() {
                    log::warn!(
                        "updated socket address for token {:?}, old={:?}, new={:?}",
                        msg.1,
                        op.unwrap(),
                        msg.2
                    );
                }
            }
            InternalMessage::DialEvent(DialEvent::DispatchMessage(send_to, payload, response)) => {
                let arc = id_conns.clone();
                let idc = arc.lock().unwrap();
                let recipient = idc.get(&send_to);
                if recipient.is_none() {
                    log::warn!("trying to send message to unknown peer: {:?}", recipient);
                    continue;
                }
                let recipient_sock_addr = recipient.unwrap();
                let host_sock_addr = idc.get(&server_token).unwrap();
                let host_sock = stream_conns.get(host_sock_addr).unwrap();
                match host_sock.send_to(&payload, *recipient_sock_addr) {
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
}
