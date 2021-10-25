use super::{DialEvent, FromServerEvent, InternalMessage, OrdPayload, PayloadEvent};
use mio::net::UdpSocket;
use mio::Token;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot, Mutex,
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
        println!("Peer handle: get host port");
        let (send, recv): (oneshot::Sender<String>, oneshot::Receiver<String>) = oneshot::channel();
        let sender = self.0.clone();
        sender.try_send(InternalMessage::FromServerEvent(
            FromServerEvent::GetHostPort(send),
        ));

        let res = match recv.await {
            Ok(v) => v,
            Err(_) => {
                panic!("the sender dropped");
            }
        };

        res
    }
}

pub async fn spawn_peer_listeners(rx: Receiver<InternalMessage>, notify: Arc<Notify>) {
    let join_peer = tokio::spawn(async move {
        peer_loop(rx, notify).await;
    });

    join_peer.await;
}

// peer_loop contains the operations that concern all the peers connected to the server.
async fn peer_loop(mut rx: Receiver<InternalMessage>, notify: Arc<Notify>) {
    let token_to_sock: HashMap<Token, SocketAddr> = HashMap::new();
    let token_to_sock = Arc::new(Mutex::new(token_to_sock));
    let server_token = Token(1024);
    let mut server_udp: Option<Arc<Mutex<UdpSocket>>> = None;
    loop {
        while let Some(msg) = rx.recv().await {
            println!("Receiving messages in peer loop");
            match msg {
                InternalMessage::FromServerEvent(FromServerEvent::HostSocket(addr, sock)) => {
                    println!("FromServerEvent: HostSocket(addr)");
                    let arc = token_to_sock.clone();
                    let mut idc = arc.lock().await;
                    idc.insert(server_token, addr);
                    // signals readiness to request for host port
                    notify.notify_one();

                    server_udp = Some(sock);
                    drop(idc);
                }
                InternalMessage::FromServerEvent(FromServerEvent::GetHostPort(sender)) => {
                    println!("FromServerEvent: GetHostPort(sender)");
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
                    println!("FromServerEvent: New Client");
                    let arc = token_to_sock.clone();
                    let mut idc = arc.lock().await;
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
                InternalMessage::DialEvent(DialEvent::DispatchMessage(
                    send_to,
                    payload,
                    response,
                )) => {
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
                    let srv = Arc::try_unwrap(server_udp.clone().unwrap())
                        .unwrap()
                        .into_inner();
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
}
