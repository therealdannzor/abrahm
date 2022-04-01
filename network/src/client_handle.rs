use super::common::create_p2p_message;
use super::discovery::create_rnd_number;
use super::utils::any_udp_socket;
use super::{FromServerEvent, OrdPayload, PayloadEvent, PeerShortId};
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::Notify;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot, Mutex,
};

#[derive(Clone)]
pub struct MessagePeerHandle(
    // transmit channel to send messages to other peers
    Sender<FromServerEvent>,
    // transmit channel to request messages received from other peers
    Sender<PayloadEvent>,
    // keep track of payloads sent
    u32,
);

impl MessagePeerHandle {
    pub fn new(tx_outbound: Sender<FromServerEvent>, tx_inbound: Sender<PayloadEvent>) -> Self {
        Self {
            0: tx_outbound,
            1: tx_inbound,
            2: 0,
        }
    }

    pub async fn get_host_port(&self) -> String {
        let (send, recv): (oneshot::Sender<String>, oneshot::Receiver<String>) = oneshot::channel();
        let sender = self.0.clone();
        let _ = sender.send(FromServerEvent::GetHostPort(send)).await;

        let res = match recv.await {
            Ok(v) => v,
            Err(_) => {
                panic!("the sender dropped");
            }
        };

        res
    }

    pub async fn send_payload(&mut self, msg: String, my_id_at_recipient: usize) {
        self.2 += 1;
        let id = PeerShortId(my_id_at_recipient);
        let p = OrdPayload(msg.as_bytes().to_vec(), self.2);
        let sender = self.1.clone();
        let _ = sender.send(PayloadEvent::StoreMessage(id, p)).await;
    }
}

pub async fn spawn_peer_listeners(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    rx: Receiver<FromServerEvent>,
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
    let id_to_ord_payload: HashMap<usize, Vec<OrdPayload>> = HashMap::new();
    let id_to_ord_payload = Arc::new(Mutex::new(id_to_ord_payload));
    tokio::spawn(async move {
        loop {
            while let Some(msg) = rx.recv().await {
                match msg {
                    PayloadEvent::StoreMessage(i, ord_payload) => {
                        let arc = id_to_ord_payload.clone();
                        let mut inner = arc.lock().await;
                        if inner.get(&i.0).is_none() {
                            inner.insert(i.0, Vec::new());
                        }
                        inner.get(&i.0).unwrap().clone().push(ord_payload);
                    }
                    PayloadEvent::Get(i, sender) => {
                        let arc = id_to_ord_payload.clone();
                        let inner = arc.lock().await;
                        let _ = match inner.get(&i.0) {
                            Some(p) => sender.send(p.to_vec()),
                            None => sender.send(vec![OrdPayload(vec![0], 0)]),
                        };
                    }
                }
            }
        }
    });
}

// peer_loop supports the internal operations of the peers it is connected to
async fn peer_loop(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    mut rx: Receiver<FromServerEvent>,
    notify: Arc<Notify>,
) {
    // String -> usize
    let hex_key_to_id = Arc::new(Mutex::new(HashMap::new()));
    let mut server_port: Option<String> = None;
    tokio::spawn(async move {
        loop {
            while let Some(msg) = rx.recv().await {
                let secret_key = sk.clone();
                let public_key = pk.clone();
                match msg {
                    FromServerEvent::HostSocket(port) => {
                        server_port = Some(port);
                        // signals readiness to request for host port
                        notify.notify_one();
                    }
                    FromServerEvent::GetHostPort(sender) => {
                        if server_port.is_some() {
                            let _ = sender.send(server_port.clone().unwrap());
                        } else {
                            panic!("server backend not initialized, this should not happen");
                        }
                    }
                    FromServerEvent::NewClient(msg) => {
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
                        let peer_id: String = msg.1.clone().to_string();

                        // Use the same port as the server backend to receive messages on
                        let port = server_port.clone().unwrap();
                        payload.push_str(&peer_id);
                        payload.push_str(&port);

                        // create p2p message that includes the public key as hex string as a
                        // final confirmation of who the recipient is speaking to and who now
                        // have given the recipient a short code, i.e. upgraded the connection
                        // between the two
                        let full_msg = create_p2p_message(public_key, secret_key, &payload);

                        let mut resp = "127.0.0.1:".to_string();
                        resp.push_str(&msg.2);

                        let socket = any_udp_socket().await;

                        let arc = hex_key_to_id.clone();
                        let mut inner = arc.lock().await;
                        let key_slice = msg.0.clone()[80..89].to_string();
                        inner.insert(msg.0, msg.1);
                        log::debug!("key ({}..) linked to id {}", key_slice, msg.1.to_string());

                        // send each upgrade ACK message a couple of times to make sure it hits home
                        for _ in 0..8 {
                            let resp_address = resp.clone();
                            let payload = full_msg.clone();

                            let random_num = create_rnd_number(3, 6).try_into().unwrap();
                            // sleep some random time between to not overflow the network
                            let dur = tokio::time::Duration::from_secs(random_num);
                            tokio::time::sleep(dur).await;

                            let _ = socket.send_to(&payload, resp_address).await;
                        }
                    }
                }
            }
            log::error!("peer loop exited, this should not happen");
        }
    });
}
