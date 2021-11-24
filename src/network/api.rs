use super::discovery::{create_rnd_number, spawn_peer_discovery_loop, ValidatedPeer};
use super::{InternalMessage, OrdPayload, PayloadEvent};
use crate::network::client_handle::{spawn_peer_listeners, MessagePeerHandle};
use crate::network::common::public_key_and_payload_to_vec;
use crate::network::server_handle::spawn_server_accept_loop;
use crate::swiss_knife::helper::hash_and_sign_message_digest;
use std::convert::TryInto;
use std::error::Error;
use std::sync::Arc;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::net::UdpSocket;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    oneshot::error::TryRecvError,
    Notify,
};
use tokio::task::JoinHandle;

pub struct Networking {
    // List of (presumably) connected and validated peers which the client can communicate with
    peers: Vec<ValidatedPeer>,
    // Handler to send commands internally and externally
    handle: Option<MessagePeerHandle>,
}

impl Networking {
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            handle: None,
        }
    }

    pub fn set_peers(&mut self, p: Vec<ValidatedPeer>) {
        self.peers = p;
    }

    pub fn set_handler(&mut self, h: MessagePeerHandle) {
        self.handle = Some(h);
    }

    pub fn get_registered_peers(&self) -> Vec<ValidatedPeer> {
        self.peers.clone()
    }

    pub async fn send_payload_to(&self, payload: String, recipient: mio::Token) -> usize {
        let res = self
            .handle
            .as_ref()
            .unwrap()
            .send_payload(payload.into_bytes(), recipient)
            .await;

        match res.await {
            Ok(v) => v,
            Err(e) => {
                log::error!("could not send payload: {}", e);
                return 0;
            }
        }
    }

    pub async fn get_messages_from(
        &self,
        target: mio::Token,
    ) -> Result<Vec<OrdPayload>, TryRecvError> {
        Ok(self
            .handle
            .as_ref()
            .unwrap()
            .send_get(target)
            .await
            .try_recv()?)
    }
}

// spawn_peer_discovery_listener finds the other peers on the same network.
// It needs to know the host server loop to tell other peers to speak with it there.
// This port is received by a succcessful call to `spawn_io_listeners`.
// When it has discovered all peers, it returns all [port, public_key] pairs.
pub async fn spawn_peer_discovery_listener(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    server_port: String,
    mut validator_list: Vec<String>,
) -> Vec<ValidatedPeer> {
    let (tx_peer_discv, mut rx_peer_discv): (Sender<ValidatedPeer>, Receiver<ValidatedPeer>) =
        mpsc::channel(128);

    let (kill_tx, mut kill_rx): (Sender<bool>, Receiver<bool>) = mpsc::channel(2);

    let whoami: String = hex::encode(pk.clone());
    // no need to discover ourselves
    validator_list.remove(
        validator_list
            .iter()
            .position(|x| *x == whoami)
            .expect("local node id not found in validator whitelist"),
    );

    let amount_to_validate = validator_list.len();

    let not = Notify::new();

    let public_key = pk.clone();
    let secret_key = sk.clone();
    let join = tokio::spawn(async move {
        spawn_peer_discovery_loop(
            public_key,
            secret_key,
            server_port,
            tx_peer_discv,
            kill_tx,
            validator_list,
        )
        .await
    });

    let _ = join.await;

    let mut peers_found: Vec<ValidatedPeer> = Vec::new();
    while let Some(msg) = rx_peer_discv.recv().await {
        peers_found.push(msg);
        if peers_found.len() == amount_to_validate {
            log::info!("all peers found, sending ready messages");
            not.notify_one();
            break;
        }
    }

    not.notified().await;
    let pf = peers_found.clone();
    let join = tokio::spawn(async move { ready_to_connect(pk.clone(), sk.clone(), pf).await });

    let _ = join.await;

    while let Some(msg) = kill_rx.recv().await {
        if msg == true {
            break;
        }
    }

    log::info!("returning a list of the discovered peers");
    peers_found
}

async fn ready_to_connect(pk: EcdsaPublicKey, sk: EcdsaPrivateKey, peers: Vec<ValidatedPeer>) {
    log::info!("peer ready to connect");
    let five_to_eight = create_rnd_number(5, 9).try_into().unwrap();
    let socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(socket) => socket,
        Err(e) => {
            panic!("udp error when starting discovery connected phase: {}", e);
        }
    };
    for i in 0..peers.len() {
        let mut address = "127.0.0.1:".to_string();
        let port = peers[i].disc_port();
        address.push_str(&port.clone());
        let payload = create_ready_message(pk.clone(), sk.clone());
        // sleep some random time between 5 and 8 seconds to not overflow the network
        let dur = tokio::time::Duration::from_secs(five_to_eight);
        tokio::time::sleep(dur).await;

        let res = socket.send_to(&payload, address.clone()).await;

        if res.is_err() {
            log::error!("ready message dispatch failed: {:?}", res);
        }
    }
}

fn create_ready_message(public_key: EcdsaPublicKey, secret_key: EcdsaPrivateKey) -> Vec<u8> {
    let msg = "READYREADY".to_string();
    let mut result = Vec::new();
    // First half is PUBLIC_KEY | 'READYREADY' (in bytes)
    let first_half = public_key_and_payload_to_vec(public_key, msg);
    // Second half is H(PUBLIC_KEY | 'READYREADY')_C (in bytes)
    let second_half = hash_and_sign_message_digest(secret_key, first_half.clone());

    result.extend(first_half);
    result.extend(second_half);

    result
}

pub async fn spawn_io_listeners(val_set: Vec<String>) -> (String, MessagePeerHandle) {
    // out channels correpond to communication outside the host, i.e. with other peers
    let (tx_out, rx_out): (Sender<InternalMessage>, Receiver<InternalMessage>) = mpsc::channel(128);
    let tx_out_2 = tx_out.clone();
    // in channels correspond to communication within the host, i.e. deals with payloads received
    let (tx_in, rx_in): (Sender<PayloadEvent>, Receiver<PayloadEvent>) = mpsc::channel(64);
    let tx_in_2 = tx_in.clone();
    // sempahores
    let notif = Arc::new(Notify::new());
    let notif2 = notif.clone();

    // peer loop
    tokio::spawn(async move {
        // semaphore moved to loop to make setup is completed before giving green light
        spawn_peer_listeners(rx_out, notif2).await;
    });
    // new connections loop
    tokio::spawn(async move {
        spawn_server_accept_loop(tx_out, tx_in, val_set).await;
    });
    // stop sign, wait for green light
    notif.notified().await;
    let mph = MessagePeerHandle::new(tx_out_2, tx_in_2);
    // receive answer from backend on which port the new conn loop listens to
    let port = mph.get_host_port().await;

    (port, mph)
}
