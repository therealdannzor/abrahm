use super::discovery::{create_rnd_number, spawn_peer_discovery_loop, ValidatedPeer};
use super::{FromServerEvent, OrdPayload, PayloadEvent, UpgradedPeerData};
use crate::network::client_handle::{spawn_peer_listeners, MessagePeerHandle};
use crate::network::common::{create_p2p_message, public_key_and_payload_to_vec};
use crate::network::server_handle::spawn_server_accept_loop;
use crate::network::udp_utils::any_udp_socket;
use crate::swiss_knife::helper::hash_and_sign_message_digest;
use std::convert::TryInto;
use std::error::Error;
use std::sync::Arc;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::{
    mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender},
    oneshot::error::TryRecvError,
    Notify,
};
use tokio::task::JoinHandle;

pub struct Networking {
    // List of (presumably) connected and validated peers which the client can communicate with
    peers: Vec<UpgradedPeerData>,
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

    pub fn set_peers(&mut self, p: Vec<UpgradedPeerData>) {
        self.peers = p;
    }

    pub fn set_handler(&mut self, h: MessagePeerHandle) {
        self.handle = Some(h);
    }

    pub fn get_registered_peers(&self) -> Vec<UpgradedPeerData> {
        self.peers.clone()
    }

    pub fn get_handle(&self) -> MessagePeerHandle {
        if self.handle.is_none() {
            panic!("handle setup not done correctly, this should not happen");
        }
        self.handle.clone().unwrap()
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
    mut ug_rx: UnboundedReceiver<UpgradedPeerData>,
) -> Vec<UpgradedPeerData> {
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
    let serv_port = server_port.clone();
    let join = tokio::spawn(async move {
        spawn_peer_discovery_loop(
            public_key,
            secret_key,
            serv_port,
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
    let public_key = pk.clone();
    let secret_key = sk.clone();
    let join = tokio::spawn(async move { ready_to_connect(public_key, secret_key, pf).await });

    let _ = join.await;

    while let Some(msg) = kill_rx.recv().await {
        if msg == true {
            not.notify_one();
            break;
        }
    }

    not.notified().await;
    let pf = peers_found.clone();
    let serv_port = server_port.clone();
    let join =
        tokio::spawn(
            async move { upgrade_server_backend(pk.clone(), sk.clone(), pf, serv_port).await },
        );

    let _ = join.await;

    let mut ug_peers: Vec<UpgradedPeerData> = Vec::new();
    while let Some(msg) = ug_rx.recv().await {
        if !ug_peers.contains(&msg) {
            ug_peers.push(msg);
            log::debug!(
                "added {}/{} upgraded peers",
                ug_peers.len(),
                peers_found.len()
            );
        }
        if ug_peers.len() == peers_found.len() {
            not.notify_one();
            break;
        }
    }

    not.notified().await;
    log::info!("full upgrade of peer protocol done");
    ug_peers
}

async fn upgrade_server_backend(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    peers: Vec<ValidatedPeer>,
    server_port: String,
) {
    let socket = any_udp_socket().await;
    let synced_peers: Vec<String> = Vec::new();

    for i in 0..3 * peers.len() {
        let mut address = "127.0.0.1:".to_string();
        let port = peers[i % peers.len()].serv_port();
        address.push_str(&port.clone());
        let mut message = "UPGRD".to_string();
        message.push_str(&server_port);
        let payload = create_p2p_message(pk.clone(), sk.clone(), &message);

        let random_num = create_rnd_number(4, 10).try_into().unwrap();
        // sleep some random time between to not overflow the network
        let dur = tokio::time::Duration::from_secs(random_num);
        tokio::time::sleep(dur).await;

        let _ = socket.send_to(&payload, address).await;
    }
}

async fn ready_to_connect(pk: EcdsaPublicKey, sk: EcdsaPrivateKey, peers: Vec<ValidatedPeer>) {
    log::info!("peer ready for connect phase");
    let five_to_eight = create_rnd_number(5, 9).try_into().unwrap();
    let socket = any_udp_socket().await;

    for i in 0..peers.len() {
        let mut address = "127.0.0.1:".to_string();
        let port = peers[i].disc_port();
        address.push_str(&port.clone());
        let payload = create_p2p_message(pk.clone(), sk.clone(), "READYREADY");
        // sleep some random time between 5 and 8 seconds to not overflow the network
        let dur = tokio::time::Duration::from_secs(five_to_eight);
        tokio::time::sleep(dur).await;

        if let Err(e) = socket.send_to(&payload, address).await {
            log::error!("ready message dispatch failed: {:?}", e);
        }
    }
}

pub async fn spawn_io_listeners(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    val_set: Vec<String>,
    root_hash: String,
) -> (
    String,
    MessagePeerHandle,
    UnboundedReceiver<UpgradedPeerData>,
) {
    // out channels correpond to communication outside the host, i.e. with other peers
    let (tx_out, rx_out): (Sender<FromServerEvent>, Receiver<FromServerEvent>) = mpsc::channel(500);
    let tx_out_2 = tx_out.clone();
    // in channels correspond to communication within the host, i.e. deals with payloads received
    let (tx_in, rx_in): (Sender<PayloadEvent>, Receiver<PayloadEvent>) = mpsc::channel(500);
    let tx_in_2 = tx_in.clone();

    let (tx_ug, rx_ug): (
        UnboundedSender<UpgradedPeerData>,
        UnboundedReceiver<UpgradedPeerData>,
    ) = mpsc::unbounded_channel();
    // sempahores
    let notif = Arc::new(Notify::new());
    let notif1 = notif.clone();
    let notif2 = notif.clone();

    // peer loop
    tokio::spawn(async move {
        // semaphore moved to loop to make setup is completed before giving green light
        spawn_peer_listeners(pk, sk, rx_out, rx_in, notif1).await;
    });
    // new connections loop
    tokio::spawn(async move {
        spawn_server_accept_loop(tx_out, tx_in, tx_ug, val_set, notif2, root_hash).await;
    });
    // stop sign, wait for green light
    notif.notified().await;
    notif.notified().await;

    let mph = MessagePeerHandle::new(tx_out_2, tx_in_2);
    // receive answer from backend on which port the new conn loop listens to
    let port = mph.get_host_port().await;

    (port, mph, rx_ug)
}
