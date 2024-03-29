use super::discovery::{create_rnd_number, spawn_peer_discovery_loop, ValidatedPeer};
use super::{FromServerEvent, PayloadEvent, PeerStreamHandle, UpgradedPeerData};
use crate::client_handle::{spawn_peer_listeners, MessagePeerHandle};
use crate::common::create_p2p_message;
use crate::message::FixedHandshakes;
use crate::peer::peer_handshake_loop;
use crate::server_handle::spawn_server_accept_loop;
use crate::utils::{any_udp_socket, get_tcp_and_addr};
use std::convert::TryInto;
use std::sync::Arc;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::{
    mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender},
    Notify,
};

pub struct Networking {
    // List of (presumably) connected and validated peers which the client can communicate with
    peers: Vec<PeerStreamHandle>,
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

    pub fn set_peers(&mut self, p: Vec<PeerStreamHandle>) {
        self.peers = p;
    }

    pub fn set_handler(&mut self, h: MessagePeerHandle) {
        self.handle = Some(h);
    }

    pub fn get_registered_peers(&self) -> Vec<PeerStreamHandle> {
        self.peers.clone()
    }

    pub fn get_handle(&self) -> MessagePeerHandle {
        if self.handle.is_none() {
            panic!("handle setup not done correctly, this should not happen");
        }
        self.handle.clone().unwrap()
    }
}

pub async fn spawn_handshake_loop(_upgraded: Vec<UpgradedPeerData>) {}

// spawn_peer_discovery_listener finds the other peers on the same network.
// It needs to know the host handshake loop to tell other peers to speak with it there.
// This port is received by a successful call to `spawn_io_listeners`.
// When it has discovered all peers, it returns all [port, public_key] pairs.
pub async fn spawn_peer_discovery_listener(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    backend_port: String,
    mut validator_list: Vec<String>,
    mut ug_rx: UnboundedReceiver<UpgradedPeerData>,
) -> Vec<PeerStreamHandle> {
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

    let (tcp_listener, handshake_port) = get_tcp_and_addr().await;
    let tcp_listener = Arc::new(tcp_listener);

    // the backend port needs to be passed to both the discovery listener and upgrade step
    let b = backend_port.clone();
    let join = tokio::spawn(async move {
        spawn_peer_discovery_loop(
            public_key,
            secret_key,
            b,
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
    let b = backend_port.clone();
    let join = tokio::spawn(async move { ready_to_connect(public_key, secret_key, pf, b).await });

    let _ = join.await;

    while let Some(msg) = kill_rx.recv().await {
        if msg == true {
            log::debug!("kill signal received, discovery over");
            not.notify_one();
            break;
        }
    }

    not.notified().await;
    let pf = peers_found.clone();
    let pk1 = pk.clone();
    let sk1 = sk.clone();
    let join =
        tokio::spawn(async move { upgrade_server_backend(pk1, sk1, pf, backend_port).await });

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

    let fix_handshakes =
        FixedHandshakes::new(pk.clone(), handshake_port.clone(), sk.clone()).unwrap();
    let mut peer_handles: Vec<PeerStreamHandle> = Vec::new();
    let mut err_channels: Vec<mpsc::Receiver<String>> = Vec::new();
    // spawn listeners for each peer
    for peer in ug_peers.iter() {
        let listener = tcp_listener.clone();
        let other_peer_key = peer.key_type();

        // spawn handshake loop for each (upgraded) peer
        let (send_api, recv_err) = peer_handshake_loop(
            Some(listener),
            other_peer_key.clone(),
            None,
            None,
            fix_handshakes.clone(),
            false,
        )
        .await;
        let p = PeerStreamHandle(peer.clone(), send_api);
        peer_handles.push(p);
        err_channels.push(recv_err);
    }

    log::info!("full upgrade of peer protocol done");
    peer_handles
}

async fn upgrade_server_backend(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    peers: Vec<ValidatedPeer>,
    backend_port: String,
) {
    let socket = any_udp_socket().await;

    for i in 0..2 * peers.len() {
        let port = peers[i % peers.len()].backend_port();
        let address = create_peer_address(port);

        let mut msg = "UPGRD".to_string();
        msg.push_str(&backend_port);
        let payload = create_p2p_message(pk.clone(), sk.clone(), &msg);

        let random_num = create_rnd_number(4, 10).try_into().unwrap();
        // sleep some random time between to not overflow the network
        let dur = tokio::time::Duration::from_secs(random_num);
        tokio::time::sleep(dur).await;

        if let Err(e) = socket.send_to(&payload, address).await {
            log::error!("failed to send upgrade message: {:?}", e);
        }
    }
}

async fn ready_to_connect(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    peers: Vec<ValidatedPeer>,
    backend_port: String,
) {
    log::info!("peer ready for connect phase");
    let five_to_eight = create_rnd_number(5, 9).try_into().unwrap();
    let socket = any_udp_socket().await;

    for i in 0..peers.len() {
        let address = create_peer_address(peers[i].disc_port());
        let mut msg = "READY".to_string();
        msg.push_str(&backend_port);
        let payload = create_p2p_message(pk.clone(), sk.clone(), &msg);
        // sleep some random time between 5 and 8 seconds to not overflow the network
        let dur = tokio::time::Duration::from_secs(five_to_eight);
        tokio::time::sleep(dur).await;

        if let Err(e) = socket.send_to(&payload, address).await {
            log::error!("ready message dispatch failed: {:?}", e);
        }
    }
}

fn create_peer_address(port: String) -> String {
    let mut address = "127.0.0.1:".to_string();
    address.push_str(&port);
    address
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

    let public = pk.clone();
    let secret = sk.clone();
    // peer loop
    tokio::spawn(async move {
        // semaphore moved to loop to make sure setup is completed before giving green light
        spawn_peer_listeners(public, secret, rx_out, rx_in, notif1).await;
    });
    // new connections loop
    tokio::spawn(async move {
        spawn_server_accept_loop(tx_out, tx_in, tx_ug, val_set, notif2, root_hash, pk, sk).await;
    });
    // stop sign, wait for green light
    notif.notified().await;
    notif.notified().await;

    let mph = MessagePeerHandle::new(tx_out_2, tx_in_2);
    // receive answer from backend on which port the new conn loop listens to
    let port = mph.get_host_port().await;

    (port, mph, rx_ug)
}
