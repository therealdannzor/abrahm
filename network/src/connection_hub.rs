#![allow(dead_code)]
use crate::utils::get_tcp_and_addr;
use crate::UpgradedPeerData;
use std::sync::Mutex;
use themis::keys::EcdsaPublicKey;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Receiver;

// Hub orchestrates connections and peers, responsible for driving the network protocol
pub struct Hub {
    // List of peers: found and upgraded
    peers: Vec<UpgradedPeerData>,

    local_peer: UpgradedPeerData,

    // If the node is processing, it will need to finish
    // before beginning to transmit messages again
    running: Mutex<bool>,

    listener: TcpListener,

    // Channel to add new trusted peers
    add_trusted_peer: Receiver<UpgradedPeerData>,

    // State of the type of connections being made
    state: Mutex<usize>,
}

impl Hub {
    pub async fn new(
        peers: Vec<UpgradedPeerData>,
        local_key: EcdsaPublicKey,
        add_trusted_peer: Receiver<UpgradedPeerData>,
    ) -> Self {
        let (listener, port) = get_tcp_and_addr().await;
        let local_peer = UpgradedPeerData(local_key, port, 0);
        Self {
            peers,
            local_peer,
            running: Mutex::new(false),
            listener,
            add_trusted_peer,
            state: Mutex::new(0),
        }
    }

    fn add_peer(&mut self, p: UpgradedPeerData) {
        self.peers.push(p);
    }

    pub fn count_peers(&self) -> usize {
        self.peers.len()
    }

    pub fn peers(&self) -> Vec<UpgradedPeerData> {
        self.peers.clone()
    }

    pub fn local_peer(&self) -> UpgradedPeerData {
        self.local_peer.clone()
    }
}
