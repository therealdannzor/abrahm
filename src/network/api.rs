use super::mdns::{spawn_peer_discovery_loop, ValidatedPeer};
use super::{InternalMessage, OrdPayload, PayloadEvent};
use crate::network::client_handle::{spawn_peer_listeners, MessagePeerHandle};
use crate::network::server_handle::spawn_server_accept_loop;
use std::sync::Arc;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    oneshot::error::TryRecvError,
    Notify,
};

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
    validator_list: Vec<String>,
) -> Vec<ValidatedPeer> {
    let (tx_peer_discv, mut rx_peer_discv): (Sender<ValidatedPeer>, Receiver<ValidatedPeer>) =
        mpsc::channel(8);

    // subtract by one because we have already discovered ourself, by definition
    let amount_to_validate = validator_list.len() - 1;

    let join = tokio::spawn(async move {
        spawn_peer_discovery_loop(pk, sk, server_port, tx_peer_discv, validator_list.clone()).await
    });

    let _ = join.await;

    let mut peers_found: Vec<ValidatedPeer> = Vec::new();
    while let Some(msg) = rx_peer_discv.recv().await {
        peers_found.push(msg);
        if peers_found.len() == amount_to_validate {
            break;
        }
    }

    log::info!("returning a list of the discovered peers");
    peers_found
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
