#![allow(unused)]

use super::client_handle::{spawn_peer_listeners, MessagePeerHandle};
use super::mdns::{spawn_peer_discovery_loop, ValidatedPeer};
use super::server_handle::spawn_server_accept_loop;
use super::{InternalMessage, OrdPayload, PayloadEvent};
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::oneshot::error::TryRecvError;
use tokio::task::JoinHandle;

pub struct Networking(MessagePeerHandle);

impl Networking {
    pub fn new(handle: MessagePeerHandle) -> Self {
        Self { 0: handle }
    }

    pub async fn send_payload_to(
        &self,
        payload: String,
        recipient: mio::Token,
    ) -> Result<usize, TryRecvError> {
        Ok(self
            .0
            .send_payload(payload.into_bytes(), recipient)
            .await
            .try_recv()?)
    }

    pub async fn get_messages_from(
        &self,
        target: mio::Token,
    ) -> Result<Vec<OrdPayload>, TryRecvError> {
        Ok(self.0.send_get(target).await.try_recv()?)
    }
}

pub struct NetworkIoHandlers {
    message_handle: MessagePeerHandle,
    peer_join: JoinHandle<()>,
    inbox_join: JoinHandle<()>,
    server_join: JoinHandle<()>,
}

impl NetworkIoHandlers {
    pub async fn get_port(&self) -> String {
        self.message_handle.get_host_port().await
    }
    pub fn get_peer_join_handle(self) -> JoinHandle<()> {
        self.peer_join
    }
    pub fn get_inbox_join_handle(self) -> JoinHandle<()> {
        self.inbox_join
    }
    pub fn get_server_join_handle(self) -> JoinHandle<()> {
        self.server_join
    }
}

pub async fn spawn_network_io_listeners(validator_list: Vec<String>) -> NetworkIoHandlers {
    // out channels correpond to communication outside the host, i.e. with other peers
    let (tx_out, rx_out): (Sender<InternalMessage>, Receiver<InternalMessage>) = mpsc::channel(64);
    let tx_out_2 = tx_out.clone();

    // in channels correspond to communication within the host, i.e. deals with payloads received
    let (tx_in, rx_in): (Sender<PayloadEvent>, Receiver<PayloadEvent>) = mpsc::channel(64);
    let tx_in_2 = tx_in.clone();

    let (message_handle, peer_join, inbox_join) =
        spawn_peer_listeners(tx_out, rx_out, tx_in, rx_in).await;

    let server_join = spawn_server_accept_loop(validator_list, tx_out_2, tx_in_2).await;

    NetworkIoHandlers {
        message_handle,
        peer_join,
        inbox_join,
        server_join,
    }
}

pub async fn spawn_peer_discovery_listener(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    server_port: String,
    validator_list: Vec<String>,
) -> (Receiver<ValidatedPeer>, JoinHandle<()>) {
    let (tx_peer_discv, rx_peer_discv): (Sender<ValidatedPeer>, Receiver<ValidatedPeer>) =
        mpsc::channel(8);

    let join = spawn_peer_discovery_loop(pk, sk, server_port, tx_peer_discv, validator_list).await;

    (rx_peer_discv, join)
}
