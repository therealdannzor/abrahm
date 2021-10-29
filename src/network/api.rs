#![allow(unused)]

use super::client_handle::MessagePeerHandle;
use super::mdns::{spawn_peer_discovery_loop, ValidatedPeer};
use super::{InternalMessage, OrdPayload, PayloadEvent};
use std::sync::Arc;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    oneshot::error::TryRecvError,
    Notify,
};
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
    pub peer_join: JoinHandle<()>,
    pub server_join: JoinHandle<()>,
}

pub async fn spawn_peer_discovery_listener(
    pk: EcdsaPublicKey,
    sk: EcdsaPrivateKey,
    server_port: String,
    validator_list: Vec<String>,
) -> Receiver<ValidatedPeer> {
    let (tx_peer_discv, rx_peer_discv): (Sender<ValidatedPeer>, Receiver<ValidatedPeer>) =
        mpsc::channel(8);

    let join = tokio::spawn(async move {
        spawn_peer_discovery_loop(pk, sk, server_port, tx_peer_discv, validator_list).await
    });

    join.await;

    rx_peer_discv
}
