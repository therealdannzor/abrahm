#![allow(unused)]

use super::client_handle::{spawn_peer_listeners, MessagePeerHandle};
use super::server_handle::spawn_server_accept_loop;
use super::{InternalMessage, OrdPayload, PayloadEvent};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::oneshot::{self, error::TryRecvError};
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

pub async fn spawn_network_io_listeners(
    validator_list: Vec<String>,
) -> (
    MessagePeerHandle,
    JoinHandle<()>,
    JoinHandle<()>,
    JoinHandle<()>,
) {
    // out channels correpond to communication outside the host, i.e. with other peers
    let (tx_out, rx_out): (Sender<InternalMessage>, Receiver<InternalMessage>) = mpsc::channel(64);
    let tx_out_2 = tx_out.clone();

    // in channels correspond to communication within the host, i.e. deals with payloads received
    let (tx_in, rx_in): (Sender<PayloadEvent>, Receiver<PayloadEvent>) = mpsc::channel(64);
    let tx_in_2 = tx_in.clone();

    let join_server = spawn_server_accept_loop(validator_list, tx_out_2, tx_in_2).await;

    let (message_peer_handle, join_peer, join_inbox) =
        spawn_peer_listeners(tx_out, rx_out, tx_in, rx_in).await;

    (message_peer_handle, join_server, join_peer, join_inbox)
}
