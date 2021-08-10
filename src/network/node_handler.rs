#![allow(unused)]

use super::node_actor::{run_actor, ActorMessage, NodeActor};
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};

#[derive(Clone)]
pub struct NodeActorHandler {
    sender: tokio_mpsc::Sender<ActorMessage>,
}

impl NodeActorHandler {
    pub fn new(id: EcdsaPublicKey, cap: usize) -> Self {
        let (sender, receiver) = tokio_mpsc::channel(cap);
        let actor = NodeActor::new(id, cap, receiver);
        tokio::spawn(run_actor(actor));
        Self { sender }
    }

    pub async fn expose_port(&self) -> bool {
        let (sender, receiver) = oneshot::channel();
        let msg = ActorMessage::OpenPort { response: sender };
        let _ = self.sender.send(msg).await;
        receiver.await.expect("task cancelled")
    }

    pub async fn get_unique_port(&self) -> u16 {
        let (sender, receiver) = oneshot::channel();
        let msg = ActorMessage::GetPort { response: sender };
        let _ = self.sender.send(msg).await;
        receiver.await.expect("task cancelled")
    }
}
