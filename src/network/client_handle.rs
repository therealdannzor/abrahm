#![allow(unused)]

use mio::net::{SocketAddr, TcpStream};
use std::default::Default;
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub enum ActorMessage {}

#[derive(Debug)]
pub struct ClientHandle {
    id: EcdsaPublicKey,
    ip: SocketAddr,
    chan: Sender<ActorMessage>,
    kill: JoinHandle<()>,
}

impl ClientHandle {
    pub fn new(
        id: EcdsaPublicKey,
        ip: SocketAddr,
        chan: Sender<ActorMessage>,
        kill: JoinHandle<()>,
    ) -> Self {
        Self { id, ip, chan, kill }
    }

    pub fn send(&mut self, msg: ActorMessage) -> Result<(), std::io::Error> {
        if self.chan.try_send(msg).is_err() {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "channel disconnected or full buffer",
            ))
        } else {
            Ok(())
        }
    }

    pub fn kill(self) {
        drop(self);
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        self.kill.abort()
    }
}
