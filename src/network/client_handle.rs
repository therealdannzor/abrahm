#![allow(unused)]

use super::event_loop::ServerHandle;
use super::{FromServerEvent, ToServerEvent};
use mio::net::{SocketAddr, TcpStream};
use std::default::Default;
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct ClientHandle {
    id: EcdsaPublicKey,
    ip: SocketAddr,
    chan: Sender<FromServerEvent>,
    kill: JoinHandle<()>,
}

// A handle used by the server to communicate with the client
impl ClientHandle {
    pub fn new(
        id: EcdsaPublicKey,
        ip: SocketAddr,
        chan: Sender<FromServerEvent>,
        kill: JoinHandle<()>,
    ) -> Self {
        Self { id, ip, chan, kill }
    }

    // send a message to this client actor
    pub fn send(&mut self, msg: FromServerEvent) -> Result<(), std::io::Error> {
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

// ClientData contains internal data needed to by this actor to communicate with a client
struct ClientData {
    id: EcdsaPublicKey,
    handle: ServerHandle,
    chan: Receiver<FromServerEvent>,
    stream: TcpStream,
}

pub fn spawn_client_actor(
    id: EcdsaPublicKey,
    socket: SocketAddr,
    handle: ServerHandle,
    stream: TcpStream,
) {
    let (send, recv): (Sender<FromServerEvent>, Receiver<FromServerEvent>) = mpsc::channel(32);
    let cd = ClientData {
        id,
        handle: handle.clone(),
        chan: recv,
        stream,
    };

    let (oneshot_tx, oneshot_rx): (
        oneshot::Sender<ClientHandle>,
        oneshot::Receiver<ClientHandle>,
    ) = oneshot::channel();
    let kill = 1;
}

async fn client_actor(oneshot_rx: oneshot::Receiver<ClientHandle>, mut data: ClientData) {
    let oneshot_rx = match oneshot_rx.await {
        Ok(handle) => handle,
        Err(_) => return,
    };
    data.handle.send(ToServerEvent::NewClient(oneshot_rx));
}
