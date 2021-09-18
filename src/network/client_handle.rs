#![allow(unused)]

use super::event_loop::ServerHandle;
use super::{FromServerEvent, ToServerEvent};
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};
use std::default::Default;
use std::io;
use std::net::SocketAddr;
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct ClientHandle {
    id: Token,
    socket: SocketAddr,
    chan: Sender<FromServerEvent>,
    kill: JoinHandle<()>,
}

// A handle used by the server to communicate with the client
impl ClientHandle {
    pub fn new(
        id: Token,
        socket: SocketAddr,
        chan: Sender<FromServerEvent>,
        kill: JoinHandle<()>,
    ) -> Self {
        Self {
            id,
            socket,
            chan,
            kill,
        }
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
    id: Token,
    handle: ServerHandle,
    chan: Receiver<FromServerEvent>,
    stream: TcpStream,
}

pub async fn open_client_factory(id: Token, socket: SocketAddr, mut handle: ServerHandle) {
    match client_factory_loop(id, socket, handle.clone()) {
        Ok(()) => {}
        Err(e) => {
            handle.send(ToServerEvent::FatalError(e)).await;
        }
    }
}

fn client_factory_loop(
    id: Token,
    socket: SocketAddr,
    handle: ServerHandle,
) -> Result<(), io::Error> {
    let listen = TcpListener::bind(socket)?;

    loop {
        let (tcp_connection, socket_addr) = listen.accept()?;
        spawn_client_actor(id, socket_addr, handle.clone(), tcp_connection);
    }
}

fn spawn_client_actor(id: Token, socket: SocketAddr, handle: ServerHandle, stream: TcpStream) {
    let (mpsc_tx, mpsc_rx): (Sender<FromServerEvent>, Receiver<FromServerEvent>) =
        mpsc::channel(32);
    let cd = ClientData {
        id: id.clone(),
        handle: handle.clone(),
        chan: mpsc_rx,
        stream,
    };

    let (oneshot_tx, oneshot_rx): (
        oneshot::Sender<ClientHandle>,
        oneshot::Receiver<ClientHandle>,
    ) = oneshot::channel();
    let kill = tokio::spawn(client_actor(oneshot_rx, cd));

    let handle = ClientHandle::new(id, socket, mpsc_tx, kill);

    let _ = oneshot_tx.send(handle);
}

async fn client_actor(oneshot_rx: oneshot::Receiver<ClientHandle>, mut data: ClientData) {
    let oneshot_rx = match oneshot_rx.await {
        Ok(handle) => handle,
        Err(_) => return,
    };

    // send a receiver part to the server to receive events from the client
    data.handle.send(ToServerEvent::NewClient(oneshot_rx)).await;

    match client_worker(data).await {
        Ok(()) => {}
        Err(e) => eprintln!("this should not happen: {}", e),
    }
}

async fn client_worker(mut data: ClientData) -> Result<(), std::io::Error> {
    let mut poller = Poll::new()?;
    let mut events = Events::with_capacity(256);
    Ok(())
}
