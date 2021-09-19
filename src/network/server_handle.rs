#![allow(unused)]

use super::tcp_utils::{handle_client_event, next_token, open_socket};
use super::{FromServerEvent, ToServerEvent};
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use std::{
    collections::{HashMap, VecDeque},
    io,
};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct ToServerHandle {
    tx: Sender<ToServerEvent>,
}

impl ToServerHandle {
    pub fn new(tx: Sender<ToServerEvent>) -> Self {
        Self { tx }
    }

    // server inbound message of:
    // (1) a new client connection; or
    // (2) an error message of a failed upstream
    pub async fn send(&mut self, message: ToServerEvent) {
        if self.tx.send(message).await.is_err() {
            panic!("there is no event loop running!");
        }
    }
}

pub struct FromServerHandle {
    rx: Receiver<FromServerEvent>,
}

impl FromServerHandle {
    pub fn new(rx: Receiver<FromServerEvent>) -> Self {
        Self { rx }
    }

    // server outbound messages (tuples) of `Token` (id) and `Vec<u8>` (payload)
    pub async fn receive(&mut self) -> FromServerEvent {
        self.rx.recv().await.unwrap()
    }
}

pub fn spawn_event_listener() -> (ToServerHandle, FromServerHandle, JoinHandle<()>) {
    let (send_ts, recv_ts): (Sender<ToServerEvent>, Receiver<ToServerEvent>) = channel(32);
    let (send_fs, recv_fs): (Sender<FromServerEvent>, Receiver<FromServerEvent>) = channel(32);
    let ts_handle = ToServerHandle::new(send_ts);
    let fs_handle = FromServerHandle::new(recv_fs);
    let join = tokio::spawn(async move {
        let res = match event_loop(recv_ts, send_fs).await {
            Ok(()) => {}
            Err(e) => {
                panic!("event loop failed: {:?}", e);
            }
        };
    });

    (ts_handle, fs_handle, join)
}

const ECDSA_PUB_KEY_SIZE_BITS: usize = 90;
const MESSAGE_SIZE: usize = 256; // TODO: assert proper size
async fn event_loop(
    recv: Receiver<ToServerEvent>,
    tx: Sender<FromServerEvent>,
) -> Result<(), io::Error> {
    const PEER_TOKEN: Token = Token(0);
    const SERVER_TOKEN: Token = Token(1024);

    let mut unique_token = Token(PEER_TOKEN.0 + 1);
    let mut connections: HashMap<Token, TcpStream> = HashMap::new();
    let mut poller = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut mailbox: HashMap<Token, VecDeque<String>> = HashMap::new();

    // create listening server and register it will poll to receive events
    let mut server = open_socket();
    let port = server.local_addr().unwrap().port();
    let _ = poller
        .registry()
        .register(&mut server, SERVER_TOKEN, Interest::READABLE);

    loop {
        poller.poll(&mut events, /* no timeout */ None)?;

        for event in events.iter() {
            match event.token() {
                SERVER_TOKEN => loop {
                    let (mut conn, _address) = match server.accept() {
                        Ok((conn, _address)) => (conn, _address),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // this is normal, try again
                            break;
                        }
                        Err(e) => {
                            // something went really wrong
                            return Err(e);
                        }
                    };

                    let new_friend_token = next_token(&mut unique_token);
                    let _ =
                        poller
                            .registry()
                            .register(&mut conn, new_friend_token, Interest::WRITABLE);
                    connections.insert(new_friend_token, conn);
                },
                client_token => loop {
                    // maybe we have an event
                    let _done = if let Some(conn) = connections.get_mut(&client_token) {
                        let resp = handle_client_event(conn, event, None);
                        if resp.is_ok() {
                            tx.send(FromServerEvent::Message(client_token, resp.unwrap()));
                        }
                        true
                    } else {
                        // false alarm, no event, just ignore
                        false
                    };
                },
            }
        }
    }

    Ok(())
}
