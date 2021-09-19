#![allow(unused)]

use super::client_handle::ClientHandle;
use super::tcp_utils::{handle_client_event, next_token, open_socket};
use super::ToServerEvent;
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Registry, Token};
use std::{
    collections::{HashMap, VecDeque},
    default::Default,
    io,
    io::prelude::*,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::from_utf8,
};
use tokio::sync::mpsc::{channel, error::SendError, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct ServerHandle {
    tx: Sender<ToServerEvent>,
}

impl ServerHandle {
    pub fn new(tx: Sender<ToServerEvent>) -> Self {
        Self { tx }
    }

    // send is used to signal an alert the server of:
    // (1) a new client connection; or
    // (2) a message from a known client
    pub async fn send(&mut self, message: ToServerEvent) {
        if self.tx.send(message).await.is_err() {
            panic!("there is no event loop running!");
        }
    }
}

pub fn spawn_event_listener() -> (ServerHandle, JoinHandle<()>) {
    let (send, recv): (Sender<ToServerEvent>, Receiver<ToServerEvent>) = channel(32);
    let handle = ServerHandle::new(send);
    let join = tokio::spawn(async move {
        let res = match event_loop(recv).await {
            Ok(()) => {}
            Err(e) => {
                panic!("event loop failed: {:?}", e);
            }
        };
    });

    (handle, join)
}

const PEER_TOKEN: Token = Token(0);
const SERVER_TOKEN: Token = Token(1024);
const ECDSA_PUB_KEY_SIZE_BITS: usize = 90;
const MESSAGE_SIZE: usize = 256; // TODO: assert proper size

async fn event_loop(mut recv: Receiver<ToServerEvent>) -> Result<(), io::Error> {
    let mut unique_token = Token(PEER_TOKEN.0 + 1);
    let mut connections: HashMap<Token, TcpStream> = HashMap::new();
    let mut poller = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut client_handle: HashMap<Token, ClientHandle> = HashMap::new();
    let mut mailbox: HashMap<Token, VecDeque<String>> = HashMap::new();

    // create listening server and register it will poll to receive events
    let mut server = open_socket();
    let port = server.local_addr().unwrap().port();
    poller
        .registry()
        .register(&mut server, SERVER_TOKEN, Interest::READABLE);

    loop {
        poller.poll(&mut events, /* no timeout */ None)?;

        for event in events.iter() {
            match event.token() {
                SERVER_TOKEN => loop {
                    let (mut conn, address) = match server.accept() {
                        Ok((conn, address)) => (conn, address),
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
                    poller
                        .registry()
                        .register(&mut conn, new_friend_token, Interest::WRITABLE);
                    connections.insert(new_friend_token, conn);
                },
                client_token => loop {
                    // maybe we have an event
                    let done = if let Some(conn) = connections.get_mut(&client_token) {
                        let resp = handle_client_event(conn, event, None);
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
