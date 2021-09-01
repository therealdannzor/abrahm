#![allow(unused)]

use super::client_handle::ClientHandle;
use log::info;
use mio::net::{TcpListener, TcpStream};
use mio::{event::Event, Events, Interest, Poll, Registry, Token};
use std::{
    collections::{HashMap, VecDeque},
    default::Default,
    io,
    io::prelude::*,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::from_utf8,
};
use themis::keys::EcdsaPublicKey;
use tokio::sync::mpsc::{channel, error::SendError, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

// InboundMessage holds the different message types which are sent to the server.
// This includes both events from clients connecting but also internal events.
pub enum InboundMessage {
    OpenPort { response: oneshot::Sender<u16> },

    NewClient(EcdsaPublicKey, TcpListener, oneshot::Sender<Token>),
    ToClient(Token, Vec<u8>),
    ErrorMessage(io::Error),
}

pub struct ServerHandle {
    tx: Sender<InboundMessage>,
}

impl ServerHandle {
    pub fn new(tx: Sender<InboundMessage>) -> Self {
        Self { tx }
    }

    pub async fn expose_port(&self) -> Option<u16> {
        let (send, receive) = oneshot::channel();
        let msg = InboundMessage::OpenPort { response: send };
        if self.tx.send(msg).await.is_err() {
            return None;
        }
        Some(receive.await.unwrap())
    }

    pub async fn new_client(
        &self,
        key: EcdsaPublicKey,
        listener: TcpListener,
    ) -> Result<Token, io::Error> {
        let (send, receive) = oneshot::channel();
        let msg = InboundMessage::NewClient(key, listener, send);
        if self.tx.send(msg).await.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "new client send message field",
            ));
        }
        Ok(receive.await.unwrap())
    }
    pub fn spawn_event_listener() -> (ServerHandle, JoinHandle<()>) {
        let (send, recv) = channel(32);
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
}

const PEER_TOKEN: Token = Token(0);
const SERVER_TOKEN: Token = Token(1024);
const ECDSA_PUB_KEY_SIZE_BITS: usize = 90;
const MESSAGE_SIZE: usize = 256; // TODO: assert proper size

async fn event_loop(mut recv: Receiver<InboundMessage>) -> Result<(), io::Error> {
    let mut unique_token = Token(PEER_TOKEN.0 + 1);
    let mut connections: HashMap<Token, TcpStream> = HashMap::new();
    let mut poller = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut identities: HashMap<Token, EcdsaPublicKey> = HashMap::new();
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
                        let resp = handle_client_event(poller.registry(), conn, event, None);
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

fn handle_client_event(
    registry: &Registry,
    connection: &mut TcpStream,
    event: &Event,
    payload: Option<&[u8]>,
) -> io::Result<Vec<u8>> {
    let mut result: Vec<u8> = Vec::new();

    if event.is_writable() && payload.is_some() {
        let data = payload.unwrap();
        write_stream_data(connection, data);
    } else if event.is_readable() {
        result = read_stream_data(connection).unwrap();
    }

    Ok(result)
}

fn open_socket() -> TcpListener {
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let socket = SocketAddr::new(loopback, 1024);

    let mut srv = match TcpListener::bind(socket) {
        Ok(s) => s,
        Err(e) => panic!("could not bind socket, error: {:?}", e),
    };

    srv
}

// Updates the token to make sure we have unique ones for each stream.
fn next_token(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}

// Checks our receive buffer whether there is something to read.
// If this is true, we remove it from the buffer and log it to the user.
// If this is false, we do nothing.
fn check_bytes_read(mut amount: usize, recv: &mut Vec<u8>) -> Option<&[u8]> {
    if amount != 0 {
        let recv = &recv[..amount];
        if let Ok(buf) = from_utf8(recv) {
            let trimmed = buf.trim_end();
            info!("received data: {}", buf.trim_end());
            Some(recv)
        } else {
            info!("received (non utf-8) data: {:?}", recv);
            None
        }
    } else {
        None
    }
}

fn write_stream_data(connection: &mut TcpStream, data: &[u8]) -> io::Result<bool> {
    match connection.write(data) {
        Ok(n) if n < data.len() => return Err(io::ErrorKind::WriteZero.into()),
        Ok(_) => {
            return Ok(true);
        }
        // We are not ready yet
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            return Ok(false);
        }
        // We can work around this by trying again
        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
            return write_stream_data(connection, data)
        }
        // Unexpected errors that are undesired
        Err(e) => return Err(e),
    }
}

fn read_stream_data(connection: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut conn_closed = false;
    let mut rcv_dat = vec![0, 255];
    let mut bytes_read = 0;
    let mut result: Vec<u8> = Vec::new();

    loop {
        match connection.read(&mut rcv_dat[bytes_read..]) {
            Ok(0) => {
                conn_closed = true;
                break;
            }
            Ok(n) => {
                bytes_read += n;
                if bytes_read == rcv_dat.len() {
                    rcv_dat.resize(rcv_dat.len() + 1024, 0);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    let octs = check_bytes_read(bytes_read, &mut rcv_dat);
    if octs.is_none() {
        return Ok(result);
    } else {
        result = octs.unwrap().to_vec();
    }

    if conn_closed {
        info!("connection closed");
    }
    Ok(result)
}
